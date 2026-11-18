package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/agenthub"
	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/orchestrator/tls"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

type adoptFixture struct {
	srv      *Server
	db       *db.DB
	hub      *agenthub.Hub
	handler  http.Handler
	cookie   *http.Cookie
	agentTok string
	domainID string
	issuer   *lockingIssuer
}

// newAdoptFixture seeds a central-TLS domain app.example.com served by agent-1
// and a second agent, agent-2, that serves nothing.
func newAdoptFixture(t *testing.T) *adoptFixture {
	t.Helper()
	srv, database := testServer(t)
	hub := agenthub.New()
	srv.SetAgentHub(hub, &stubPusher{hub: hub})
	issuer := &lockingIssuer{}
	srv.SetCertIssuer(issuer)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)
	tok := makeAgent(t, database, "agent-1", "edge1.example.com", models.AgentStatusAdopted, nil)
	makeAgent(t, database, "agent-2", "edge2.example.com", models.AgentStatusAdopted, nil)

	database.CreateProvider(&models.Provider{ID: "prov-1", Type: "cloudflare", Name: "CF", Config: `{"api_token":"test"}`})
	database.CreateZone(&models.Zone{ID: "zone-1", ProviderID: "prov-1", ExternalID: "ext-1", Name: "example.com"})
	database.CreateServer(&models.Server{ID: "srv-1", AgentID: "agent-1", Name: "S1", Address: "10.0.0.1"})
	dom := &models.Domain{Subdomain: "app", ZoneID: "zone-1", ServerID: "srv-1", Port: 80, SSLMode: models.SSLModeAuto, Status: models.DomainStatusActive}
	if err := database.CreateDomain(dom); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	return &adoptFixture{srv: srv, db: database, hub: hub, handler: handler, cookie: cookie, agentTok: tok,
		domainID: strconv.FormatInt(dom.ID, 10), issuer: issuer}
}

// report stores a detection for agentID listing certs.
func (f *adoptFixture) report(t *testing.T, agentID string, certs ...models.DiscoveredCert) {
	t.Helper()
	if err := f.db.UpdateAgentDetection(agentID, &models.ProxyDetection{Installed: true, Kind: "nginx", DiscoveredCerts: certs}); err != nil {
		t.Fatal(err)
	}
}

func discovered(t *testing.T, certPEM string, names ...string) models.DiscoveredCert {
	t.Helper()
	fp, err := tls.LeafFingerprint(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return models.DiscoveredCert{
		Fingerprint: fp, Names: names, Source: "certbot",
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(60 * 24 * time.Hour),
		CertPath: "/etc/letsencrypt/live/app.example.com/fullchain.pem",
		KeyPath:  "/etc/letsencrypt/live/app.example.com/privkey.pem",
	}
}

// adopt starts the adoption in the background and answers the upload request
// the way agent agentID would, using answer to build the upload.
func (f *adoptFixture) adopt(t *testing.T, body map[string]string, answer func(req proxymodel.CertUploadRequest) (string, proxymodel.CertUpload)) *httptest.ResponseRecorder {
	t.Helper()
	events, unsub := f.hub.Subscribe("agent-1")
	defer unsub()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- doRequest(t, f.handler, "POST", "/api/v1/domains/"+f.domainID+"/certificate/adopt", body, f.cookie)
	}()
	for {
		select {
		case w := <-done:
			return w
		case ev := <-events:
			if ev.Type != agenthub.EventCertUploadRequest {
				continue
			}
			var req proxymodel.CertUploadRequest
			if err := json.Unmarshal(ev.Data, &req); err != nil {
				t.Fatal(err)
			}
			if answer == nil {
				continue
			}
			agentID, up := answer(req)
			w := doRequestWithAuth(t, f.handler, "POST", "/api/v1/agents/"+agentID+"/certificates/upload", up, f.agentTok)
			if agentID != "agent-1" {
				if w.Code != http.StatusForbidden {
					t.Errorf("foreign upload status = %d, want 403", w.Code)
				}
				// The real agent then answers so the adoption can finish.
				up.RequestID = req.RequestID
				doRequestWithAuth(t, f.handler, "POST", "/api/v1/agents/agent-1/certificates/upload",
					proxymodel.CertUpload{RequestID: req.RequestID, Fingerprint: req.Fingerprint, Error: "stop"}, f.agentTok)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("adoption did not finish")
		}
	}
}

func TestAdoptDomainCertificate(t *testing.T) {
	appCert, appKey := selfSignedPEM(t, time.Now().Add(60*24*time.Hour), "app.example.com")
	otherCert, otherKey := selfSignedPEM(t, time.Now().Add(60*24*time.Hour), "app.example.com")

	tests := []struct {
		name       string
		reportOn   string // agent reporting the cert; "" = agent-1
		connected  bool
		edit       func(*models.DiscoveredCert)
		body       func(fp string) map[string]string
		answer     func(fp string) func(proxymodel.CertUploadRequest) (string, proxymodel.CertUpload)
		wantStatus int
	}{
		{
			name: "adopts the uploaded bundle", connected: true,
			answer: func(string) func(proxymodel.CertUploadRequest) (string, proxymodel.CertUpload) {
				return func(r proxymodel.CertUploadRequest) (string, proxymodel.CertUpload) {
					return "agent-1", proxymodel.CertUpload{RequestID: r.RequestID, Fingerprint: r.Fingerprint, CertPEM: appCert, KeyPEM: appKey, SourcePath: "/etc/letsencrypt/live/app.example.com/fullchain.pem"}
				}
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "fingerprint with colons and upper case", connected: true,
			body: func(fp string) map[string]string {
				var parts []string
				for i := 0; i < len(fp); i += 2 {
					parts = append(parts, strings.ToUpper(fp[i:i+2]))
				}
				return map[string]string{"fingerprint": strings.Join(parts, ":")}
			},
			answer: func(string) func(proxymodel.CertUploadRequest) (string, proxymodel.CertUpload) {
				return func(r proxymodel.CertUploadRequest) (string, proxymodel.CertUpload) {
					return "agent-1", proxymodel.CertUpload{RequestID: r.RequestID, Fingerprint: r.Fingerprint, CertPEM: appCert, KeyPEM: appKey}
				}
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "agent swaps in another certificate", connected: true,
			answer: func(string) func(proxymodel.CertUploadRequest) (string, proxymodel.CertUpload) {
				return func(r proxymodel.CertUploadRequest) (string, proxymodel.CertUpload) {
					return "agent-1", proxymodel.CertUpload{RequestID: r.RequestID, Fingerprint: r.Fingerprint, CertPEM: otherCert, KeyPEM: otherKey}
				}
			},
			wantStatus: http.StatusBadGateway,
		},
		{
			name: "agent reports an error", connected: true,
			answer: func(string) func(proxymodel.CertUploadRequest) (string, proxymodel.CertUpload) {
				return func(r proxymodel.CertUploadRequest) (string, proxymodel.CertUpload) {
					return "agent-1", proxymodel.CertUpload{RequestID: r.RequestID, Fingerprint: r.Fingerprint, Error: "private key not readable"}
				}
			},
			wantStatus: http.StatusBadGateway,
		},
		{
			name: "another agent cannot answer", connected: true,
			answer: func(string) func(proxymodel.CertUploadRequest) (string, proxymodel.CertUpload) {
				return func(r proxymodel.CertUploadRequest) (string, proxymodel.CertUpload) {
					return "agent-2", proxymodel.CertUpload{RequestID: r.RequestID, Fingerprint: r.Fingerprint, CertPEM: appCert, KeyPEM: appKey}
				}
			},
			wantStatus: http.StatusBadGateway,
		},
		{
			name: "mismatched key is rejected", connected: true,
			answer: func(string) func(proxymodel.CertUploadRequest) (string, proxymodel.CertUpload) {
				return func(r proxymodel.CertUploadRequest) (string, proxymodel.CertUpload) {
					return "agent-1", proxymodel.CertUpload{RequestID: r.RequestID, Fingerprint: r.Fingerprint, CertPEM: appCert, KeyPEM: otherKey}
				}
			},
			wantStatus: http.StatusBadRequest,
		},
		{name: "agent offline", connected: false, wantStatus: http.StatusConflict},
		{name: "not reported", connected: true, body: func(string) map[string]string { return map[string]string{"fingerprint": strings.Repeat("ab", 32)} }, wantStatus: http.StatusNotFound},
		{name: "malformed fingerprint", connected: true, body: func(string) map[string]string { return map[string]string{"fingerprint": "xyz"} }, wantStatus: http.StatusBadRequest},
		{name: "reported with error", connected: true, edit: func(d *models.DiscoveredCert) { d.Error = "private key not readable by the agent: permission denied" }, wantStatus: http.StatusConflict},
		{name: "inside the renew window", connected: true, edit: func(d *models.DiscoveredCert) { d.NotAfter = time.Now().Add(5 * 24 * time.Hour) }, wantStatus: http.StatusConflict},
		{name: "wrong names", connected: true, edit: func(d *models.DiscoveredCert) { d.Names = []string{"other.example.com"} }, wantStatus: http.StatusConflict},
		{name: "explicit agent without the cert", connected: true, body: func(fp string) map[string]string { return map[string]string{"fingerprint": fp, "agent_id": "agent-2"} }, wantStatus: http.StatusNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newAdoptFixture(t)
			dc := discovered(t, appCert, "app.example.com")
			if tc.edit != nil {
				tc.edit(&dc)
			}
			reporter := tc.reportOn
			if reporter == "" {
				reporter = "agent-1"
			}
			f.report(t, reporter, dc)
			body := map[string]string{"fingerprint": dc.Fingerprint}
			if tc.body != nil {
				body = tc.body(dc.Fingerprint)
			}

			var w *httptest.ResponseRecorder
			if tc.connected {
				var answer func(proxymodel.CertUploadRequest) (string, proxymodel.CertUpload)
				if tc.answer != nil {
					answer = tc.answer(dc.Fingerprint)
				}
				w = f.adopt(t, body, answer)
			} else {
				w = doRequest(t, f.handler, "POST", "/api/v1/domains/"+f.domainID+"/certificate/adopt", body, f.cookie)
			}
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.wantStatus, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "PRIVATE KEY") {
				t.Fatal("response leaks private key material")
			}
			stored, err := f.db.GetCertificate("app.example.com")
			if tc.wantStatus != http.StatusOK {
				if err == nil {
					t.Fatal("failed adoption stored a certificate")
				}
				return
			}
			if err != nil {
				t.Fatalf("GetCertificate: %v", err)
			}
			if stored.Source != models.CertSourceImported || stored.CertPEM != appCert {
				t.Errorf("stored source=%q, cert matches=%v", stored.Source, stored.CertPEM == appCert)
			}
			if f.issuer.locked != 1 || f.issuer.unlocked != 1 {
				t.Errorf("host lock taken %d / released %d times, want 1 / 1", f.issuer.locked, f.issuer.unlocked)
			}
			entries, _, err := f.db.ListAuditLog(20, 0)
			if err != nil {
				t.Fatal(err)
			}
			var audited bool
			for _, e := range entries {
				if strings.Contains(e.Details, "PRIVATE KEY") || strings.Contains(e.Details, "BEGIN") {
					t.Errorf("audit entry %q carries PEM material", e.Action)
				}
				if e.Action == "cert_adopted" && e.EntityID == "app.example.com" {
					audited = true
				}
			}
			if !audited {
				t.Error("no cert_adopted audit entry")
			}
		})
	}
}

func TestAgentCertUpload_unsolicitedIsRefused(t *testing.T) {
	f := newAdoptFixture(t)
	w := doRequestWithAuth(t, f.handler, "POST", "/api/v1/agents/agent-1/certificates/upload",
		proxymodel.CertUpload{RequestID: "certup-nope", Fingerprint: strings.Repeat("ab", 32), CertPEM: "x", KeyPEM: "y"}, f.agentTok)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	w = doRequestWithAuth(t, f.handler, "POST", "/api/v1/agents/agent-2/certificates/upload",
		proxymodel.CertUpload{RequestID: "certup-nope"}, "wrong-token")
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("bad token status = %d, want 401/403", w.Code)
	}
}

func TestDomainCertificateCandidates(t *testing.T) {
	f := newAdoptFixture(t)
	appCert, _ := selfSignedPEM(t, time.Now().Add(60*24*time.Hour), "app.example.com")
	wildCert, _ := selfSignedPEM(t, time.Now().Add(60*24*time.Hour), "*.example.com")
	unrelated, _ := selfSignedPEM(t, time.Now().Add(60*24*time.Hour), "mail.other.org")
	serving := discovered(t, appCert, "app.example.com")
	unreadable := discovered(t, wildCert, "*.example.com")
	unreadable.Error = "private key not readable by the agent: permission denied"
	f.report(t, "agent-1", serving, discovered(t, unrelated, "mail.other.org"),
		models.DiscoveredCert{Source: "certbot", CertPath: "/etc/letsencrypt/live", Error: "cannot list directory: permission denied"})
	f.report(t, "agent-2", unreadable)

	w := doRequest(t, f.handler, "GET", "/api/v1/domains/"+f.domainID+"/certificate/candidates", nil, f.cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Host       string          `json:"host"`
		Candidates []certCandidate `json:"candidates"`
		Hints      []certScanHint  `json:"hints"`
		Deferred   *time.Time      `json:"issuance_deferred_until"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Host != "app.example.com" || len(resp.Candidates) != 2 {
		t.Fatalf("resp = %+v, want two candidates for app.example.com", resp)
	}
	first, second := resp.Candidates[0], resp.Candidates[1]
	if !first.Serving || !first.Adoptable || first.Fingerprint != serving.Fingerprint {
		t.Errorf("first candidate = %+v, want the serving agent's adoptable cert", first)
	}
	if second.AgentID != "agent-2" || second.Adoptable || second.Reason == "" {
		t.Errorf("second candidate = %+v, want agent-2's unadoptable cert with a reason", second)
	}
	if len(resp.Hints) != 1 || resp.Hints[0].Path != "/etc/letsencrypt/live" {
		t.Errorf("hints = %+v", resp.Hints)
	}
	if resp.Deferred == nil {
		t.Error("a new domain with an adoptable cert on its agent should report deferred issuance")
	}
}

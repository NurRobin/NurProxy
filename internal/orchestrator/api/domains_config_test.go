package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/reconciler"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// captureHub records the intent sets the reconciler publishes, standing in for
// a connected agent stream so the test can observe exactly what the next push
// would deliver to the agent.
type captureHub struct {
	mu   sync.Mutex
	sets []proxymodel.IntentSet
}

func (h *captureHub) Connected(string) bool                                { return true }
func (h *captureHub) PublishIntents(string, []proxymodel.RouteIntent) bool { return true }

func (h *captureHub) PublishIntentSet(_ string, set proxymodel.IntentSet) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sets = append(h.sets, set)
	return true
}

func (h *captureHub) last() (proxymodel.IntentSet, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.sets) == 0 {
		return proxymodel.IntentSet{}, false
	}
	return h.sets[len(h.sets)-1], true
}

// TestDomainConfig_ResetAndUpdate_resetManualArtifact covers the drift-accept
// trap: once the domain's "dom-<id>" artifact is Source=manual, the reconciler
// pushes its stored bytes verbatim and ignores the domain row, and the agent's
// apply-ACK of those identical bytes hits AppendConfigArtifactVersion's
// semantic-equality gate before the source-updating UPDATE — so the artifact
// stays manual forever. A config reset (or a new manual config) on the domain
// row alone therefore never reaches the agent. Reset/update must also drop the
// manual artifact, after which the next push renders from the domain model.
func TestDomainConfig_ResetAndUpdate_resetManualArtifact(t *testing.T) {
	const staleManual = `{"handle":[{"handler":"static_response","body":"drift-accepted"}]}`
	const newManual = `{"handle":[{"handler":"static_response","body":"new-manual"}]}`

	cases := []struct {
		name         string
		acceptDrift  bool // promote the artifact to Source=manual first
		method       string
		pathSuffix   string // appended to /api/v1/domains/{id}
		body         interface{}
		wantArtifact bool   // artifact row still present after the call
		wantRaw      string // "" = next push must render from the domain model
	}{
		{
			name:        "reset after drift-accept renders from the domain model",
			acceptDrift: true,
			method:      "POST",
			pathSuffix:  "/config/reset",
		},
		{
			name:        "manual update after drift-accept deploys the new bytes",
			acceptDrift: true,
			method:      "PUT",
			pathSuffix:  "/config",
			body:        map[string]json.RawMessage{"config": json.RawMessage(newManual)},
			wantRaw:     newManual,
		},
		{
			name:       "reset removes a stale generated artifact before rendering the model",
			method:     "POST",
			pathSuffix: "/config/reset",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, database := testServer(t)
			h := srv.Handler()
			cookie := setupAdmin(t, h)
			dom := makePreviewDomain(t, srv, "", "")

			artifactID := fmt.Sprintf("dom-%d", dom.ID)
			seedArtifact(t, srv, "a1", artifactID, `{"handle":[]}`)
			if tc.acceptDrift {
				w := doRequest(t, h, "POST", "/api/v1/artifacts/"+artifactID+"/accept",
					map[string]string{"content": staleManual}, cookie)
				if w.Code != http.StatusOK {
					t.Fatalf("accept: %d %s", w.Code, w.Body.String())
				}
				art, err := database.GetConfigArtifact(artifactID)
				if err != nil || art.Source != models.ArtifactSourceManual {
					t.Fatalf("accept did not promote artifact to manual: %+v (%v)", art, err)
				}
			}

			path := fmt.Sprintf("/api/v1/domains/%d%s", dom.ID, tc.pathSuffix)
			w := doRequest(t, h, tc.method, path, tc.body, cookie)
			if w.Code != http.StatusOK {
				t.Fatalf("%s %s: %d %s", tc.method, path, w.Code, w.Body.String())
			}

			_, artErr := database.GetConfigArtifact(artifactID)
			if tc.wantArtifact && artErr != nil {
				t.Fatalf("generated artifact should survive a reset: %v", artErr)
			}
			if !tc.wantArtifact {
				if artErr == nil {
					t.Fatal("manual artifact should be deleted so the next push renders from the domain model")
				}
				assertAuditEntry(t, database, "config_artifact", artifactID, "reset")
			}

			// "Next push": exactly what the reconciler would deliver to the agent now.
			hub := &captureHub{}
			rec := reconciler.New(database, nil, time.Minute)
			rec.SetHub(hub)
			if err := rec.PushAgentRoutes("a1"); err != nil {
				t.Fatalf("PushAgentRoutes: %v", err)
			}
			set, ok := hub.last()
			if !ok || len(set.Intents) != 1 {
				t.Fatalf("expected 1 pushed intent, got %+v", set)
			}
			route := set.Intents[0].Route
			if route.Host != "app.example.com" {
				t.Errorf("pushed host = %q, want app.example.com", route.Host)
			}
			if route.Raw.Content == staleManual {
				t.Fatal("push still carries the stale drift-accepted bytes")
			}
			if tc.wantRaw == "" {
				if route.IsRaw() {
					t.Errorf("push should render from the domain model, got raw content %q", route.Raw.Content)
				}
				if route.Upstream.Port != dom.Port {
					t.Errorf("model-rendered upstream port = %d, want %d", route.Upstream.Port, dom.Port)
				}
			} else if route.Raw.Content != tc.wantRaw {
				t.Errorf("pushed raw content = %q, want the new manual config %q", route.Raw.Content, tc.wantRaw)
			}
		})
	}
}

// assertAuditEntry fails the test unless an audit entry with the given identity
// and action exists.
func assertAuditEntry(t *testing.T, database interface {
	ListAuditLog(limit, offset int) ([]models.AuditLogEntry, int, error)
}, entityType, entityID, action string) {
	t.Helper()
	entries, _, err := database.ListAuditLog(50, 0)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	for _, e := range entries {
		if e.EntityType == entityType && e.EntityID == entityID && e.Action == action {
			return
		}
	}
	t.Errorf("no audit entry %s/%s action=%s", entityType, entityID, action)
}

// seedDomainTopology creates provider, zone, agent (existing-mode nginx), server
// and one domain, returning the domain ID and its FQDN.
func seedDomainTopology(t *testing.T, srv *Server, cookie *http.Cookie) (int64, string) {
	t.Helper()
	database := srv.db
	p := &models.Provider{ID: "prov-1", Type: "cloudflare", Name: "CF", Config: `{"api_token":"test"}`}
	if err := database.CreateProvider(p); err != nil {
		t.Fatal(err)
	}
	z := &models.Zone{ID: "zone-1", ProviderID: "prov-1", ExternalID: "ext-1", Name: "example.com"}
	if err := database.CreateZone(z); err != nil {
		t.Fatal(err)
	}
	a := &models.Agent{
		ID: "agent-1", Name: "Agent", FQDN: "agent.example.com",
		DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted,
		ProxyMode:      "existing",
		ProxyDetection: &models.ProxyDetection{Installed: true, Kind: "nginx"},
	}
	if err := database.CreateAgent(a); err != nil {
		t.Fatal(err)
	}
	// proxy_mode is owned by the heartbeat (CreateAgent defaults it to built-in),
	// so set it explicitly to model an agent running in existing mode.
	if err := database.UpdateAgentHealth("agent-1", "", "", "", false, "existing"); err != nil {
		t.Fatal(err)
	}
	s := &models.Server{ID: "srv-1", AgentID: "agent-1", Name: "Backend", Address: "10.0.0.1"}
	if err := database.CreateServer(s); err != nil {
		t.Fatal(err)
	}

	w := doRequest(t, srv.Handler(), "POST", "/api/v1/domains", map[string]interface{}{
		"subdomain": "health",
		"zone_id":   "zone-1",
		"server_id": "srv-1",
		"port":      8080,
	}, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("create domain: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var dom models.Domain
	if err := json.NewDecoder(w.Body).Decode(&dom); err != nil {
		t.Fatal(err)
	}
	return dom.ID, "health.example.com"
}

// Without an applied artifact the config editor falls back to a fresh preview
// render. Its placeholder cert paths must match the agent's real cert-store
// convention (<data-dir>/certs/<host>.crt + .key.plain) — the old placeholders
// pointed at /var/lib/nurproxy/certs/<host>.key, which does not exist on any
// agent, and saving them as a manual config broke nginx -t.
func TestDomainConfigPreviewUsesAgentCertStorePaths(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)
	domainID, fqdn := seedDomainTopology(t, srv, cookie)

	w := doRequest(t, handler, "GET", "/api/v1/domains/"+strconv.FormatInt(domainID, 10)+"/config", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("get config: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Manual  bool   `json:"manual"`
		Backend string `json:"backend"`
		Applied bool   `json:"applied"`
		Config  string `json:"config"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Manual {
		t.Error("expected manual=false for generated preview")
	}
	if resp.Applied {
		t.Error("expected applied=false when no artifact exists")
	}
	if resp.Backend != "nginx" {
		t.Fatalf("expected backend nginx, got %q", resp.Backend)
	}
	wantCert := "/var/lib/nurproxy-agent/certs/" + fqdn + ".crt"
	wantKey := "/var/lib/nurproxy-agent/certs/" + fqdn + ".key.plain"
	if !strings.Contains(resp.Config, wantCert) {
		t.Errorf("preview missing cert path %s:\n%s", wantCert, resp.Config)
	}
	if !strings.Contains(resp.Config, wantKey) {
		t.Errorf("preview missing key path %s:\n%s", wantKey, resp.Config)
	}
	if strings.Contains(resp.Config, "/var/lib/nurproxy/certs/") {
		t.Errorf("preview still renders the orchestrator cert dir:\n%s", resp.Config)
	}
}

// Once the agent has round-tripped its applied config into the artifact store,
// the config editor must serve those bytes — the real on-disk vhost with the
// agent's actual cert paths — instead of re-rendering a guessed preview.
func TestDomainConfigPrefersAppliedArtifact(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)
	domainID, fqdn := seedDomainTopology(t, srv, cookie)

	applied := "# applied by agent\nserver {\n  server_name " + fqdn + ";\n  ssl_certificate /custom/certs/" + fqdn + ".crt;\n}\n"
	art := &models.ConfigArtifact{
		ID:      "dom-" + strconv.FormatInt(domainID, 10),
		AgentID: "agent-1",
		Backend: "nginx",
		Target:  models.Target{Kind: models.TargetKindFile, Path: "/etc/nginx/sites-available/" + fqdn + ".conf"},
		Source:  models.ArtifactSourceGenerated,
		DomainID: func() *int64 {
			id := domainID
			return &id
		}(),
		Content: applied,
	}
	if err := database.CreateConfigArtifact(art, "test", "applied via apply-ACK"); err != nil {
		t.Fatal(err)
	}

	w := doRequest(t, handler, "GET", "/api/v1/domains/"+strconv.FormatInt(domainID, 10)+"/config", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("get config: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Manual  bool   `json:"manual"`
		Backend string `json:"backend"`
		Applied bool   `json:"applied"`
		Config  string `json:"config"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Manual {
		t.Error("expected manual=false")
	}
	if !resp.Applied {
		t.Error("expected applied=true when an artifact exists")
	}
	if resp.Backend != "nginx" {
		t.Errorf("expected backend nginx, got %q", resp.Backend)
	}
	if resp.Config != applied {
		t.Errorf("expected the applied artifact content verbatim, got:\n%s", resp.Config)
	}

	// A manual override still wins over the artifact.
	w = doRequest(t, handler, "PUT", "/api/v1/domains/"+strconv.FormatInt(domainID, 10)+"/config",
		map[string]interface{}{"config": "# manual override"}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("set manual config: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	w = doRequest(t, handler, "GET", "/api/v1/domains/"+strconv.FormatInt(domainID, 10)+"/config", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("get manual config: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var manualResp struct {
		Manual bool   `json:"manual"`
		Config string `json:"config"`
	}
	if err := json.NewDecoder(w.Body).Decode(&manualResp); err != nil {
		t.Fatal(err)
	}
	if !manualResp.Manual {
		t.Error("expected manual=true after manual override")
	}
	if manualResp.Config != "# manual override" {
		t.Errorf("expected the manual content, got %q", manualResp.Config)
	}
}

package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// selfSignedPEM mints a self-signed server cert for names, valid until notAfter.
func selfSignedPEM(t *testing.T, notAfter time.Time, names ...string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

// lockingIssuer stands in for the TLS renewer: busy simulates an ACME order
// holding the host lock.
type lockingIssuer struct {
	busy             bool
	locked, unlocked int
}

func (f *lockingIssuer) EnsureCertForHost(context.Context, string) error { return nil }

func (f *lockingIssuer) TryLockHost(string) (func(), bool) {
	if f.busy {
		return nil, false
	}
	f.locked++
	return func() { f.unlocked++ }, true
}

func TestImportDomainCertificate(t *testing.T) {
	inTwoMonths := time.Now().Add(60 * 24 * time.Hour)
	appCert, appKey := selfSignedPEM(t, inTwoMonths, "app.example.com")
	wildCert, wildKey := selfSignedPEM(t, inTwoMonths, "*.example.com", "example.com")
	soonCert, soonKey := selfSignedPEM(t, time.Now().Add(10*24*time.Hour), "app.example.com")
	otherCert, otherKey := selfSignedPEM(t, inTwoMonths, "other.example.com")

	tests := []struct {
		name        string
		domainID    string // "" = the seeded domain
		sslMode     models.SSLMode
		tlsPolicy   string
		cert, key   string
		noAuth      bool
		deleting    bool
		orderBusy   bool
		oversized   bool
		wantStatus  int
		wantWarning bool
	}{
		{name: "exact host", cert: appCert, key: appKey, wantStatus: http.StatusOK},
		{name: "wildcard", cert: wildCert, key: wildKey, wantStatus: http.StatusOK},
		{name: "combined pem in cert field", cert: appCert + appKey, key: appKey, wantStatus: http.StatusOK},
		{name: "inside renew window warns", cert: soonCert, key: soonKey, wantStatus: http.StatusOK, wantWarning: true},
		{name: "wrong host", cert: otherCert, key: otherKey, wantStatus: http.StatusBadRequest},
		{name: "mismatched key", cert: appCert, key: otherKey, wantStatus: http.StatusBadRequest},
		{name: "missing key", cert: appCert, wantStatus: http.StatusBadRequest},
		{name: "tls off", sslMode: models.SSLModeOff, cert: appCert, key: appKey, wantStatus: http.StatusConflict},
		{name: "self-acme", tlsPolicy: "self-acme", cert: appCert, key: appKey, wantStatus: http.StatusConflict},
		{name: "unknown domain", domainID: "999", cert: appCert, key: appKey, wantStatus: http.StatusNotFound},
		{name: "bad id", domainID: "abc", cert: appCert, key: appKey, wantStatus: http.StatusBadRequest},
		{name: "unauthenticated", noAuth: true, cert: appCert, key: appKey, wantStatus: http.StatusUnauthorized},
		{name: "domain being deleted", deleting: true, cert: appCert, key: appKey, wantStatus: http.StatusConflict},
		{name: "acme order in flight", orderBusy: true, cert: appCert, key: appKey, wantStatus: http.StatusConflict},
		{name: "oversized body", oversized: true, key: appKey, wantStatus: http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, database := testServer(t)
			issuer := &lockingIssuer{busy: tc.orderBusy}
			srv.SetCertIssuer(issuer)
			handler := srv.Handler()
			cookie := setupAdmin(t, handler)

			database.CreateProvider(&models.Provider{ID: "prov-1", Type: "cloudflare", Name: "CF", Config: `{"api_token":"test"}`})
			database.CreateZone(&models.Zone{ID: "zone-1", ProviderID: "prov-1", ExternalID: "ext-1", Name: "example.com"})
			database.CreateAgent(&models.Agent{ID: "agent-1", Name: "Agent", FQDN: "agent.example.com", DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted})
			database.CreateServer(&models.Server{ID: "srv-1", AgentID: "agent-1", Name: "S1", Address: "10.0.0.1"})
			sslMode := tc.sslMode
			if sslMode == "" {
				sslMode = models.SSLModeAuto
			}
			dom := &models.Domain{Subdomain: "app", ZoneID: "zone-1", ServerID: "srv-1", Port: 80, SSLMode: sslMode, Status: models.DomainStatusActive}
			dom.ProxyConfig.TLSPolicy = tc.tlsPolicy
			if err := database.CreateDomain(dom); err != nil {
				t.Fatalf("CreateDomain: %v", err)
			}
			if tc.deleting {
				if err := database.UpdateDomainStatus(dom.ID, models.DomainStatusDeleting, ""); err != nil {
					t.Fatal(err)
				}
			}
			id := tc.domainID
			if id == "" {
				id = strconv.FormatInt(dom.ID, 10)
			}
			cert := tc.cert
			if tc.oversized {
				cert = strings.Repeat("A", 5<<20)
			}
			var cookies []*http.Cookie
			if !tc.noAuth {
				cookies = append(cookies, cookie)
			}

			w := doRequest(t, handler, "PUT", "/api/v1/domains/"+id+"/certificate",
				map[string]string{"cert_pem": cert, "key_pem": tc.key}, cookies...)
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.wantStatus, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "PRIVATE KEY") {
				t.Fatal("response leaks private key material")
			}

			stored, err := database.GetCertificate("app.example.com")
			if tc.wantStatus != http.StatusOK {
				if err == nil {
					t.Fatalf("rejected import still stored a certificate")
				}
				return
			}
			if err != nil {
				t.Fatalf("GetCertificate after import: %v", err)
			}
			if stored.Source != models.CertSourceImported || stored.ExpiresAt.IsZero() {
				t.Errorf("stored cert: source=%q expires=%v, want imported with expiry", stored.Source, stored.ExpiresAt)
			}
			// selfSignedPEM backdates NotBefore by an hour; issued_at must be that.
			if !stored.IssuedAt.Before(time.Now().Add(-30 * time.Minute)) {
				t.Errorf("issued_at = %v, want the leaf's NotBefore", stored.IssuedAt)
			}
			if issuer.locked != 1 || issuer.unlocked != 1 {
				t.Errorf("host lock taken %d / released %d times, want 1 / 1", issuer.locked, issuer.unlocked)
			}
			if strings.Contains(stored.CertPEM, "PRIVATE KEY") {
				t.Error("stored cert_pem contains private key material")
			}
			if !strings.Contains(stored.KeyPEM, "PRIVATE KEY") {
				t.Error("stored key missing")
			}

			var resp map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if _, warned := resp["warning"]; warned != tc.wantWarning {
				t.Errorf("warning present = %v, want %v (%v)", warned, tc.wantWarning, resp)
			}
		})
	}
}

// TestImportDomainCertificate_replacesIssuedCert checks that an import
// overwrites an ACME cert already on file for the host and audits the change.
func TestImportDomainCertificate_replacesIssuedCert(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)

	database.CreateProvider(&models.Provider{ID: "prov-1", Type: "cloudflare", Name: "CF", Config: `{"api_token":"test"}`})
	database.CreateZone(&models.Zone{ID: "zone-1", ProviderID: "prov-1", ExternalID: "ext-1", Name: "example.com"})
	database.CreateAgent(&models.Agent{ID: "agent-1", Name: "Agent", FQDN: "agent.example.com", DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted})
	database.CreateServer(&models.Server{ID: "srv-1", AgentID: "agent-1", Name: "S1", Address: "10.0.0.1"})
	dom := &models.Domain{Subdomain: "app", ZoneID: "zone-1", ServerID: "srv-1", Port: 80, SSLMode: models.SSLModeAuto, Status: models.DomainStatusActive}
	if err := database.CreateDomain(dom); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	if err := database.UpsertCertificate(&models.Certificate{ID: "app.example.com", Host: "app.example.com", Names: []string{"app.example.com"}, CertPEM: "OLD", KeyPEM: "OLD", ExpiresAt: time.Now().Add(80 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}

	certPEM, keyPEM := selfSignedPEM(t, time.Now().Add(60*24*time.Hour), "app.example.com")
	w := doRequest(t, handler, "PUT", "/api/v1/domains/"+strconv.FormatInt(dom.ID, 10)+"/certificate",
		map[string]string{"cert_pem": certPEM, "key_pem": keyPEM}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("import: %d %s", w.Code, w.Body.String())
	}
	stored, err := database.GetCertificate("app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if stored.CertPEM != certPEM || stored.Source != models.CertSourceImported {
		t.Errorf("import did not replace the issued cert: source=%q", stored.Source)
	}
	certs, err := database.ListCertificates()
	if err != nil || len(certs) != 1 {
		t.Fatalf("want exactly one stored cert after replace, got %d (%v)", len(certs), err)
	}

	entries, _, err := database.ListAuditLog(50, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "cert_imported" && e.EntityID == "app.example.com" {
			found = true
		}
	}
	if !found {
		t.Error("no cert_imported audit entry")
	}
}

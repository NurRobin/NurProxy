package api

import (
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
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// Deleting a server, agent, or zone while a domain still references it must be
// refused with 409. Without the guard the DB's ON DELETE CASCADE hard-removes the
// domain rows before the reconciler can tear down their DNS records and certs,
// orphaning them at the provider (the v0.3.0 e2e test reproduced exactly this).
func TestDeleteParent_BlockedWhileDomainsExist(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)

	database.CreateProvider(&models.Provider{ID: "prov-1", Type: "cloudflare", Name: "CF", Config: `{"api_token":"test"}`})
	database.CreateZone(&models.Zone{ID: "zone-1", ProviderID: "prov-1", ExternalID: "ext-1", Name: "example.com"})
	database.CreateAgent(&models.Agent{ID: "agent-1", Name: "Agent", FQDN: "agent.example.com", DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted})
	database.CreateServer(&models.Server{ID: "srv-1", AgentID: "agent-1", Name: "S1", Address: "10.0.0.1"})
	if err := database.CreateDomain(&models.Domain{Subdomain: "app", ZoneID: "zone-1", ServerID: "srv-1", Port: 80, SSLMode: models.SSLModeAuto, Status: models.DomainStatusActive}); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}

	// Each parent delete must be refused with 409 and name the blocking domain.
	for _, tc := range []struct{ what, path string }{
		{"server", "/api/v1/servers/srv-1"},
		{"agent", "/api/v1/agents/agent-1"},
		{"zone", "/api/v1/zones/zone-1"},
	} {
		w := doRequest(t, handler, "DELETE", tc.path, nil, cookie)
		if w.Code != http.StatusConflict {
			t.Fatalf("DELETE %s with live domain: got %d, want 409", tc.what, w.Code)
		}
		var body struct {
			Error   string   `json:"error"`
			Domains []string `json:"domains"`
		}
		if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
			t.Fatalf("%s: decode 409 body: %v", tc.what, err)
		}
		if len(body.Domains) != 1 || body.Domains[0] != "app" {
			t.Errorf("%s: 409 body domains = %v, want [app]", tc.what, body.Domains)
		}
	}

	// The server must still exist (the refused delete is a no-op).
	if doms, _ := database.ListDomains(db.DomainFilter{ServerID: "srv-1"}); len(doms) != 1 {
		t.Fatalf("domain should be untouched after refused deletes, have %d", len(doms))
	}
}

// Once the domains are gone (the reconciler finished teardown), the parent deletes
// succeed. A parent with no domains is never blocked.
func TestDeleteParent_AllowedWhenNoDomains(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)

	database.CreateProvider(&models.Provider{ID: "prov-1", Type: "cloudflare", Name: "CF", Config: `{"api_token":"test"}`})
	database.CreateZone(&models.Zone{ID: "zone-1", ProviderID: "prov-1", ExternalID: "ext-1", Name: "example.com"})
	database.CreateAgent(&models.Agent{ID: "agent-1", Name: "Agent", FQDN: "agent.example.com", DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted})
	database.CreateServer(&models.Server{ID: "srv-1", AgentID: "agent-1", Name: "S1", Address: "10.0.0.1"})
	if err := database.CreateDomain(&models.Domain{Subdomain: "app", ZoneID: "zone-1", ServerID: "srv-1", Port: 80, SSLMode: models.SSLModeAuto, Status: models.DomainStatusActive}); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}

	// Simulate the reconciler having finished domain teardown: the row is gone.
	doms, _ := database.ListDomains(db.DomainFilter{ServerID: "srv-1"})
	if len(doms) != 1 {
		t.Fatalf("setup: expected 1 domain, got %d", len(doms))
	}
	if err := database.DeleteDomain(doms[0].ID); err != nil {
		t.Fatalf("DeleteDomain: %v", err)
	}

	if w := doRequest(t, handler, "DELETE", "/api/v1/servers/srv-1", nil, cookie); w.Code != http.StatusOK {
		t.Fatalf("DELETE server with no domains: got %d, want 200", w.Code)
	}
	if w := doRequest(t, handler, "DELETE", "/api/v1/zones/zone-1", nil, cookie); w.Code != http.StatusOK {
		t.Fatalf("DELETE zone with no domains: got %d, want 200", w.Code)
	}
	if w := doRequest(t, handler, "DELETE", "/api/v1/agents/agent-1", nil, cookie); w.Code != http.StatusOK {
		t.Fatalf("DELETE agent with no domains: got %d, want 200", w.Code)
	}
}

// TestImportDomainCertificate covers the #80 migration path: an operator-
// provided bundle is validated, stored host-keyed like an issued cert, and
// rejected when the key mismatches or the cert does not cover the FQDN.
func TestImportDomainCertificate(t *testing.T) {
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

	certPEM, keyPEM := selfSignedPEM(t, "app.example.com")
	path := "/api/v1/domains/" + strconv.FormatInt(dom.ID, 10) + "/certificate"

	w := doRequest(t, handler, "PUT", path, map[string]string{"cert_pem": string(certPEM), "key_pem": string(keyPEM)}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("import: got %d: %s", w.Code, w.Body.String())
	}
	stored, err := database.GetCertificate("app.example.com")
	if err != nil {
		t.Fatalf("GetCertificate after import: %v", err)
	}
	if stored.CertPEM != string(certPEM) || stored.ExpiresAt.IsZero() {
		t.Errorf("stored cert incomplete: expires=%v", stored.ExpiresAt)
	}

	// Wrong host: the cert does not cover the FQDN → 400.
	otherCert, otherKey := selfSignedPEM(t, "other.example.com")
	w = doRequest(t, handler, "PUT", path, map[string]string{"cert_pem": string(otherCert), "key_pem": string(otherKey)}, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("wrong-host import: got %d, want 400", w.Code)
	}

	// Mismatched key → 400.
	w = doRequest(t, handler, "PUT", path, map[string]string{"cert_pem": string(certPEM), "key_pem": string(otherKey)}, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("mismatched-key import: got %d, want 400", w.Code)
	}
}

// selfSignedPEM mints a short-lived self-signed cert for host (tests only).
func selfSignedPEM(t *testing.T, host string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

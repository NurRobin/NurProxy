package api

import (
	"encoding/json"
	"net/http"
	"testing"

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

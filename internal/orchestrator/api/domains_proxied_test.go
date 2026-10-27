package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	_ "github.com/NurRobin/NurProxy/internal/provider/cloudflare" // registers "cloudflare"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// proxiedFixture seeds a Cloudflare zone, a zone on a provider without a proxy
// mode, and a server to hang domains on.
func proxiedFixture(t *testing.T, database *db.DB) {
	t.Helper()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(database.CreateProvider(&models.Provider{ID: "prov-cf", Type: "cloudflare", Name: "CF", Config: `{"api_token":"x"}`}))
	must(database.CreateProvider(&models.Provider{ID: "prov-other", Type: "otherdns", Name: "Other", Config: `{}`}))
	must(database.CreateZone(&models.Zone{ID: "zone-cf", ProviderID: "prov-cf", ExternalID: "e1", Name: "example.com"}))
	must(database.CreateZone(&models.Zone{ID: "zone-other", ProviderID: "prov-other", ExternalID: "e2", Name: "other.test"}))
	must(database.CreateAgent(&models.Agent{ID: "agent-1", Name: "A", FQDN: "agent.example.com", DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted}))
	must(database.CreateServer(&models.Server{ID: "srv-1", AgentID: "agent-1", Name: "B", Address: "10.0.0.1"}))
}

func TestDomainProxied_create(t *testing.T) {
	tests := []struct {
		name     string
		zone     string
		proxied  any // omitted when nil-interface
		certOnly bool
		wantCode int
		want     *bool
	}{
		{"omitted on cloudflare", "zone-cf", nil, false, http.StatusCreated, nil},
		{"true on cloudflare", "zone-cf", true, false, http.StatusCreated, boolPtr(true)},
		{"false on cloudflare", "zone-cf", false, false, http.StatusCreated, boolPtr(false)},
		{"false on other provider", "zone-other", false, false, http.StatusCreated, boolPtr(false)},
		{"true on other provider", "zone-other", true, false, http.StatusBadRequest, nil},
		{"true on cert-only", "zone-cf", true, true, http.StatusBadRequest, nil},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, database := testServer(t)
			handler := srv.Handler()
			cookie := setupAdmin(t, handler)
			proxiedFixture(t, database)

			body := map[string]any{
				"subdomain": fmt.Sprintf("app%d", i), "zone_id": tc.zone, "server_id": "srv-1",
				"port": 8080, "cert_only": tc.certOnly,
			}
			if tc.proxied != nil {
				body["proxied"] = tc.proxied
			}
			w := doRequest(t, handler, "POST", "/api/v1/domains", body, cookie)
			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.wantCode, w.Body.String())
			}
			if w.Code != http.StatusCreated {
				return
			}
			var dom models.Domain
			if err := json.NewDecoder(w.Body).Decode(&dom); err != nil {
				t.Fatal(err)
			}
			stored, err := database.GetDomain(dom.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !sameBoolPtr(stored.Proxied, tc.want) {
				t.Errorf("stored proxied = %v, want %v", stored.Proxied, tc.want)
			}
		})
	}
}

func TestDomainProxied_update(t *testing.T) {
	tests := []struct {
		name     string
		initial  *bool
		body     string
		wantCode int
		want     *bool
	}{
		{"absent leaves true", boolPtr(true), `{"port":9090}`, http.StatusOK, boolPtr(true)},
		{"null clears to keep", boolPtr(true), `{"proxied":null}`, http.StatusOK, nil},
		{"false sets off", nil, `{"proxied":false}`, http.StatusOK, boolPtr(false)},
		{"true sets on", boolPtr(false), `{"proxied":true}`, http.StatusOK, boolPtr(true)},
		{"move proxied domain to non-cloudflare zone refused", boolPtr(true), `{"zone_id":"zone-other"}`, http.StatusBadRequest, boolPtr(true)},
		{"move with null to non-cloudflare zone allowed", boolPtr(true), `{"zone_id":"zone-other","proxied":null}`, http.StatusOK, nil},
		{"bad value", nil, `{"proxied":"yes"}`, http.StatusBadRequest, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, database := testServer(t)
			handler := srv.Handler()
			cookie := setupAdmin(t, handler)
			proxiedFixture(t, database)
			dom := &models.Domain{
				Subdomain: "app", ZoneID: "zone-cf", ServerID: "srv-1", Port: 8080,
				SSLMode: models.SSLModeAuto, Status: models.DomainStatusActive, Proxied: tc.initial,
			}
			if err := database.CreateDomain(dom); err != nil {
				t.Fatal(err)
			}
			var raw json.RawMessage = []byte(tc.body)
			w := doRequest(t, handler, "PUT", fmt.Sprintf("/api/v1/domains/%d", dom.ID), raw, cookie)
			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.wantCode, w.Body.String())
			}
			stored, err := database.GetDomain(dom.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !sameBoolPtr(stored.Proxied, tc.want) {
				t.Errorf("stored proxied = %v, want %v", stored.Proxied, tc.want)
			}
		})
	}
}

// The provider list tells the dashboard which zones can be proxied.
func TestListProviders_supportsProxied(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)
	proxiedFixture(t, database)

	w := doRequest(t, handler, "GET", "/api/v1/providers", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var list []struct {
		ID              string `json:"id"`
		SupportsProxied bool   `json:"supports_proxied"`
	}
	if err := json.NewDecoder(w.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"prov-cf": true, "prov-other": false}
	for _, p := range list {
		if p.SupportsProxied != want[p.ID] {
			t.Errorf("%s supports_proxied = %v, want %v", p.ID, p.SupportsProxied, want[p.ID])
		}
	}
	if len(list) != 2 {
		t.Fatalf("got %d providers, want 2", len(list))
	}
}

func boolPtr(b bool) *bool { return &b }

func sameBoolPtr(a, b *bool) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

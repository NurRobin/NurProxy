package api

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
)

// TestDomainTLSWildcardValidation covers the tls_wildcard opt-in on create and
// update: accepted for a single central-TLS label below the zone, refused with
// a clear error for the apex, deeper names and non-central TLS, and re-checked
// against the final state when an update renames the domain or changes policy.
func TestDomainTLSWildcardValidation(t *testing.T) {
	tests := []struct {
		name     string
		method   string // POST creates a new domain, PUT updates the seeded "health" one
		body     map[string]any
		wantCode int
		wantErr  string
		want     bool // stored tls_wildcard on success
	}{
		{name: "create single label", method: http.MethodPost,
			body: map[string]any{"subdomain": "app", "tls_wildcard": true}, wantCode: http.StatusCreated, want: true},
		{name: "create via proxy_config", method: http.MethodPost,
			body: map[string]any{"subdomain": "app", "proxy_config": map[string]any{"tls_wildcard": true}}, wantCode: http.StatusCreated, want: true},
		{name: "create apex refused", method: http.MethodPost,
			body: map[string]any{"subdomain": "@", "tls_wildcard": true}, wantCode: http.StatusBadRequest, wantErr: "apex"},
		{name: "create nested label refused", method: http.MethodPost,
			body: map[string]any{"subdomain": "app.sub", "tls_wildcard": true}, wantCode: http.StatusBadRequest, wantErr: "single label"},
		{name: "create self-acme refused", method: http.MethodPost,
			body: map[string]any{"subdomain": "app", "tls_wildcard": true, "proxy_config": map[string]any{"tls_policy": "self-acme"}}, wantCode: http.StatusBadRequest, wantErr: "central TLS"},
		{name: "create ssl off refused", method: http.MethodPost,
			body: map[string]any{"subdomain": "app", "tls_wildcard": true, "ssl_mode": "off"}, wantCode: http.StatusBadRequest, wantErr: "central TLS"},
		{name: "update opt in", method: http.MethodPut,
			body: map[string]any{"tls_wildcard": true}, wantCode: http.StatusOK, want: true},
		{name: "update rename to nested name with opt in refused", method: http.MethodPut,
			body: map[string]any{"tls_wildcard": true, "subdomain": "a.b"}, wantCode: http.StatusBadRequest, wantErr: "single label"},
		{name: "update explicit opt out", method: http.MethodPut,
			body: map[string]any{"tls_wildcard": false}, wantCode: http.StatusOK, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, database := testServer(t)
			handler := srv.Handler()
			cookie := setupAdmin(t, handler)
			domainID, _ := seedDomainTopology(t, srv, cookie)
			path := "/api/v1/domains/" + strconv.FormatInt(domainID, 10)
			body := tt.body
			if tt.method == http.MethodPost {
				path = "/api/v1/domains"
				body = map[string]any{"zone_id": "zone-1", "server_id": "srv-1", "port": 8080}
				for k, v := range tt.body {
					body[k] = v
				}
			}
			w := doRequest(t, handler, tt.method, path, body, cookie)
			if w.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d: %s", w.Code, tt.wantCode, w.Body.String())
			}
			if tt.wantErr != "" {
				if !strings.Contains(w.Body.String(), tt.wantErr) {
					t.Fatalf("error = %s, want it to mention %q", w.Body.String(), tt.wantErr)
				}
				return
			}
			domains, err := database.ListDomains(db.DomainFilter{})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, d := range domains {
				if d.Subdomain == "app" || (tt.method == http.MethodPut && d.ID == domainID) {
					found = true
					if d.ProxyConfig.TLSWildcard != tt.want {
						t.Fatalf("stored tls_wildcard = %v, want %v", d.ProxyConfig.TLSWildcard, tt.want)
					}
				}
			}
			if !found {
				t.Fatal("domain not stored")
			}
		})
	}
}

// TestUpdateDomainPolicyChangeKeepsWildcardConsistent refuses switching a
// wildcard domain away from central TLS unless the opt-in is cleared in the
// same request.
func TestUpdateDomainPolicyChangeKeepsWildcardConsistent(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)
	domainID, _ := seedDomainTopology(t, srv, cookie)
	path := "/api/v1/domains/" + strconv.FormatInt(domainID, 10)

	if w := doRequest(t, handler, http.MethodPut, path, map[string]any{"tls_wildcard": true}, cookie); w.Code != http.StatusOK {
		t.Fatalf("opt in: %d %s", w.Code, w.Body.String())
	}
	w := doRequest(t, handler, http.MethodPut, path, map[string]any{"proxy_config": map[string]any{"tls_policy": "self-acme"}}, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("policy switch with opt-in kept: %d %s, want 400", w.Code, w.Body.String())
	}
	w = doRequest(t, handler, http.MethodPut, path, map[string]any{"tls_wildcard": false, "proxy_config": map[string]any{"tls_policy": "self-acme"}}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("policy switch with opt-out: %d %s, want 200", w.Code, w.Body.String())
	}
}

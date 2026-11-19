package api

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// TestDomainHeaderConfigVarsValidation checks that a custom header value with
// "${" is refused for a domain served by Apache (by capability, or by the
// detected kind for agents that predate it) and still accepted for nginx,
// which reads "${var}" as a request variable.
func TestDomainHeaderConfigVarsValidation(t *testing.T) {
	apacheCaps := &models.ProxyCapabilities{ReverseProxy: true, CustomHeaders: true, HeaderConfigVars: true}
	oldApacheCaps := &models.ProxyCapabilities{ReverseProxy: true, CustomHeaders: true}
	nginxCaps := &models.ProxyCapabilities{ReverseProxy: true, CustomHeaders: true}
	varHeader := map[string]any{"custom_response_headers": map[string]string{"X-User": "${APACHE_RUN_USER}"}}
	plainHeader := map[string]any{"custom_request_headers": map[string]string{"X-Cost": "$5 {flat}"}}

	tests := []struct {
		name     string
		kind     string
		caps     *models.ProxyCapabilities
		method   string
		config   map[string]any
		wantCode int
	}{
		{"apache refuses variable on update", "apache", apacheCaps, http.MethodPut, varHeader, http.StatusBadRequest},
		{"apache refuses variable on create", "apache", apacheCaps, http.MethodPost, varHeader, http.StatusBadRequest},
		{"apache predating capability refuses by kind", "apache", oldApacheCaps, http.MethodPut, varHeader, http.StatusBadRequest},
		{"apache accepts dollar and braces apart", "apache", apacheCaps, http.MethodPut, plainHeader, http.StatusOK},
		{"nginx keeps variable form", "nginx", nginxCaps, http.MethodPut, varHeader, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, database := testServer(t)
			handler := srv.Handler()
			cookie := setupAdmin(t, handler)
			domainID, _ := seedDomainTopology(t, srv, cookie)
			if err := database.UpdateAgentDetection("agent-1", &models.ProxyDetection{Installed: true, Kind: tt.kind}); err != nil {
				t.Fatal(err)
			}
			if err := database.UpdateAgentCapabilities("agent-1", tt.caps); err != nil {
				t.Fatal(err)
			}
			path := "/api/v1/domains/" + strconv.FormatInt(domainID, 10)
			body := map[string]any{"proxy_config": tt.config}
			if tt.method == http.MethodPost {
				path = "/api/v1/domains"
				body = map[string]any{"subdomain": "private", "zone_id": "zone-1", "server_id": "srv-1", "port": 8080, "proxy_config": tt.config}
			}
			w := doRequest(t, handler, tt.method, path, body, cookie)
			if w.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d: %s", w.Code, tt.wantCode, w.Body.String())
			}
			if tt.wantCode == http.StatusBadRequest && !strings.Contains(w.Body.String(), "X-User") {
				t.Fatalf("refusal does not name the header: %s", w.Body.String())
			}
		})
	}
}

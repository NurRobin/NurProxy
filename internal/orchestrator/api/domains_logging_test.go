package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// TestDomainLoggingValidation covers the per-domain logging fields on create
// and update: value checks, normalization of "default", the capability check
// against the serving agent, and the top-level shortcut fields that change
// only the logging settings.
func TestDomainLoggingValidation(t *testing.T) {
	nginxCaps := &models.ProxyCapabilities{ReverseProxy: true, AccessLog: true, ErrorLogLevel: true}
	caddyCaps := &models.ProxyCapabilities{ReverseProxy: true, AccessLog: true}
	oldAgentCaps := &models.ProxyCapabilities{ReverseProxy: true, RateLimit: true}

	tests := []struct {
		name       string
		caps       *models.ProxyCapabilities // nil: agent never reported a matrix
		method     string                    // POST creates a new domain, PUT updates the seeded one
		body       map[string]any
		wantCode   int
		wantAccess string
		wantLevel  string
	}{
		{name: "create off and crit on nginx", caps: nginxCaps, method: http.MethodPost,
			body: map[string]any{"access_log": "off", "error_log_level": "crit"}, wantCode: http.StatusCreated, wantAccess: "off", wantLevel: "crit"},
		{name: "create via proxy_config", caps: nginxCaps, method: http.MethodPost,
			body: map[string]any{"proxy_config": map[string]any{"access_log": "off"}}, wantCode: http.StatusCreated, wantAccess: "off"},
		{name: "create unknown access mode", caps: nginxCaps, method: http.MethodPost,
			body: map[string]any{"access_log": "anonymized"}, wantCode: http.StatusBadRequest},
		{name: "update injected level", caps: nginxCaps, method: http.MethodPut,
			body: map[string]any{"proxy_config": map[string]any{"error_log_level": "crit; include /etc/shadow"}}, wantCode: http.StatusBadRequest},
		{name: "update default normalizes to empty", caps: nginxCaps, method: http.MethodPut,
			body: map[string]any{"access_log": "default", "error_log_level": "default"}, wantCode: http.StatusOK},
		{name: "update without reported matrix", caps: nil, method: http.MethodPut,
			body: map[string]any{"access_log": "off", "error_log_level": "error"}, wantCode: http.StatusOK, wantAccess: "off", wantLevel: "error"},
		{name: "built-in caddy accepts access off", caps: caddyCaps, method: http.MethodPut,
			body: map[string]any{"access_log": "off"}, wantCode: http.StatusOK, wantAccess: "off"},
		{name: "built-in caddy refuses error level", caps: caddyCaps, method: http.MethodPut,
			body: map[string]any{"error_log_level": "crit"}, wantCode: http.StatusBadRequest},
		{name: "agent predating the feature refuses access off", caps: oldAgentCaps, method: http.MethodPut,
			body: map[string]any{"access_log": "off"}, wantCode: http.StatusBadRequest},
		{name: "agent predating the feature accepts unrelated update", caps: oldAgentCaps, method: http.MethodPut,
			body: map[string]any{"port": 9090}, wantCode: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, database := testServer(t)
			handler := srv.Handler()
			cookie := setupAdmin(t, handler)
			domainID, _ := seedDomainTopology(t, srv, cookie)
			if tt.caps != nil {
				if err := database.UpdateAgentCapabilities("agent-1", tt.caps); err != nil {
					t.Fatal(err)
				}
			}
			path := "/api/v1/domains/" + strconv.FormatInt(domainID, 10)
			body := tt.body
			if tt.method == http.MethodPost {
				path = "/api/v1/domains"
				body = map[string]any{"subdomain": "private", "zone_id": "zone-1", "server_id": "srv-1", "port": 8080}
				for k, v := range tt.body {
					body[k] = v
				}
			}
			w := doRequest(t, handler, tt.method, path, body, cookie)
			if w.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d: %s", w.Code, tt.wantCode, w.Body.String())
			}
			if w.Code >= 300 {
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
			if stored.ProxyConfig.AccessLog != tt.wantAccess || stored.ProxyConfig.ErrorLogLevel != tt.wantLevel {
				t.Fatalf("stored access=%q level=%q, want %q %q", stored.ProxyConfig.AccessLog, stored.ProxyConfig.ErrorLogLevel, tt.wantAccess, tt.wantLevel)
			}
		})
	}
}

// TestDomainLoggingPatchKeepsOtherProxySettings checks that the top-level
// access_log / error_log_level fields change only those settings, so the CLI
// and MCP can set them without wiping the rest of proxy_config.
func TestDomainLoggingPatchKeepsOtherProxySettings(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)
	domainID, fqdn := seedDomainTopology(t, srv, cookie)
	path := "/api/v1/domains/" + strconv.FormatInt(domainID, 10)
	if w := doRequest(t, handler, http.MethodPut, path, map[string]any{"proxy_config": map[string]any{"max_body_size": "50m", "tls_policy": "off"}}, cookie); w.Code != http.StatusOK {
		t.Fatalf("seed proxy_config: %d %s", w.Code, w.Body.String())
	}
	if w := doRequest(t, handler, http.MethodPut, path, map[string]any{"access_log": "off", "error_log_level": "crit"}, cookie); w.Code != http.StatusOK {
		t.Fatalf("logging patch: %d %s", w.Code, w.Body.String())
	}
	dom, err := database.GetDomain(domainID)
	if err != nil {
		t.Fatal(err)
	}
	if dom.ProxyConfig.MaxBodySize != "50m" || dom.ProxyConfig.TLSPolicy != "off" {
		t.Fatalf("logging patch dropped other settings: %+v", dom.ProxyConfig)
	}

	// The preview the dashboard shows renders the directives for nginx.
	server, err := database.GetServer(dom.ServerID)
	if err != nil {
		t.Fatal(err)
	}
	_, cfg, err := srv.renderDomainPreview(dom, server, fqdn)
	if err != nil {
		t.Fatal(err)
	}
	text, _ := cfg.(string)
	if !strings.Contains(text, "access_log off;") || !strings.Contains(text, "error_log /var/log/nginx/error.log crit;") {
		t.Fatalf("nginx preview lacks the logging directives:\n%s", text)
	}
}

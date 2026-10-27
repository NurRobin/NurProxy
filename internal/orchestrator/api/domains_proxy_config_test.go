package api

import (
	"net/http"
	"reflect"
	"strconv"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// storedProxyConfig is a domain config with fields the dashboard's General and
// Headers tabs don't show, as set through the API or CLI.
func storedProxyConfig() models.ProxyConfig {
	return models.ProxyConfig{
		WebSocket:             true,
		MaxBodySize:           "10m",
		CustomRequestHeaders:  map[string]string{"X-Old": "1"},
		CustomResponseHeaders: map[string]string{"X-Frame-Options": "DENY"},
		PathStrip:             "/api",
		UpstreamScheme:        "https",
		TimeoutRead:           30,
		BasicAuth:             &models.BasicAuthConfig{Username: "admin", Password: "$2a$10$abcdefghijklmnopqrstuv"},
		IPAllowlist:           []string{"10.0.0.0/8"},
		IPBlocklist:           []string{"192.0.2.1"},
		RateLimit:             5,
		RawConfig:             models.RawConfig{Backend: "caddy", Content: `{"handle":[]}`},
		TLSPolicy:             "self-acme",
	}
}

// Regression for #163: a PUT with a partial proxy_config must keep every stored
// field it doesn't mention.
func TestUpdateDomainProxyConfigMerge(t *testing.T) {
	cases := []struct {
		name   string
		body   map[string]any
		want   func(models.ProxyConfig) models.ProxyConfig
		status int
	}{
		{
			name: "dashboard general tab keeps hidden fields",
			body: map[string]any{
				"websocket": false, "force_https": true,
				"proxy_config": map[string]any{
					"websocket": false, "force_https": true, "max_body_size": "20m",
					"custom_request_headers": map[string]string{"X-New": "2"},
				},
			},
			want: func(c models.ProxyConfig) models.ProxyConfig {
				c.WebSocket = false
				c.ForceHTTPS = true
				c.MaxBodySize = "20m"
				c.CustomRequestHeaders = map[string]string{"X-New": "2"}
				return c
			},
		},
		{
			name: "no proxy_config leaves it untouched",
			body: map[string]any{"port": 8081},
			want: func(c models.ProxyConfig) models.ProxyConfig { return c },
		},
		{
			name: "null proxy_config leaves it untouched",
			body: map[string]any{"proxy_config": nil},
			want: func(c models.ProxyConfig) models.ProxyConfig { return c },
		},
		{
			name: "empty object leaves it untouched",
			body: map[string]any{"proxy_config": map[string]any{}},
			want: func(c models.ProxyConfig) models.ProxyConfig { return c },
		},
		{
			name: "explicit null clears basic auth only",
			body: map[string]any{"proxy_config": map[string]any{"basic_auth": nil}},
			want: func(c models.ProxyConfig) models.ProxyConfig {
				c.BasicAuth = nil
				return c
			},
		},
		{
			name: "explicit nulls clear lists, raw config and tls policy",
			body: map[string]any{"proxy_config": map[string]any{
				"ip_allowlist": nil, "ip_blocklist": nil, "raw_config": nil,
				"tls_policy": nil, "custom_request_headers": nil,
			}},
			want: func(c models.ProxyConfig) models.ProxyConfig {
				c.IPAllowlist = nil
				c.IPBlocklist = nil
				c.RawConfig = models.RawConfig{}
				c.TLSPolicy = ""
				c.CustomRequestHeaders = nil
				return c
			},
		},
		{
			name: "list replaces the stored list",
			body: map[string]any{"proxy_config": map[string]any{"ip_allowlist": []string{"172.16.0.0/12"}}},
			want: func(c models.ProxyConfig) models.ProxyConfig {
				c.IPAllowlist = []string{"172.16.0.0/12"}
				return c
			},
		},
		{
			name: "key differing in case replaces the stored field",
			body: map[string]any{"proxy_config": map[string]any{"TLS_Policy": "off"}},
			want: func(c models.ProxyConfig) models.ProxyConfig {
				c.TLSPolicy = "off"
				return c
			},
		},
		{
			name: "full config replaces every field",
			body: map[string]any{"proxy_config": map[string]any{
				"websocket": false, "force_https": true, "max_body_size": "1m",
				"custom_request_headers": nil, "custom_response_headers": nil,
				"path_strip": "", "path_rewrite": "/v2", "upstream_scheme": "http",
				"timeout_read": 0, "timeout_write": 15, "timeout_idle": 0,
				"basic_auth":   map[string]string{"username": "ops", "password": "$2a$10$zyxwvutsrqponmlkjihgfe"},
				"ip_allowlist": nil, "ip_blocklist": []string{"198.51.100.7"},
				"rate_limit": 0, "raw_config": nil, "tls_policy": "central",
			}},
			want: func(models.ProxyConfig) models.ProxyConfig {
				return models.ProxyConfig{
					ForceHTTPS:     true,
					MaxBodySize:    "1m",
					PathRewrite:    "/v2",
					UpstreamScheme: "http",
					TimeoutWrite:   15,
					BasicAuth:      &models.BasicAuthConfig{Username: "ops", Password: "$2a$10$zyxwvutsrqponmlkjihgfe"},
					IPBlocklist:    []string{"198.51.100.7"},
					TLSPolicy:      "central",
				}
			},
		},
		{
			name:   "non-object proxy_config is rejected",
			body:   map[string]any{"proxy_config": []string{"websocket"}},
			want:   func(c models.ProxyConfig) models.ProxyConfig { return c },
			status: http.StatusBadRequest,
		},
		{
			name:   "wrong field type is rejected",
			body:   map[string]any{"proxy_config": map[string]any{"rate_limit": "fast"}},
			want:   func(c models.ProxyConfig) models.ProxyConfig { return c },
			status: http.StatusBadRequest,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, database := testServer(t)
			handler := srv.Handler()
			cookie := setupAdmin(t, handler)
			domainID, _ := seedDomainTopology(t, srv, cookie)
			dom, err := database.GetDomain(domainID)
			if err != nil {
				t.Fatal(err)
			}
			dom.ProxyConfig = storedProxyConfig()
			if err := database.UpdateDomain(dom); err != nil {
				t.Fatal(err)
			}

			w := doRequest(t, handler, http.MethodPut, "/api/v1/domains/"+strconv.FormatInt(domainID, 10), tc.body, cookie)
			wantStatus := tc.status
			if wantStatus == 0 {
				wantStatus = http.StatusOK
			}
			if w.Code != wantStatus {
				t.Fatalf("status = %d, want %d: %s", w.Code, wantStatus, w.Body.String())
			}

			got, err := database.GetDomain(domainID)
			if err != nil {
				t.Fatal(err)
			}
			if want := tc.want(storedProxyConfig()); !reflect.DeepEqual(got.ProxyConfig, want) {
				t.Errorf("proxy_config =\n%+v\nwant\n%+v", got.ProxyConfig, want)
			}
		})
	}
}

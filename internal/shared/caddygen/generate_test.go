package caddygen

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

func TestSlugify(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "example-com"},
		{"sub.domain.example.com", "sub-domain-example-com"},
		{"UPPER.COM", "upper-com"},
		{"my--host..com", "my-host-com"},
		{"a.b.c", "a-b-c"},
		{"simple", "simple"},
		{".leading.dot.", "leading-dot"},
		{"special!@#chars.com", "special-chars-com"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := slugify(tt.input)
			if got != tt.want {
				t.Errorf("slugify(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestGenerateRoute_Basic(t *testing.T) {
	cfg := proxymodel.Route{
		Host:     "app.example.com",
		Upstream: proxymodel.Upstream{Addr: "10.0.0.1", Port: 8080},
	}

	raw, err := GenerateRoute(cfg)
	if err != nil {
		t.Fatalf("GenerateRoute returned error: %v", err)
	}

	// Must be valid JSON.
	var generic map[string]interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}

	// Unmarshal into the typed struct.
	var route CaddyRoute
	if err := json.Unmarshal(raw, &route); err != nil {
		t.Fatalf("unmarshal into CaddyRoute: %v", err)
	}

	if route.ID != "domain-app-example-com" {
		t.Errorf("ID = %q, want %q", route.ID, "domain-app-example-com")
	}
	if !route.Terminal {
		t.Error("Terminal should be true")
	}
	if len(route.Match) != 1 || len(route.Match[0].Host) != 1 || route.Match[0].Host[0] != "app.example.com" {
		t.Errorf("unexpected match: %+v", route.Match)
	}

	// The handle array should contain a subroute.
	if len(route.Handle) != 1 {
		t.Fatalf("expected 1 top-level handler, got %d", len(route.Handle))
	}
	if route.Handle[0].Handler != "subroute" {
		t.Errorf("handler = %q, want %q", route.Handle[0].Handler, "subroute")
	}

	// Inside the subroute, the first route should have a reverse_proxy handler.
	if len(route.Handle[0].Routes) != 1 {
		t.Fatalf("expected 1 inner route, got %d", len(route.Handle[0].Routes))
	}

	innerHandles := route.Handle[0].Routes[0].Handle
	if len(innerHandles) != 1 {
		t.Fatalf("expected 1 inner handler, got %d", len(innerHandles))
	}

	// Re-marshal the inner handler and check it's a reverse_proxy.
	rpBytes, _ := json.Marshal(innerHandles[0])
	var rp ReverseProxy
	if err := json.Unmarshal(rpBytes, &rp); err != nil {
		t.Fatalf("unmarshal reverse_proxy: %v", err)
	}
	if rp.Handler != "reverse_proxy" {
		t.Errorf("inner handler = %q, want %q", rp.Handler, "reverse_proxy")
	}
	if len(rp.Upstreams) != 1 || rp.Upstreams[0].Dial != "10.0.0.1:8080" {
		t.Errorf("unexpected upstreams: %+v", rp.Upstreams)
	}

	// Check default headers.
	if rp.Headers == nil || rp.Headers.Request == nil {
		t.Fatal("expected request headers to be set")
	}
	if v, ok := rp.Headers.Request.Set["X-Forwarded-Proto"]; !ok || len(v) == 0 || v[0] != "{http.request.scheme}" {
		t.Errorf("missing or wrong X-Forwarded-Proto header: %v", rp.Headers.Request.Set)
	}
	if v, ok := rp.Headers.Request.Set["X-Real-IP"]; !ok || len(v) == 0 || v[0] != "{http.request.remote.host}" {
		t.Errorf("missing or wrong X-Real-IP header: %v", rp.Headers.Request.Set)
	}
}

func TestGenerateRoute_WebSocket(t *testing.T) {
	cfg := proxymodel.Route{
		Host:      "ws.example.com",
		Upstream:  proxymodel.Upstream{Addr: "10.0.0.2", Port: 9090},
		WebSocket: true,
	}

	raw, err := GenerateRoute(cfg)
	if err != nil {
		t.Fatalf("GenerateRoute returned error: %v", err)
	}

	var route CaddyRoute
	if err := json.Unmarshal(raw, &route); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	rpBytes, _ := json.Marshal(route.Handle[0].Routes[0].Handle[0])
	var rp ReverseProxy
	if err := json.Unmarshal(rpBytes, &rp); err != nil {
		t.Fatalf("unmarshal reverse_proxy: %v", err)
	}

	if rp.FlushInterval != -1 {
		t.Errorf("FlushInterval = %d, want -1", rp.FlushInterval)
	}
}

func TestGenerateRoute_CustomHeaders(t *testing.T) {
	cfg := proxymodel.Route{
		Host:     "headers.example.com",
		Upstream: proxymodel.Upstream{Addr: "10.0.0.3", Port: 3000},
		RequestHeaders: map[string]string{
			"X-Custom-Req": "req-value",
		},
		ResponseHeaders: map[string]string{
			"X-Custom-Resp": "resp-value",
		},
	}

	raw, err := GenerateRoute(cfg)
	if err != nil {
		t.Fatalf("GenerateRoute returned error: %v", err)
	}

	var route CaddyRoute
	if err := json.Unmarshal(raw, &route); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	rpBytes, _ := json.Marshal(route.Handle[0].Routes[0].Handle[0])
	var rp ReverseProxy
	if err := json.Unmarshal(rpBytes, &rp); err != nil {
		t.Fatalf("unmarshal reverse_proxy: %v", err)
	}

	// Check custom request header merged with defaults.
	if rp.Headers == nil || rp.Headers.Request == nil {
		t.Fatal("expected request headers")
	}
	if v, ok := rp.Headers.Request.Set["X-Custom-Req"]; !ok || len(v) == 0 || v[0] != "req-value" {
		t.Errorf("custom request header missing or wrong: %v", rp.Headers.Request.Set)
	}
	// Default headers should still be present.
	if _, ok := rp.Headers.Request.Set["X-Forwarded-Proto"]; !ok {
		t.Error("default X-Forwarded-Proto header missing")
	}

	// Check custom response header.
	if rp.Headers == nil || rp.Headers.Response == nil {
		t.Fatal("expected response headers")
	}
	if v, ok := rp.Headers.Response.Set["X-Custom-Resp"]; !ok || len(v) == 0 || v[0] != "resp-value" {
		t.Errorf("custom response header missing or wrong: %v", rp.Headers.Response.Set)
	}
}

func TestGenerateRoute_MaxBodySize(t *testing.T) {
	cfg := proxymodel.Route{
		Host:        "upload.example.com",
		Upstream:    proxymodel.Upstream{Addr: "10.0.0.4", Port: 4000},
		MaxBodySize: "100m",
	}

	raw, err := GenerateRoute(cfg)
	if err != nil {
		t.Fatalf("GenerateRoute returned error: %v", err)
	}

	var route CaddyRoute
	if err := json.Unmarshal(raw, &route); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// The subroute's inner route should have 2 handlers: request_body + reverse_proxy.
	innerHandles := route.Handle[0].Routes[0].Handle
	if len(innerHandles) != 2 {
		t.Fatalf("expected 2 inner handlers (request_body + reverse_proxy), got %d", len(innerHandles))
	}

	// First handler should be request_body.
	bodyBytes, _ := json.Marshal(innerHandles[0])
	var body Handler
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		t.Fatalf("unmarshal request_body: %v", err)
	}
	if body.Handler != "request_body" {
		t.Errorf("first handler = %q, want %q", body.Handler, "request_body")
	}
	if body.MaxSize != "100m" {
		t.Errorf("MaxSize = %q, want %q", body.MaxSize, "100m")
	}
}

func TestGenerateRoute_MaxBodySize_Unlimited(t *testing.T) {
	cfg := proxymodel.Route{
		Host:        "upload.example.com",
		Upstream:    proxymodel.Upstream{Addr: "10.0.0.4", Port: 4000},
		MaxBodySize: "unlimited",
	}

	raw, err := GenerateRoute(cfg)
	if err != nil {
		t.Fatalf("GenerateRoute returned error: %v", err)
	}

	var route CaddyRoute
	if err := json.Unmarshal(raw, &route); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// "unlimited" should not produce a request_body handler.
	innerHandles := route.Handle[0].Routes[0].Handle
	if len(innerHandles) != 1 {
		t.Fatalf("expected 1 inner handler (reverse_proxy only), got %d", len(innerHandles))
	}
}

func TestGenerateRoute_HTTPSUpstream(t *testing.T) {
	cfg := proxymodel.Route{
		Host:     "secure.example.com",
		Upstream: proxymodel.Upstream{Addr: "10.0.0.5", Port: 8443, Scheme: proxymodel.SchemeHTTPS},
	}

	raw, err := GenerateRoute(cfg)
	if err != nil {
		t.Fatalf("GenerateRoute returned error: %v", err)
	}

	var route CaddyRoute
	if err := json.Unmarshal(raw, &route); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	rpBytes, _ := json.Marshal(route.Handle[0].Routes[0].Handle[0])
	var rp ReverseProxy
	if err := json.Unmarshal(rpBytes, &rp); err != nil {
		t.Fatalf("unmarshal reverse_proxy: %v", err)
	}

	if rp.Transport == nil {
		t.Fatal("expected Transport to be set for HTTPS upstream")
	}
	if rp.Transport.Protocol != "http" {
		t.Errorf("Transport.Protocol = %q, want %q", rp.Transport.Protocol, "http")
	}
	if rp.Transport.TLS == nil {
		t.Error("expected Transport.TLS to be set")
	}
}

func TestGenerateRoute_ManualOverride(t *testing.T) {
	customJSON := `{"@id":"custom-route","match":[{"host":["custom.example.com"]}],"terminal":true}`

	cfg := proxymodel.Route{
		Host: "custom.example.com",
		Raw:  proxymodel.RawConfig{Backend: "caddy", Content: customJSON},
	}

	raw, err := GenerateRoute(cfg)
	if err != nil {
		t.Fatalf("GenerateRoute returned error: %v", err)
	}

	// Should return the raw JSON verbatim.
	var result map[string]interface{}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}

	if id, ok := result["@id"].(string); !ok || id != "custom-route" {
		t.Errorf("@id = %v, want %q", result["@id"], "custom-route")
	}
}

func TestGenerateRoute_ManualOverride_InvalidJSON(t *testing.T) {
	cfg := proxymodel.Route{
		Raw: proxymodel.RawConfig{Backend: "caddy", Content: "not valid json{"},
	}

	_, err := GenerateRoute(cfg)
	if err == nil {
		t.Fatal("expected error for invalid raw Caddy JSON")
	}
}

func TestGenerateRoute_ManualOverride_WrongBackend(t *testing.T) {
	cfg := proxymodel.Route{
		Raw: proxymodel.RawConfig{Backend: "nginx", Content: "server {}"},
	}

	_, err := GenerateRoute(cfg)
	if err == nil {
		t.Fatal("expected error for raw config tagged for a non-caddy backend")
	}
}

func TestGenerateRoute_ForceHTTPS(t *testing.T) {
	cfg := proxymodel.Route{
		Host:       "redirect.example.com",
		Upstream:   proxymodel.Upstream{Addr: "10.0.0.6", Port: 5000},
		ForceHTTPS: true,
	}

	raw, err := GenerateRoute(cfg)
	if err != nil {
		t.Fatalf("GenerateRoute returned error: %v", err)
	}

	var route CaddyRoute
	if err := json.Unmarshal(raw, &route); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Should have 2 top-level handlers: redirect subroute + main subroute.
	if len(route.Handle) != 2 {
		t.Fatalf("expected 2 top-level handlers, got %d", len(route.Handle))
	}

	// The first handler should be the redirect subroute containing a static_response.
	redirectSubroute := route.Handle[0]
	if redirectSubroute.Handler != "subroute" {
		t.Errorf("first handler = %q, want %q", redirectSubroute.Handler, "subroute")
	}
	if len(redirectSubroute.Routes) != 1 || len(redirectSubroute.Routes[0].Handle) != 1 {
		t.Fatal("redirect subroute structure unexpected")
	}

	// The redirect must be gated on the http protocol to avoid an HTTPS loop.
	redirectRoute := redirectSubroute.Routes[0]
	if !redirectRoute.Terminal {
		t.Error("redirect route should be terminal")
	}
	if len(redirectRoute.Match) != 1 || redirectRoute.Match[0]["protocol"] != "http" {
		t.Errorf("redirect should match protocol=http, got %v", redirectRoute.Match)
	}

	srBytes, _ := json.Marshal(redirectSubroute.Routes[0].Handle[0])
	var sr StaticResponse
	if err := json.Unmarshal(srBytes, &sr); err != nil {
		t.Fatalf("unmarshal static_response: %v", err)
	}
	if sr.Handler != "static_response" {
		t.Errorf("redirect handler = %q, want %q", sr.Handler, "static_response")
	}
	if sr.StatusCode != "302" {
		t.Errorf("StatusCode = %q, want %q", sr.StatusCode, "302")
	}
	if locs, ok := sr.Headers["Location"]; !ok || len(locs) == 0 {
		t.Error("redirect Location header missing")
	}
}

func TestGenerateRoute_MissingRequired(t *testing.T) {
	tests := []struct {
		name string
		cfg  proxymodel.Route
	}{
		{"missing Host", proxymodel.Route{Upstream: proxymodel.Upstream{Addr: "10.0.0.1", Port: 80}}},
		{"missing UpstreamAddr", proxymodel.Route{Host: "test.com", Upstream: proxymodel.Upstream{Port: 80}}},
		{"missing UpstreamPort", proxymodel.Route{Host: "test.com", Upstream: proxymodel.Upstream{Addr: "10.0.0.1"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GenerateRoute(tt.cfg)
			if err == nil {
				t.Error("expected error for missing required field")
			}
		})
	}
}

// mainRouteHandlers marshals every inner handler of the main route back to
// JSON so tests can assert on the presence of specific handlers/keys.
func mainRouteHandlers(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	var route CaddyRoute
	if err := json.Unmarshal(raw, &route); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// The main route is the last inner route of the (last) subroute handler.
	sub := route.Handle[len(route.Handle)-1]
	mainRoute := sub.Routes[len(sub.Routes)-1]
	out := make([]string, 0, len(mainRoute.Handle))
	for _, h := range mainRoute.Handle {
		b, _ := json.Marshal(h)
		out = append(out, string(b))
	}
	return out
}

func TestGenerateRoute_PathStripAndRewrite(t *testing.T) {
	raw, err := GenerateRoute(proxymodel.Route{
		Host:     "p.example.com",
		Upstream: proxymodel.Upstream{Addr: "10.0.0.1", Port: 80},
		Path:     proxymodel.PathRules{StripPrefix: "/api", Rewrite: "/v2{http.request.uri.path}"},
	})
	if err != nil {
		t.Fatalf("GenerateRoute: %v", err)
	}
	handlers := mainRouteHandlers(t, raw)
	joined := strings.Join(handlers, "\n")
	if !strings.Contains(joined, `"strip_path_prefix":"/api"`) {
		t.Errorf("missing strip_path_prefix handler:\n%s", joined)
	}
	if !strings.Contains(joined, `"uri":"/v2`) {
		t.Errorf("missing rewrite uri handler:\n%s", joined)
	}
	// rewrite handlers must come before reverse_proxy.
	if idxRP := strings.Index(joined, "reverse_proxy"); idxRP >= 0 {
		if strings.Index(joined, "strip_path_prefix") > idxRP {
			t.Error("strip_path_prefix should precede reverse_proxy")
		}
	}
}

func TestGenerateRoute_Timeouts(t *testing.T) {
	raw, err := GenerateRoute(proxymodel.Route{
		Host:     "t.example.com",
		Upstream: proxymodel.Upstream{Addr: "10.0.0.1", Port: 80},
		Timeouts: proxymodel.Timeouts{Read: 30, Write: 10, Idle: 120},
	})
	if err != nil {
		t.Fatalf("GenerateRoute: %v", err)
	}
	var route CaddyRoute
	if err := json.Unmarshal(raw, &route); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	sub := route.Handle[len(route.Handle)-1]
	mainRoute := sub.Routes[len(sub.Routes)-1]
	rpBytes, _ := json.Marshal(mainRoute.Handle[len(mainRoute.Handle)-1])
	var rp ReverseProxy
	if err := json.Unmarshal(rpBytes, &rp); err != nil {
		t.Fatalf("unmarshal reverse_proxy: %v", err)
	}
	if rp.Transport == nil {
		t.Fatal("expected transport for timeouts")
	}
	if rp.Transport.DialTimeout != "10s" {
		t.Errorf("DialTimeout = %q, want 10s", rp.Transport.DialTimeout)
	}
	if rp.Transport.ResponseHeaderTimeout != "30s" {
		t.Errorf("ResponseHeaderTimeout = %q, want 30s", rp.Transport.ResponseHeaderTimeout)
	}
	if rp.Transport.KeepAlive == nil || rp.Transport.KeepAlive.IdleTimeout != "120s" {
		t.Errorf("KeepAlive idle = %+v, want 120s", rp.Transport.KeepAlive)
	}
}

func TestGenerateRoute_BasicAuth(t *testing.T) {
	raw, err := GenerateRoute(proxymodel.Route{
		Host:      "auth.example.com",
		Upstream:  proxymodel.Upstream{Addr: "10.0.0.1", Port: 80},
		BasicAuth: &proxymodel.BasicAuth{Username: "alice", PasswordHash: "$2a$14$abcdefghijklmnopqrstuv"},
	})
	if err != nil {
		t.Fatalf("GenerateRoute: %v", err)
	}
	joined := strings.Join(mainRouteHandlers(t, raw), "\n")
	if !strings.Contains(joined, `"handler":"authentication"`) {
		t.Errorf("missing authentication handler:\n%s", joined)
	}
	if !strings.Contains(joined, `"http_basic"`) {
		t.Errorf("missing http_basic provider:\n%s", joined)
	}
	wantPW := base64.StdEncoding.EncodeToString([]byte("$2a$14$abcdefghijklmnopqrstuv"))
	if !strings.Contains(joined, wantPW) {
		t.Errorf("password not base64-encoded as expected (%s):\n%s", wantPW, joined)
	}
}

func TestGenerateRoute_IPLists(t *testing.T) {
	raw, err := GenerateRoute(proxymodel.Route{
		Host:        "ip.example.com",
		Upstream:    proxymodel.Upstream{Addr: "10.0.0.1", Port: 80},
		IPBlocklist: []string{"1.2.3.0/24"},
		IPAllowlist: []string{"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("GenerateRoute: %v", err)
	}
	var route CaddyRoute
	if err := json.Unmarshal(raw, &route); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	sub := route.Handle[len(route.Handle)-1]
	// Expect 3 inner routes: blocklist guard, allowlist guard, main route.
	if len(sub.Routes) != 3 {
		t.Fatalf("expected 3 inner routes (block, allow, main), got %d", len(sub.Routes))
	}
	if !sub.Routes[0].Terminal || !sub.Routes[1].Terminal {
		t.Error("guard routes must be terminal")
	}
	full := string(raw)
	if !strings.Contains(full, `"remote_ip"`) || !strings.Contains(full, `"1.2.3.0/24"`) {
		t.Errorf("blocklist matcher missing: %s", full)
	}
	if !strings.Contains(full, `"not"`) || !strings.Contains(full, `"10.0.0.0/8"`) {
		t.Errorf("allowlist negated matcher missing: %s", full)
	}
}

func TestGenerateRoute_RateLimit(t *testing.T) {
	raw, err := GenerateRoute(proxymodel.Route{
		Host:      "rl.example.com",
		Upstream:  proxymodel.Upstream{Addr: "10.0.0.1", Port: 80},
		RateLimit: proxymodel.RateLimit{RequestsPerSecond: 25},
	})
	if err != nil {
		t.Fatalf("GenerateRoute: %v", err)
	}
	joined := strings.Join(mainRouteHandlers(t, raw), "\n")
	if !strings.Contains(joined, `"handler":"rate_limit"`) {
		t.Errorf("missing rate_limit handler:\n%s", joined)
	}
	if !strings.Contains(joined, `"max_events":25`) {
		t.Errorf("rate_limit max_events not set to 25:\n%s", joined)
	}
}

func TestConfigFromDomain(t *testing.T) {
	d := models.Domain{
		Port:       3000,
		WebSocket:  true,
		ForceHTTPS: false,
		ProxyConfig: models.ProxyConfig{
			ForceHTTPS:  true, // OR-ed with top-level
			MaxBodySize: "20m",
			PathStrip:   "/x",
			TimeoutRead: 5,
			IPAllowlist: []string{"1.1.1.1/32"},
			RateLimit:   3,
			BasicAuth:   &models.BasicAuthConfig{Username: "u", Password: "h"},
		},
	}
	route := ConfigFromDomain(d, "x.example.com", "10.0.0.9")
	if route.Upstream.Addr != "10.0.0.9" || route.Upstream.Port != 3000 {
		t.Errorf("upstream wrong: %+v", route)
	}
	if !route.WebSocket || !route.ForceHTTPS {
		t.Errorf("ws/forcehttps OR-ing wrong: %+v", route)
	}
	if route.Path.StripPrefix != "/x" || route.Timeouts.Read != 5 || route.RateLimit.RequestsPerSecond != 3 {
		t.Errorf("proxy fields not mapped: %+v", route)
	}
	if route.BasicAuth == nil || route.BasicAuth.Username != "u" || route.BasicAuth.PasswordHash != "h" {
		t.Errorf("basic auth not mapped: %+v", route)
	}
	if len(route.IPAllowlist) != 1 || route.IPAllowlist[0] != "1.1.1.1/32" {
		t.Errorf("ip allowlist not mapped: %+v", route)
	}

	// And the generated route must be valid JSON.
	if _, err := GenerateRoute(route); err != nil {
		t.Fatalf("GenerateRoute from ConfigFromDomain: %v", err)
	}
}

func TestConfigFromDomain_RawConfig(t *testing.T) {
	d := models.Domain{
		Port: 80,
		ProxyConfig: models.ProxyConfig{
			RawConfig: models.RawConfig{Backend: "caddy", Content: `{"@id":"r"}`},
		},
	}
	route := ConfigFromDomain(d, "raw.example.com", "10.0.0.1")
	if !route.IsRaw() {
		t.Fatalf("expected raw route, got %+v", route.Raw)
	}
	if route.Raw.Backend != "caddy" {
		t.Errorf("raw backend = %q, want caddy", route.Raw.Backend)
	}
	if route.Raw.Content != `{"@id":"r"}` {
		t.Errorf("raw content = %q", route.Raw.Content)
	}
}

// TestConfigFromDomain_TLSPolicy verifies the per-domain TLS provisioning policy
// (§7) is mapped onto the route's TLS config: central by default, self-acme as
// the explicit fallback, off honored from either the policy or SSLMode.
func TestConfigFromDomain_TLSPolicy(t *testing.T) {
	tests := []struct {
		name    string
		cfg     models.ProxyConfig
		sslMode models.SSLMode
		want    proxymodel.TLSPolicy
	}{
		{name: "empty defaults to central", want: proxymodel.TLSPolicyCentral},
		{name: "explicit central", cfg: models.ProxyConfig{TLSPolicy: "central"}, want: proxymodel.TLSPolicyCentral},
		{name: "self-acme fallback", cfg: models.ProxyConfig{TLSPolicy: "self-acme"}, want: proxymodel.TLSPolicySelfACME},
		{name: "explicit off", cfg: models.ProxyConfig{TLSPolicy: "off"}, want: proxymodel.TLSPolicyOff},
		{name: "ssl mode off falls back to off", sslMode: models.SSLModeOff, want: proxymodel.TLSPolicyOff},
		{name: "unknown policy defaults to central", cfg: models.ProxyConfig{TLSPolicy: "bogus"}, want: proxymodel.TLSPolicyCentral},
		{name: "explicit policy wins over ssl mode off", cfg: models.ProxyConfig{TLSPolicy: "self-acme"}, sslMode: models.SSLModeOff, want: proxymodel.TLSPolicySelfACME},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := models.Domain{Port: 80, ProxyConfig: tt.cfg, SSLMode: tt.sslMode}
			route := ConfigFromDomain(d, "h.example.com", "10.0.0.1")
			if route.TLS.Policy != tt.want {
				t.Errorf("TLS.Policy = %q, want %q", route.TLS.Policy, tt.want)
			}
		})
	}
}

func TestGenerateRoute_ValidJSON(t *testing.T) {
	// Ensure all generated routes are valid JSON by round-tripping through
	// json.Unmarshal into a generic map.
	configs := []proxymodel.Route{
		{Host: "a.com", Upstream: proxymodel.Upstream{Addr: "1.2.3.4", Port: 80}},
		{Host: "b.com", Upstream: proxymodel.Upstream{Addr: "1.2.3.4", Port: 80}, WebSocket: true},
		{Host: "c.com", Upstream: proxymodel.Upstream{Addr: "1.2.3.4", Port: 80}, MaxBodySize: "50m"},
		{Host: "d.com", Upstream: proxymodel.Upstream{Addr: "1.2.3.4", Port: 443, Scheme: proxymodel.SchemeHTTPS}},
		{Host: "e.com", Upstream: proxymodel.Upstream{Addr: "1.2.3.4", Port: 80}, ForceHTTPS: true},
		{
			Host:            "f.com",
			Upstream:        proxymodel.Upstream{Addr: "1.2.3.4", Port: 80},
			RequestHeaders:  map[string]string{"X-A": "1"},
			ResponseHeaders: map[string]string{"X-B": "2"},
		},
	}
	for _, cfg := range configs {
		t.Run(cfg.Host, func(t *testing.T) {
			raw, err := GenerateRoute(cfg)
			if err != nil {
				t.Fatalf("GenerateRoute error: %v", err)
			}
			var generic map[string]interface{}
			if err := json.Unmarshal(raw, &generic); err != nil {
				t.Fatalf("generated JSON is not valid: %v\nJSON: %s", err, string(raw))
			}
		})
	}
}

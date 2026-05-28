package caddygen

import (
	"encoding/json"
	"testing"
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
	cfg := DomainConfig{
		FQDN:         "app.example.com",
		UpstreamAddr: "10.0.0.1",
		UpstreamPort: 8080,
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
	cfg := DomainConfig{
		FQDN:         "ws.example.com",
		UpstreamAddr: "10.0.0.2",
		UpstreamPort: 9090,
		WebSocket:    true,
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
	cfg := DomainConfig{
		FQDN:         "headers.example.com",
		UpstreamAddr: "10.0.0.3",
		UpstreamPort: 3000,
		CustomRequestHeaders: map[string]string{
			"X-Custom-Req": "req-value",
		},
		CustomResponseHeaders: map[string]string{
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
	cfg := DomainConfig{
		FQDN:         "upload.example.com",
		UpstreamAddr: "10.0.0.4",
		UpstreamPort: 4000,
		MaxBodySize:  "100m",
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
	cfg := DomainConfig{
		FQDN:         "upload.example.com",
		UpstreamAddr: "10.0.0.4",
		UpstreamPort: 4000,
		MaxBodySize:  "unlimited",
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
	cfg := DomainConfig{
		FQDN:           "secure.example.com",
		UpstreamAddr:   "10.0.0.5",
		UpstreamPort:   8443,
		UpstreamScheme: "https",
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

	cfg := DomainConfig{
		FQDN:     "custom.example.com",
		RawCaddy: customJSON,
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
	cfg := DomainConfig{
		RawCaddy: "not valid json{",
	}

	_, err := GenerateRoute(cfg)
	if err == nil {
		t.Fatal("expected error for invalid RawCaddy JSON")
	}
}

func TestGenerateRoute_ForceHTTPS(t *testing.T) {
	cfg := DomainConfig{
		FQDN:         "redirect.example.com",
		UpstreamAddr: "10.0.0.6",
		UpstreamPort: 5000,
		ForceHTTPS:   true,
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
		cfg  DomainConfig
	}{
		{"missing FQDN", DomainConfig{UpstreamAddr: "10.0.0.1", UpstreamPort: 80}},
		{"missing UpstreamAddr", DomainConfig{FQDN: "test.com", UpstreamPort: 80}},
		{"missing UpstreamPort", DomainConfig{FQDN: "test.com", UpstreamAddr: "10.0.0.1"}},
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

func TestGenerateRoute_ValidJSON(t *testing.T) {
	// Ensure all generated routes are valid JSON by round-tripping through
	// json.Unmarshal into a generic map.
	configs := []DomainConfig{
		{FQDN: "a.com", UpstreamAddr: "1.2.3.4", UpstreamPort: 80},
		{FQDN: "b.com", UpstreamAddr: "1.2.3.4", UpstreamPort: 80, WebSocket: true},
		{FQDN: "c.com", UpstreamAddr: "1.2.3.4", UpstreamPort: 80, MaxBodySize: "50m"},
		{FQDN: "d.com", UpstreamAddr: "1.2.3.4", UpstreamPort: 443, UpstreamScheme: "https"},
		{FQDN: "e.com", UpstreamAddr: "1.2.3.4", UpstreamPort: 80, ForceHTTPS: true},
		{
			FQDN: "f.com", UpstreamAddr: "1.2.3.4", UpstreamPort: 80,
			CustomRequestHeaders:  map[string]string{"X-A": "1"},
			CustomResponseHeaders: map[string]string{"X-B": "2"},
		},
	}
	for _, cfg := range configs {
		t.Run(cfg.FQDN, func(t *testing.T) {
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

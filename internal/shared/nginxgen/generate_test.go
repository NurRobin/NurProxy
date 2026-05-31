package nginxgen

import (
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// baseRoute is a minimal valid structured route used as a starting point for
// table cases. TLS defaults to off so cases opt into a cert explicitly.
func baseRoute() proxymodel.Route {
	return proxymodel.Route{
		Host:     "app.example.com",
		Upstream: proxymodel.Upstream{Addr: "10.0.0.4", Port: 8080},
		TLS:      proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
	}
}

func TestRender_structured_intentToConfig(t *testing.T) {
	tests := []struct {
		name        string
		input       Input
		wantServer  []string // substrings that MUST appear in the server block
		notServer   []string // substrings that must NOT appear
		wantPream   []string // substrings that MUST appear in the http preamble
		wantWarn    []string // Warning.Option values expected (any order)
		wantNoWarns bool
	}{
		{
			name:  "reverse_proxy_basic",
			input: Input{Route: baseRoute()},
			wantServer: []string{
				"server {",
				"listen 80;",
				"server_name app.example.com;",
				"location / {",
				"proxy_pass http://10.0.0.4:8080;",
				"proxy_set_header Host $host;",
				"proxy_set_header X-Real-IP $remote_addr;",
				"proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
				"proxy_set_header X-Forwarded-Proto $scheme;",
			},
			notServer:   []string{"listen 443", "proxy_set_header Upgrade", "ssl_certificate"},
			wantNoWarns: true,
		},
		{
			name: "websocket_upgrade_headers",
			input: func() Input {
				r := baseRoute()
				r.WebSocket = true
				return Input{Route: r}
			}(),
			wantServer: []string{
				"proxy_http_version 1.1;",
				"proxy_set_header Upgrade $http_upgrade;",
				`proxy_set_header Connection "upgrade";`,
			},
			wantNoWarns: true,
		},
		{
			name: "force_https_with_cert_emits_redirect_server",
			input: func() Input {
				r := baseRoute()
				r.TLS = proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyCentral}
				r.ForceHTTPS = true
				return Input{Route: r, CertPath: "/etc/ssl/app.crt", KeyPath: "/etc/ssl/app.key"}
			}(),
			wantServer: []string{
				"listen 80;",
				"return 301 https://$host$request_uri;",
				"listen 443 ssl;",
				"ssl_certificate /etc/ssl/app.crt;",
				"ssl_certificate_key /etc/ssl/app.key;",
			},
			wantNoWarns: true,
		},
		{
			name: "force_https_without_cert_dropped_with_warning",
			input: func() Input {
				r := baseRoute() // TLS off
				r.ForceHTTPS = true
				return Input{Route: r}
			}(),
			notServer: []string{"return 301", "listen 443"},
			wantWarn:  []string{"force_https"},
		},
		{
			name: "custom_request_and_response_headers",
			input: func() Input {
				r := baseRoute()
				r.RequestHeaders = map[string]string{"X-Tenant": "acme"}
				r.ResponseHeaders = map[string]string{"X-Frame-Options": "DENY"}
				return Input{Route: r}
			}(),
			wantServer: []string{
				"proxy_set_header X-Tenant acme;",
				"add_header X-Frame-Options DENY always;",
			},
			wantNoWarns: true,
		},
		{
			name: "path_strip_prefix",
			input: func() Input {
				r := baseRoute()
				r.Path = proxymodel.PathRules{StripPrefix: "/api"}
				return Input{Route: r}
			}(),
			wantServer:  []string{`rewrite ^/api/?(.*)$ /$1 break;`},
			wantNoWarns: true,
		},
		{
			name: "path_rewrite",
			input: func() Input {
				r := baseRoute()
				r.Path = proxymodel.PathRules{Rewrite: "/newpath"}
				return Input{Route: r}
			}(),
			wantServer:  []string{`rewrite ^.*$ /newpath break;`},
			wantNoWarns: true,
		},
		{
			name: "basic_auth_with_authfile",
			input: func() Input {
				r := baseRoute()
				r.BasicAuth = &proxymodel.BasicAuth{Username: "admin", PasswordHash: "$2y$..."}
				return Input{Route: r, AuthFile: "/etc/nginx/nurproxy/app.htpasswd"}
			}(),
			wantServer: []string{
				`auth_basic "Restricted: app.example.com";`,
				"auth_basic_user_file /etc/nginx/nurproxy/app.htpasswd;",
			},
			wantNoWarns: true,
		},
		{
			name: "basic_auth_without_authfile_dropped",
			input: func() Input {
				r := baseRoute()
				r.BasicAuth = &proxymodel.BasicAuth{Username: "admin", PasswordHash: "x"}
				return Input{Route: r} // no AuthFile
			}(),
			notServer: []string{"auth_basic"},
			wantWarn:  []string{"basic_auth"},
		},
		{
			name: "ip_allow_and_block",
			input: func() Input {
				r := baseRoute()
				r.IPBlocklist = []string{"203.0.113.0/24"}
				r.IPAllowlist = []string{"10.0.0.0/8"}
				return Input{Route: r}
			}(),
			wantServer: []string{
				"deny 203.0.113.0/24;",
				"allow 10.0.0.0/8;",
				"deny all;",
			},
			wantNoWarns: true,
		},
		{
			name: "rate_limit_emits_zone_and_limit_req",
			input: func() Input {
				r := baseRoute()
				r.RateLimit = proxymodel.RateLimit{RequestsPerSecond: 5}
				return Input{Route: r}
			}(),
			wantPream:   []string{"limit_req_zone $binary_remote_addr zone=nurproxy_app_example_com:10m rate=5r/s;"},
			wantServer:  []string{"limit_req zone=nurproxy_app_example_com burst=5 nodelay;"},
			wantNoWarns: true,
		},
		{
			name: "rate_limit_subsecond_uses_per_minute",
			input: func() Input {
				r := baseRoute()
				r.RateLimit = proxymodel.RateLimit{RequestsPerSecond: 0.5}
				return Input{Route: r}
			}(),
			wantPream:   []string{"rate=30r/m;"},
			wantServer:  []string{"burst=1 nodelay;"},
			wantNoWarns: true,
		},
		{
			name: "max_body_size",
			input: func() Input {
				r := baseRoute()
				r.MaxBodySize = "10MB"
				return Input{Route: r}
			}(),
			wantServer:  []string{"client_max_body_size 10m;"},
			wantNoWarns: true,
		},
		{
			name: "max_body_size_unlimited",
			input: func() Input {
				r := baseRoute()
				r.MaxBodySize = "unlimited"
				return Input{Route: r}
			}(),
			wantServer:  []string{"client_max_body_size 0;"},
			wantNoWarns: true,
		},
		{
			name: "upstream_https_scheme",
			input: func() Input {
				r := baseRoute()
				r.Upstream.Scheme = proxymodel.SchemeHTTPS
				return Input{Route: r}
			}(),
			wantServer:  []string{"proxy_pass https://10.0.0.4:8080;"},
			wantNoWarns: true,
		},
		{
			name: "upstream_timeouts",
			input: func() Input {
				r := baseRoute()
				r.Timeouts = proxymodel.Timeouts{Read: 30, Write: 10, Idle: 60}
				return Input{Route: r}
			}(),
			wantServer: []string{
				"proxy_connect_timeout 10s;",
				"proxy_send_timeout 10s;",
				"proxy_read_timeout 30s;",
			},
			wantNoWarns: true,
		},
		{
			name: "central_tls_provided_cert_references",
			input: func() Input {
				r := baseRoute()
				r.TLS = proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyCentral}
				return Input{Route: r, CertPath: "/var/lib/nurproxy/certs/app.crt", KeyPath: "/var/lib/nurproxy/certs/app.key"}
			}(),
			wantServer: []string{
				"listen 443 ssl;",
				"http2 on;",
				"ssl_certificate /var/lib/nurproxy/certs/app.crt;",
				"ssl_certificate_key /var/lib/nurproxy/certs/app.key;",
			},
			wantNoWarns: true,
		},
		{
			name: "central_tls_without_cert_falls_back_to_plaintext_with_warning",
			input: func() Input {
				r := baseRoute()
				r.TLS = proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyCentral}
				return Input{Route: r} // no cert paths
			}(),
			wantServer: []string{"listen 80;"},
			notServer:  []string{"ssl_certificate", "listen 443"},
			wantWarn:   []string{"tls"},
		},
		{
			name: "self_acme_unsupported_dropped_with_warning",
			input: func() Input {
				r := baseRoute()
				r.TLS = proxymodel.TLSConfig{Policy: proxymodel.TLSPolicySelfACME}
				return Input{Route: r}
			}(),
			wantServer: []string{"listen 80;"},
			notServer:  []string{"listen 443", "ssl_certificate"},
			wantWarn:   []string{"tls"},
		},
		{
			name: "wildcard_cert_warns_shared_key_but_still_tls",
			input: func() Input {
				r := baseRoute()
				r.TLS = proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyCentral, Wildcard: true}
				return Input{Route: r, CertPath: "/c.crt", KeyPath: "/c.key"}
			}(),
			wantServer: []string{"listen 443 ssl;", "ssl_certificate /c.crt;"},
			wantWarn:   []string{"tls_wildcard"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := Render(tt.input)
			if err != nil {
				t.Fatalf("Render returned error: %v", err)
			}
			for _, want := range tt.wantServer {
				if !strings.Contains(res.Server, want) {
					t.Errorf("server block missing %q\n--- got ---\n%s", want, res.Server)
				}
			}
			for _, no := range tt.notServer {
				if strings.Contains(res.Server, no) {
					t.Errorf("server block unexpectedly contains %q\n--- got ---\n%s", no, res.Server)
				}
			}
			for _, want := range tt.wantPream {
				if !strings.Contains(res.HTTPPreamble, want) {
					t.Errorf("http preamble missing %q\n--- got ---\n%s", want, res.HTTPPreamble)
				}
			}
			gotWarns := warnOptions(res.Warnings)
			if tt.wantNoWarns && len(res.Warnings) != 0 {
				t.Errorf("expected no warnings, got %v", gotWarns)
			}
			for _, w := range tt.wantWarn {
				if !contains(gotWarns, w) {
					t.Errorf("expected warning option %q, got %v", w, gotWarns)
				}
			}
		})
	}
}

func TestRender_rawNginx_returnedVerbatim(t *testing.T) {
	content := "server {\n    listen 80;\n    # operator's own block\n}\n"
	res, err := Render(Input{Route: proxymodel.Route{
		Raw: proxymodel.RawConfig{Backend: "nginx", Content: content},
	}})
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	if res.Server != content {
		t.Errorf("raw content not returned verbatim:\ngot  %q\nwant %q", res.Server, content)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("raw render should not warn, got %v", warnOptions(res.Warnings))
	}
}

func TestRender_rawWrongBackend_errors(t *testing.T) {
	_, err := Render(Input{Route: proxymodel.Route{
		Raw: proxymodel.RawConfig{Backend: "caddy", Content: "{}"},
	}})
	if err == nil {
		t.Fatal("expected error for raw config tagged for another backend")
	}
}

func TestRender_invalidStructured_errors(t *testing.T) {
	tests := []struct {
		name  string
		route proxymodel.Route
	}{
		{"missing_host", proxymodel.Route{Upstream: proxymodel.Upstream{Addr: "x", Port: 80}}},
		{"missing_upstream_addr", proxymodel.Route{Host: "h", Upstream: proxymodel.Upstream{Port: 80}}},
		{"bad_port", proxymodel.Route{Host: "h", Upstream: proxymodel.Upstream{Addr: "x", Port: 0}}},
		{"port_too_high", proxymodel.Route{Host: "h", Upstream: proxymodel.Upstream{Addr: "x", Port: 70000}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Render(Input{Route: tt.route}); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestRender_deterministic guards byte-stable output across runs (sorted header
// keys, fixed directive order), which matters for diff-stable storage (§4).
func TestRender_deterministic(t *testing.T) {
	r := baseRoute()
	r.RequestHeaders = map[string]string{"X-B": "2", "X-A": "1", "X-C": "3"}
	r.ResponseHeaders = map[string]string{"Z-Three": "c", "Z-One": "a", "Z-Two": "b"}
	in := Input{Route: r}

	first, err := Render(in)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for i := 0; i < 20; i++ {
		got, err := Render(in)
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		if got.Server != first.Server {
			t.Fatalf("non-deterministic output on iteration %d", i)
		}
	}
	// Request headers must appear in sorted order.
	ai := strings.Index(first.Server, "X-A")
	bi := strings.Index(first.Server, "X-B")
	ci := strings.Index(first.Server, "X-C")
	if ai >= bi || bi >= ci {
		t.Errorf("request headers not in sorted order: A=%d B=%d C=%d", ai, bi, ci)
	}
}

func TestNormalizeBodySize(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"10MB", "10m"},
		{"10mb", "10m"},
		{"500k", "500k"},
		{"2G", "2g"},
		{"unlimited", "0"},
		{"  5M  ", "5m"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := normalizeBodySize(tt.in); got != tt.want {
				t.Errorf("normalizeBodySize(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSlugify(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"app.example.com", "app_example_com"},
		{"UPPER.COM", "upper_com"},
		{"a--b..c", "a_b_c"},
		{".lead.dot.", "lead_dot"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := slugify(tt.in); got != tt.want {
				t.Errorf("slugify(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestFormatRate(t *testing.T) {
	tests := []struct {
		in   float64
		want string
	}{
		{5, "5r/s"},
		{1, "1r/s"},
		{0.5, "30r/m"},
		{0.01, "1r/m"},
		{100, "100r/s"},
	}
	for _, tt := range tests {
		if got := formatRate(tt.in); got != tt.want {
			t.Errorf("formatRate(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func warnOptions(ws []Warning) []string {
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		out = append(out, w.Option)
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

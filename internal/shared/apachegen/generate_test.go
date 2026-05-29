package apachegen

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
		wantVHost   []string // substrings that MUST appear in the vhost block
		notVHost    []string // substrings that must NOT appear
		wantWarn    []string // Warning.Option values expected (any order)
		wantNoWarns bool
	}{
		{
			name:  "reverse_proxy_basic",
			input: Input{Route: baseRoute()},
			wantVHost: []string{
				"<VirtualHost *:80>",
				"ServerName app.example.com",
				"ProxyPreserveHost On",
				"ProxyPass / http://10.0.0.4:8080/",
				"ProxyPassReverse / http://10.0.0.4:8080/",
				"RequestHeader set X-Forwarded-Proto http",
				"</VirtualHost>",
			},
			notVHost:    []string{"*:443", "SSLEngine", "RewriteCond", "AuthType"},
			wantNoWarns: true,
		},
		{
			name: "websocket_upgrade_rewrite",
			input: func() Input {
				r := baseRoute()
				r.WebSocket = true
				return Input{Route: r}
			}(),
			wantVHost: []string{
				"RewriteEngine On",
				"RewriteCond %{HTTP:Upgrade} =websocket [NC]",
				"RewriteRule ^/?(.*)$ ws://10.0.0.4:8080/$1 [P,L]",
				"ProxyPass / http://10.0.0.4:8080/",
			},
			wantNoWarns: true,
		},
		{
			name: "websocket_https_upstream_uses_wss",
			input: func() Input {
				r := baseRoute()
				r.WebSocket = true
				r.Upstream.Scheme = proxymodel.SchemeHTTPS
				return Input{Route: r}
			}(),
			wantVHost: []string{
				"RewriteRule ^/?(.*)$ wss://10.0.0.4:8080/$1 [P,L]",
				"ProxyPass / https://10.0.0.4:8080/",
			},
			wantNoWarns: true,
		},
		{
			name: "force_https_with_cert_emits_redirect_and_tls_vhost",
			input: func() Input {
				r := baseRoute()
				r.TLS = proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyCentral}
				r.ForceHTTPS = true
				return Input{Route: r, CertPath: "/etc/ssl/app.crt", KeyPath: "/etc/ssl/app.key"}
			}(),
			wantVHost: []string{
				"<VirtualHost *:80>",
				"Redirect permanent / https://app.example.com/",
				"<VirtualHost *:443>",
				"SSLEngine on",
				"SSLCertificateFile /etc/ssl/app.crt",
				"SSLCertificateKeyFile /etc/ssl/app.key",
				"RequestHeader set X-Forwarded-Proto https",
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
			notVHost: []string{"Redirect permanent", "*:443"},
			wantWarn: []string{"force_https"},
		},
		{
			name: "tls_central_without_cert_falls_back_plaintext",
			input: func() Input {
				r := baseRoute()
				r.TLS = proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyCentral}
				return Input{Route: r} // no cert/key
			}(),
			wantVHost: []string{"<VirtualHost *:80>"},
			notVHost:  []string{"SSLEngine", "*:443"},
			wantWarn:  []string{"tls"},
		},
		{
			name: "self_acme_unsupported_dropped",
			input: func() Input {
				r := baseRoute()
				r.TLS = proxymodel.TLSConfig{Policy: proxymodel.TLSPolicySelfACME}
				return Input{Route: r}
			}(),
			notVHost: []string{"SSLEngine", "*:443"},
			wantWarn: []string{"tls"},
		},
		{
			name: "wildcard_cert_warns_shared_key",
			input: func() Input {
				r := baseRoute()
				r.TLS = proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyCentral, Wildcard: true}
				return Input{Route: r, CertPath: "/c", KeyPath: "/k"}
			}(),
			wantVHost: []string{"<VirtualHost *:443>", "SSLEngine on"},
			wantWarn:  []string{"tls_wildcard"},
		},
		{
			name: "custom_request_and_response_headers_sorted",
			input: func() Input {
				r := baseRoute()
				r.RequestHeaders = map[string]string{"X-Req": "one", "A-Req": "two"}
				r.ResponseHeaders = map[string]string{"X-Resp": "yes"}
				return Input{Route: r}
			}(),
			wantVHost: []string{
				"RequestHeader set A-Req two",
				"RequestHeader set X-Req one",
				"Header always set X-Resp yes",
			},
			wantNoWarns: true,
		},
		{
			name: "header_value_with_spaces_is_quoted",
			input: func() Input {
				r := baseRoute()
				r.ResponseHeaders = map[string]string{"Content-Security-Policy": "default-src 'self'"}
				return Input{Route: r}
			}(),
			wantVHost:   []string{`Header always set Content-Security-Policy "default-src 'self'"`},
			wantNoWarns: true,
		},
		{
			name: "strip_prefix_rewrites_path",
			input: func() Input {
				r := baseRoute()
				r.Path = proxymodel.PathRules{StripPrefix: "/api"}
				return Input{Route: r}
			}(),
			wantVHost: []string{
				"RewriteEngine On",
				`RewriteRule ^/api/?(.*)$ http://10.0.0.4:8080/$1 [P]`,
				"ProxyPassReverse / http://10.0.0.4:8080/",
			},
			notVHost:    []string{"ProxyPass / http://"},
			wantNoWarns: true,
		},
		{
			name: "full_rewrite_uri",
			input: func() Input {
				r := baseRoute()
				r.Path = proxymodel.PathRules{Rewrite: "/newpath"}
				return Input{Route: r}
			}(),
			wantVHost: []string{
				"RewriteEngine On",
				"RewriteRule ^.*$ http://10.0.0.4:8080/newpath [P]",
			},
			wantNoWarns: true,
		},
		{
			name: "basic_auth_with_authfile",
			input: func() Input {
				r := baseRoute()
				r.BasicAuth = &proxymodel.BasicAuth{Username: "u", PasswordHash: "h"}
				return Input{Route: r, AuthFile: "/etc/apache2/.htpasswd-app"}
			}(),
			wantVHost: []string{
				"<Location />",
				"AuthType Basic",
				`AuthName "Restricted: app.example.com"`,
				"AuthUserFile /etc/apache2/.htpasswd-app",
				"Require valid-user",
				"</Location>",
			},
			wantNoWarns: true,
		},
		{
			name: "basic_auth_without_authfile_dropped",
			input: func() Input {
				r := baseRoute()
				r.BasicAuth = &proxymodel.BasicAuth{Username: "u", PasswordHash: "h"}
				return Input{Route: r} // no AuthFile
			}(),
			notVHost: []string{"AuthType", "Require valid-user"},
			wantWarn: []string{"basic_auth"},
		},
		{
			name: "ip_allowlist_only",
			input: func() Input {
				r := baseRoute()
				r.IPAllowlist = []string{"10.0.0.0/8", "192.168.1.0/24"}
				return Input{Route: r}
			}(),
			wantVHost: []string{
				"<RequireAll>",
				"Require ip 10.0.0.0/8 192.168.1.0/24",
				"</RequireAll>",
			},
			notVHost:    []string{"Require all granted"},
			wantNoWarns: true,
		},
		{
			name: "ip_blocklist_only_allows_rest",
			input: func() Input {
				r := baseRoute()
				r.IPBlocklist = []string{"1.2.3.4/32"}
				return Input{Route: r}
			}(),
			wantVHost: []string{
				"<RequireAll>",
				"Require all granted",
				"Require not ip 1.2.3.4/32",
			},
			wantNoWarns: true,
		},
		{
			name: "ip_allow_and_block_compose",
			input: func() Input {
				r := baseRoute()
				r.IPAllowlist = []string{"10.0.0.0/8"}
				r.IPBlocklist = []string{"10.1.2.3/32"}
				return Input{Route: r}
			}(),
			wantVHost: []string{
				"Require ip 10.0.0.0/8",
				"Require not ip 10.1.2.3/32",
			},
			notVHost:    []string{"Require all granted"},
			wantNoWarns: true,
		},
		{
			name: "max_body_size_to_bytes",
			input: func() Input {
				r := baseRoute()
				r.MaxBodySize = "10MB"
				return Input{Route: r}
			}(),
			wantVHost:   []string{"LimitRequestBody 10000000"},
			wantNoWarns: true,
		},
		{
			name: "max_body_size_unlimited",
			input: func() Input {
				r := baseRoute()
				r.MaxBodySize = "unlimited"
				return Input{Route: r}
			}(),
			wantVHost:   []string{"LimitRequestBody 0"},
			wantNoWarns: true,
		},
		{
			name: "max_body_size_unparseable_dropped",
			input: func() Input {
				r := baseRoute()
				r.MaxBodySize = "lots"
				return Input{Route: r}
			}(),
			notVHost: []string{"LimitRequestBody"},
			wantWarn: []string{"max_body_size"},
		},
		{
			name: "upstream_timeouts",
			input: func() Input {
				r := baseRoute()
				r.Timeouts = proxymodel.Timeouts{Read: 30, Write: 5}
				return Input{Route: r}
			}(),
			wantVHost:   []string{"connectiontimeout=5", "timeout=30"},
			wantNoWarns: true,
		},
		{
			name: "https_upstream_scheme",
			input: func() Input {
				r := baseRoute()
				r.Upstream.Scheme = proxymodel.SchemeHTTPS
				return Input{Route: r}
			}(),
			wantVHost:   []string{"ProxyPass / https://10.0.0.4:8080/"},
			wantNoWarns: true,
		},
		{
			name: "rate_limit_dropped_with_warning",
			input: func() Input {
				r := baseRoute()
				r.RateLimit = proxymodel.RateLimit{RequestsPerSecond: 10}
				return Input{Route: r}
			}(),
			notVHost: []string{"RateLimit", "limit_req"},
			wantWarn: []string{"rate_limit"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := Render(tt.input)
			if err != nil {
				t.Fatalf("Render() error = %v", err)
			}
			for _, want := range tt.wantVHost {
				if !strings.Contains(res.VHost, want) {
					t.Errorf("vhost missing %q\n--- vhost ---\n%s", want, res.VHost)
				}
			}
			for _, no := range tt.notVHost {
				if strings.Contains(res.VHost, no) {
					t.Errorf("vhost unexpectedly contains %q\n--- vhost ---\n%s", no, res.VHost)
				}
			}
			gotWarn := make(map[string]bool)
			for _, w := range res.Warnings {
				gotWarn[w.Option] = true
			}
			for _, w := range tt.wantWarn {
				if !gotWarn[w] {
					t.Errorf("expected warning %q, got %v", w, res.Warnings)
				}
			}
			if tt.wantNoWarns && len(res.Warnings) != 0 {
				t.Errorf("expected no warnings, got %v", res.Warnings)
			}
		})
	}
}

func TestRender_raw_apacheBackendVerbatim(t *testing.T) {
	content := "<VirtualHost *:80>\n    ServerName raw.example.com\n</VirtualHost>\n"
	res, err := Render(Input{Route: proxymodel.Route{
		Host: "raw.example.com",
		Raw:  proxymodel.RawConfig{Backend: "apache", Content: content},
	}})
	if err != nil {
		t.Fatalf("Render() raw error = %v", err)
	}
	if res.VHost != content {
		t.Errorf("raw vhost = %q, want verbatim %q", res.VHost, content)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("raw render should not warn, got %v", res.Warnings)
	}
}

func TestRender_raw_wrongBackend_errors(t *testing.T) {
	_, err := Render(Input{Route: proxymodel.Route{
		Host: "x.example.com",
		Raw:  proxymodel.RawConfig{Backend: "nginx", Content: "server {}"},
	}})
	if err == nil {
		t.Fatal("expected error for raw config tagged for another backend")
	}
}

func TestRender_validation_errors(t *testing.T) {
	tests := []struct {
		name  string
		route proxymodel.Route
	}{
		{name: "missing_host", route: proxymodel.Route{Upstream: proxymodel.Upstream{Addr: "x", Port: 80}}},
		{name: "missing_upstream_addr", route: proxymodel.Route{Host: "h", Upstream: proxymodel.Upstream{Port: 80}}},
		{name: "bad_port_zero", route: proxymodel.Route{Host: "h", Upstream: proxymodel.Upstream{Addr: "x", Port: 0}}},
		{name: "bad_port_high", route: proxymodel.Route{Host: "h", Upstream: proxymodel.Upstream{Addr: "x", Port: 70000}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Render(Input{Route: tt.route}); err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
		})
	}
}

// TestRender_deterministic guards byte-stable output across runs (maps iterate
// in random order; sortedKeys must defeat that).
func TestRender_deterministic(t *testing.T) {
	r := baseRoute()
	r.RequestHeaders = map[string]string{"A": "1", "B": "2", "C": "3"}
	r.ResponseHeaders = map[string]string{"X": "9", "Y": "8", "Z": "7"}
	in := Input{Route: r}
	first, err := Render(in)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for i := 0; i < 20; i++ {
		got, err := Render(in)
		if err != nil {
			t.Fatalf("Render iter %d: %v", i, err)
		}
		if got.VHost != first.VHost {
			t.Fatalf("non-deterministic output on iter %d:\n--- first ---\n%s\n--- got ---\n%s", i, first.VHost, got.VHost)
		}
	}
}

func TestParseSizeToBytes(t *testing.T) {
	tests := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"100", 100, true},
		{"100b", 100, true},
		{"10k", 10000, true},
		{"10kb", 10000, true},
		{"5M", 5000000, true},
		{"5MB", 5000000, true},
		{"1g", 1000000000, true},
		{"", 0, false},
		{"abc", 0, false},
		{"-5", 0, false},
	}
	for _, tt := range tests {
		got, ok := parseSizeToBytes(tt.in)
		if ok != tt.ok || (ok && got != tt.want) {
			t.Errorf("parseSizeToBytes(%q) = (%d,%v), want (%d,%v)", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

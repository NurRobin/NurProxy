package nginxparse

import (
	"reflect"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/nginxgen"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// TestParse_roundTrip_render_then_parse_recoversRoute renders a Route with
// nginxgen, parses the result back with Parse, and asserts the recovered Route
// equals the input for the feature set the mask supports. This is the core §6
// guarantee: form⇄raw is lossless for supported cases.
func TestParse_roundTrip_render_then_parse_recoversRoute(t *testing.T) {
	// The cert/auth paths the agent injects; the parser recovers the TLS *policy*
	// (central vs off) and basic-auth *presence*, not these host-specific paths,
	// which is the documented asymmetry of the mask.
	const certPath = "/etc/nurproxy/certs/app.example.com.crt"
	const keyPath = "/etc/nurproxy/certs/app.example.com.key"
	const authFile = "/etc/nurproxy/auth/app.example.com.htpasswd"

	tests := []struct {
		name  string
		route proxymodel.Route
		// want is what the mask should recover. It differs from route only where
		// the mask is intentionally lossy (basic-auth hash, rate value).
		want proxymodel.Route
	}{
		{
			name: "minimal_http_proxy",
			route: proxymodel.Route{
				Host:     "app.example.com",
				Upstream: proxymodel.Upstream{Addr: "10.0.0.4", Port: 8080},
				TLS:      proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
			},
			want: proxymodel.Route{
				Host:     "app.example.com",
				Upstream: proxymodel.Upstream{Addr: "10.0.0.4", Port: 8080, Scheme: proxymodel.SchemeHTTP},
				TLS:      proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
			},
		},
		{
			name: "https_upstream",
			route: proxymodel.Route{
				Host:     "api.example.com",
				Upstream: proxymodel.Upstream{Addr: "backend.internal", Port: 8443, Scheme: proxymodel.SchemeHTTPS},
				TLS:      proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
			},
			want: proxymodel.Route{
				Host:     "api.example.com",
				Upstream: proxymodel.Upstream{Addr: "backend.internal", Port: 8443, Scheme: proxymodel.SchemeHTTPS},
				TLS:      proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
			},
		},
		{
			name: "tls_with_force_https",
			route: proxymodel.Route{
				Host:       "secure.example.com",
				Upstream:   proxymodel.Upstream{Addr: "10.0.0.9", Port: 3000},
				ForceHTTPS: true,
				TLS:        proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyCentral},
			},
			want: proxymodel.Route{
				Host:       "secure.example.com",
				Upstream:   proxymodel.Upstream{Addr: "10.0.0.9", Port: 3000, Scheme: proxymodel.SchemeHTTP},
				ForceHTTPS: true,
				TLS:        proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyCentral},
			},
		},
		{
			name: "websocket",
			route: proxymodel.Route{
				Host:      "ws.example.com",
				Upstream:  proxymodel.Upstream{Addr: "10.0.0.5", Port: 9000},
				WebSocket: true,
				TLS:       proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
			},
			want: proxymodel.Route{
				Host:      "ws.example.com",
				Upstream:  proxymodel.Upstream{Addr: "10.0.0.5", Port: 9000, Scheme: proxymodel.SchemeHTTP},
				WebSocket: true,
				TLS:       proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
			},
		},
		{
			name: "custom_headers_and_body_size",
			route: proxymodel.Route{
				Host:            "h.example.com",
				Upstream:        proxymodel.Upstream{Addr: "10.0.0.6", Port: 8000},
				MaxBodySize:     "10MB",
				RequestHeaders:  map[string]string{"X-Custom": "abc"},
				ResponseHeaders: map[string]string{"X-Frame-Options": "DENY"},
				TLS:             proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
			},
			want: proxymodel.Route{
				Host:            "h.example.com",
				Upstream:        proxymodel.Upstream{Addr: "10.0.0.6", Port: 8000, Scheme: proxymodel.SchemeHTTP},
				MaxBodySize:     "10m", // nginx normalized form
				RequestHeaders:  map[string]string{"X-Custom": "abc"},
				ResponseHeaders: map[string]string{"X-Frame-Options": "DENY"},
				TLS:             proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
			},
		},
		{
			name: "ip_allow_block",
			route: proxymodel.Route{
				Host:        "ip.example.com",
				Upstream:    proxymodel.Upstream{Addr: "10.0.0.7", Port: 8081},
				IPAllowlist: []string{"10.0.0.0/8", "192.168.0.0/16"},
				IPBlocklist: []string{"1.2.3.4/32"},
				TLS:         proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
			},
			want: proxymodel.Route{
				Host:        "ip.example.com",
				Upstream:    proxymodel.Upstream{Addr: "10.0.0.7", Port: 8081, Scheme: proxymodel.SchemeHTTP},
				IPAllowlist: []string{"10.0.0.0/8", "192.168.0.0/16"},
				IPBlocklist: []string{"1.2.3.4/32"},
				TLS:         proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
			},
		},
		{
			name: "strip_prefix",
			route: proxymodel.Route{
				Host:     "strip.example.com",
				Upstream: proxymodel.Upstream{Addr: "10.0.0.8", Port: 8082},
				Path:     proxymodel.PathRules{StripPrefix: "/api"},
				TLS:      proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
			},
			want: proxymodel.Route{
				Host:     "strip.example.com",
				Upstream: proxymodel.Upstream{Addr: "10.0.0.8", Port: 8082, Scheme: proxymodel.SchemeHTTP},
				Path:     proxymodel.PathRules{StripPrefix: "/api"},
				TLS:      proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
			},
		},
		{
			name: "timeouts",
			route: proxymodel.Route{
				Host:     "to.example.com",
				Upstream: proxymodel.Upstream{Addr: "10.0.0.10", Port: 8083},
				Timeouts: proxymodel.Timeouts{Read: 60, Write: 30},
				TLS:      proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
			},
			want: proxymodel.Route{
				Host:     "to.example.com",
				Upstream: proxymodel.Upstream{Addr: "10.0.0.10", Port: 8083, Scheme: proxymodel.SchemeHTTP},
				Timeouts: proxymodel.Timeouts{Read: 60, Write: 30},
				TLS:      proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rendered, err := nginxgen.Render(nginxgen.Input{
				Route:    tt.route,
				CertPath: certPath,
				KeyPath:  keyPath,
				AuthFile: authFile,
			})
			if err != nil {
				t.Fatalf("render: %v", err)
			}

			res := Parse(rendered.Server)
			if !res.OK {
				t.Fatalf("Parse not OK; notes=%v unparsed=%v", res.Notes, res.Unparsed)
			}
			if len(res.Unparsed) != 0 {
				t.Fatalf("clean parse left unparsed text: %v", res.Unparsed)
			}
			if !reflect.DeepEqual(res.Route, tt.want) {
				t.Errorf("round-trip mismatch:\n got = %+v\nwant = %+v", res.Route, tt.want)
			}
		})
	}
}

// TestParse_basicAuth_recoversPresence_butNotCredentials asserts the mask flags
// basic-auth presence (so the form shows it) but is not OK, because the htpasswd
// hash cannot be recovered from the config (it lives in a separate file).
func TestParse_basicAuth_recoversPresence_butNotCredentials(t *testing.T) {
	route := proxymodel.Route{
		Host:      "auth.example.com",
		Upstream:  proxymodel.Upstream{Addr: "10.0.0.11", Port: 8084},
		BasicAuth: &proxymodel.BasicAuth{Username: "admin", PasswordHash: "$2y$..."},
		TLS:       proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
	}
	rendered, err := nginxgen.Render(nginxgen.Input{Route: route, AuthFile: "/etc/nurproxy/auth/x"})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	res := Parse(rendered.Server)
	if res.Route.BasicAuth == nil {
		t.Fatal("expected basic-auth presence to be recovered")
	}
	if res.OK {
		t.Error("expected mask to be advisory (not OK) when basic auth is present")
	}
}

// TestParse_unparseable_preservedVerbatim asserts the parser never destroys text
// it cannot map. Each input carries something unknown; the unknown bytes must
// survive in Result.Unparsed and OK must be false.
func TestParse_unparseable_preservedVerbatim(t *testing.T) {
	tests := []struct {
		name         string
		content      string
		wantPreserve string // substring that must survive in Unparsed
	}{
		{
			name: "unknown_directive_in_server",
			content: `server {
    listen 80;
    server_name x.example.com;
    gzip on;
    location / {
        proxy_pass http://10.0.0.1:80;
    }
}`,
			wantPreserve: "gzip on",
		},
		{
			name: "unknown_top_level_block",
			content: `upstream backend {
    server 10.0.0.1:80;
}
server {
    listen 80;
    server_name y.example.com;
    location / {
        proxy_pass http://10.0.0.2:80;
    }
}`,
			wantPreserve: "upstream backend",
		},
		{
			name: "stray_top_level_directive",
			content: `worker_processes 4;
server {
    listen 80;
    server_name z.example.com;
    location / {
        proxy_pass http://10.0.0.3:80;
    }
}`,
			wantPreserve: "worker_processes 4",
		},
		{
			name: "unknown_directive_in_location",
			content: `server {
    listen 80;
    server_name q.example.com;
    location / {
        proxy_pass http://10.0.0.4:80;
        proxy_buffering off;
    }
}`,
			wantPreserve: "proxy_buffering off",
		},
		{
			name: "complex_proxy_pass_with_path",
			content: `server {
    listen 80;
    server_name p.example.com;
    location / {
        proxy_pass http://10.0.0.5:80/prefix;
    }
}`,
			wantPreserve: "/prefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Parse(tt.content)
			if res.OK {
				t.Errorf("expected OK=false for input with unparseable content")
			}
			joined := strings.Join(res.Unparsed, "\n")
			if !strings.Contains(joined, tt.wantPreserve) {
				t.Errorf("unparseable text not preserved: want substring %q in\n%s", tt.wantPreserve, joined)
			}
		})
	}
}

// TestParse_emptyAndNoServer_isNotOK_butNeverPanics covers degenerate inputs.
func TestParse_emptyAndNoServer_isNotOK_butNeverPanics(t *testing.T) {
	for _, in := range []string{"", "   ", "# just a comment\n", "http { }", "}}}{{{"} {
		res := Parse(in)
		if res.OK {
			t.Errorf("Parse(%q) unexpectedly OK", in)
		}
	}
}

// TestParse_twoProxiedServers_preservesBothRaw asserts that a multi-vhost file
// (which the single-route mask cannot represent) is preserved raw, not mangled.
func TestParse_twoProxiedServers_preservesBothRaw(t *testing.T) {
	content := `server {
    listen 80;
    server_name a.example.com;
    location / { proxy_pass http://10.0.0.1:80; }
}
server {
    listen 80;
    server_name b.example.com;
    location / { proxy_pass http://10.0.0.2:80; }
}`
	res := Parse(content)
	if res.OK {
		t.Fatal("expected OK=false for two proxied servers")
	}
	joined := strings.Join(res.Unparsed, "\n")
	if !strings.Contains(joined, "a.example.com") || !strings.Contains(joined, "b.example.com") {
		t.Errorf("both servers must be preserved raw; got\n%s", joined)
	}
}

// TestParse_handWritten_cleanProxy parses a config a human might write (not from
// nginxgen) to prove best-effort recognition beyond our own output.
func TestParse_handWritten_cleanProxy(t *testing.T) {
	content := `server {
    listen 443 ssl;
    server_name hand.example.com;
    ssl_certificate /etc/ssl/x.crt;
    ssl_certificate_key /etc/ssl/x.key;
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}`
	res := Parse(content)
	if !res.OK {
		t.Fatalf("expected clean parse; notes=%v unparsed=%v", res.Notes, res.Unparsed)
	}
	if res.Route.Host != "hand.example.com" {
		t.Errorf("host = %q", res.Route.Host)
	}
	if res.Route.Upstream.Addr != "127.0.0.1" || res.Route.Upstream.Port != 5000 {
		t.Errorf("upstream = %+v", res.Route.Upstream)
	}
	if res.Route.TLS.Policy != proxymodel.TLSPolicyCentral {
		t.Errorf("TLS policy = %q, want central (ssl detected)", res.Route.TLS.Policy)
	}
}

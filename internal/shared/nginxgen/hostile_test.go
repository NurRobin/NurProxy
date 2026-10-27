package nginxgen

import (
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// TestRender_hostileValuesRefused covers values that would end the current
// nginx directive or start a new one. Render must refuse them instead of
// emitting them.
func TestRender_hostileValuesRefused(t *testing.T) {
	tests := map[string]func(*proxymodel.Route){
		"host with semicolon":          func(r *proxymodel.Route) { r.Host = "app.example.com;include /etc/x" },
		"host with newline":            func(r *proxymodel.Route) { r.Host = "app.example.com\ninclude /etc/x;" },
		"host with quote":              func(r *proxymodel.Route) { r.Host = `app.example.com"` },
		"upstream with semicolon":      func(r *proxymodel.Route) { r.Upstream.Addr = "10.0.0.4;include /etc/x;#" },
		"upstream with path":           func(r *proxymodel.Route) { r.Upstream.Addr = "10.0.0.4/x" },
		"header name with space":       func(r *proxymodel.Route) { r.ResponseHeaders = map[string]string{"X-A b": "v"} },
		"header name with semicolon":   func(r *proxymodel.Route) { r.RequestHeaders = map[string]string{"X;include": "v"} },
		"header value with newline":    func(r *proxymodel.Route) { r.ResponseHeaders = map[string]string{"X-A": "v\ninclude /etc/x;"} },
		"header value with NUL":        func(r *proxymodel.Route) { r.RequestHeaders = map[string]string{"X-A": "v\x00"} },
		"header value with backslash":  func(r *proxymodel.Route) { r.ResponseHeaders = map[string]string{"X-A": `\";include /etc/x;#`} },
		"body size with semicolon":     func(r *proxymodel.Route) { r.MaxBodySize = "10m;include /etc/x" },
		"rewrite with space":           func(r *proxymodel.Route) { r.Path.Rewrite = "/x last; include /etc/x" },
		"strip prefix with brace":      func(r *proxymodel.Route) { r.Path.StripPrefix = "/x{" },
		"allowlist entry with space":   func(r *proxymodel.Route) { r.IPAllowlist = []string{"10.0.0.0/8; include /etc/x"} },
		"blocklist entry with newline": func(r *proxymodel.Route) { r.IPBlocklist = []string{"1.2.3.4\ninclude /etc/x"} },
		"username with colon":          func(r *proxymodel.Route) { r.BasicAuth = &proxymodel.BasicAuth{Username: "a:b", PasswordHash: "$2y$x"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			r := baseRoute()
			mutate(&r)
			res, err := Render(Input{Route: r, AuthFile: "/var/lib/nurproxy-agent/auth/x.htpasswd"})
			if err == nil {
				t.Fatalf("hostile route rendered:\n%s", res.Server)
			}
		})
	}
}

// TestRender_ipv6UpstreamIsBracketed checks proxy_pass for IPv6 upstreams,
// with or without brackets in the stored address.
func TestRender_ipv6UpstreamIsBracketed(t *testing.T) {
	for _, addr := range []string{"fd00::5", "[fd00::5]"} {
		r := baseRoute()
		r.Upstream.Addr = addr
		res, err := Render(Input{Route: r})
		if err != nil {
			t.Fatal(err)
		}
		if want := "proxy_pass http://[fd00::5]:8080;"; !strings.Contains(res.Server, want) {
			t.Errorf("%s: server lacks %q:\n%s", addr, want, res.Server)
		}
	}
}

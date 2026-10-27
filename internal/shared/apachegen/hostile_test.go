package apachegen

import (
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// TestRender_hostileValuesRefused covers values that would end the current
// Apache directive line or add arguments to it. Render must refuse them
// instead of emitting them.
func TestRender_hostileValuesRefused(t *testing.T) {
	tests := map[string]func(*proxymodel.Route){
		"host with newline":            func(r *proxymodel.Route) { r.Host = "app.example.com\nInclude /etc/x" },
		"host with space":              func(r *proxymodel.Route) { r.Host = "app.example.com Include" },
		"host with quote":              func(r *proxymodel.Route) { r.Host = `app.example.com"` },
		"upstream with newline":        func(r *proxymodel.Route) { r.Upstream.Addr = "10.0.0.4/\nInclude /etc/x\n#" },
		"upstream with path":           func(r *proxymodel.Route) { r.Upstream.Addr = "10.0.0.4/x" },
		"header name with space":       func(r *proxymodel.Route) { r.ResponseHeaders = map[string]string{"X-A early": "v"} },
		"header value with newline":    func(r *proxymodel.Route) { r.ResponseHeaders = map[string]string{"X-A": "v\nInclude /etc/x"} },
		"header value with CR":         func(r *proxymodel.Route) { r.RequestHeaders = map[string]string{"X-A": "v\rInclude /etc/x"} },
		"header value with NUL":        func(r *proxymodel.Route) { r.RequestHeaders = map[string]string{"X-A": "v\x00"} },
		"header value with backslash":  func(r *proxymodel.Route) { r.ResponseHeaders = map[string]string{"X-A": `v\`} },
		"body size with newline":       func(r *proxymodel.Route) { r.MaxBodySize = "10\nInclude /etc/x" },
		"rewrite with space":           func(r *proxymodel.Route) { r.Path.Rewrite = "/x [E=A:b]" },
		"strip prefix with newline":    func(r *proxymodel.Route) { r.Path.StripPrefix = "/x\nInclude /etc/x" },
		"allowlist entry with space":   func(r *proxymodel.Route) { r.IPAllowlist = []string{"10.0.0.0/8 all"} },
		"blocklist entry with newline": func(r *proxymodel.Route) { r.IPBlocklist = []string{"1.2.3.4\nInclude /etc/x"} },
		"username with colon":          func(r *proxymodel.Route) { r.BasicAuth = &proxymodel.BasicAuth{Username: "a:b", PasswordHash: "$2y$x"} },
		"hash with newline": func(r *proxymodel.Route) {
			r.BasicAuth = &proxymodel.BasicAuth{Username: "a", PasswordHash: "$2y$x\nb:c"}
		},
		"response header expression": func(r *proxymodel.Route) {
			r.ResponseHeaders = map[string]string{"X-A": "expr=%{file:/etc/shadow}"}
		},
		"request header expression": func(r *proxymodel.Route) { r.RequestHeaders = map[string]string{"X-A": "Expr=1"} },
		"single-quoted expression": func(r *proxymodel.Route) {
			r.ResponseHeaders = map[string]string{"X-A": "'expr=%{file:/etc/passwd}'"}
		},
		"double-quoted expression": func(r *proxymodel.Route) {
			r.ResponseHeaders = map[string]string{"X-A": `"expr=%{file:/etc/passwd}"`}
		},
		"spaced expression":    func(r *proxymodel.Route) { r.RequestHeaders = map[string]string{"X-A": "  expr=1"} },
		"leading quote":        func(r *proxymodel.Route) { r.ResponseHeaders = map[string]string{"X-A": "'a b'"} },
		"spaced leading quote": func(r *proxymodel.Route) { r.ResponseHeaders = map[string]string{"X-A": ` "a`} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			r := baseRoute()
			mutate(&r)
			res, err := Render(Input{Route: r, AuthFile: "/var/lib/nurproxy-agent/auth/x.htpasswd"})
			if err == nil {
				t.Fatalf("hostile route rendered:\n%s", res.VHost)
			}
		})
	}
}

// TestRender_headerValuesAreLiteral checks that mod_headers format
// specifiers in header values are escaped, so Apache sets the value as
// written instead of expanding it.
func TestRender_headerValuesAreLiteral(t *testing.T) {
	r := baseRoute()
	r.ResponseHeaders = map[string]string{"X-Env": "%{HOME}e", "X-Pct": "100%", "X-Spaced": "a %{SSL_PROTOCOL}s b"}
	r.RequestHeaders = map[string]string{"X-Req": "%D"}
	res, err := Render(Input{Route: r})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`Header always set X-Env "%%{HOME}e"` + "\n",
		`Header always set X-Pct "100%%"` + "\n",
		`Header always set X-Spaced "a %%{SSL_PROTOCOL}s b"` + "\n",
		`RequestHeader set X-Req "%%D"` + "\n",
	} {
		if !strings.Contains(res.VHost, want) {
			t.Errorf("vhost lacks %q:\n%s", want, res.VHost)
		}
	}
}

// TestRender_ipv6UpstreamIsBracketed checks the proxy targets for IPv6
// upstreams, with or without brackets in the stored address.
func TestRender_ipv6UpstreamIsBracketed(t *testing.T) {
	for _, addr := range []string{"fd00::5", "[fd00::5]"} {
		r := baseRoute()
		r.Upstream.Addr = addr
		r.WebSocket = true
		res, err := Render(Input{Route: r})
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"ProxyPass / http://[fd00::5]:8080/", "ws://[fd00::5]:8080/$1"} {
			if !strings.Contains(res.VHost, want) {
				t.Errorf("%s: vhost lacks %q:\n%s", addr, want, res.VHost)
			}
		}
	}
}

package apachegen

import (
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

package apachegen

import (
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// TestRender_sslProxyEngine checks that a vhost with any https upstream
// turns on SSLProxyEngine (mod_proxy answers 500 without it) and that
// http-only vhosts render without it, as before.
func TestRender_sslProxyEngine(t *testing.T) {
	https := proxymodel.Upstream{Addr: "10.0.0.5", Port: 8443, Scheme: proxymodel.SchemeHTTPS}
	tests := []struct {
		name   string
		mutate func(*proxymodel.Route)
		want   bool
	}{
		{"http only", func(*proxymodel.Route) {}, false},
		{"http path route", func(r *proxymodel.Route) {
			r.PathRoutes = []proxymodel.PathRoute{{Match: proxymodel.PathMatchExact, Path: "/a", Upstream: proxymodel.Upstream{Addr: "10.0.0.6", Port: 80}}}
		}, false},
		{"https default", func(r *proxymodel.Route) { r.Upstream = https }, true},
		{"https default websocket", func(r *proxymodel.Route) { r.Upstream = https; r.WebSocket = true }, true},
		{"https path route", func(r *proxymodel.Route) {
			r.PathRoutes = []proxymodel.PathRoute{{Match: proxymodel.PathMatchPrefix, Path: "/a", Upstream: https}}
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := proxymodel.Route{Host: "app.example.com", Upstream: proxymodel.Upstream{Addr: "10.0.0.4", Port: 8080}, TLS: proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff}}
			tt.mutate(&route)
			res, err := Render(Input{Route: route})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(res.VHost, "    SSLProxyEngine on\n"); got != map[bool]int{true: 1, false: 0}[tt.want] {
				t.Fatalf("SSLProxyEngine lines = %d, want present=%v:\n%s", got, tt.want, res.VHost)
			}
		})
	}
}

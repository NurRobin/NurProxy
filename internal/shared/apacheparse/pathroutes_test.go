package apacheparse

import (
	"fmt"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/apachegen"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

func pathRoutesFixture() []proxymodel.PathRoute {
	return []proxymodel.PathRoute{
		{Match: proxymodel.PathMatchExact, Path: "/api/world", Upstream: proxymodel.Upstream{Addr: "192.168.178.210", Port: 80}},
		{Match: proxymodel.PathMatchExact, Path: "/", Upstream: proxymodel.Upstream{Addr: "10.0.0.10", Port: 81}},
		{Match: proxymodel.PathMatchPrefix, Path: "/media", Upstream: proxymodel.Upstream{Addr: "10.0.0.7", Port: 9000}},
		{Match: proxymodel.PathMatchPrefix, Path: "/live.v2", WebSocket: true, Upstream: proxymodel.Upstream{Addr: "10.0.0.7", Port: 9001}},
		{Match: proxymodel.PathMatchExact, Path: "/socket", WebSocket: true, Upstream: proxymodel.Upstream{Addr: "backend.internal", Port: 9443, Scheme: proxymodel.SchemeHTTPS}},
		{Match: proxymodel.PathMatchPrefix, Path: "/ws.v1", StripPrefix: true, WebSocket: true, Upstream: proxymodel.Upstream{Addr: "fd00::5", Port: 8443, Scheme: proxymodel.SchemeHTTPS}},
		{Match: proxymodel.PathMatchPrefix, Path: "/admin", Upstream: proxymodel.Upstream{Addr: "10.0.0.8", Port: 8081}},
		{Match: proxymodel.PathMatchExact, Path: "/admin", Upstream: proxymodel.Upstream{Addr: "10.0.0.9", Port: 8082}},
	}
}

// TestValidateManagedAdmitsPathRouteOutput renders path routes together with
// every default-upstream path handling apachegen has (plain, WebSocket,
// strip prefix, rewrite, HTTPS) and requires each output to pass.
func TestValidateManagedAdmitsPathRouteOutput(t *testing.T) {
	variants := map[string]func(*proxymodel.Route){
		"plain":          func(*proxymodel.Route) {},
		"websocket":      func(r *proxymodel.Route) { r.WebSocket = true },
		"strip prefix":   func(r *proxymodel.Route) { r.Path.StripPrefix = "/app" },
		"rewrite":        func(r *proxymodel.Route) { r.Path.Rewrite = "/fixed" },
		"https upstream": func(r *proxymodel.Route) { r.Upstream.Scheme = proxymodel.SchemeHTTPS },
		"timeouts":       func(r *proxymodel.Route) { r.Timeouts = proxymodel.Timeouts{Read: 60, Write: 30} },
		"tls and auth": func(r *proxymodel.Route) {
			r.TLS = proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyCentral}
			r.ForceHTTPS = true
			r.BasicAuth = &proxymodel.BasicAuth{Username: "u", PasswordHash: "h"}
			r.IPAllowlist = []string{"10.0.0.0/8"}
		},
	}
	for name, mutate := range variants {
		for _, single := range append([][]proxymodel.PathRoute{pathRoutesFixture()}, splitRoutes(pathRoutesFixture())...) {
			route := proxymodel.Route{Host: testHost, Upstream: proxymodel.Upstream{Addr: "10.0.0.4", Port: 8080}, PathRoutes: single}
			mutate(&route)
			res, err := apachegen.Render(apachegen.Input{Route: route, CertPath: testCert, KeyPath: testKey, AuthFile: testAuth})
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if err := ValidateManaged(res.VHost, testPolicy); err != nil {
				t.Fatalf("%s: path route output refused: %v\n%s", name, err, res.VHost)
			}
		}
	}
}

func splitRoutes(routes []proxymodel.PathRoute) [][]proxymodel.PathRoute {
	out := make([][]proxymodel.PathRoute, len(routes))
	for i := range routes {
		out[i] = routes[i : i+1]
	}
	return out
}

// TestValidateManagedRefusesPathRouteNearMisses keeps the path route forms
// to exactly what apachegen renders.
func TestValidateManagedRefusesPathRouteNearMisses(t *testing.T) {
	inVHost := func(lines string) string { return fmt.Sprintf(proxiedVHost, lines) }
	tests := []struct{ name, line, want string }{
		{"regex alternation", `ProxyPassMatch ^/(a|b)$ http://10.0.0.5:80`, "ProxyPassMatch"},
		{"open regex", `ProxyPassMatch ^/api http://10.0.0.5:80`, "ProxyPassMatch"},
		{"unanchored", `ProxyPassMatch /api$ http://10.0.0.5:80`, "ProxyPassMatch"},
		{"wildcard regex", `ProxyPassMatch ^/.*$ http://10.0.0.5:80`, "ProxyPassMatch"},
		{"unescaped dot", `ProxyPassMatch ^/a.b$ http://10.0.0.5:80`, "ProxyPassMatch"},
		{"other escape", `ProxyPassMatch ^/a\+b$ http://10.0.0.5:80`, "ProxyPassMatch"},
		{"dot segment", `ProxyPassMatch ^/a/\.\./b$ http://10.0.0.5:80`, "ProxyPassMatch"},
		{"prefix root", `ProxyPassMatch ^/(?:/.*)?$ http://10.0.0.5:80`, "ProxyPassMatch"},
		{"quoted regex", `ProxyPassMatch "^/api$" http://10.0.0.5:80`, "ProxyPassMatch"},
		{"exact with target path", `ProxyPassMatch ^/api$ http://10.0.0.5:80/x`, "ProxyPassMatch"},
		{"prefix with backreference", `ProxyPassMatch ^/api(?:/.*)?$ http://10.0.0.5:80/$1`, "ProxyPassMatch"},
		{"strip without backreference", `ProxyPassMatch ^/api(?:/(.*))?$ http://10.0.0.5:80`, "ProxyPassMatch"},
		{"strip other backreference", `ProxyPassMatch ^/api(?:/(.*))?$ http://10.0.0.5:80/x$1`, "ProxyPassMatch"},
		{"match to socket", `ProxyPassMatch ^/api$ unix:/run/x.sock|http://localhost`, "ProxyPassMatch"},
		{"match to fcgi", `ProxyPassMatch ^/api$ fcgi://127.0.0.1:9000`, "ProxyPassMatch"},
		{"match to websocket", `ProxyPassMatch ^/api$ ws://10.0.0.5:80`, "ProxyPassMatch"},
		{"match with other param", `ProxyPassMatch ^/api$ http://10.0.0.5:80 retry=0`, "ProxyPassMatch"},
		{"match with duplicate param", `ProxyPassMatch ^/api$ http://10.0.0.5:80 timeout=1 timeout=2`, "ProxyPassMatch"},
		{"match excluded path", `ProxyPassMatch ^/api$ !`, "ProxyPassMatch"},
		{"reverse other path", `ProxyPassReverse /a b/ http://10.0.0.5:80/`, "ProxyPassReverse"},
		{"reverse relative path", `ProxyPassReverse api/ http://10.0.0.5:80/`, "ProxyPassReverse"},
		{"reverse path without slash", `ProxyPassReverse /api http://10.0.0.5:80/`, "ProxyPassReverse"},
		{"reverse to fcgi", `ProxyPassReverse /api/ fcgi://10.0.0.5:80/`, "ProxyPassReverse"},
		{"cond not negated", `RewriteCond %{REQUEST_URI} ^/api$`, "RewriteCond"},
		{"cond strip regex", `RewriteCond %{REQUEST_URI} !^/api(?:/(.*))?$`, "RewriteCond"},
		{"cond open regex", `RewriteCond %{REQUEST_URI} !^/api`, "RewriteCond"},
		{"cond with flag", `RewriteCond %{REQUEST_URI} !^/api$ [OR]`, "RewriteCond"},
		{"cond other variable", `RewriteCond %{QUERY_STRING} !^/api$`, "RewriteCond"},
		{"cond file test", `RewriteCond %{REQUEST_FILENAME} -f`, "RewriteCond"},
		{"cond expression", `RewriteCond expr "-f '/etc/shadow'"`, "RewriteCond"},
		{"ssl proxy engine off", `SSLProxyEngine off`, "SSLProxyEngine"},
		{"ssl proxy check", `SSLProxyCheckPeerName off`, "SSLProxyCheckPeerName"},
		{"ssl proxy client cert", `SSLProxyMachineCertificateFile /etc/shadow`, "SSLProxyMachineCertificateFile"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := inVHost("    " + tt.line)
			err := ValidateManaged(content, testPolicy)
			if err == nil {
				t.Fatalf("near miss admitted:\n%s", content)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}

// TestValidateManagedAdmitsPathRouteLines admits each rendered line form on
// its own, so the near-miss cases above fail for their difference only.
func TestValidateManagedAdmitsPathRouteLines(t *testing.T) {
	for _, line := range []string{
		`ProxyPassMatch ^/api/world$ http://192.168.178.210:80`,
		`ProxyPassMatch ^/media(?:/.*)?$ https://backend.internal:9000 connectiontimeout=30 timeout=60`,
		`ProxyPassMatch ^/ws\.v1(?:/(.*))?$ http://[fd00::5]:8443/$1`,
		`ProxyPassReverse /ws.v1/ http://[fd00::5]:8443/`,
		`RewriteCond %{REQUEST_URI} !^/api/world$`,
		`RewriteCond %{REQUEST_URI} !^/media(?:/.*)?$`,
		`SSLProxyEngine on`,
	} {
		if err := ValidateManaged(fmt.Sprintf(proxiedVHost, "    "+line), testPolicy); err != nil {
			t.Errorf("%s: %v", line, err)
		}
	}
}

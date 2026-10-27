package apachegen

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/")

// goldenCases covers the route shapes in use today plus the logging overrides.
// The files for the cases without logging were written by the renderer as it
// was before per-route logging existed, so a diff there means existing vhosts
// would change on disk and every agent would re-apply them.
func goldenCases() []struct {
	name  string
	input Input
} {
	tlsInput := func(r proxymodel.Route) Input {
		r.TLS = proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyCentral}
		return Input{Route: r, CertPath: "/var/lib/nurproxy-agent/certs/app.example.com.crt", KeyPath: "/var/lib/nurproxy-agent/certs/app.example.com.key.plain"}
	}
	full := func() proxymodel.Route {
		r := baseRoute()
		r.ForceHTTPS = true
		r.WebSocket = true
		r.MaxBodySize = "50MB"
		r.RequestHeaders = map[string]string{"X-Team": "edge"}
		r.ResponseHeaders = map[string]string{"X-Frame-Options": "DENY"}
		r.Timeouts = proxymodel.Timeouts{Read: 60, Write: 30}
		r.BasicAuth = &proxymodel.BasicAuth{Username: "u", PasswordHash: "$2a$10$x"}
		r.IPAllowlist = []string{"10.0.0.0/8"}
		r.IPBlocklist = []string{"10.6.6.6/32"}
		return r
	}
	withLogging := func(in Input, mode proxymodel.AccessLogMode, level string) Input {
		in.Route.AccessLog = mode
		in.Route.ErrorLogLevel = level
		return in
	}
	fullTLS := tlsInput(full())
	fullTLS.AuthFile = "/etc/apache2/nurproxy-auth/app.example.com.htpasswd"

	return []struct {
		name  string
		input Input
	}{
		{"plain", Input{Route: baseRoute()}},
		{"tls", tlsInput(baseRoute())},
		{"full_tls", fullTLS},
		{"plain_access_off", withLogging(Input{Route: baseRoute()}, proxymodel.AccessLogOff, "")},
		{"plain_error_crit", withLogging(Input{Route: baseRoute()}, proxymodel.AccessLogDefault, "crit")},
		{"full_tls_access_off_error_crit", withLogging(fullTLS, proxymodel.AccessLogOff, "crit")},
	}
}

func TestRender_golden(t *testing.T) {
	for _, tc := range goldenCases() {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Render(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			got := res.Preamble + "----\n" + res.VHost
			path := filepath.Join("testdata", tc.name+".golden")
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Errorf("render differs from %s\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
			}
		})
	}
}

//go:build linux

package helper

import (
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// TestRenderRouteChecksRenderedNginxPolicy checks that every nginx vhost the
// helper renders passes nginxparse.ValidateRendered, including basic auth and
// rate limits, and that a rendered file outside the policy is never returned.
func TestRenderRouteChecksRenderedNginxPolicy(t *testing.T) {
	action, _, _ := newManagedApplyTest(t)
	route := proxymodel.Route{
		Host:            "app.example.com",
		Upstream:        proxymodel.Upstream{Addr: "127.0.0.1", Port: 8080},
		ForceHTTPS:      true,
		WebSocket:       true,
		MaxBodySize:     "10m",
		RequestHeaders:  map[string]string{"X-A": `say "hi"`},
		ResponseHeaders: map[string]string{"Content-Security-Policy": "default-src 'self'; img-src *"},
		BasicAuth:       &proxymodel.BasicAuth{Username: "operator", PasswordHash: testAuthHash},
		IPAllowlist:     []string{"10.0.0.0/8"},
		IPBlocklist:     []string{},
		RateLimit:       proxymodel.RateLimit{RequestsPerSecond: 5},
		TLS:             proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyCentral},
	}
	certPath := action.layout.CertificateDir + "/app.example.com.crt"
	keyPath := action.layout.CertificateDir + "/app.example.com.key.plain"
	authPath := managedAuthFilePath(action.layout.AuthDir(), route.Host)
	content, err := action.renderRoute(route, certPath, keyPath, authPath)
	if err != nil {
		t.Fatalf("renderRoute: %v", err)
	}
	for _, want := range []string{"auth_basic_user_file " + authPath, "limit_req zone=", "limit_req_zone "} {
		if !strings.Contains(content, want) {
			t.Fatalf("rendered vhost lacks %q:\n%s", want, content)
		}
	}
	// A certificate path nginx would read as two words cannot pass the
	// policy, so the render is refused instead of written.
	if _, err := action.renderRoute(route, certPath+" x", keyPath, authPath); err == nil || !strings.Contains(err.Error(), "managed policy") {
		t.Fatalf("renderRoute with a split certificate path = %v, want a policy error", err)
	}
}

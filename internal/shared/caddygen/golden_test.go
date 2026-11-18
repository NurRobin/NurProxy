package caddygen

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/")

func goldenFullRoute() proxymodel.Route {
	return proxymodel.Route{
		Host:            "app.example.com",
		Upstream:        proxymodel.Upstream{Addr: "10.0.0.4", Port: 8080},
		ForceHTTPS:      true,
		WebSocket:       true,
		MaxBodySize:     "50MB",
		RequestHeaders:  map[string]string{"X-Team": "edge"},
		ResponseHeaders: map[string]string{"X-Frame-Options": "DENY"},
		Path:            proxymodel.PathRules{StripPrefix: "/app"},
		Timeouts:        proxymodel.Timeouts{Read: 60, Write: 30},
		BasicAuth:       &proxymodel.BasicAuth{Username: "u", PasswordHash: "$2a$10$x"},
		IPAllowlist:     []string{"10.0.0.0/8"},
		IPBlocklist:     []string{"10.6.6.6/32"},
		RateLimit:       proxymodel.RateLimit{RequestsPerSecond: 5},
	}
}

// TestGenerateRoute_golden pins the route JSON. full.golden was written by
// the renderer as it was before path routes existed, so a diff there means
// every built-in Caddy route would change.
func TestGenerateRoute_golden(t *testing.T) {
	withPaths := goldenFullRoute()
	withPaths.PathRoutes = []proxymodel.PathRoute{
		{Match: proxymodel.PathMatchPrefix, Path: "/media", Upstream: proxymodel.Upstream{Addr: "10.0.0.7", Port: 9000}},
		{Match: proxymodel.PathMatchExact, Path: "/api/world", Upstream: proxymodel.Upstream{Addr: "192.168.178.210", Port: 80}},
		{Match: proxymodel.PathMatchPrefix, Path: "/ws", StripPrefix: true, WebSocket: true, Upstream: proxymodel.Upstream{Addr: "10.0.0.8", Port: 8443, Scheme: proxymodel.SchemeHTTPS}},
	}
	for name, route := range map[string]proxymodel.Route{
		"full":             goldenFullRoute(),
		"full_path_routes": withPaths,
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := GenerateRoute(route)
			if err != nil {
				t.Fatal(err)
			}
			var got bytes.Buffer
			if err := json.Indent(&got, raw, "", "  "); err != nil {
				t.Fatal(err)
			}
			got.WriteString("\n")
			path := filepath.Join("testdata", name+".golden.json")
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != string(want) {
				t.Errorf("route differs from %s\n--- got ---\n%s\n--- want ---\n%s", path, got.String(), want)
			}
		})
	}
}

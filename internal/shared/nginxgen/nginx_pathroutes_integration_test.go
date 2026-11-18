//go:build integration

package nginxgen

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

const nginxImage = "nginx:1.29-alpine"

// nginxPathRoutesUpstream answers every request on port with 200 and
// headers naming the upstream and the path and query it received.
func nginxPathRoutesUpstream(port int, name string) string {
	return fmt.Sprintf(`server {
    listen 127.0.0.1:%d;
    location / {
        add_header X-Upstream %s always;
        add_header X-Path $uri always;
        add_header X-Query "$args" always;
        return 200 "ok\n";
    }
}
`, port, name)
}

// TestIntegration_nginxServesPathRoutes renders path routes, checks them with
// `nginx -t` and sends requests through a real nginx to see which upstream
// receives which path. The expectations are the same as the Apache
// integration test's, so both backends route a request alike.
func TestIntegration_nginxServesPathRoutes(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skipf("docker not usable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dir := t.TempDir()
	routes := []proxymodel.PathRoute{
		{Match: proxymodel.PathMatchExact, Path: "/api/world", Upstream: proxymodel.Upstream{Addr: "127.0.0.1", Port: 8082}},
		{Match: proxymodel.PathMatchPrefix, Path: "/media", Upstream: proxymodel.Upstream{Addr: "127.0.0.1", Port: 8083}},
		{Match: proxymodel.PathMatchPrefix, Path: "/ws.v1", StripPrefix: true, WebSocket: true, Upstream: proxymodel.Upstream{Addr: "127.0.0.1", Port: 8084}},
		{Match: proxymodel.PathMatchPrefix, Path: "/media/hd", Upstream: proxymodel.Upstream{Addr: "127.0.0.1", Port: 8084}},
	}
	var conf strings.Builder
	conf.WriteString("events {}\nhttp {\n")
	for i, name := range []string{"A", "B", "C", "D"} {
		conf.WriteString(nginxPathRoutesUpstream(8081+i, name))
	}
	for _, host := range []struct {
		name   string
		mutate func(*proxymodel.Route)
	}{
		{"paths.example.com", nil},
		{"strip.example.com", func(r *proxymodel.Route) { r.Path.StripPrefix = "/app" }},
		{"rewrite.example.com", func(r *proxymodel.Route) { r.Path.Rewrite = "/fixed" }},
	} {
		r := proxymodel.Route{
			Host:       host.name,
			Upstream:   proxymodel.Upstream{Addr: "127.0.0.1", Port: 8081},
			TLS:        proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
			PathRoutes: routes,
		}
		if host.mutate != nil {
			host.mutate(&r)
		}
		res, err := Render(Input{Route: r})
		if err != nil {
			t.Fatal(err)
		}
		conf.WriteString(res.Server)
	}
	conf.WriteString("}\n")
	if err := os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte(conf.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	out, err := exec.CommandContext(ctx, "docker", "run", "-d", "--rm",
		"-v", dir+":/conf:ro", "--entrypoint", "sleep", nginxImage, "300").CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	container := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })

	if out, err := exec.CommandContext(ctx, "docker", "exec", container, "nginx", "-t", "-c", "/conf/nginx.conf").CombinedOutput(); err != nil {
		t.Fatalf("nginx -t: %v\n%s\n--- config ---\n%s", err, out, conf.String())
	}
	if out, err := exec.CommandContext(ctx, "docker", "exec", "-d", container, "nginx", "-c", "/conf/nginx.conf", "-g", "daemon off;").CombinedOutput(); err != nil {
		t.Fatalf("starting nginx: %v\n%s", err, out)
	}

	header := func(out, name string) string {
		m := regexp.MustCompile(`(?mi)^[ \t]*` + name + `:[ \t]*(.*?)[ \t\r]*$`).FindStringSubmatch(out)
		if m == nil {
			return ""
		}
		return m[1]
	}
	request := func(host, target string) (upstream, path, query string) {
		out, _ := exec.CommandContext(ctx, "docker", "exec", container, "wget", "-S", "-O", "/dev/null", "--header", "Host: "+host, "http://127.0.0.1"+target).CombinedOutput()
		return header(string(out), "X-Upstream"), header(string(out), "X-Path"), header(string(out), "X-Query")
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if up, _, _ := request("paths.example.com", "/"); up != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("nginx did not start serving")
		}
		time.Sleep(200 * time.Millisecond)
	}

	tests := []struct {
		host, target string
		upstream     string
		path, query  string
	}{
		{"paths.example.com", "/", "A", "/", ""},
		{"paths.example.com", "/api/world", "B", "/api/world", ""},
		{"paths.example.com", "/api/world?x=1", "B", "/api/world", "x=1"},
		{"paths.example.com", "/api/worldx", "A", "/api/worldx", ""},
		{"paths.example.com", "/api/world/", "A", "/api/world/", ""},
		{"paths.example.com", "/media", "C", "/media", ""},
		{"paths.example.com", "/media/a/b?q=2", "C", "/media/a/b", "q=2"},
		{"paths.example.com", "/mediax", "A", "/mediax", ""},
		{"paths.example.com", "/media/hd/1", "D", "/media/hd/1", ""},
		{"paths.example.com", "/media/hdx", "C", "/media/hdx", ""},
		{"paths.example.com", "/ws.v1", "D", "/", ""},
		{"paths.example.com", "/ws.v1/socket?t=3", "D", "/socket", "t=3"},
		{"paths.example.com", "/ws.v1x", "A", "/ws.v1x", ""},
		{"strip.example.com", "/app/x", "A", "/x", ""},
		{"strip.example.com", "/media/y", "C", "/media/y", ""},
		{"strip.example.com", "/api/world", "B", "/api/world", ""},
		{"strip.example.com", "/ws.v1/z", "D", "/z", ""},
		{"rewrite.example.com", "/anything", "A", "/fixed", ""},
		{"rewrite.example.com", "/media/z", "C", "/media/z", ""},
	}
	for _, tt := range tests {
		t.Run(tt.host+tt.target, func(t *testing.T) {
			up, path, query := request(tt.host, tt.target)
			if up != tt.upstream || path != tt.path || query != tt.query {
				t.Fatalf("GET %s%s reached upstream %q path %q query %q, want %q %q %q", tt.host, tt.target, up, path, query, tt.upstream, tt.path, tt.query)
			}
		})
	}
}

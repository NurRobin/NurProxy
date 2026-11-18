//go:build integration

package apachegen

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

// pathRoutesMainConf runs four upstreams on 127.0.0.1:8081-8084. Each answers
// every request with 200 and headers naming itself and the path and query it
// received (busybox wget prints no headers for an error status). The %s is the vhost file to include.
const pathRoutesMainConf = `ServerRoot "/usr/local/apache2"
Listen 80
Listen 127.0.0.1:8081
Listen 127.0.0.1:8082
Listen 127.0.0.1:8083
Listen 127.0.0.1:8084
Listen 127.0.0.1:8085
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule headers_module modules/mod_headers.so
LoadModule rewrite_module modules/mod_rewrite.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule proxy_wstunnel_module modules/mod_proxy_wstunnel.so
LoadModule socache_shmcb_module modules/mod_socache_shmcb.so
LoadModule ssl_module modules/mod_ssl.so
User daemon
Group daemon
ServerName localhost
ErrorLog /proc/self/fd/2
%s
Include %s
`

func pathRoutesUpstream(port int, name string) string {
	return fmt.Sprintf(`<VirtualHost 127.0.0.1:%d>
    DocumentRoot "/usr/local/apache2/htdocs"
    <Directory "/usr/local/apache2/htdocs">
        Require all granted
    </Directory>
    RewriteEngine On
    RewriteRule ^ /index.html [E=UP_PATH:%%{REQUEST_URI},E=UP_QUERY:%%{QUERY_STRING},L]
    Header always set X-Upstream %s
    Header always set X-Path "%%{UP_PATH}e"
    Header always set X-Query "%%{UP_QUERY}e"
</VirtualHost>
`, port, name)
}

// TestIntegration_httpdServesPathRoutes renders path routes, checks them
// with `httpd -t` and sends requests through a real httpd to see which
// upstream receives which path: exact beats prefix, a prefix stops at a
// segment boundary, strip_prefix removes the path, and the default
// upstream's catch-all rewrite leaves the path routes alone.
func TestIntegration_httpdServesPathRoutes(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skipf("docker not usable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dir, err := os.MkdirTemp("", "apachegen-paths-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	routes := []proxymodel.PathRoute{
		{Match: proxymodel.PathMatchPrefix, Path: "/live", WebSocket: true, Upstream: proxymodel.Upstream{Addr: "127.0.0.1", Port: 8083}},
		{Match: proxymodel.PathMatchExact, Path: "/secure", Upstream: proxymodel.Upstream{Addr: "127.0.0.1", Port: 8085, Scheme: proxymodel.SchemeHTTPS}},
		{Match: proxymodel.PathMatchExact, Path: "/api/world", Upstream: proxymodel.Upstream{Addr: "127.0.0.1", Port: 8082}},
		{Match: proxymodel.PathMatchPrefix, Path: "/media", Upstream: proxymodel.Upstream{Addr: "127.0.0.1", Port: 8083}},
		{Match: proxymodel.PathMatchPrefix, Path: "/ws.v1", StripPrefix: true, WebSocket: true, Upstream: proxymodel.Upstream{Addr: "127.0.0.1", Port: 8084}},
		{Match: proxymodel.PathMatchPrefix, Path: "/media/hd", Upstream: proxymodel.Upstream{Addr: "127.0.0.1", Port: 8084}},
	}
	route := func(host string, mutate func(*proxymodel.Route)) proxymodel.Route {
		r := proxymodel.Route{
			Host:       host,
			Upstream:   proxymodel.Upstream{Addr: "127.0.0.1", Port: 8081},
			TLS:        proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
			PathRoutes: routes,
		}
		if mutate != nil {
			mutate(&r)
		}
		return r
	}
	var vhosts strings.Builder
	for _, r := range []proxymodel.Route{
		route("paths.example.com", nil),
		route("ws.example.com", func(r *proxymodel.Route) { r.WebSocket = true }),
		route("strip.example.com", func(r *proxymodel.Route) { r.Path.StripPrefix = "/app" }),
		route("rewrite.example.com", func(r *proxymodel.Route) { r.Path.Rewrite = "/fixed" }),
		route("tlsup.example.com", func(r *proxymodel.Route) {
			r.Upstream = proxymodel.Upstream{Addr: "127.0.0.1", Port: 8085, Scheme: proxymodel.SchemeHTTPS}
		}),
	} {
		res, err := Render(Input{Route: r})
		if err != nil {
			t.Fatal(err)
		}
		vhosts.WriteString(res.VHost + "\n")
	}
	// E speaks TLS, so reaching it needs SSLProxyEngine on in the proxy vhost.
	certPath, keyPath := writeSelfSignedCert(t, dir)
	tlsUpstream := strings.Replace(pathRoutesUpstream(8085, "E"), "</VirtualHost>",
		"    SSLEngine on\n    SSLCertificateFile "+certPath+"\n    SSLCertificateKeyFile "+keyPath+"\n</VirtualHost>", 1)
	upstreams := pathRoutesUpstream(8081, "A") + pathRoutesUpstream(8082, "B") + pathRoutesUpstream(8083, "C") + pathRoutesUpstream(8084, "D") + tlsUpstream
	writeFile(t, filepath.Join(dir, "vhosts.conf"), vhosts.String())
	writeFile(t, filepath.Join(dir, "httpd.conf"), fmt.Sprintf(pathRoutesMainConf, upstreams, filepath.Join(dir, "vhosts.conf")))

	out, err := exec.CommandContext(ctx, "docker", "run", "-d", "--rm",
		"-v", dir+":"+dir+":ro", "--entrypoint", "sleep", httpdImage, "300").CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	container := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })

	conf := filepath.Join(dir, "httpd.conf")
	if out, err := exec.CommandContext(ctx, "docker", "exec", container, "httpd", "-t", "-f", conf).CombinedOutput(); err != nil || !strings.Contains(string(out), "Syntax OK") {
		t.Fatalf("httpd -t: %v\n%s\n--- vhosts ---\n%s", err, out, vhosts.String())
	}
	if out, err := exec.CommandContext(ctx, "docker", "exec", "-d", container, "httpd-foreground", "-f", conf).CombinedOutput(); err != nil {
		t.Fatalf("starting httpd: %v\n%s", err, out)
	}

	header := func(out, name string) string {
		m := regexp.MustCompile(`(?mi)^[ \t]*` + name + `:[ \t]*(.*?)[ \t\r]*$`).FindStringSubmatch(out)
		if m == nil {
			return ""
		}
		return m[1]
	}
	request := func(host, target string, extra ...string) (upstream, path, query string) {
		args := append([]string{"exec", container, "wget", "-S", "-O", "/dev/null", "--header", "Host: " + host}, extra...)
		args = append(args, "http://127.0.0.1"+target)
		out, _ := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		return header(string(out), "X-Upstream"), header(string(out), "X-Path"), header(string(out), "X-Query")
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if up, _, _ := request("paths.example.com", "/"); up != "" {
			break
		}
		if time.Now().After(deadline) {
			out, _ := exec.CommandContext(ctx, "docker", "exec", container, "wget", "-S", "-O", "-", "--header", "Host: paths.example.com", "http://127.0.0.1/").CombinedOutput()
			logs, _ := exec.CommandContext(ctx, "docker", "logs", container).CombinedOutput()
			t.Fatalf("httpd did not start serving:\n%s\n%s", out, logs)
		}
		time.Sleep(200 * time.Millisecond)
	}

	upgrade := []string{"--header", "Connection: Upgrade", "--header", "Upgrade: websocket"}
	tests := []struct {
		host, target string
		extra        []string
		upstream     string
		path, query  string
	}{
		{"paths.example.com", "/", nil, "A", "/", ""},
		{"paths.example.com", "/api/world", nil, "B", "/api/world", ""},
		{"paths.example.com", "/api/world?x=1", nil, "B", "/api/world", "x=1"},
		{"paths.example.com", "/api/worldx", nil, "A", "/api/worldx", ""},
		{"paths.example.com", "/api/world/", nil, "A", "/api/world/", ""},
		{"paths.example.com", "/media", nil, "C", "/media", ""},
		{"paths.example.com", "/media/a/b?q=2", nil, "C", "/media/a/b", "q=2"},
		{"paths.example.com", "/mediax", nil, "A", "/mediax", ""},
		{"paths.example.com", "/media/hd/1", nil, "D", "/media/hd/1", ""},
		{"paths.example.com", "/media/hdx", nil, "C", "/media/hdx", ""},
		{"paths.example.com", "/ws.v1", nil, "D", "/", ""},
		{"paths.example.com", "/ws.v1/socket?t=3", nil, "D", "/socket", "t=3"},
		{"paths.example.com", "/ws.v1x", nil, "A", "/ws.v1x", ""},
		{"ws.example.com", "/media/a", upgrade, "C", "/media/a", ""},
		{"ws.example.com", "/other", upgrade, "A", "/other", ""},
		{"strip.example.com", "/app/x", nil, "A", "/x", ""},
		{"strip.example.com", "/media/y", nil, "C", "/media/y", ""},
		{"strip.example.com", "/api/world", nil, "B", "/api/world", ""},
		{"strip.example.com", "/ws.v1/z", nil, "D", "/z", ""},
		{"rewrite.example.com", "/anything", nil, "A", "/fixed", ""},
		{"rewrite.example.com", "/media/z", nil, "C", "/media/z", ""},
		{"paths.example.com", "/live/feed", upgrade, "C", "/live/feed", ""},
		{"paths.example.com", "/live", upgrade, "C", "/live", ""},
		{"paths.example.com", "/secure", nil, "E", "/secure", ""},
		{"tlsup.example.com", "/x?y=1", nil, "E", "/x", "y=1"},
		{"tlsup.example.com", "/api/world", nil, "B", "/api/world", ""},
	}
	for _, tt := range tests {
		t.Run(tt.host+tt.target, func(t *testing.T) {
			up, path, query := request(tt.host, tt.target, tt.extra...)
			if up != tt.upstream || path != tt.path || query != tt.query {
				t.Fatalf("GET %s%s reached upstream %q path %q query %q, want %q %q %q", tt.host, tt.target, up, path, query, tt.upstream, tt.path, tt.query)
			}
		})
	}
}

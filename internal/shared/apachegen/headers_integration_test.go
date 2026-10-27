//go:build integration

package apachegen

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

const headersIntegrationMainConfig = `ServerRoot "/usr/local/apache2"
Listen 8080
Listen 127.0.0.1:8081
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule headers_module modules/mod_headers.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule rewrite_module modules/mod_rewrite.so
User daemon
Group daemon
ServerName localhost
ErrorLog /proc/self/fd/2
<VirtualHost 127.0.0.1:8081>
    DocumentRoot "/usr/local/apache2/htdocs"
    <Directory "/usr/local/apache2/htdocs">
        Require all granted
    </Directory>
</VirtualHost>
Include /vhost/app.conf
`

// TestRenderedHeaderValuesAreLiteralInRealApache serves a rendered vhost from
// a real httpd and checks that header values containing mod_headers format
// sequences come back exactly as configured.
func TestRenderedHeaderValuesAreLiteralInRealApache(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker not usable: %v\n%s", err, out)
	}
	values := map[string]string{
		"X-Env":    "%{HOME}e",
		"X-Pct":    "100%",
		"X-Format": "%D %t",
		"X-Quoted": `a "b" %{PATH}e`,
	}
	route := proxymodel.Route{
		Host:            "app.example.test",
		Upstream:        proxymodel.Upstream{Addr: "127.0.0.1", Port: 8081},
		ResponseHeaders: values,
		TLS:             proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
	}
	rendered, err := Render(Input{Route: route})
	if err != nil {
		t.Fatal(err)
	}
	vhost := strings.Replace(rendered.VHost, "<VirtualHost *:80>", "<VirtualHost *:8080>", 1)
	// Control: an unescaped format sequence is expanded, so the check above
	// would notice missing escapes.
	vhost = strings.Replace(vhost, "    ProxyPreserveHost On", "    Header always set X-Control %{HTTPD_PREFIX}e\n    ProxyPreserveHost On", 1)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.conf"), []byte(vhost), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "httpd.conf"), []byte(headersIntegrationMainConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	script := `httpd -f /vhost/httpd.conf -k start || exit 1
for i in $(seq 50); do wget -q -S -O /dev/null --header 'Host: app.example.test' http://127.0.0.1:8080/index.html 2>/tmp/h && break; sleep 0.1; done
cat /tmp/h`
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", "none",
		"-v", dir+":/vhost:ro", "--entrypoint", "sh", "httpd:2.4-alpine", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s\n--- vhost ---\n%s", err, out, vhost)
	}
	if strings.Contains(string(out), "X-Control: %{HTTPD_PREFIX}e") || !strings.Contains(string(out), "X-Control: ") {
		t.Fatalf("control header was not expanded by mod_headers:\n%s", out)
	}
	for name, want := range values {
		if !strings.Contains(string(out), name+": "+want+"\n") {
			t.Errorf("response lacks %s: %s\n%s\n--- vhost ---\n%s", name, want, out, vhost)
		}
	}
}

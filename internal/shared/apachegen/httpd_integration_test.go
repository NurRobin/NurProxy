//go:build integration

package apachegen

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
	"golang.org/x/crypto/bcrypt"
)

const httpdImage = "httpd:2.4-alpine"

// httpdMainConf loads the modules the rendered vhosts use and serves a static
// upstream on 127.0.0.1:8081. The %s is the vhost file to include.
const httpdMainConf = `ServerRoot "/usr/local/apache2"
Listen 80
Listen 443
Listen 127.0.0.1:8081
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authn_core_module modules/mod_authn_core.so
LoadModule authn_file_module modules/mod_authn_file.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule authz_host_module modules/mod_authz_host.so
LoadModule authz_user_module modules/mod_authz_user.so
LoadModule auth_basic_module modules/mod_auth_basic.so
LoadModule alias_module modules/mod_alias.so
LoadModule headers_module modules/mod_headers.so
LoadModule rewrite_module modules/mod_rewrite.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule socache_shmcb_module modules/mod_socache_shmcb.so
LoadModule ssl_module modules/mod_ssl.so
LoadModule dir_module modules/mod_dir.so
User daemon
Group daemon
ServerName localhost
ErrorLog /proc/self/fd/2
<VirtualHost 127.0.0.1:8081>
    DocumentRoot "/usr/local/apache2/htdocs"
    <Directory "/usr/local/apache2/htdocs">
        Require all granted
    </Directory>
    DirectoryIndex index.html
</VirtualHost>
Include %s
`

// TestIntegration_httpdAcceptsRenderedAccessControl runs every access-control
// shape the renderer emits through a real `httpd -t` (#166: a <RequireAll>
// directly in <VirtualHost> failed configtest), then serves them and checks
// that the rules decide requests as intended, from 127.0.0.1 inside the
// container.
func TestIntegration_httpdAcceptsRenderedAccessControl(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skipf("docker not usable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// MkdirTemp + chmod rather than t.TempDir: the httpd worker (daemon) reads
	// the htpasswd file at request time, so every directory must be traversable.
	dir, err := os.MkdirTemp("", "apachegen-httpd-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := writeSelfSignedCert(t, dir)
	authFile := filepath.Join(dir, "app.htpasswd")
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, authFile, "operator:"+string(hash)+"\n")

	route := func(host string, mutate func(*proxymodel.Route)) proxymodel.Route {
		r := proxymodel.Route{
			Host:     host,
			Upstream: proxymodel.Upstream{Addr: "127.0.0.1", Port: 8081},
			TLS:      proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
		}
		if mutate != nil {
			mutate(&r)
		}
		return r
	}
	withAuth := func(r *proxymodel.Route) {
		r.BasicAuth = &proxymodel.BasicAuth{Username: "operator", PasswordHash: string(hash)}
	}
	cases := []struct {
		name  string
		route proxymodel.Route
	}{
		{"plain", route("plain.example.com", nil)},
		{"tls", route("tls.example.com", func(r *proxymodel.Route) {
			r.TLS = proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyCentral}
			r.ForceHTTPS = true
		})},
		{"tls_allowlist_basic_auth", route("tlsauth.example.com", func(r *proxymodel.Route) {
			r.TLS = proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyCentral}
			r.ForceHTTPS = true
			r.IPAllowlist = []string{"127.0.0.1"}
			withAuth(r)
		})},
		{"allowlist", route("allow.example.com", func(r *proxymodel.Route) {
			r.IPAllowlist = []string{"127.0.0.1", "10.0.0.0/8"}
		})},
		{"allowlist_other_range", route("allow-other.example.com", func(r *proxymodel.Route) {
			r.IPAllowlist = []string{"203.0.113.0/24"}
		})},
		{"denylist", route("deny.example.com", func(r *proxymodel.Route) {
			r.IPBlocklist = []string{"127.0.0.1"}
		})},
		{"denylist_other_range", route("deny-other.example.com", func(r *proxymodel.Route) {
			r.IPBlocklist = []string{"203.0.113.0/24"}
		})},
		{"allowlist_and_denylist", route("allow-deny.example.com", func(r *proxymodel.Route) {
			r.IPAllowlist = []string{"127.0.0.0/8"}
			r.IPBlocklist = []string{"127.0.0.1"}
		})},
		{"basic_auth", route("auth.example.com", withAuth)},
		{"basic_auth_allowlist", route("auth-allow.example.com", func(r *proxymodel.Route) {
			withAuth(r)
			r.IPAllowlist = []string{"127.0.0.1"}
		})},
		{"basic_auth_allowlist_other_range", route("auth-allow-other.example.com", func(r *proxymodel.Route) {
			withAuth(r)
			r.IPAllowlist = []string{"203.0.113.0/24"}
		})},
		{"basic_auth_denylist", route("auth-deny.example.com", func(r *proxymodel.Route) {
			withAuth(r)
			r.IPBlocklist = []string{"127.0.0.1"}
		})},
	}

	var all strings.Builder
	for _, c := range cases {
		res, err := Render(Input{Route: c.route, CertPath: certPath, KeyPath: keyPath, AuthFile: authFile})
		if err != nil {
			t.Fatalf("%s: Render: %v", c.name, err)
		}
		if len(res.Warnings) != 0 {
			t.Fatalf("%s: unexpected warnings: %v", c.name, res.Warnings)
		}
		caseDir := filepath.Join(dir, c.name)
		if err := os.Mkdir(caseDir, 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(caseDir, "vhost.conf"), res.VHost)
		writeFile(t, filepath.Join(caseDir, "httpd.conf"), fmt.Sprintf(httpdMainConf, filepath.Join(caseDir, "vhost.conf")))
		all.WriteString(res.VHost + "\n")
	}
	writeFile(t, filepath.Join(dir, "all.conf"), all.String())
	writeFile(t, filepath.Join(dir, "httpd.conf"), fmt.Sprintf(httpdMainConf, filepath.Join(dir, "all.conf")))

	// The container idles first so each case gets its own configtest; httpd is
	// started on the combined config only after that config passes too.
	out, err := exec.CommandContext(ctx, "docker", "run", "-d", "--rm",
		"-v", dir+":"+dir+":ro", "--entrypoint", "sleep",
		httpdImage, "300").CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	container := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })

	configtest := func(conf string) error {
		out, err := exec.CommandContext(ctx, "docker", "exec", container, "httpd", "-t", "-f", conf).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "Syntax OK") {
			return fmt.Errorf("httpd -t: %v\n%s", err, out)
		}
		return nil
	}
	for _, c := range cases {
		t.Run("configtest/"+c.name, func(t *testing.T) {
			if err := configtest(filepath.Join(dir, c.name, "httpd.conf")); err != nil {
				vhost, _ := os.ReadFile(filepath.Join(dir, c.name, "vhost.conf"))
				t.Fatalf("real httpd rejected the rendered config: %v\n--- vhost ---\n%s", err, vhost)
			}
		})
	}
	if err := configtest(filepath.Join(dir, "httpd.conf")); err != nil {
		t.Fatalf("combined config: %v", err)
	}
	if out, err := exec.CommandContext(ctx, "docker", "exec", "-d", container,
		"httpd-foreground", "-f", filepath.Join(dir, "httpd.conf")).CombinedOutput(); err != nil {
		t.Fatalf("starting httpd: %v\n%s", err, out)
	}

	status := func(host, credentials string) int {
		args := []string{"exec", container, "wget", "-S", "-O", "/dev/null", "--header", "Host: " + host}
		if credentials != "" {
			args = append(args, "--header", "Authorization: Basic "+credentials)
		}
		args = append(args, "http://127.0.0.1/")
		out, _ := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		m := regexp.MustCompile(`HTTP/1\.[01] (\d{3})`).FindStringSubmatch(string(out))
		if m == nil {
			return 0
		}
		var code int
		_, _ = fmt.Sscanf(m[1], "%d", &code)
		return code
	}
	deadline := time.Now().Add(30 * time.Second)
	for status("plain.example.com", "") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("httpd did not start serving")
		}
		time.Sleep(200 * time.Millisecond)
	}

	good := "b3BlcmF0b3I6czNjcmV0" // operator:s3cret
	bad := "b3BlcmF0b3I6d3Jvbmc="  // operator:wrong
	requests := []struct {
		name, host, credentials string
		want                    int
	}{
		{"plain", "plain.example.com", "", 200},
		{"force_https_redirect", "tls.example.com", "", 301},
		{"allowlist_match", "allow.example.com", "", 200},
		{"allowlist_no_match", "allow-other.example.com", "", 403},
		{"denylist_match", "deny.example.com", "", 403},
		{"denylist_no_match", "deny-other.example.com", "", 200},
		{"allow_and_deny_both_match", "allow-deny.example.com", "", 403},
		{"basic_auth_missing", "auth.example.com", "", 401},
		{"basic_auth_wrong", "auth.example.com", bad, 401},
		{"basic_auth_right", "auth.example.com", good, 200},
		{"auth_allowlist_missing_credentials", "auth-allow.example.com", "", 401},
		{"auth_allowlist_right", "auth-allow.example.com", good, 200},
		{"auth_allowlist_no_match_right_credentials", "auth-allow-other.example.com", good, 403},
		{"auth_denylist_match_right_credentials", "auth-deny.example.com", good, 403},
	}
	for _, r := range requests {
		t.Run("request/"+r.name, func(t *testing.T) {
			if got := status(r.host, r.credentials); got != r.want {
				t.Fatalf("GET http://%s/ = %d, want %d", r.host, got, r.want)
			}
		})
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeSelfSignedCert writes a throwaway cert/key pair httpd can load for the
// TLS vhosts and returns their paths.
func writeSelfSignedCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"*.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeFile(t, certPath, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	writeFile(t, keyPath, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})))
	return certPath, keyPath
}

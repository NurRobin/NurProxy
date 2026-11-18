//go:build integration

package apacheparse

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
	"strings"
	"testing"
	"time"
)

const httpdImage = "httpd:2.4-alpine"

const httpdMainConf = `ServerRoot "/usr/local/apache2"
Listen 80
Listen 443
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
LoadModule proxy_wstunnel_module modules/mod_proxy_wstunnel.so
LoadModule socache_shmcb_module modules/mod_socache_shmcb.so
LoadModule ssl_module modules/mod_ssl.so
LoadModule log_config_module modules/mod_log_config.so
LogFormat "%%h %%l %%u %%t \"%%r\" %%>s %%b" common
User daemon
Group daemon
ServerName main.invalid
ErrorLog /proc/self/fd/2
Include %s
`

// TestIntegration_httpdReadsPolicyConfigsAsThePolicyDoes checks the policy
// against a real httpd: every config it admits passes `httpd -t`, and for a
// comment ending in a backslash httpd really swallows the next line, which
// is why the policy refuses it.
func TestIntegration_httpdReadsPolicyConfigsAsThePolicyDoes(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skipf("docker not usable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("", "apacheparse-httpd-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	certs, auth := filepath.Join(dir, "certs"), filepath.Join(dir, "auth")
	for _, d := range []string{certs, auth} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeSelfSignedCert(t, filepath.Join(certs, filepath.Base(testCert)), filepath.Join(certs, filepath.Base(testKey)))
	writeTestFile(t, filepath.Join(auth, filepath.Base(testAuth)), "operator:$apr1$x$y\n")

	type confCase struct{ name, content string }
	var cases []confCase
	for _, c := range boundedRawConfigs() {
		cases = append(cases, confCase{strings.ReplaceAll(c.name, " ", "_"), c.content})
	}
	hidden := strings.Replace(fmt.Sprintf(proxiedVHost, ""), "    ServerName app.example.com\n", "    # hidden \\\n    ServerName app.example.com\n", 1)
	cases = append(cases, confCase{"comment_continuation", hidden})
	for _, c := range cases {
		writeTestFile(t, filepath.Join(dir, c.name+".vhost"), c.content)
		writeTestFile(t, filepath.Join(dir, c.name+".conf"), fmt.Sprintf(httpdMainConf, filepath.Join(dir, c.name+".vhost")))
	}

	out, err := exec.CommandContext(ctx, "docker", "run", "-d", "--rm",
		"-v", dir+":"+dir+":ro",
		"-v", certs+":"+filepath.Dir(testCert)+":ro",
		"-v", auth+":"+filepath.Dir(testAuth)+":ro",
		"--entrypoint", "sleep", httpdImage, "300").CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	container := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	httpd := func(conf string, args ...string) (string, error) {
		out, err := exec.CommandContext(ctx, "docker", append([]string{"exec", container, "httpd", "-f", conf}, args...)...).CombinedOutput()
		return string(out), err
	}

	for _, c := range cases[:len(cases)-1] {
		t.Run("configtest/"+c.name, func(t *testing.T) {
			if out, err := httpd(filepath.Join(dir, c.name+".conf"), "-t"); err != nil || !strings.Contains(out, "Syntax OK") {
				t.Fatalf("real httpd rejected an admitted config: %v\n%s\n--- vhost ---\n%s", err, out, c.content)
			}
		})
	}
	t.Run("comment_continuation_swallows_next_line", func(t *testing.T) {
		if err := ValidateManaged(hidden, testPolicy); err == nil {
			t.Fatal("policy admitted a comment ending in a backslash")
		}
		out, err := httpd(filepath.Join(dir, "comment_continuation.conf"), "-t", "-D", "DUMP_VHOSTS")
		if err != nil {
			t.Fatalf("httpd -S: %v\n%s", err, out)
		}
		if strings.Contains(out, "app.example.com") {
			t.Fatalf("httpd kept the ServerName after a continued comment; the refusal may be unnecessary:\n%s", out)
		}
	})
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeSelfSignedCert(t *testing.T, certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: testHost},
		DNSNames:     []string{testHost},
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
	writeTestFile(t, certPath, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	writeTestFile(t, keyPath, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})))
}

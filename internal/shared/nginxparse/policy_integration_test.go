//go:build integration

package nginxparse

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
	"sort"
	"strings"
	"testing"
	"time"
)

const policyIntegrationMainConfig = `events {}
http {
    include /cases/%s;
}
`

// TestValidateManagedAgreesWithRealNginx runs `nginx -t` on every policy test
// case in a real nginx. Each case's log paths are rewritten to a per-case
// marker file, so a marker that nginx creates proves nginx read a log
// directive there. The test requires that:
//   - every admitted config is valid nginx and opens no marker;
//   - for every case, nginx opens a marker exactly when this package's
//     tokenizer sees an error_log or access_log directive naming it and nginx accepts the
//     config, i.e. both read the same directives.
func TestValidateManagedAgreesWithRealNginx(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker not usable: %v\n%s", err, out)
	}
	type nginxCase struct {
		name     string
		content  string
		admitted bool
		validate func(string, ManagedPolicy) error
	}
	var cases []nginxCase
	for name, content := range policyTestAccepted {
		cases = append(cases, nginxCase{name: "accepted/" + name, content: content, admitted: true, validate: ValidateManaged})
	}
	for name, generated := range policyTestGeneratedConfigs(t) {
		// nginx -t resolves upstream host names; keep the check offline.
		content := strings.ReplaceAll(generated.full, "backend.internal", "127.0.0.1")
		cases = append(cases, nginxCase{name: "generated/" + name, content: content, admitted: true, validate: ValidateRendered})
	}
	for _, tt := range policyTestRefused {
		cases = append(cases, nginxCase{name: "refused/" + tt.name, content: tt.content, validate: ValidateManaged})
	}
	// Escaped header values that nginx must read as one value: if it ended
	// the string early, the error_log after it would open a marker.
	hostileValues := strings.Replace(policyTestRendered, "    location / {",
		`    add_header X-B "\\\";error_log /tmp/x.log info;#" always;`+"\n"+
			`    add_header X-C "\\\\\";error_log /tmp/x.log info;#\\" always;`+"\n"+
			`    add_header X-D "a\\" always;`+"\n    location / {", 1)
	cases = append(cases, nginxCase{name: "rendered/escaped header values", content: hostileValues, admitted: true, validate: ValidateRendered})
	cases = append(cases, nginxCase{name: "rendered/sample", content: policyTestRendered, admitted: true, validate: ValidateRendered})
	cases = append(cases, nginxCase{name: "rendered/unescaped quote", content: strings.Replace(policyTestRendered, `"\\\";include /etc/x;#"`, `"\\";error_log /tmp/x.log info;#"`, 1), validate: ValidateRendered})
	for name, content := range policyTestRenderedRefused {
		cases = append(cases, nginxCase{name: "rendered refused/" + name, content: content, validate: ValidateRendered})
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].name < cases[j].name })

	root := t.TempDir()
	casesDir := filepath.Join(root, "cases")
	certDir := filepath.Join(root, "certs")
	for _, dir := range []string{casesDir, certDir} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeIntegrationCertificate(t, filepath.Join(certDir, filepath.Base(policyTestCert)), filepath.Join(certDir, filepath.Base(policyTestKey)))
	markers := make([]string, len(cases))
	for i, c := range cases {
		markers[i] = fmt.Sprintf("/markers/case-%03d.log", i)
		content := strings.ReplaceAll(c.content, "/tmp/x.log", markers[i])
		cases[i].content = content
		if err := c.validate(content, policyTestPolicyFor(content)); c.admitted && err != nil {
			t.Fatalf("%s: admitted case no longer passes the policy: %v", c.name, err)
		}
		if !c.admitted && c.validate(content, policyTestPolicyFor(content)) == nil {
			t.Fatalf("%s: refused case passes the policy", c.name)
		}
		file := fmt.Sprintf("case-%03d.conf", i)
		if err := os.WriteFile(filepath.Join(casesDir, file), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(casesDir, file+".main"), []byte(fmt.Sprintf(policyIntegrationMainConfig, file)), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	script := `for main in /cases/*.main; do
  if nginx -q -t -c "$main" >/dev/null 2>&1; then echo "rc $(basename "$main" .conf.main) 0"; else echo "rc $(basename "$main" .conf.main) 1"; fi
done
for marker in /markers/*; do [ -e "$marker" ] && echo "marker $marker"; done
true`
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", "none",
		"--tmpfs", "/markers",
		"-v", casesDir+":/cases:ro",
		"-v", certDir+":"+filepath.Dir(policyTestCert)+":ro",
		"--entrypoint", "sh", "nginx:1.29-alpine", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	accepted := map[string]bool{}
	opened := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		switch {
		case len(fields) == 3 && fields[0] == "rc":
			accepted[fields[1]] = fields[2] == "0"
		case len(fields) == 2 && fields[0] == "marker":
			opened[fields[1]] = true
		}
	}
	for i, c := range cases {
		id := fmt.Sprintf("case-%03d", i)
		nginxOK, ran := accepted[id]
		if !ran {
			t.Fatalf("%s: nginx did not run\n%s", c.name, out)
		}
		if c.admitted && !nginxOK {
			t.Errorf("%s: admitted config fails nginx -t:\n%s", c.name, c.content)
		}
		ours := tokenizerSeesLogDirective(c.content, markers[i])
		if opened[markers[i]] != (ours && nginxOK) {
			t.Errorf("%s: nginx opened marker = %v, tokenizer sees log directive = %v, nginx -t ok = %v:\n%s", c.name, opened[markers[i]], ours, nginxOK, c.content)
		}
		if c.admitted && opened[markers[i]] {
			t.Errorf("%s: admitted config made nginx open a file", c.name)
		}
	}
	// The refused cases include log directives nginx does read; without any
	// marker the harness would not be observing nginx at all.
	if len(opened) == 0 {
		t.Fatalf("nginx opened no marker for any case; the harness is not observing nginx\n%s", out)
	}
	t.Logf("%d cases, nginx opened %d markers", len(cases), len(opened))
}

// tokenizerSeesLogDirective reports whether parseConfig reads an error_log or access_log
// directive with the given path anywhere in the config.
func tokenizerSeesLogDirective(content, path string) bool {
	blocks, directives, err := parseConfig(content)
	if err != nil {
		return false
	}
	var walk func([]block, []directive) bool
	walk = func(bs []block, ds []directive) bool {
		for _, d := range ds {
			if len(d.tokens) >= 2 && (d.tokens[0].value == "error_log" || d.tokens[0].value == "access_log") && d.tokens[1].value == path {
				return true
			}
		}
		for _, b := range bs {
			if walk(b.blocks, b.directives) {
				return true
			}
		}
		return false
	}
	return walk(blocks, directives)
}

func writeIntegrationCertificate(t *testing.T, certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: policyTestHost},
		DNSNames:     []string{policyTestHost},
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
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o644); err != nil {
		t.Fatal(err)
	}
}

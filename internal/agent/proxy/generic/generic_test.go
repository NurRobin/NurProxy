package generic

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/agent/proxy/certstore"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// fakeRunner records reloads and returns a scripted test outcome.
type fakeRunner struct {
	testErr  error
	hasTest  bool
	reloads  int
	reloaded bool
}

func (f *fakeRunner) Test(context.Context) (bool, string, error) {
	return f.hasTest, "", f.testErr
}
func (f *fakeRunner) Reload(context.Context) error {
	f.reloads++
	f.reloaded = true
	return nil
}

func newBackend(t *testing.T, tmpl string) (*Backend, *fakeRunner) {
	t.Helper()
	dir := t.TempDir()
	b, err := New(proxy.Config{
		Type:      "custom",
		ConfigDir: dir,
		ReloadCmd: "systemctl reload myengine",
		Template:  tmpl,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fr := &fakeRunner{hasTest: true}
	b.WithRunner(fr)
	return b, fr
}

func httpRoute(host string) proxymodel.Route {
	return proxymodel.Route{
		Host:     host,
		Upstream: proxymodel.Upstream{Addr: "10.0.0.5", Port: 8080, Scheme: proxymodel.SchemeHTTP},
		TLS:      proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
	}
}

func TestNew_validation(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		cfg  proxy.Config
	}{
		{"no template", proxy.Config{ConfigDir: dir, ReloadCmd: "x"}},
		{"no reload", proxy.Config{ConfigDir: dir, Template: "x"}},
		{"no config dir", proxy.Config{Template: "x", ReloadCmd: "x"}},
		{"bad template", proxy.Config{ConfigDir: dir, ReloadCmd: "x", Template: "{{ .Nope "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}

func TestGenericBackendRemainsDiagnosisOnlyForRecovery(t *testing.T) {
	b, _ := newBackend(t, "{{.Host}}")
	if _, ok := any(b).(proxy.RecoveryInspector); ok {
		t.Fatal("custom backend unexpectedly exposes automatic recovery")
	}
}

func TestNew_fileExtDefaultsAndDots(t *testing.T) {
	dir := t.TempDir()
	base := proxy.Config{ConfigDir: dir, ReloadCmd: "x", Template: "x"}
	b1, _ := New(base)
	if b1.fileExt != ".conf" {
		t.Errorf("default ext = %q, want .conf", b1.fileExt)
	}
	base.FileExt = "cfg"
	b2, _ := New(base)
	if b2.fileExt != ".cfg" {
		t.Errorf("ext = %q, want .cfg (dot added)", b2.fileExt)
	}
}

func TestRender_structured(t *testing.T) {
	b, _ := newBackend(t, "{{.Host}} -> {{.UpstreamAddr}} scheme={{.Scheme}} tls={{.TLS}} ws={{.WebSocket}}")
	r := httpRoute("app.example.com")
	r.WebSocket = true
	art, err := b.Render(context.Background(), r)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	want := "app.example.com -> 10.0.0.5:8080 scheme=http tls=false ws=true"
	if art.Content != want {
		t.Errorf("content = %q, want %q", art.Content, want)
	}
	if !strings.HasSuffix(art.Target.Path, "nurproxy-app.example.com.conf") {
		t.Errorf("target path = %q, want nurproxy-<host>.conf", art.Target.Path)
	}
}

func TestRender_centralCertPaths(t *testing.T) {
	dir := t.TempDir()
	store := certstore.New(filepath.Join(dir, "certs"), nil)
	if _, err := store.Install(certstore.Bundle{Host: "app.example.com", CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	b, err := New(proxy.Config{
		ConfigDir: dir, ReloadCmd: "x",
		Template: "{{if .CertPath}}cert={{.CertPath}} key={{.KeyPath}}{{else}}NOCERT{{end}}",
		CertDir:  filepath.Join(dir, "certs"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := proxymodel.Route{Host: "app.example.com", Upstream: proxymodel.Upstream{Addr: "10.0.0.5", Port: 80}, TLS: proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyCentral}}
	art, err := b.Render(context.Background(), r)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(art.Content, "cert=") || strings.Contains(art.Content, "NOCERT") {
		t.Errorf("central-TLS render should reference the installed cert, got %q", art.Content)
	}
}

func TestRender_rawPassthroughAndWrongBackend(t *testing.T) {
	b, _ := newBackend(t, "ignored")
	raw := proxymodel.Route{Host: "h.example.com", Raw: proxymodel.RawConfig{Backend: "custom", Content: "VERBATIM"}}
	art, err := b.Render(context.Background(), raw)
	if err != nil {
		t.Fatalf("Render raw: %v", err)
	}
	if art.Content != "VERBATIM" {
		t.Errorf("raw content = %q, want VERBATIM", art.Content)
	}
	wrong := proxymodel.Route{Host: "h.example.com", Raw: proxymodel.RawConfig{Backend: "nginx", Content: "x"}}
	if _, err := b.Render(context.Background(), wrong); err == nil {
		t.Error("raw config tagged for another backend must be refused")
	}
}

func TestApply_writesAndReloads(t *testing.T) {
	b, fr := newBackend(t, "{{.Host}}")
	art, _ := b.Render(context.Background(), httpRoute("app.example.com"))
	if err := b.Apply(context.Background(), []proxy.Artifact{art}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	data, err := os.ReadFile(art.Target.Path)
	if err != nil {
		t.Fatalf("reading applied file: %v", err)
	}
	if string(data) != "app.example.com" {
		t.Errorf("applied content = %q", string(data))
	}
	if !fr.reloaded {
		t.Error("Apply should reload after a passing test")
	}
	// No temp file should linger after a commit.
	if _, err := os.Stat(art.Target.Path + tempSuffix); !os.IsNotExist(err) {
		t.Error("temp file should be removed after commit")
	}
}

func TestApply_rollbackOnTestFailure(t *testing.T) {
	b, fr := newBackend(t, "{{.Host}}")
	art, _ := b.Render(context.Background(), httpRoute("app.example.com"))
	// Pre-existing content at the destination must be restored on a failed test.
	if err := os.WriteFile(art.Target.Path, []byte("PRIOR"), 0o644); err != nil {
		t.Fatal(err)
	}
	fr.testErr = context.DeadlineExceeded
	if err := b.Apply(context.Background(), []proxy.Artifact{art}); err == nil {
		t.Fatal("Apply should fail when the test command fails")
	}
	data, _ := os.ReadFile(art.Target.Path)
	if string(data) != "PRIOR" {
		t.Errorf("destination should be restored to PRIOR on rollback, got %q", string(data))
	}
	if fr.reloaded {
		t.Error("a failed test must not reload")
	}
}

func TestReadManaged_managedVsAdopted(t *testing.T) {
	b, _ := newBackend(t, "x")
	managed := b.managedPath("app.example.com")
	if err := os.WriteFile(managed, []byte("m"), 0o644); err != nil {
		t.Fatal(err)
	}
	adopted := filepath.Join(b.configDir, "operator.conf")
	if err := os.WriteFile(adopted, []byte("o"), 0o644); err != nil {
		t.Fatal(err)
	}
	arts, err := b.ReadManaged(context.Background())
	if err != nil {
		t.Fatalf("ReadManaged: %v", err)
	}
	got := map[string]bool{}
	for _, a := range arts {
		got[filepath.Base(a.Target.Path)] = a.Adopted
	}
	if got[filepath.Base(managed)] {
		t.Error("nurproxy-generated file should be Adopted=false")
	}
	if !got["operator.conf"] {
		t.Error("operator file should be Adopted=true")
	}
}

func TestPrune_removesManagedNotKept(t *testing.T) {
	b, fr := newBackend(t, "x")
	keep := b.managedPath("keep.example.com")
	drop := b.managedPath("drop.example.com")
	operator := filepath.Join(b.configDir, "operator.conf")
	for _, p := range []string{keep, drop, operator} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	n, err := b.Prune(context.Background(), []proxy.Target{{Kind: proxy.TargetKindFile, Path: keep}})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned %d, want 1", n)
	}
	if _, err := os.Stat(drop); !os.IsNotExist(err) {
		t.Error("unkept managed file should be removed")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Error("kept managed file should survive")
	}
	if _, err := os.Stat(operator); err != nil {
		t.Error("operator file must never be pruned")
	}
	if !fr.reloaded {
		t.Error("Prune should reload after removing a file")
	}
}

func TestCapabilities_declared(t *testing.T) {
	dir := t.TempDir()
	caps := &proxy.Capabilities{WebSocket: true, CentralTLS: true}
	b, err := New(proxy.Config{ConfigDir: dir, ReloadCmd: "x", Template: "x", DeclaredCaps: caps, CertDir: filepath.Join(dir, "certs")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c := b.Capabilities()
	if !c.ReverseProxy {
		t.Error("reverse proxy is always implied")
	}
	if !c.WebSocket {
		t.Error("declared websocket should be reported")
	}
	if c.ForceHTTPS {
		t.Error("undeclared capability should be false")
	}
	if !c.CentralTLS {
		t.Error("central TLS declared + cert store configured should be true")
	}
}

func TestCapabilities_centralTLSNeedsStore(t *testing.T) {
	b, _ := newBackend(t, "x") // no CertDir
	if b.Capabilities().CentralTLS {
		t.Error("central TLS must be false without a cert store")
	}
}

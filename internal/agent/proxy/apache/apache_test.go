package apache

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// fakeRunner is an injectable Runner that records calls and returns canned
// results so Apply's atomic orchestration is testable without a real apache.
type fakeRunner struct {
	testOut   string
	testErr   error
	reloadErr error
	tests     int
	reloads   int
}

func (f *fakeRunner) Test(ctx context.Context) (string, error) {
	f.tests++
	return f.testOut, f.testErr
}

func (f *fakeRunner) Reload(ctx context.Context) error {
	f.reloads++
	return f.reloadErr
}

// newDebianBackend builds a backend rooted at a temp sites-available dir (Debian
// layout, with sites-enabled symlinks) and an injected runner.
func newDebianBackend(t *testing.T, r Runner) (*Backend, Layout) {
	t.Helper()
	dir := t.TempDir()
	b := New(proxy.Config{Type: "apache", ConfigDir: filepath.Join(dir, "sites-available")})
	b.WithRunner(r)
	return b, b.layout
}

// newRHELBackend builds a backend rooted at a temp conf.d dir (RHEL flat layout,
// no symlinks) and an injected runner.
func newRHELBackend(t *testing.T, r Runner) (*Backend, Layout) {
	t.Helper()
	dir := t.TempDir()
	b := New(proxy.Config{Type: "apache", ConfigDir: filepath.Join(dir, "conf.d")})
	b.WithRunner(r)
	return b, b.layout
}

func sampleArtifact(b *Backend, host, content string) proxy.Artifact {
	return proxy.Artifact{
		Target:  proxy.Target{Kind: proxy.TargetKindFile, Path: b.layout.AvailablePath(host)},
		Content: content,
		Enabled: true,
	}
}

func TestApply_debian_success_writesFileSymlinkAndReloads(t *testing.T) {
	r := &fakeRunner{}
	b, layout := newDebianBackend(t, r)
	art := sampleArtifact(b, "app.example.com", "<VirtualHost *:80></VirtualHost>\n")

	if err := b.Apply(context.Background(), []proxy.Artifact{art}); err != nil {
		t.Fatalf("Apply error: %v", err)
	}

	got, err := os.ReadFile(art.Target.Path)
	if err != nil {
		t.Fatalf("reading applied file: %v", err)
	}
	if string(got) != art.Content {
		t.Errorf("file content = %q, want %q", got, art.Content)
	}
	link := layout.EnabledPath("app.example.com")
	if !symlinkPresent(link) {
		t.Errorf("expected sites-enabled symlink at %q", link)
	}
	if _, err := os.Stat(art.Target.Path + tempSuffix); !os.IsNotExist(err) {
		t.Errorf("temp file should be removed after commit, stat err = %v", err)
	}
	if r.tests != 1 || r.reloads != 1 {
		t.Errorf("tests=%d reloads=%d, want 1/1", r.tests, r.reloads)
	}
}

func TestApply_rhel_confd_noSymlink_reloads(t *testing.T) {
	r := &fakeRunner{}
	b, layout := newRHELBackend(t, r)
	if !layout.IsConfD() {
		t.Fatalf("expected conf.d layout, got Enabled=%q", layout.Enabled)
	}
	art := sampleArtifact(b, "app.example.com", "<VirtualHost *:80></VirtualHost>\n")

	if err := b.Apply(context.Background(), []proxy.Artifact{art}); err != nil {
		t.Fatalf("Apply error: %v", err)
	}
	// The file lives in conf.d; there is no enable symlink (presence == enabled).
	if _, err := os.Stat(art.Target.Path); err != nil {
		t.Fatalf("expected conf.d file present: %v", err)
	}
	if layout.EnabledPath("app.example.com") != "" {
		t.Errorf("conf.d layout should have no enabled path")
	}
	if r.reloads != 1 {
		t.Errorf("reloads=%d, want 1", r.reloads)
	}
}

func TestApply_configtestFails_rollsBack_newFile(t *testing.T) {
	r := &fakeRunner{testErr: errors.New("bad"), testOut: "Syntax error on line 3 of /x/nurproxy-app.example.com.conf:"}
	b, layout := newDebianBackend(t, r)
	art := sampleArtifact(b, "app.example.com", "<VirtualHost *:80></VirtualHost>\n")

	err := b.Apply(context.Background(), []proxy.Artifact{art})
	if err == nil {
		t.Fatal("expected Apply to fail on configtest error")
	}
	if _, statErr := os.Stat(art.Target.Path); !os.IsNotExist(statErr) {
		t.Errorf("brand-new file should be removed on rollback")
	}
	if symlinkPresent(layout.EnabledPath("app.example.com")) {
		t.Errorf("symlink should not survive rollback of a new file")
	}
	if _, statErr := os.Stat(art.Target.Path + tempSuffix); !os.IsNotExist(statErr) {
		t.Errorf("temp file should be removed on rollback")
	}
	if r.reloads != 0 {
		t.Errorf("reload should not run after a failed configtest")
	}
}

func TestApply_configtestFails_rollsBack_priorContent(t *testing.T) {
	r := &fakeRunner{}
	b, _ := newDebianBackend(t, r)
	host := "app.example.com"

	// First good apply establishes prior content.
	first := sampleArtifact(b, host, "<VirtualHost *:80># v1</VirtualHost>\n")
	if err := b.Apply(context.Background(), []proxy.Artifact{first}); err != nil {
		t.Fatalf("first apply: %v", err)
	}

	// Second apply fails configtest; prior content must be restored.
	r.testErr = errors.New("bad")
	r.testOut = "Syntax error on line 1 of /x/nurproxy-app.example.com.conf:"
	second := sampleArtifact(b, host, "<VirtualHost *:80># v2 BROKEN</VirtualHost>\n")
	if err := b.Apply(context.Background(), []proxy.Artifact{second}); err == nil {
		t.Fatal("expected second apply to fail")
	}
	got, err := os.ReadFile(first.Target.Path)
	if err != nil {
		t.Fatalf("reading restored file: %v", err)
	}
	if string(got) != first.Content {
		t.Errorf("prior content not restored: got %q want %q", got, first.Content)
	}
}

// TestApply_symlinkFails_restoresPriorContent reproduces the operator setup where
// the sites-enabled entry is a copied regular file (not a symlink): ensureSymlink
// refuses to clobber it and Apply fails. The prior content of the live file must
// be restored — the failed apply must not leave the new (rejected) config on disk.
func TestApply_symlinkFails_restoresPriorContent(t *testing.T) {
	r := &fakeRunner{}
	b, layout := newDebianBackend(t, r)

	if err := os.MkdirAll(layout.Available, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.Enabled, 0o755); err != nil {
		t.Fatal(err)
	}

	dest := layout.AvailablePath("app.example.com")
	prior := "<VirtualHost *:80># GOOD\n</VirtualHost>\n"
	if err := os.WriteFile(dest, []byte(prior), 0o644); err != nil {
		t.Fatal(err)
	}
	// Operator activated by COPYING a regular file into sites-enabled (not a
	// symlink); ensureSymlink refuses to replace it, so Apply fails mid-iteration.
	if err := os.WriteFile(layout.EnabledPath("app.example.com"), []byte("copied\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	art := sampleArtifact(b, "app.example.com", "<VirtualHost *:80># NEW\n</VirtualHost>\n")
	if err := b.Apply(context.Background(), []proxy.Artifact{art}); err == nil {
		t.Fatal("expected error when sites-enabled holds a regular file")
	}
	got, readErr := os.ReadFile(dest)
	if readErr != nil {
		t.Fatalf("reading restored file: %v", readErr)
	}
	if string(got) != prior {
		t.Errorf("restored content = %q, want prior %q", got, prior)
	}
	if r.tests != 0 {
		t.Errorf("configtest ran %d times, want 0 (failed before validation)", r.tests)
	}
}

func TestApply_reloadFails_rollsBack(t *testing.T) {
	r := &fakeRunner{reloadErr: errors.New("reload boom")}
	b, layout := newDebianBackend(t, r)
	art := sampleArtifact(b, "app.example.com", "<VirtualHost *:80></VirtualHost>\n")

	if err := b.Apply(context.Background(), []proxy.Artifact{art}); err == nil {
		t.Fatal("expected Apply to fail on reload error")
	}
	if _, statErr := os.Stat(art.Target.Path); !os.IsNotExist(statErr) {
		t.Errorf("file should be removed on rollback after reload failure")
	}
	if symlinkPresent(layout.EnabledPath("app.example.com")) {
		t.Errorf("symlink should not survive rollback after reload failure")
	}
}

func TestApply_configtestFails_returnsAttributedError(t *testing.T) {
	r := &fakeRunner{
		testErr: errors.New("exit 1"),
		testOut: "AH00526: Syntax error on line 9 of /etc/apache2/sites-enabled/operator.conf:\nInvalid command 'Bogus'",
	}
	b, _ := newDebianBackend(t, r)
	art := sampleArtifact(b, "app.example.com", "<VirtualHost *:80></VirtualHost>\n")

	err := b.Apply(context.Background(), []proxy.Artifact{art})
	var ce *commandError
	if !errors.As(err, &ce) {
		t.Fatalf("error type = %T, want *commandError", err)
	}
	if !ce.Attribution.Located {
		t.Fatalf("attribution should be located")
	}
	if ce.Attribution.Ours {
		t.Errorf("blame should be the operator's file, not ours")
	}
	if ce.Attribution.Line != 9 {
		t.Errorf("line = %d, want 9", ce.Attribution.Line)
	}
}

func TestRemove_debian_deletesFileAndSymlink(t *testing.T) {
	r := &fakeRunner{}
	b, layout := newDebianBackend(t, r)
	host := "gone.example.com"
	art := sampleArtifact(b, host, "<VirtualHost *:80></VirtualHost>\n")
	if err := b.Apply(context.Background(), []proxy.Artifact{art}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := b.Remove(context.Background(), art.Target); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(art.Target.Path); !os.IsNotExist(err) {
		t.Errorf("config file should be removed")
	}
	if symlinkPresent(layout.EnabledPath(host)) {
		t.Errorf("symlink should be removed")
	}
}

func TestRemove_missingFile_notAnError(t *testing.T) {
	r := &fakeRunner{}
	b, _ := newDebianBackend(t, r)
	tgt := proxy.Target{Kind: proxy.TargetKindFile, Path: b.layout.AvailablePath("nope.example.com")}
	if err := b.Remove(context.Background(), tgt); err != nil {
		t.Errorf("removing a missing file should be a no-op, got %v", err)
	}
}

func TestReadManaged_adoptsAllFiles_taggingManagedVsOperator(t *testing.T) {
	r := &fakeRunner{}
	b, layout := newDebianBackend(t, r)
	if err := os.MkdirAll(layout.Available, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.Enabled, 0o755); err != nil {
		t.Fatal(err)
	}

	// A managed (generated) file.
	managed := layout.AvailablePath("managed.example.com")
	if err := os.WriteFile(managed, []byte("<VirtualHost *:80></VirtualHost>\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Enable it via symlink.
	if err := os.Symlink(managed, layout.EnabledPath("managed.example.com")); err != nil {
		t.Fatal(err)
	}
	// An operator-authored file (no nurproxy- prefix).
	operator := filepath.Join(layout.Available, "operator.conf")
	if err := os.WriteFile(operator, []byte("<VirtualHost *:80># mine</VirtualHost>\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// An in-flight temp must be skipped.
	if err := os.WriteFile(managed+tempSuffix, []byte("temp"), 0o644); err != nil {
		t.Fatal(err)
	}

	arts, err := b.ReadManaged(context.Background())
	if err != nil {
		t.Fatalf("ReadManaged: %v", err)
	}
	byBase := map[string]proxy.Artifact{}
	for _, a := range arts {
		byBase[filepath.Base(a.Target.Path)] = a
	}
	if _, ok := byBase[filepath.Base(managed)+tempSuffix]; ok {
		t.Errorf("temp file should be skipped")
	}
	m, ok := byBase[ManagedFileName("managed.example.com")]
	if !ok {
		t.Fatalf("managed file not read")
	}
	if m.Adopted {
		t.Errorf("managed file should not be Adopted")
	}
	if !m.Enabled {
		t.Errorf("managed file symlink present, Enabled should be true")
	}
	o, ok := byBase["operator.conf"]
	if !ok {
		t.Fatalf("operator file not read")
	}
	if !o.Adopted {
		t.Errorf("operator file should be Adopted (Source: manual)")
	}
}

func TestReadManaged_confd_presenceMeansEnabled(t *testing.T) {
	r := &fakeRunner{}
	b, layout := newRHELBackend(t, r)
	if err := os.MkdirAll(layout.Available, 0o755); err != nil {
		t.Fatal(err)
	}
	f := layout.AvailablePath("app.example.com")
	if err := os.WriteFile(f, []byte("<VirtualHost *:80></VirtualHost>\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	arts, err := b.ReadManaged(context.Background())
	if err != nil {
		t.Fatalf("ReadManaged: %v", err)
	}
	if len(arts) != 1 || !arts[0].Enabled {
		t.Errorf("conf.d file should report Enabled=true via presence, got %+v", arts)
	}
}

func TestReadManaged_missingDir_returnsNil(t *testing.T) {
	r := &fakeRunner{}
	b, _ := newDebianBackend(t, r)
	arts, err := b.ReadManaged(context.Background())
	if err != nil {
		t.Fatalf("ReadManaged on missing dir: %v", err)
	}
	if arts != nil {
		t.Errorf("expected nil artifacts for missing dir, got %v", arts)
	}
}

func TestRender_dropsUnsupportedRateLimit(t *testing.T) {
	r := &fakeRunner{}
	b, _ := newDebianBackend(t, r)
	route := proxymodel.Route{
		Host:      "app.example.com",
		Upstream:  proxymodel.Upstream{Addr: "10.0.0.4", Port: 8080},
		RateLimit: proxymodel.RateLimit{RequestsPerSecond: 5},
		TLS:       proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
	}
	art, err := b.Render(context.Background(), route)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	// Render never errors on a dropped option; the artifact still has a vhost.
	if art.Content == "" {
		t.Errorf("expected non-empty content even with a dropped option")
	}
	if art.Target.Path != b.layout.AvailablePath("app.example.com") {
		t.Errorf("target path = %q", art.Target.Path)
	}
}

func TestCapabilities_rateLimitFalse_centralTLSDependsOnCertStore(t *testing.T) {
	noCerts := New(proxy.Config{Type: "apache", ConfigDir: "/etc/apache2/sites-available"})
	if noCerts.Capabilities().RateLimit {
		t.Errorf("apache must report RateLimit=false")
	}
	if noCerts.Capabilities().CentralTLS {
		t.Errorf("CentralTLS should be false without a cert dir")
	}
	withCerts := New(proxy.Config{Type: "apache", ConfigDir: "/etc/apache2/sites-available", CertDir: t.TempDir()})
	if !withCerts.Capabilities().CentralTLS {
		t.Errorf("CentralTLS should be true with a cert dir")
	}
}

func TestApply_emptyArtifacts_noop(t *testing.T) {
	r := &fakeRunner{}
	b, _ := newDebianBackend(t, r)
	if err := b.Apply(context.Background(), nil); err != nil {
		t.Errorf("empty apply should be a no-op, got %v", err)
	}
	if r.tests != 0 || r.reloads != 0 {
		t.Errorf("empty apply should not run commands")
	}
}

func TestRegistered_includesApache(t *testing.T) {
	found := false
	for _, n := range proxy.Registered() {
		if n == "apache" {
			found = true
		}
	}
	if !found {
		t.Errorf("apache backend should be registered in init(); registered = %v", proxy.Registered())
	}
}

func TestProbeDirs_debianLayout_includesEnabledDir(t *testing.T) {
	b := New(proxy.Config{Type: "apache", ConfigDir: "/etc/apache2/sites-available"})
	dirs := b.ProbeDirs()
	if len(dirs) != 2 {
		t.Fatalf("Debian layout should probe sites-available + sites-enabled, got %v", dirs)
	}
	if dirs[0] != "/etc/apache2/sites-available" || dirs[1] != "/etc/apache2/sites-enabled" {
		t.Fatalf("unexpected probe dirs: %v", dirs)
	}
}

func TestProbeDirs_confDLayout_onlyAvailableDir(t *testing.T) {
	b := New(proxy.Config{Type: "apache", ConfigDir: "/etc/httpd/conf.d"})
	dirs := b.ProbeDirs()
	if len(dirs) != 1 || dirs[0] != "/etc/httpd/conf.d" {
		t.Fatalf("conf.d layout should probe only the one dir, got %v", dirs)
	}
}

func TestReloadHint_default_andOverride(t *testing.T) {
	b := New(proxy.Config{Type: "apache", ConfigDir: "/etc/apache2/sites-available", Binary: "/usr/sbin/apachectl"})
	if got := b.ReloadHint(); got != "/usr/sbin/apachectl graceful" {
		t.Fatalf("default ReloadHint = %q", got)
	}
	o := New(proxy.Config{Type: "apache", ConfigDir: "/etc/apache2/sites-available", ReloadCmd: "sudo systemctl reload apache2"})
	if got := o.ReloadHint(); got != "sudo systemctl reload apache2" {
		t.Fatalf("override ReloadHint = %q", got)
	}
}

func TestResolvedCommands_default_andOverride(t *testing.T) {
	b := New(proxy.Config{Type: "apache", ConfigDir: "/etc/apache2/sites-available", Binary: "/usr/sbin/apachectl"})
	test, reload := b.ResolvedCommands()
	if test != "/usr/sbin/apachectl configtest" {
		t.Fatalf("default test cmd = %q", test)
	}
	if reload != "/usr/sbin/apachectl graceful" {
		t.Fatalf("default reload cmd = %q", reload)
	}

	o := New(proxy.Config{
		Type:      "apache",
		ConfigDir: "/etc/apache2/sites-available",
		Binary:    "/usr/sbin/apachectl",
		TestCmd:   "sudo /usr/sbin/apachectl configtest",
		ReloadCmd: "sudo systemctl reload apache2",
	})
	test, reload = o.ResolvedCommands()
	if test != "sudo /usr/sbin/apachectl configtest" {
		t.Fatalf("override test cmd = %q", test)
	}
	if reload != "sudo systemctl reload apache2" {
		t.Fatalf("override reload cmd = %q", reload)
	}

	// No detected binary falls back to the bare "apachectl" defaults.
	nb := New(proxy.Config{Type: "apache", ConfigDir: "/etc/apache2/sites-available", Binary: "nope-not-a-real-binary"})
	nb.binary = ""
	nb.runner = &execRunner{}
	test, reload = nb.ResolvedCommands()
	if test != "apachectl configtest" || reload != "apachectl graceful" {
		t.Fatalf("empty-binary fallback = %q / %q", test, reload)
	}
}

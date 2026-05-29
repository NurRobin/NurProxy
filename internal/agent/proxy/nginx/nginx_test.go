package nginx

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
// results so Apply's atomic orchestration is testable without a real nginx.
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

// newBackend builds a backend rooted at a temp config dir with an injected
// runner, so file operations land in the test sandbox.
func newBackend(t *testing.T, r Runner) (*Backend, Layout) {
	t.Helper()
	dir := t.TempDir()
	b := New(proxy.Config{Type: "nginx", ConfigDir: filepath.Join(dir, "sites-available")})
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

func TestApply_success_writesFileSymlinkAndReloads(t *testing.T) {
	r := &fakeRunner{}
	b, layout := newBackend(t, r)
	art := sampleArtifact(b, "app.example.com", "server { listen 80; }\n")

	if err := b.Apply(context.Background(), []proxy.Artifact{art}); err != nil {
		t.Fatalf("Apply error: %v", err)
	}

	// File written with rendered content.
	got, err := os.ReadFile(art.Target.Path)
	if err != nil {
		t.Fatalf("reading applied file: %v", err)
	}
	if string(got) != art.Content {
		t.Errorf("file content = %q, want %q", got, art.Content)
	}
	// Symlink present in sites-enabled.
	link := layout.EnabledPath("app.example.com")
	if !symlinkPresent(link) {
		t.Errorf("expected sites-enabled symlink at %q", link)
	}
	// Temp file cleaned up.
	if _, err := os.Stat(art.Target.Path + tempSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temp file should be removed, stat err = %v", err)
	}
	if r.tests != 1 || r.reloads != 1 {
		t.Errorf("tests=%d reloads=%d, want 1 and 1", r.tests, r.reloads)
	}
}

// newConfDBackend builds a backend rooted at a temp RHEL/Fedora conf.d dir, so
// the apply path exercises the flat (no-symlink) layout.
func newConfDBackend(t *testing.T, r Runner) *Backend {
	t.Helper()
	dir := t.TempDir()
	b := New(proxy.Config{Type: "nginx", ConfigDir: filepath.Join(dir, "conf.d")})
	b.WithRunner(r)
	return b
}

func TestApply_confDLayout_writesFileNoSymlinkAndReloads(t *testing.T) {
	r := &fakeRunner{}
	b := newConfDBackend(t, r)
	if !b.layout.IsConfD() {
		t.Fatalf("expected conf.d layout, got Enabled=%q", b.layout.Enabled)
	}
	art := sampleArtifact(b, "app.example.com", "server { listen 80; }\n")

	if err := b.Apply(context.Background(), []proxy.Artifact{art}); err != nil {
		t.Fatalf("Apply error: %v", err)
	}
	got, err := os.ReadFile(art.Target.Path)
	if err != nil {
		t.Fatalf("reading applied conf.d file: %v", err)
	}
	if string(got) != art.Content {
		t.Errorf("file content = %q, want %q", got, art.Content)
	}
	if filepath.Base(art.Target.Path) != "nurproxy-app.example.com.conf" {
		t.Errorf("conf.d file base = %q, want nurproxy-app.example.com.conf", filepath.Base(art.Target.Path))
	}
	// No sites-enabled directory is created on the flat conf.d layout.
	enabledDir := filepath.Join(filepath.Dir(filepath.Dir(art.Target.Path)), "sites-enabled")
	if _, statErr := os.Stat(enabledDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("conf.d layout must not create a sites-enabled dir, stat err = %v", statErr)
	}
	if _, statErr := os.Stat(art.Target.Path + tempSuffix); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("temp file should be removed, stat err = %v", statErr)
	}
	if r.tests != 1 || r.reloads != 1 {
		t.Errorf("tests=%d reloads=%d, want 1 and 1", r.tests, r.reloads)
	}
}

func TestRemove_confDLayout_deletesFileNoSymlinkStep(t *testing.T) {
	r := &fakeRunner{}
	b := newConfDBackend(t, r)
	art := sampleArtifact(b, "app.example.com", "server { listen 80; }\n")
	if err := b.Apply(context.Background(), []proxy.Artifact{art}); err != nil {
		t.Fatalf("Apply error: %v", err)
	}
	if err := b.Remove(context.Background(), art.Target); err != nil {
		t.Fatalf("Remove error: %v", err)
	}
	if _, statErr := os.Stat(art.Target.Path); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("conf.d file should be removed, stat err = %v", statErr)
	}
	if r.reloads != 2 { // Apply + Remove
		t.Errorf("reloads=%d, want 2", r.reloads)
	}
}

func TestReadManaged_confDLayout_filePresenceIsEnabled(t *testing.T) {
	b := newConfDBackend(t, &fakeRunner{})
	if err := os.MkdirAll(b.layout.Available, 0o755); err != nil {
		t.Fatal(err)
	}
	managed := b.layout.AvailablePath("app.example.com")
	if err := os.WriteFile(managed, []byte("server {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	arts, err := b.ReadManaged(context.Background())
	if err != nil {
		t.Fatalf("ReadManaged error: %v", err)
	}
	if len(arts) != 1 {
		t.Fatalf("ReadManaged returned %d artifacts, want 1", len(arts))
	}
	if !arts[0].Enabled {
		t.Error("on the conf.d layout a present file is enabled by definition")
	}
}

func TestApply_testFails_rollsBackNewFile_andAttributesOurError(t *testing.T) {
	r := &fakeRunner{
		testErr: errors.New("exit 1"),
		testOut: "", // filled below per host path
	}
	b, layout := newBackend(t, r)
	art := sampleArtifact(b, "app.example.com", "server { bad; }\n")
	r.testOut = `nginx: [emerg] unknown directive "bad" in ` + art.Target.Path + ":1"

	err := b.Apply(context.Background(), []proxy.Artifact{art})
	if err == nil {
		t.Fatal("expected error on failing nginx -t")
	}
	var ce *commandError
	if !errors.As(err, &ce) {
		t.Fatalf("error type = %T, want *commandError", err)
	}
	if !ce.Attribution.Ours {
		t.Errorf("Attribution.Ours = false, want true (error in our generated file)")
	}
	// New file removed on rollback (it did not exist before).
	if _, statErr := os.Stat(art.Target.Path); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("new file should be removed on rollback, stat err = %v", statErr)
	}
	// No symlink left behind.
	if symlinkPresent(layout.EnabledPath("app.example.com")) {
		t.Errorf("symlink should not survive rollback")
	}
	// Temp removed.
	if _, statErr := os.Stat(art.Target.Path + tempSuffix); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("temp file should be removed on rollback, stat err = %v", statErr)
	}
	if r.reloads != 0 {
		t.Errorf("reload should not run when nginx -t fails, reloads=%d", r.reloads)
	}
}

func TestApply_testFails_restoresPriorContent(t *testing.T) {
	r := &fakeRunner{testErr: errors.New("exit 1"), testOut: "nginx: [emerg] error in /etc/nginx/sites-enabled/other:5"}
	b, _ := newBackend(t, r)

	// Seed a prior good version of the managed file.
	dest := b.layout.AvailablePath("app.example.com")
	if err := os.MkdirAll(b.layout.Available, 0o755); err != nil {
		t.Fatal(err)
	}
	prior := "server { listen 80; # GOOD\n}\n"
	if err := os.WriteFile(dest, []byte(prior), 0o644); err != nil {
		t.Fatal(err)
	}

	art := sampleArtifact(b, "app.example.com", "server { listen 80; # NEW BROKEN\n}\n")
	err := b.Apply(context.Background(), []proxy.Artifact{art})
	if err == nil {
		t.Fatal("expected error")
	}
	var ce *commandError
	if !errors.As(err, &ce) {
		t.Fatalf("want *commandError, got %T", err)
	}
	if ce.Attribution.Ours {
		t.Errorf("Ours = true, want false (the blamed file is the operator's other vhost)")
	}
	// Prior content restored.
	got, readErr := os.ReadFile(dest)
	if readErr != nil {
		t.Fatalf("reading restored file: %v", readErr)
	}
	if string(got) != prior {
		t.Errorf("restored content = %q, want prior %q", got, prior)
	}
}

func TestApply_reloadFails_rollsBack(t *testing.T) {
	r := &fakeRunner{reloadErr: errors.New("reload boom")}
	b, _ := newBackend(t, r)
	art := sampleArtifact(b, "app.example.com", "server { listen 80; }\n")

	err := b.Apply(context.Background(), []proxy.Artifact{art})
	if err == nil {
		t.Fatal("expected error on reload failure")
	}
	// New file rolled back even though nginx -t passed.
	if _, statErr := os.Stat(art.Target.Path); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("file should be rolled back on reload failure, stat err = %v", statErr)
	}
	if r.tests != 1 || r.reloads != 1 {
		t.Errorf("tests=%d reloads=%d, want 1 and 1", r.tests, r.reloads)
	}
}

func TestApply_emptyArtifacts_noop(t *testing.T) {
	r := &fakeRunner{}
	b, _ := newBackend(t, r)
	if err := b.Apply(context.Background(), nil); err != nil {
		t.Fatalf("Apply(nil) error: %v", err)
	}
	if r.tests != 0 || r.reloads != 0 {
		t.Errorf("empty apply should not invoke runner, tests=%d reloads=%d", r.tests, r.reloads)
	}
}

func TestRender_structuredRoute_producesFileArtifact(t *testing.T) {
	b, _ := newBackend(t, &fakeRunner{})
	route := proxymodel.Route{
		Host:     "app.example.com",
		Upstream: proxymodel.Upstream{Addr: "10.0.0.4", Port: 8080},
	}
	art, err := b.Render(context.Background(), route)
	if err != nil {
		t.Fatalf("Render error: %v", err)
	}
	if art.Target.Kind != proxy.TargetKindFile {
		t.Errorf("Target.Kind = %q, want file", art.Target.Kind)
	}
	if filepath.Base(art.Target.Path) != "nurproxy-app.example.com.conf" {
		t.Errorf("Target.Path base = %q, want nurproxy-app.example.com.conf", filepath.Base(art.Target.Path))
	}
	if art.Content == "" {
		t.Error("Render produced empty content")
	}
}

func TestReadManaged_adoptsAllFiles_taggingManagedVsOperator(t *testing.T) {
	b, _ := newBackend(t, &fakeRunner{})
	if err := os.MkdirAll(b.layout.Available, 0o755); err != nil {
		t.Fatal(err)
	}
	// One NurProxy-managed file, one operator file: adoption reads BOTH (§4, no
	// whitelist), tagging only the operator file Adopted.
	managed := b.layout.AvailablePath("app.example.com")
	if err := os.WriteFile(managed, []byte("server {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	operator := filepath.Join(b.layout.Available, "operator-site.conf")
	if err := os.WriteFile(operator, []byte("server { listen 8080; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A temp file from an in-flight apply must be skipped.
	if err := os.WriteFile(managed+tempSuffix, []byte("half\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	arts, err := b.ReadManaged(context.Background())
	if err != nil {
		t.Fatalf("ReadManaged error: %v", err)
	}
	if len(arts) != 2 {
		t.Fatalf("ReadManaged returned %d artifacts, want 2 (all files, temp skipped)", len(arts))
	}
	byBase := map[string]proxy.Artifact{}
	for _, a := range arts {
		byBase[filepath.Base(a.Target.Path)] = a
	}
	m, ok := byBase["nurproxy-app.example.com.conf"]
	if !ok {
		t.Fatal("managed file missing from adoption read")
	}
	if m.Adopted {
		t.Error("NurProxy-managed file should have Adopted=false")
	}
	o, ok := byBase["operator-site.conf"]
	if !ok {
		t.Fatal("operator file missing from adoption read")
	}
	if !o.Adopted {
		t.Error("operator-authored file should have Adopted=true (Source: manual)")
	}
	if o.Content != "server { listen 8080; }\n" {
		t.Errorf("operator content = %q, want verbatim", o.Content)
	}
}

func TestRemove_deletesFileAndSymlink_thenReloads(t *testing.T) {
	r := &fakeRunner{}
	b, layout := newBackend(t, r)
	art := sampleArtifact(b, "app.example.com", "server { listen 80; }\n")
	if err := b.Apply(context.Background(), []proxy.Artifact{art}); err != nil {
		t.Fatalf("Apply error: %v", err)
	}

	if err := b.Remove(context.Background(), art.Target); err != nil {
		t.Fatalf("Remove error: %v", err)
	}
	if _, err := os.Stat(art.Target.Path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("file should be removed, stat err = %v", err)
	}
	if symlinkPresent(layout.EnabledPath("app.example.com")) {
		t.Errorf("symlink should be removed")
	}
	if r.reloads != 2 { // one for Apply, one for Remove
		t.Errorf("reloads=%d, want 2", r.reloads)
	}
}

func TestEnsureSymlink_refusesToClobberRegularFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.conf")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.conf")
	if err := os.WriteFile(link, []byte("operator file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureSymlink(target, link); err == nil {
		t.Fatal("expected error refusing to clobber a regular file")
	}
}

func TestInfo_reportsNginxKindAndPaths(t *testing.T) {
	b := New(proxy.Config{Type: "nginx", ConfigDir: "/etc/nginx/sites-available", Binary: "/usr/sbin/nginx"}).WithVersion("1.24.0")
	info := b.Info()
	if info.Kind != proxy.KindNginx {
		t.Errorf("Kind = %q, want nginx", info.Kind)
	}
	if info.Version != "1.24.0" {
		t.Errorf("Version = %q, want 1.24.0", info.Version)
	}
	if info.ConfigDir != "/etc/nginx/sites-available" {
		t.Errorf("ConfigDir = %q", info.ConfigDir)
	}
}

func TestFactory_registered(t *testing.T) {
	p, err := proxy.Get("nginx", proxy.Config{Type: "nginx", ConfigDir: "/etc/nginx/sites-available"})
	if err != nil {
		t.Fatalf("proxy.Get(nginx) error: %v", err)
	}
	if p.Info().Kind != proxy.KindNginx {
		t.Errorf("Info().Kind = %q, want nginx", p.Info().Kind)
	}
}

func TestProbeDirs_debianLayout_includesEnabledDir(t *testing.T) {
	b := New(proxy.Config{Type: "nginx", ConfigDir: "/etc/nginx/sites-available"})
	dirs := b.ProbeDirs()
	if len(dirs) != 2 {
		t.Fatalf("Debian layout should probe sites-available + sites-enabled, got %v", dirs)
	}
	if dirs[0] != "/etc/nginx/sites-available" || dirs[1] != "/etc/nginx/sites-enabled" {
		t.Fatalf("unexpected probe dirs: %v", dirs)
	}
}

func TestProbeDirs_confDLayout_onlyAvailableDir(t *testing.T) {
	b := New(proxy.Config{Type: "nginx", ConfigDir: "/etc/nginx/conf.d"})
	dirs := b.ProbeDirs()
	if len(dirs) != 1 || dirs[0] != "/etc/nginx/conf.d" {
		t.Fatalf("conf.d layout should probe only the one dir, got %v", dirs)
	}
}

func TestReloadHint_default_andOverride(t *testing.T) {
	b := New(proxy.Config{Type: "nginx", ConfigDir: "/etc/nginx/sites-available", Binary: "/usr/sbin/nginx"})
	if got := b.ReloadHint(); got != "/usr/sbin/nginx -s reload" {
		t.Fatalf("default ReloadHint = %q", got)
	}
	o := New(proxy.Config{Type: "nginx", ConfigDir: "/etc/nginx/sites-available", ReloadCmd: "sudo systemctl reload nginx"})
	if got := o.ReloadHint(); got != "sudo systemctl reload nginx" {
		t.Fatalf("override ReloadHint = %q", got)
	}
}

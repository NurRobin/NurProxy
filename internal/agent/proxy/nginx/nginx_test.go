package nginx

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// TestExecRunner_command_sudoAndResolve covers the §12 fix: an unprivileged agent
// runs the proxy command via `sudo -n` (so a scoped sudoers entry is actually
// used), a bare override binary is resolved to an absolute path (so it matches an
// absolute sudoers command), and NURPROXY_NO_SUDO disables the wrapper.
func TestExecRunner_command_sudoAndResolve(t *testing.T) {
	r := &execRunner{binary: "/usr/sbin/nginx"}

	t.Run("NURPROXY_NO_SUDO runs directly", func(t *testing.T) {
		t.Setenv("NURPROXY_NO_SUDO", "1")
		cmd := r.command(context.Background(), "", "-t")
		if len(cmd.Args) != 2 || cmd.Args[0] != "/usr/sbin/nginx" || cmd.Args[1] != "-t" {
			t.Fatalf("want direct [/usr/sbin/nginx -t], got %v", cmd.Args)
		}
	})

	t.Run("non-root wraps in sudo -n", func(t *testing.T) {
		if os.Geteuid() <= 0 {
			t.Skip("not a non-root POSIX user; sudo wrapping does not apply")
		}
		t.Setenv("NURPROXY_NO_SUDO", "")
		cmd := r.command(context.Background(), "", "-t")
		want := []string{"sudo", "-n", "/usr/sbin/nginx", "-t"}
		if len(cmd.Args) != len(want) {
			t.Fatalf("args = %v, want %v", cmd.Args, want)
		}
		for i := range want {
			if cmd.Args[i] != want[i] {
				t.Fatalf("args = %v, want %v", cmd.Args, want)
			}
		}
	})

	t.Run("bare override binary resolves to absolute", func(t *testing.T) {
		abs, err := exec.LookPath("sh")
		if err != nil {
			t.Skip("sh not in PATH")
		}
		ro := &execRunner{binary: "/usr/sbin/nginx", testCmd: "sh -c ok"}
		name, args := ro.spec(ro.testCmd, []string{"-t"})
		if name != abs {
			t.Errorf("bare override binary = %q, want absolute %q", name, abs)
		}
		if len(args) != 2 || args[0] != "-c" || args[1] != "ok" {
			t.Errorf("args = %v, want [-c ok]", args)
		}
	})
}

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

// TestRender_basicAuth_writesHtpasswdAndReferencesIt proves basic auth is now
// functional on nginx: Render materializes the htpasswd file from the intent's
// bcrypt entry and the rendered vhost references it via auth_basic_user_file
// (instead of dropping basic auth with a warning).
func TestRender_basicAuth_writesHtpasswdAndReferencesIt(t *testing.T) {
	b, _ := newBackend(t, &fakeRunner{})
	route := proxymodel.Route{
		Host:     "secure.example.com",
		Upstream: proxymodel.Upstream{Addr: "127.0.0.1", Port: 8080},
		BasicAuth: &proxymodel.BasicAuth{
			Username:     "admin",
			PasswordHash: "$2y$12$abcdefghijklmnopqrstuvwxyzABCDEF0123456789abcdeF",
		},
	}
	art, err := b.Render(context.Background(), route)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(art.Content, "auth_basic ") || !strings.Contains(art.Content, "auth_basic_user_file") {
		t.Errorf("rendered vhost missing basic-auth directives:\n%s", art.Content)
	}
	for _, w := range art.Warnings {
		if strings.Contains(w, "basic_auth") {
			t.Errorf("basic_auth should NOT be dropped now: %q", w)
		}
	}
	authPath := b.authFilePath("secure.example.com")
	data, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatalf("htpasswd not written: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != "admin:$2y$12$abcdefghijklmnopqrstuvwxyzABCDEF0123456789abcdeF" {
		t.Errorf("htpasswd content = %q", got)
	}
	if !strings.Contains(art.Content, authPath) {
		t.Errorf("vhost does not reference the htpasswd path %q:\n%s", authPath, art.Content)
	}
}

// TestPrune_removesOrphanedGeneratedKeepsOperatorAndDesired proves Prune deletes
// only NurProxy-generated vhosts absent from the keep set (a deleted domain's
// leftover, §3 no ghost vhost), never an operator's adopted config, and reloads
// once when something was removed.
func TestPrune_removesOrphanedGeneratedKeepsOperatorAndDesired(t *testing.T) {
	r := &fakeRunner{}
	b, layout := newBackend(t, r)
	ctx := context.Background()

	keep := sampleArtifact(b, "keep.example.com", "server { listen 80; }\n")   // generated, stays
	orphan := sampleArtifact(b, "gone.example.com", "server { listen 80; }\n") // generated, deleted
	if err := b.Apply(ctx, []proxy.Artifact{keep, orphan}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// An operator-authored config (no nurproxy- prefix) must never be touched.
	operatorPath := filepath.Join(layout.Available, "operator-site.conf")
	if err := os.WriteFile(operatorPath, []byte("server { listen 80; }\n"), 0o644); err != nil {
		t.Fatalf("seeding operator file: %v", err)
	}

	r.reloads = 0
	n, err := b.Prune(ctx, []proxy.Target{keep.Target})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned = %d, want 1", n)
	}
	if _, err := os.Stat(orphan.Target.Path); !os.IsNotExist(err) {
		t.Errorf("orphaned generated vhost still present: %v", err)
	}
	if _, err := os.Stat(layout.EnabledPath("gone.example.com")); !os.IsNotExist(err) {
		t.Errorf("orphaned symlink still present")
	}
	if _, err := os.Stat(keep.Target.Path); err != nil {
		t.Errorf("kept generated vhost was removed: %v", err)
	}
	if _, err := os.Stat(operatorPath); err != nil {
		t.Errorf("operator config was removed — must never be pruned: %v", err)
	}
	if r.reloads != 1 {
		t.Errorf("reload calls = %d, want 1 (one reload after pruning)", r.reloads)
	}

	// A second prune with the same keep set removes nothing and does not reload.
	r.reloads = 0
	if n, err := b.Prune(ctx, []proxy.Target{keep.Target}); err != nil || n != 0 {
		t.Errorf("idempotent prune: n=%d err=%v, want 0,nil", n, err)
	}
	if r.reloads != 0 {
		t.Errorf("no-op prune reloaded %d times, want 0", r.reloads)
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

// TestApply_symlinkFails_restoresPriorContent reproduces the operator setup where
// the sites-enabled entry is a copied regular file (not a symlink): ensureSymlink
// refuses to clobber it and Apply fails. The prior content of the live
// sites-available file must be restored — the failed apply must not leave the new
// (rejected) config on disk.
func TestApply_symlinkFails_restoresPriorContent(t *testing.T) {
	r := &fakeRunner{}
	b, layout := newBackend(t, r)

	if err := os.MkdirAll(layout.Available, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.Enabled, 0o755); err != nil {
		t.Fatal(err)
	}

	// Seed a prior good version of the managed file.
	dest := layout.AvailablePath("app.example.com")
	prior := "server { listen 80; # GOOD\n}\n"
	if err := os.WriteFile(dest, []byte(prior), 0o644); err != nil {
		t.Fatal(err)
	}
	// Operator activated by COPYING a regular file into sites-enabled (not a
	// symlink); ensureSymlink refuses to replace it, so Apply fails mid-iteration.
	if err := os.WriteFile(layout.EnabledPath("app.example.com"), []byte("copied\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	art := sampleArtifact(b, "app.example.com", "server { listen 80; # NEW\n}\n")
	if err := b.Apply(context.Background(), []proxy.Artifact{art}); err == nil {
		t.Fatal("expected error when sites-enabled holds a regular file")
	}
	// The live file must be restored to its prior content, not left as the new one.
	got, readErr := os.ReadFile(dest)
	if readErr != nil {
		t.Fatalf("reading restored file: %v", readErr)
	}
	if string(got) != prior {
		t.Errorf("restored content = %q, want prior %q", got, prior)
	}
	// nginx -t must never have run (we failed before staging completed).
	if r.tests != 0 {
		t.Errorf("nginx -t ran %d times, want 0 (failed before validation)", r.tests)
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

func TestReadManaged_enabledBySymlinkOrCopiedFile(t *testing.T) {
	b, layout := newBackend(t, &fakeRunner{})
	if err := os.MkdirAll(b.layout.Available, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(b.layout.Enabled, 0o755); err != nil {
		t.Fatal(err)
	}

	// Three vhosts in sites-available: one activated by symlink (NurProxy's
	// canonical way), one activated by a COPIED regular file (some operators do
	// this), and one not activated at all.
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(b.layout.Available, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("sym.example.com.conf", "server { server_name sym; }\n")
	write("copy.example.com.conf", "server { server_name copy; }\n")
	write("off.example.com.conf", "server { server_name off; }\n")

	// Symlink activation.
	if err := os.Symlink(filepath.Join(b.layout.Available, "sym.example.com.conf"), filepath.Join(layout.Enabled, "sym.example.com.conf")); err != nil {
		t.Fatal(err)
	}
	// Copied-file activation (a real file in sites-enabled, not a symlink).
	if err := os.WriteFile(filepath.Join(layout.Enabled, "copy.example.com.conf"), []byte("server { server_name copy; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	arts, err := b.ReadManaged(context.Background())
	if err != nil {
		t.Fatalf("ReadManaged error: %v", err)
	}
	enabled := map[string]bool{}
	for _, a := range arts {
		enabled[filepath.Base(a.Target.Path)] = a.Enabled
	}
	if !enabled["sym.example.com.conf"] {
		t.Error("symlink-activated vhost should be Enabled=true")
	}
	if !enabled["copy.example.com.conf"] {
		t.Error("copied-file-activated vhost should be Enabled=true (operators activate by copy too)")
	}
	if enabled["off.example.com.conf"] {
		t.Error("non-activated vhost should be Enabled=false")
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

func TestResolvedCommands_default_andOverride(t *testing.T) {
	b := New(proxy.Config{Type: "nginx", ConfigDir: "/etc/nginx/sites-available", Binary: "/usr/sbin/nginx"})
	test, reload := b.ResolvedCommands()
	if test != "/usr/sbin/nginx -t" {
		t.Fatalf("default test cmd = %q", test)
	}
	if reload != "/usr/sbin/nginx -s reload" {
		t.Fatalf("default reload cmd = %q", reload)
	}

	o := New(proxy.Config{
		Type:      "nginx",
		ConfigDir: "/etc/nginx/sites-available",
		Binary:    "/usr/sbin/nginx",
		TestCmd:   "sudo /usr/sbin/nginx -t",
		ReloadCmd: "sudo systemctl reload nginx",
	})
	test, reload = o.ResolvedCommands()
	if test != "sudo /usr/sbin/nginx -t" {
		t.Fatalf("override test cmd = %q", test)
	}
	if reload != "sudo systemctl reload nginx" {
		t.Fatalf("override reload cmd = %q", reload)
	}

	// No detected binary falls back to the bare "nginx" defaults rather than
	// emitting " -t" with an empty binary.
	nb := New(proxy.Config{Type: "nginx", ConfigDir: "/etc/nginx/sites-available", Binary: "nope-not-a-real-binary"})
	nb.binary = ""
	nb.runner = &execRunner{}
	test, reload = nb.ResolvedCommands()
	if test != "nginx -t" || reload != "nginx -s reload" {
		t.Fatalf("empty-binary fallback = %q / %q", test, reload)
	}
}

// newBackendWithCerts builds a backend whose cert store points at a temp dir, so
// Remove/Prune cert-scrubbing can be exercised. Returns the backend, its layout
// and the cert directory.
func newBackendWithCerts(t *testing.T, r Runner) (*Backend, Layout, string) {
	t.Helper()
	dir := t.TempDir()
	certDir := filepath.Join(dir, "certs")
	b := New(proxy.Config{Type: "nginx", ConfigDir: filepath.Join(dir, "sites-available"), CertDir: certDir})
	b.WithRunner(r)
	if b.certs == nil {
		t.Fatal("expected cert store to be configured")
	}
	return b, b.layout, certDir
}

// installCertArtifacts writes the cert plus a stray .key.plain for a host into
// certDir, mirroring what Install + CertPaths leave on disk so the test can
// assert Remove/Prune scrub them.
func installCertArtifacts(t *testing.T, b *Backend, host string) []string {
	t.Helper()
	certPEM := []byte("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n")
	keyPEM := []byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n")
	if err := b.InstallCerts(context.Background(), []proxy.CertBundle{{Host: host, CertPEM: certPEM, KeyPEM: keyPEM}}); err != nil {
		t.Fatalf("InstallCerts: %v", err)
	}
	base := filepath.Join(b.certs.Dir(), host)
	// Materialize a decrypted plaintext key as CertPaths would on the encrypted
	// path — the file whose lingering presence the fix targets.
	plain := base + ".key.plain"
	if err := os.WriteFile(plain, keyPEM, 0o600); err != nil {
		t.Fatalf("seed .key.plain: %v", err)
	}
	return []string{base + ".crt", base + ".key", plain}
}

func assertGone(t *testing.T, paths []string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("cert artifact %q still present (stat err=%v)", p, err)
		}
	}
}

// TestRemove_scrubsCertArtifacts proves a removed managed vhost's centrally
// issued cert/key files (including the decrypted .key.plain) are deleted, while
// an operator-authored config never triggers a cert scrub.
func TestRemove_scrubsCertArtifacts(t *testing.T) {
	t.Run("managed vhost scrubs certs", func(t *testing.T) {
		b, layout, _ := newBackendWithCerts(t, &fakeRunner{})
		host := "app.example.com"
		artifacts := installCertArtifacts(t, b, host)
		// A managed config file at the layout's path; Remove targets it.
		confPath := layout.AvailablePath(host)
		if err := os.MkdirAll(layout.Available, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(confPath, []byte("server {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := b.Remove(context.Background(), proxy.Target{Kind: proxy.TargetKindFile, Path: confPath}); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		assertGone(t, artifacts)
	})

	t.Run("operator config leaves certs untouched", func(t *testing.T) {
		b, layout, certDir := newBackendWithCerts(t, &fakeRunner{})
		// An unrelated host's cert artifacts in the store.
		host := "app.example.com"
		artifacts := installCertArtifacts(t, b, host)
		// Remove an operator-authored config (no nurproxy- prefix): no cert scrub.
		opPath := filepath.Join(layout.Available, "operator-site.conf")
		if err := os.MkdirAll(layout.Available, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(opPath, []byte("server {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := b.Remove(context.Background(), proxy.Target{Kind: proxy.TargetKindFile, Path: opPath}); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		for _, p := range artifacts {
			if _, err := os.Stat(p); err != nil {
				t.Errorf("unrelated cert artifact %q was wrongly removed: %v", p, err)
			}
		}
		_ = certDir
	})
}

// TestPrune_scrubsCertArtifacts proves a pruned orphan vhost's cert/key files
// are deleted while a kept vhost's stay.
func TestPrune_scrubsCertArtifacts(t *testing.T) {
	b, layout, _ := newBackendWithCerts(t, &fakeRunner{})
	if err := os.MkdirAll(layout.Available, 0o755); err != nil {
		t.Fatal(err)
	}

	orphanHost := "orphan.example.com"
	keepHost := "keep.example.com"
	orphanArts := installCertArtifacts(t, b, orphanHost)
	keepArts := installCertArtifacts(t, b, keepHost)

	orphanConf := layout.AvailablePath(orphanHost)
	keepConf := layout.AvailablePath(keepHost)
	for _, p := range []string{orphanConf, keepConf} {
		if err := os.WriteFile(p, []byte("server {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	n, err := b.Prune(context.Background(), []proxy.Target{{Kind: proxy.TargetKindFile, Path: keepConf}})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("Prune removed %d, want 1", n)
	}
	assertGone(t, orphanArts)
	for _, p := range keepArts {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("kept host cert artifact %q was wrongly removed: %v", p, err)
		}
	}
}

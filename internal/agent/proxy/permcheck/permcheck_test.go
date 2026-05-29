package permcheck

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRunner is a hand-written TestRunner (no mock framework, per conventions):
// it returns a canned output + error for the reload-privilege probe.
type fakeRunner struct {
	out string
	err error
}

func (f fakeRunner) Test(context.Context) (string, error) { return f.out, f.err }

func TestProbe_writableDirAndNoRunner_ok(t *testing.T) {
	dir := t.TempDir()
	res := Probe(context.Background(), Options{Backend: "nginx", Dirs: []string{dir}})
	if !res.OK() {
		t.Fatalf("expected OK, got %+v", res)
	}
	if res.HealthError() != "" {
		t.Fatalf("expected no health error, got %q", res.HealthError())
	}
	// The probe must leave nothing behind.
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("probe left files behind: %v", entries)
	}
}

func TestProbe_missingDir_reportsActionableWriteError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	res := Probe(context.Background(), Options{Backend: "nginx", Dirs: []string{missing}})
	if res.CanWrite {
		t.Fatalf("expected CanWrite=false for a missing dir")
	}
	if !strings.Contains(res.WriteError, "does not exist") {
		t.Fatalf("write error not actionable: %q", res.WriteError)
	}
	if !strings.Contains(res.HealthError(), "group that owns") {
		t.Fatalf("health error should point at the group/ownership fix: %q", res.HealthError())
	}
}

func TestProbe_pathIsFileNotDir_reportsWriteError(t *testing.T) {
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := Probe(context.Background(), Options{Backend: "nginx", Dirs: []string{f}})
	if res.CanWrite {
		t.Fatalf("expected CanWrite=false when path is a file")
	}
	if !strings.Contains(res.WriteError, "not a directory") {
		t.Fatalf("unexpected write error: %q", res.WriteError)
	}
}

func TestProbe_readOnlyDir_reportsWriteError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode bits do not restrict root, skipping read-only probe")
	}
	dir := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(dir, 0o500); err != nil { // r-x, no write
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	res := Probe(context.Background(), Options{Backend: "nginx", Dirs: []string{dir}})
	if res.CanWrite {
		t.Fatalf("expected CanWrite=false for a read-only dir, got %+v", res)
	}
	if !strings.Contains(res.WriteError, "cannot write") {
		t.Fatalf("unexpected write error: %q", res.WriteError)
	}
}

func TestProbe_emptyDirs_skipsWriteProbe(t *testing.T) {
	res := Probe(context.Background(), Options{Backend: "caddy"})
	if !res.CanWrite {
		t.Fatalf("empty Dirs should skip the write probe (CanWrite=true)")
	}
	if !res.OK() {
		t.Fatalf("expected OK with no dirs and no runner, got %+v", res)
	}
}

func TestProbe_reload_table(t *testing.T) {
	tests := []struct {
		name          string
		runner        fakeRunner
		wantCanReload bool
		wantMsgSubstr string
	}{
		{
			name:          "reload command succeeds",
			runner:        fakeRunner{out: "syntax is ok\ntest is successful\n", err: nil},
			wantCanReload: true,
		},
		{
			name:          "config invalid but command ran is not a permission failure",
			runner:        fakeRunner{out: "nginx: [emerg] unknown directive \"foo\"\n", err: errors.New("exit status 1")},
			wantCanReload: true,
		},
		{
			name:          "permission denied in output fails the probe",
			runner:        fakeRunner{out: "sudo: a password is required\n", err: errors.New("exit status 1")},
			wantCanReload: false,
			wantMsgSubstr: "narrowly-scoped sudoers",
		},
		{
			name:          "not in sudoers fails the probe",
			runner:        fakeRunner{out: "user is not allowed to execute '/usr/sbin/nginx -t' as root", err: errors.New("exit status 1")},
			wantCanReload: false,
			wantMsgSubstr: "narrowly-scoped sudoers",
		},
		{
			name:          "os.ErrPermission error fails the probe",
			runner:        fakeRunner{out: "", err: os.ErrPermission},
			wantCanReload: false,
			wantMsgSubstr: "narrowly-scoped sudoers",
		},
		{
			name:          "command not found fails the probe",
			runner:        fakeRunner{out: "", err: exec.ErrNotFound},
			wantCanReload: false,
			wantMsgSubstr: "narrowly-scoped sudoers",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Probe(context.Background(), Options{
				Backend:    "nginx",
				Runner:     tt.runner,
				ReloadHint: "/usr/sbin/nginx -s reload",
			})
			if res.CanReload != tt.wantCanReload {
				t.Fatalf("CanReload = %v, want %v (msg=%q)", res.CanReload, tt.wantCanReload, res.ReloadError)
			}
			if tt.wantMsgSubstr != "" && !strings.Contains(res.ReloadError, tt.wantMsgSubstr) {
				t.Fatalf("reload error %q missing %q", res.ReloadError, tt.wantMsgSubstr)
			}
			if !tt.wantCanReload && !strings.Contains(res.ReloadError, "/usr/sbin/nginx -s reload") {
				t.Fatalf("reload error should include the exact command hint: %q", res.ReloadError)
			}
		})
	}
}

func TestProbe_nilRunner_skipsReloadProbe(t *testing.T) {
	res := Probe(context.Background(), Options{Backend: "caddy", Dirs: []string{t.TempDir()}})
	if !res.CanReload {
		t.Fatalf("nil Runner should skip the reload probe (CanReload=true)")
	}
}

func TestProbe_bothFail_healthErrorCombinesBoth(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	res := Probe(context.Background(), Options{
		Backend:    "nginx",
		Dirs:       []string{missing},
		Runner:     fakeRunner{out: "permission denied", err: errors.New("exit status 1")},
		ReloadHint: "/usr/sbin/nginx -s reload",
	})
	if res.OK() {
		t.Fatalf("expected not OK when both probes fail")
	}
	he := res.HealthError()
	if !strings.Contains(he, "not writable") || !strings.Contains(he, "cannot be reloaded") {
		t.Fatalf("combined health error missing a part: %q", he)
	}
}

// TestProbe_neverPanics_onDegenerateInput guards invariant: a permission failure
// must never crash the agent. We feed the worst inputs (nil-ish, empty, runner
// that errors) and assert Probe returns rather than panicking.
func TestProbe_neverPanics_onDegenerateInput(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Probe panicked: %v", r)
		}
	}()
	cases := []Options{
		{},
		{Dirs: []string{"", "", ""}},
		{Backend: "", Dirs: []string{"/proc/nonexistent/deep/path"}},
		{Runner: fakeRunner{err: errors.New("boom")}},
		{Dirs: []string{t.TempDir(), t.TempDir()}, Runner: fakeRunner{}},
	}
	for _, c := range cases {
		_ = Probe(context.Background(), c)
	}
}

func TestResult_HealthError_okWhenBothPresent(t *testing.T) {
	r := Result{CanWrite: true, CanReload: true}
	if r.HealthError() != "" {
		t.Fatalf("expected empty health error when OK, got %q", r.HealthError())
	}
	if !r.OK() {
		t.Fatalf("expected OK")
	}
}

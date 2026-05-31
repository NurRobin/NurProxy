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

// TestWriteMessage_runtimeAware asserts the write-failure message points at the
// fix that actually applies for the runtime context, not always group ownership.
func TestWriteMessage_runtimeAware(t *testing.T) {
	roErr := errors.New(`cannot write to config directory "/etc/nginx": open /etc/nginx/.x: read-only file system`)
	eaccesErr := errors.New(`cannot write to config directory "/etc/nginx": permission denied`)

	tests := []struct {
		name    string
		opts    Options
		err     error
		want    string // substring that must appear
		notWant string // substring that must NOT appear
	}{
		{
			name:    "read-only fs under systemd → sandbox/ReadWritePaths, not group",
			opts:    Options{Backend: "nginx", InitSystem: InitSystemdName, UnitName: "nurproxy-agent.service", RunAsRoot: true},
			err:     roErr,
			want:    "ReadWritePaths",
			notWant: "group that owns",
		},
		{
			name: "read-only fs under systemd names the unit for systemctl edit",
			opts: Options{Backend: "nginx", InitSystem: InitSystemdName, UnitName: "nurproxy-agent.service"},
			err:  roErr,
			want: "systemctl edit nurproxy-agent.service",
		},
		{
			name:    "root without systemd is not a group problem",
			opts:    Options{Backend: "nginx", RunAsRoot: true},
			err:     eaccesErr,
			want:    "runs as root",
			notWant: "group that owns",
		},
		{
			name: "unprivileged keeps the group/ownership fix",
			opts: Options{Backend: "nginx"},
			err:  eaccesErr,
			want: "group that owns",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := writeMessage(tt.opts, tt.err)
			if !strings.Contains(msg, tt.want) {
				t.Errorf("message %q missing %q", msg, tt.want)
			}
			if tt.notWant != "" && strings.Contains(msg, tt.notWant) {
				t.Errorf("message %q should not contain %q", msg, tt.notWant)
			}
		})
	}
}

// TestReloadMessage_runtimeAware asserts a root agent is never told to fix reload
// with sudo (it doesn't use sudo): under systemd it's the sandbox AND the dropped
// capability, both named, and the proxy's real output is appended.
func TestReloadMessage_runtimeAware(t *testing.T) {
	err := errors.New("exit status 1")
	nginxOut := `cannot load certificate key "/etc/nginx/ssl/x/private.key": ... Permission denied`

	rootSystemd := reloadMessage(Options{Backend: "nginx", RunAsRoot: true, InitSystem: InitSystemdName, UnitName: "nurproxy-agent.service"}, err, nginxOut)
	if strings.Contains(rootSystemd, "sudoers") {
		t.Errorf("root agent should not be pointed at sudoers: %q", rootSystemd)
	}
	for _, want := range []string{"ReadWritePaths", "CAP_DAC_OVERRIDE", "not a sudo problem", "Proxy output:", "private.key"} {
		if !strings.Contains(rootSystemd, want) {
			t.Errorf("root+systemd reload message missing %q: %q", want, rootSystemd)
		}
	}

	// Root without systemd: still not sudo, point at file permissions, no caps drop-in.
	rootBare := reloadMessage(Options{Backend: "nginx", RunAsRoot: true}, err, "")
	if strings.Contains(rootBare, "sudoers") || !strings.Contains(rootBare, "ownership") {
		t.Errorf("root non-systemd reload message should point at file ownership, not sudo: %q", rootBare)
	}

	unpriv := reloadMessage(Options{Backend: "nginx", ReloadHint: "/usr/sbin/nginx -s reload"}, err, "")
	if !strings.Contains(unpriv, "narrowly-scoped sudoers") || !strings.Contains(unpriv, "/usr/sbin/nginx -s reload") {
		t.Errorf("unprivileged reload message should keep the scoped-sudoers fix + hint: %q", unpriv)
	}
}

// TestProxyOutputSuffix_caps asserts the appended proxy output is trimmed and
// capped so a huge config dump never floods the dashboard.
func TestProxyOutputSuffix_caps(t *testing.T) {
	if proxyOutputSuffix("   ") != "" {
		t.Error("blank output should add nothing")
	}
	big := strings.Repeat("x", 2000)
	s := proxyOutputSuffix(big)
	if len(s) > 700 || !strings.Contains(s, "…") {
		t.Errorf("long output should be capped and elided, got len=%d", len(s))
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

package selfupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

type fakeService struct {
	restarts  int
	failFirst bool
	onRestart func(n int)
}

func (f *fakeService) Name() string { return "fake" }
func (f *fakeService) Restart(context.Context) error {
	f.restarts++
	if f.failFirst && f.restarts == 1 {
		return errors.New("unit failed to start")
	}
	if f.onRestart != nil {
		f.onRestart(f.restarts)
	}
	return nil
}

type applierFixture struct {
	applier  *Applier
	binary   string
	dir      Dir
	service  *fakeService
	refreshs []string
	release  Release
}

const (
	oldBinary = "old-agent-1.2.0"
	newBinary = "new-agent-1.3.0"
)

func newApplierFixture(t *testing.T) *applierFixture {
	t.Helper()
	pki := newTestPKI(t)
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(binDir, BinaryName)
	if err := os.WriteFile(binary, []byte(oldBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	f := &applierFixture{binary: binary, dir: StateDir(filepath.Join(root, "data")), service: &fakeService{}}
	f.release = pki.release(t, "1.3.0", "linux", "amd64", []byte(newBinary))
	if err := f.dir.Stage(f.release); err != nil {
		t.Fatal(err)
	}
	if err := f.dir.WriteRequest(Request{UpgradeID: "up-1", Version: "1.3.0", FromVersion: "1.2.0", RequestedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	f.applier = &Applier{
		Dir: f.dir, BinaryPath: binary, CurrentVersion: "1.2.0", Trust: pki.trust,
		GOOS: "linux", GOARCH: "amd64", Service: f.service,
		HealthTimeout: 300 * time.Millisecond, PollInterval: 10 * time.Millisecond,
		RefreshBuildID: func(v string) error { f.refreshs = append(f.refreshs, v); return nil },
		ProbeVersion: func(_ context.Context, path string) (string, error) {
			data, err := os.ReadFile(path)
			if err != nil {
				return "", err
			}
			switch string(data) {
			case newBinary:
				return "1.3.0", nil
			case oldBinary:
				return "1.2.0", nil
			}
			return "", errors.New("exec format error")
		},
		Logf: t.Logf,
	}
	return f
}

// newAgentComesUp makes the fake service play the restarted agent writing its
// health proof.
func (f *applierFixture) newAgentComesUp(t *testing.T) {
	f.service.onRestart = func(int) {
		data, _ := os.ReadFile(f.binary)
		if string(data) != newBinary {
			return
		}
		p, err := f.dir.ReadPending()
		if err != nil || p == nil {
			t.Errorf("no pending upgrade visible to the restarted agent: %v", err)
			return
		}
		if err := f.dir.WriteHealthy(Healthy{UpgradeID: p.UpgradeID, Version: "1.3.0", At: time.Now()}); err != nil {
			t.Error(err)
		}
	}
}

func (f *applierFixture) binaryIs(t *testing.T, want string) {
	t.Helper()
	data, err := os.ReadFile(f.binary)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != want {
		t.Fatalf("binary is %q, want %q", data, want)
	}
}

func (f *applierFixture) run(t *testing.T) *Result {
	t.Helper()
	res, err := f.applier.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res == nil {
		t.Fatal("no result")
	}
	onDisk, err := f.dir.ReadResult()
	if err != nil || onDisk == nil || onDisk.State != res.State {
		t.Fatalf("result on disk %+v (%v) does not match %+v", onDisk, err, res)
	}
	if req, _ := f.dir.ReadRequest(); req != nil {
		t.Fatal("request was not claimed")
	}
	return res
}

func TestApplierSuccess(t *testing.T) {
	f := newApplierFixture(t)
	f.newAgentComesUp(t)
	res := f.run(t)
	if res.State != models.UpgradeDone || res.Version != "1.3.0" {
		t.Fatalf("result %+v", res)
	}
	f.binaryIs(t, newBinary)
	prev, err := os.ReadFile(PreviousPath(f.binary))
	if err != nil || string(prev) != oldBinary {
		t.Fatalf("previous binary %q, %v", prev, err)
	}
	info, _ := os.Stat(f.binary)
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", info.Mode())
	}
	if f.service.restarts != 1 || strings.Join(f.refreshs, ",") != "1.3.0" {
		t.Fatalf("restarts=%d refresh=%v", f.service.restarts, f.refreshs)
	}
	if p, _ := f.dir.ReadPending(); p != nil {
		t.Fatal("pending left behind")
	}
	if _, err := os.Stat(filepath.Join(string(f.dir), stagedDirName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("staged files left behind")
	}
}

func TestApplierRollsBackWhenNewAgentStaysSilent(t *testing.T) {
	f := newApplierFixture(t)
	res := f.run(t)
	if res.State != models.UpgradeRolledBack || !strings.Contains(res.Error, "did not report healthy") {
		t.Fatalf("result %+v", res)
	}
	f.binaryIs(t, oldBinary)
	if f.service.restarts != 2 {
		t.Fatalf("restarts=%d, want restart into the new and back into the old binary", f.service.restarts)
	}
	if strings.Join(f.refreshs, ",") != "1.3.0,1.2.0" {
		t.Fatalf("helper build pins %v", f.refreshs)
	}
}

func TestApplierRollsBackWhenRestartFails(t *testing.T) {
	f := newApplierFixture(t)
	f.service.failFirst = true
	res := f.run(t)
	if res.State != models.UpgradeRolledBack || !strings.Contains(res.Error, "unit failed to start") {
		t.Fatalf("result %+v", res)
	}
	f.binaryIs(t, oldBinary)
}

func TestApplierIgnoresHealthOfAnotherUpgrade(t *testing.T) {
	f := newApplierFixture(t)
	f.service.onRestart = func(n int) {
		if n == 1 {
			_ = f.dir.WriteHealthy(Healthy{UpgradeID: "up-0", Version: "1.3.0"})
		}
	}
	if res := f.run(t); res.State != models.UpgradeRolledBack {
		t.Fatalf("result %+v", res)
	}
}

func TestApplierRefusesBeforeTouchingTheBinary(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, f *applierFixture)
		wantErr string
	}{
		{"tampered staged archive", func(t *testing.T, f *applierFixture) {
			rel := f.release
			rel.Archive = append(append([]byte{}, rel.Archive...), 1)
			if err := f.dir.Stage(rel); err != nil {
				t.Fatal(err)
			}
		}, "checksum mismatch"},
		{"downgrade", func(t *testing.T, f *applierFixture) {
			f.applier.CurrentVersion = "1.4.0"
		}, "only moves to newer releases"},
		{"same version", func(t *testing.T, f *applierFixture) {
			f.applier.CurrentVersion = "1.3.0"
		}, "only moves to newer releases"},
		{"development build", func(t *testing.T, f *applierFixture) {
			f.applier.CurrentVersion = "dev"
		}, "only release builds"},
		{"wrong platform", func(t *testing.T, f *applierFixture) {
			f.applier.GOARCH = "arm64"
		}, "no entry"},
		{"binary does not run", func(t *testing.T, f *applierFixture) {
			f.applier.ProbeVersion = func(context.Context, string) (string, error) { return "", errors.New("exec format error") }
		}, "does not run on this host"},
		{"binary reports another version", func(t *testing.T, f *applierFixture) {
			f.applier.ProbeVersion = func(context.Context, string) (string, error) { return "1.2.9", nil }
		}, "reports version"},
		{"staged file is a symlink", func(t *testing.T, f *applierFixture) {
			target := filepath.Join(t.TempDir(), "elsewhere")
			if err := os.WriteFile(target, f.release.Checksums, 0o600); err != nil {
				t.Fatal(err)
			}
			link := f.dir.staged(ChecksumsFile)
			_ = os.Remove(link)
			if err := os.Symlink(target, link); err != nil {
				t.Skip("symlinks unsupported")
			}
		}, "reading staged"},
		{"invalid version in request", func(t *testing.T, f *applierFixture) {
			_ = f.dir.WriteRequest(Request{UpgradeID: "up-1", Version: "../../etc"})
		}, "invalid version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newApplierFixture(t)
			tc.prepare(t, f)
			res := f.run(t)
			if res.State != models.UpgradeFailed || !strings.Contains(res.Error, tc.wantErr) {
				t.Fatalf("want failed with %q, got %+v", tc.wantErr, res)
			}
			f.binaryIs(t, oldBinary)
			if f.service.restarts != 0 || len(f.refreshs) != 0 {
				t.Fatalf("restarts=%d refresh=%v after a refusal", f.service.restarts, f.refreshs)
			}
			if _, err := os.Stat(PreviousPath(f.binary)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal(".prev written for a refused upgrade")
			}
		})
	}
}

func TestApplierWithoutRequestDoesNothing(t *testing.T) {
	f := newApplierFixture(t)
	_ = f.dir.RemoveRequest()
	res, err := f.applier.Run(context.Background())
	if err != nil || res != nil {
		t.Fatalf("got %+v, %v", res, err)
	}
	f.binaryIs(t, oldBinary)
}

func TestDecideHealth(t *testing.T) {
	good := &Healthy{UpgradeID: "u", Version: "1.3.0"}
	cases := []struct {
		name    string
		h       *Healthy
		expired bool
		want    healthDecision
	}{
		{"healthy", good, false, healthCommit},
		{"healthy after deadline", good, true, healthCommit},
		{"nothing yet", nil, false, healthWait},
		{"nothing by deadline", nil, true, healthRollback},
		{"old version reported", &Healthy{UpgradeID: "u", Version: "1.2.0"}, false, healthWait},
		{"old version by deadline", &Healthy{UpgradeID: "u", Version: "1.2.0"}, true, healthRollback},
		{"other upgrade", &Healthy{UpgradeID: "x", Version: "1.3.0"}, true, healthRollback},
	}
	for _, tc := range cases {
		if got := decideHealth(tc.h, "u", "1.3.0", tc.expired); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestServiceCommands(t *testing.T) {
	var calls []string
	run := func(_ context.Context, name string, args ...string) error {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil
	}
	for _, m := range []string{"systemd", "launchd", "openrc"} {
		s, err := NewService(m, "", run)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Restart(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		"systemctl restart nurproxy-agent.service",
		"systemctl try-restart nurproxy-agent-helper.service",
		"launchctl kickstart -k system/de.nurrobin.nurproxy-agent",
		"rc-service nurproxy-agent restart",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(calls, "\n"))
	}
	if _, err := NewService("runit", "", run); err == nil {
		t.Fatal("unknown service manager accepted")
	}
}

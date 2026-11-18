package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// DefaultHealthTimeout bounds how long the applier waits for the restarted
// agent to prove it reached the orchestrator before rolling back. Startup runs
// registration and public-IP detection before the first heartbeat, so this is
// generous.
const DefaultHealthTimeout = 3 * time.Minute

// Applier is the privileged half of a self-update. It runs as root (started by
// the systemd path unit, the launchd WatchPaths job, or the root agent itself on
// OpenRC), treats everything in the hand-off directory as untrusted, verifies
// the staged release again with its own embedded trust, swaps the binary it was
// itself started from, restarts the agent and rolls back if the new agent does
// not come up.
type Applier struct {
	Dir Dir
	// BinaryPath is the agent binary to replace. It comes from the applier's own
	// executable path, never from the request.
	BinaryPath     string
	CurrentVersion string
	Trust          Trust
	GOOS, GOARCH   string
	Service        Service
	HealthTimeout  time.Duration
	PollInterval   time.Duration
	// RefreshBuildID re-pins the root helper's expected build identity; nil
	// skips it (no helper on this host).
	RefreshBuildID func(version string) error
	// ProbeVersion runs a candidate binary and returns the version it prints.
	ProbeVersion func(ctx context.Context, path string) (string, error)
	Now          func() time.Time
	Logf         func(format string, args ...any)
}

type healthDecision int

const (
	healthWait healthDecision = iota
	healthCommit
	healthRollback
)

// decideHealth is the rollback rule: commit only on a health proof from this
// upgrade that names the target version; roll back once the deadline passed
// without one.
func decideHealth(h *Healthy, upgradeID, target string, expired bool) healthDecision {
	if h != nil && h.UpgradeID == upgradeID && h.Version == target {
		return healthCommit
	}
	if expired {
		return healthRollback
	}
	return healthWait
}

func (a *Applier) defaults() {
	if a.HealthTimeout <= 0 {
		a.HealthTimeout = DefaultHealthTimeout
	}
	if a.PollInterval <= 0 {
		a.PollInterval = 2 * time.Second
	}
	if a.Now == nil {
		a.Now = time.Now
	}
	if a.Logf == nil {
		a.Logf = log.Printf
	}
	if a.ProbeVersion == nil {
		a.ProbeVersion = probeVersion
	}
}

// Run claims a pending request and carries it out. It returns nil, nil when
// there was nothing to do. The returned Result has also been written to the
// hand-off directory for the agent to report.
func (a *Applier) Run(ctx context.Context) (*Result, error) {
	a.defaults()
	req, err := a.Dir.ReadRequest()
	if err != nil {
		_ = a.Dir.RemoveRequest()
		return nil, fmt.Errorf("unreadable self-update request discarded: %w", err)
	}
	if req == nil {
		return nil, nil
	}
	// Claim it first: a systemd PathExists= trigger fires again for as long as
	// the file exists.
	if err := a.Dir.RemoveRequest(); err != nil {
		return nil, fmt.Errorf("claiming self-update request: %w", err)
	}
	res := a.apply(ctx, *req)
	if res.State == models.UpgradeRolledBack {
		// rollback wrote it before restarting the old agent, which may already
		// have reported and removed it.
		return &res, nil
	}
	if err := a.Dir.WriteResult(res); err != nil {
		return &res, fmt.Errorf("writing self-update result: %w", err)
	}
	return &res, nil
}

func (a *Applier) fail(req Request, format string, args ...any) Result {
	a.Dir.ClearStaged()
	_ = a.Dir.RemovePending()
	msg := fmt.Sprintf(format, args...)
	a.Logf("self-update %s failed: %s", req.UpgradeID, msg)
	return Result{UpgradeID: req.UpgradeID, State: models.UpgradeFailed, Version: a.CurrentVersion, Error: msg, FinishedAt: a.Now().UTC()}
}

func (a *Applier) apply(ctx context.Context, req Request) Result {
	if !models.ValidUpgradeID(req.UpgradeID) {
		req.UpgradeID = "invalid"
		return a.fail(req, "request carries an invalid upgrade id")
	}
	target, ok := models.NormalizeReleaseVersion(req.Version)
	if !ok {
		return a.fail(req, "request carries an invalid version %q", req.Version)
	}
	if err := CheckUpgradePolicy(a.CurrentVersion, target); err != nil {
		return a.fail(req, "%v", err)
	}
	asset, err := AssetName(target, a.GOOS, a.GOARCH)
	if err != nil {
		return a.fail(req, "%v", err)
	}
	staged, err := a.Dir.LoadStaged(target, asset)
	if err != nil {
		return a.fail(req, "%v", err)
	}
	binary, err := a.Trust.Verify(staged)
	if err != nil {
		return a.fail(req, "release verification failed: %v", err)
	}
	a.Dir.ClearStaged()
	_ = a.Dir.RemoveHealthy()
	if err := a.Dir.WritePending(Pending{UpgradeID: req.UpgradeID, FromVersion: a.CurrentVersion, Version: target, StartedAt: a.Now().UTC()}); err != nil {
		return a.fail(req, "recording pending upgrade: %v", err)
	}

	info, err := os.Stat(a.BinaryPath)
	if err != nil {
		return a.fail(req, "inspecting current binary: %v", err)
	}
	candidate, err := writeCandidate(a.BinaryPath, binary, info)
	if err != nil {
		return a.fail(req, "writing new binary: %v", err)
	}
	defer func() { _ = os.Remove(candidate) }()
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	got, err := a.ProbeVersion(probeCtx, candidate)
	cancel()
	if err != nil {
		return a.fail(req, "new binary does not run on this host: %v", err)
	}
	if got != target {
		return a.fail(req, "new binary reports version %q, want %q", got, target)
	}
	if err := keepPrevious(a.BinaryPath, info); err != nil {
		return a.fail(req, "keeping the previous binary: %v", err)
	}
	if err := os.Rename(candidate, a.BinaryPath); err != nil {
		return a.fail(req, "installing new binary: %v", err)
	}
	if err := syncDir(filepath.Dir(a.BinaryPath)); err != nil {
		a.Logf("self-update: syncing %s: %v", filepath.Dir(a.BinaryPath), err)
	}
	a.Logf("self-update %s: installed %s (previous kept at %s)", req.UpgradeID, target, PreviousPath(a.BinaryPath))

	if a.RefreshBuildID != nil {
		if err := a.RefreshBuildID(target); err != nil {
			return a.rollback(req, target, fmt.Sprintf("re-pinning the root helper build failed: %v", err))
		}
	}
	if err := a.Service.Restart(ctx); err != nil {
		return a.rollback(req, target, fmt.Sprintf("restarting the agent failed: %v", err))
	}
	return a.awaitHealth(ctx, req, target)
}

func (a *Applier) awaitHealth(ctx context.Context, req Request, target string) Result {
	deadline := a.Now().Add(a.HealthTimeout)
	ticker := time.NewTicker(a.PollInterval)
	defer ticker.Stop()
	for {
		healthy, err := a.Dir.ReadHealthy()
		if err != nil {
			healthy = nil
		}
		switch decideHealth(healthy, req.UpgradeID, target, !a.Now().Before(deadline)) {
		case healthCommit:
			_ = a.Dir.RemoveHealthy()
			_ = a.Dir.RemovePending()
			a.Logf("self-update %s: agent %s is healthy", req.UpgradeID, target)
			return Result{UpgradeID: req.UpgradeID, State: models.UpgradeDone, Version: target, FinishedAt: a.Now().UTC()}
		case healthRollback:
			return a.rollback(req, target, fmt.Sprintf("the new agent did not report healthy within %s", a.HealthTimeout))
		}
		select {
		case <-ctx.Done():
			return a.rollback(req, target, "the applier was stopped before the new agent reported healthy")
		case <-ticker.C:
		}
	}
}

// rollback restores the previous binary and restarts the agent on it. The
// result is written before the restart so the old agent finds it at startup.
func (a *Applier) rollback(req Request, target, reason string) Result {
	a.Logf("self-update %s: rolling back from %s: %s", req.UpgradeID, target, reason)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res := Result{UpgradeID: req.UpgradeID, State: models.UpgradeRolledBack, Version: a.CurrentVersion, Error: reason, FinishedAt: a.Now().UTC()}
	if err := restorePrevious(a.BinaryPath); err != nil {
		res.State = models.UpgradeFailed
		res.Version = target
		res.Error = fmt.Sprintf("%s; restoring %s also failed: %v", reason, PreviousPath(a.BinaryPath), err)
		return res
	}
	if a.RefreshBuildID != nil {
		if err := a.RefreshBuildID(a.CurrentVersion); err != nil {
			res.Error += fmt.Sprintf("; re-pinning the root helper failed: %v", err)
		}
	}
	_ = a.Dir.RemoveHealthy()
	_ = a.Dir.RemovePending()
	if err := a.Dir.WriteResult(res); err != nil {
		a.Logf("self-update %s: writing rollback result: %v", req.UpgradeID, err)
	}
	if err := a.Service.Restart(ctx); err != nil {
		res.Error += fmt.Sprintf("; restarting the previous agent failed: %v", err)
	}
	return res
}

// CheckUpgradePolicy allows only a move to a strictly newer release. Rolling
// back is the applier's own business; an older signed release may carry fixed
// vulnerabilities, so it is never installed on request.
func CheckUpgradePolicy(current, target string) error {
	cmp, ok := models.CompareReleaseVersions(target, current)
	if !ok {
		return fmt.Errorf("cannot order %q against the running version %q; only release builds self-update", target, current)
	}
	if cmp <= 0 {
		return fmt.Errorf("refusing to install %s over %s: self-update only moves to newer releases", target, current)
	}
	return nil
}

// PreviousPath is where the replaced binary is kept for rollback.
func PreviousPath(binary string) string { return binary + ".prev" }

// writeCandidate writes data next to binary with binary's mode and owner and
// fsyncs it.
func writeCandidate(binary string, data []byte, like os.FileInfo) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(binary), "."+filepath.Base(binary)+".new-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(name)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return "", err
	}
	if err := f.Chmod(like.Mode().Perm() | 0o500); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := copyOwner(like, name); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}

// keepPrevious atomically replaces binary.prev with the current binary: a hard
// link when the filesystem allows it, a copy otherwise.
func keepPrevious(binary string, info os.FileInfo) error {
	prev := PreviousPath(binary)
	tmp := prev + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Link(binary, tmp); err != nil {
		if err := copyFile(binary, tmp, info); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, prev); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(binary))
}

// restorePrevious puts binary.prev back in place and keeps the .prev copy.
func restorePrevious(binary string) error {
	prev := PreviousPath(binary)
	info, err := os.Stat(prev)
	if err != nil {
		return err
	}
	tmp := binary + ".restore"
	_ = os.Remove(tmp)
	if err := copyFile(prev, tmp, info); err != nil {
		return err
	}
	if err := os.Rename(tmp, binary); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(binary))
}

func copyFile(src, dst string, info os.FileInfo) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return copyOwner(info, dst)
}

// probeVersion runs `<path> -version` and parses "nurproxy-agent <version>".
func probeVersion(ctx context.Context, path string) (string, error) {
	out, err := exec.CommandContext(ctx, path, "-version").Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("exit status %d", exitErr.ExitCode())
		}
		return "", err
	}
	fields := strings.Fields(string(out))
	if len(fields) != 2 || fields[0] != BinaryName {
		return "", fmt.Errorf("unexpected version output %q", strings.TrimSpace(string(out)))
	}
	return fields[1], nil
}

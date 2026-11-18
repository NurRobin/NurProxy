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
// OpenRC), treats everything in the agent's hand-off directory as untrusted,
// verifies the staged release again with its own embedded trust, swaps the
// binary it was itself started from, restarts the agent and rolls back if the
// new agent does not come up. It writes only to its root-owned directory and
// the binary's directory, both of which it checks first (see handoff).
type Applier struct {
	// DataDir is the agent's data directory.
	DataDir string
	// BinaryPath is the agent binary to replace. It comes from the applier's own
	// executable path, never from the request, and must be root-owned with
	// root-owned, non-writable parents.
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

	policy fsPolicy
	h      *handoff
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
	if a.policy.lstat == nil {
		a.policy = defaultPolicy()
	}
}

// Run claims a pending request and carries it out. It returns nil, nil when
// there was nothing to do. The returned Result has also been written to the
// hand-off directory for the agent to report.
func (a *Applier) Run(ctx context.Context) (*Result, error) {
	a.defaults()
	h, err := openHandoff(a.DataDir, a.policy)
	if err != nil {
		return nil, fmt.Errorf("refusing to act on %s: %w", a.DataDir, err)
	}
	defer h.Close()
	a.h = h
	defer func() { a.h = nil }()
	req, err := h.readRequest()
	if err != nil {
		_ = h.removeAgentFile(requestFile)
		h.clearStaged()
		return nil, fmt.Errorf("unreadable self-update request discarded: %w", err)
	}
	if req == nil {
		return nil, nil
	}
	// Claim it first: a systemd PathExists= trigger fires again for as long as
	// the file exists.
	if err := h.removeAgentFile(requestFile); err != nil {
		return nil, fmt.Errorf("claiming self-update request: %w", err)
	}
	_ = h.removeRootFile(resultFile)
	if err := a.policy.checkBinary(a.BinaryPath); err != nil {
		res := a.fail(*req, "%v", err)
		return a.finish(&res)
	}
	res := a.apply(ctx, *req)
	if res.State == models.UpgradeRolledBack {
		// rollback wrote it before restarting the old agent.
		return &res, nil
	}
	return a.finish(&res)
}

func (a *Applier) finish(res *Result) (*Result, error) {
	if err := a.h.writeRootJSON(resultFile, res); err != nil {
		return res, fmt.Errorf("writing self-update result: %w", err)
	}
	return res, nil
}

func (a *Applier) fail(req Request, format string, args ...any) Result {
	a.h.clearStaged()
	_ = a.h.removeRootFile(pendingFile)
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
	staged, err := a.h.loadStaged(target, asset)
	if err != nil {
		return a.fail(req, "%v", err)
	}
	binary, err := a.Trust.Verify(staged)
	if err != nil {
		return a.fail(req, "release verification failed: %v", err)
	}
	a.h.clearStaged()
	_ = a.h.removeAgentFile(healthyFile)
	if err := a.h.writeRootJSON(pendingFile, Pending{UpgradeID: req.UpgradeID, FromVersion: a.CurrentVersion, Version: target, StartedAt: a.Now().UTC()}); err != nil {
		return a.fail(req, "recording pending upgrade: %v", err)
	}

	candidate, err := writeCandidate(a.BinaryPath, binary, a.policy)
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
	if err := keepPrevious(a.BinaryPath, a.policy); err != nil {
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
		healthy, err := a.h.readHealthy()
		if err != nil {
			healthy = nil
		}
		switch decideHealth(healthy, req.UpgradeID, target, !a.Now().Before(deadline)) {
		case healthCommit:
			_ = a.h.removeAgentFile(healthyFile)
			_ = a.h.removeRootFile(pendingFile)
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
	if err := restorePrevious(a.BinaryPath, a.policy); err != nil {
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
	_ = a.h.removeAgentFile(healthyFile)
	_ = a.h.removeRootFile(pendingFile)
	if err := a.h.writeRootJSON(resultFile, res); err != nil {
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

// installedBinaryPerm is the mode of every binary the applier writes. The
// owner is always root:root: the old binary's owner is never carried over.
const installedBinaryPerm = 0o755

// writeCandidate writes data next to binary as root:root 0755 and fsyncs it.
func writeCandidate(binary string, data []byte, pol fsPolicy) (string, error) {
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
	if err := sealBinary(f, pol); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}

// sealBinary makes f root:root 0755, fsyncs and closes it.
func sealBinary(f *os.File, pol fsPolicy) error {
	if err := pol.chownRoot(f); err != nil {
		return err
	}
	if err := f.Chmod(installedBinaryPerm); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}

// keepPrevious atomically replaces binary.prev with the current binary: a hard
// link when the filesystem allows it (the binary passed checkBinary, so it is
// already root-owned), a root:root copy otherwise.
func keepPrevious(binary string, pol fsPolicy) error {
	prev := PreviousPath(binary)
	tmp := prev + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Link(binary, tmp); err != nil {
		if err := copyBinary(binary, tmp, pol); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, prev); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(binary))
}

// restorePrevious puts a root:root copy of binary.prev back in place and keeps
// the .prev file.
func restorePrevious(binary string, pol fsPolicy) error {
	tmp := binary + ".restore"
	_ = os.Remove(tmp)
	if err := copyBinary(PreviousPath(binary), tmp, pol); err != nil {
		return err
	}
	if err := os.Rename(tmp, binary); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(binary))
}

// copyBinary copies the regular file src (never a symlink) to the new file
// dst as root:root 0755.
func copyBinary(src, dst string, pol fsPolicy) error {
	in, err := openNoFollow(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if info, err := in.Stat(); err != nil {
		return err
	} else if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, installedBinaryPerm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := sealBinary(out, pol); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	return nil
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

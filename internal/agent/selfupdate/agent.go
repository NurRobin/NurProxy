package selfupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/runtimeenv"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// Reporter sends upgrade progress to the orchestrator.
type Reporter interface {
	Report(ctx context.Context, report models.UpgradeReport) error
}

// HTTPReporter posts reports to /api/v1/agents/{id}/upgrade/report.
type HTTPReporter struct {
	OrchestratorURL, AgentID, Token string
	Client                          *http.Client
}

// Report sends one report, retrying briefly on transport errors and 5xx.
func (r HTTPReporter) Report(ctx context.Context, report models.UpgradeReport) error {
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	url := strings.TrimRight(r.OrchestratorURL, "/") + "/api/v1/agents/" + r.AgentID + "/upgrade/report"
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+r.Token)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		_ = resp.Body.Close()
		switch {
		case resp.StatusCode < 300:
			return nil
		case resp.StatusCode >= 500:
			lastErr = fmt.Errorf("orchestrator returned HTTP %d", resp.StatusCode)
		default:
			// 4xx: the orchestrator does not want this report (unknown upgrade,
			// already terminal). Retrying will not change that.
			return fmt.Errorf("%w: HTTP %d", ErrReportRejected, resp.StatusCode)
		}
	}
	return lastErr
}

// ErrReportRejected marks a report the orchestrator refused for good.
var ErrReportRejected = errors.New("upgrade report rejected")

// Agent is the unprivileged half of a self-update, living in the agent
// process: it checks preconditions, downloads and pre-verifies the release,
// stages it for the applier, reports progress, proves health after a restart
// and relays the applier's verdict.
type Agent struct {
	Version  string
	DataDir  string
	DryRun   bool
	Trust    Trust
	Fetcher  Fetcher
	Reporter Reporter
	GOOS     string
	GOARCH   string
	// StartApplier launches the applier when no path trigger does (a root
	// agent under OpenRC). Nil when the trigger file starts it.
	StartApplier func(ctx context.Context) error
	// DryRunFail injects a failure into a dry-run upgrade: "verify" fails it
	// before the swap, "rollback" simulates a rolled-back restart.
	DryRunFail string
	// ClaimTimeout bounds how long a staged request may wait for the applier.
	ClaimTimeout time.Duration
	// PollInterval is how often Watch looks at the hand-off directory.
	PollInterval time.Duration
	// AfterSimulatedRestart runs when a dry-run upgrade "restarted" into the
	// target version, standing in for the immediate heartbeat of a real start.
	AfterSimulatedRestart func()

	host Host

	mu              sync.Mutex
	busy            bool
	simulated       string
	healthyReported string
}

// NewAgent builds the agent side for a live (or dry-run) agent.
func NewAgent(version, dataDir string, env runtimeenv.Env, dryRun bool, reporter Reporter) (*Agent, error) {
	trust, err := DefaultTrust()
	if err != nil {
		return nil, err
	}
	a := &Agent{
		Version: version, DataDir: dataDir, DryRun: dryRun, Trust: trust, Reporter: reporter,
		GOOS: env.OS, GOARCH: goarch(),
		host: DetectHost(version, env, dryRun),
	}
	if !dryRun && env.Init == runtimeenv.InitOpenRC && env.IsRoot {
		a.StartApplier = a.spawnApplier
	}
	return a, nil
}

// SetHost replaces the detected host facts (tests).
func (a *Agent) SetHost(h Host) { a.host = h }

// CurrentVersion is the version to report. A dry-run agent that "upgraded"
// reports the simulated target.
func (a *Agent) CurrentVersion() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.simulated != "" {
		return a.simulated
	}
	return a.Version
}

// Status is the self-update verdict for the heartbeat. The trigger file is
// re-checked so running self-update-enable takes effect without a restart.
func (a *Agent) Status() models.SelfUpdateStatus {
	h := a.host
	switch h.Init {
	case runtimeenv.InitSystemd:
		h.TriggerPresent = h.TriggerPresent || fileExists(SystemdTriggerPath)
	case runtimeenv.InitLaunchd:
		h.TriggerPresent = h.TriggerPresent || fileExists(LaunchdTriggerPath)
	}
	return h.Status()
}

func (a *Agent) dir() Dir { return StateDir(a.DataDir) }

func (a *Agent) rootDir() RootDir { return RootStateDir(a.DataDir) }

// Handle starts an upgrade in the background. A second command while one runs
// is reported as failed.
func (a *Agent) Handle(ctx context.Context, cmd models.UpgradeCommand) {
	if err := cmd.Validate(); err != nil {
		log.Printf("Self-update: ignoring invalid upgrade command: %v", err)
		return
	}
	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		a.report(ctx, cmd.UpgradeID, models.UpgradeFailed, "another upgrade is already running on this agent")
		return
	}
	a.busy = true
	a.mu.Unlock()
	go func() {
		defer func() {
			a.mu.Lock()
			a.busy = false
			a.mu.Unlock()
		}()
		if a.DryRun {
			a.simulate(ctx, cmd)
			return
		}
		a.run(ctx, cmd)
	}()
}

func (a *Agent) report(ctx context.Context, id string, state models.AgentUpgradeState, errMsg string) {
	if a.Reporter == nil {
		return
	}
	rep := models.UpgradeReport{UpgradeID: id, State: state, Version: a.CurrentVersion(), Error: errMsg}
	if err := a.Reporter.Report(ctx, rep); err != nil {
		log.Printf("Self-update: reporting %s for %s failed: %v", state, id, err)
	}
}

func (a *Agent) run(ctx context.Context, cmd models.UpgradeCommand) {
	fail := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		log.Printf("Self-update %s failed: %s", cmd.UpgradeID, msg)
		a.report(ctx, cmd.UpgradeID, models.UpgradeFailed, msg)
	}
	status := a.Status()
	if !status.Supported {
		fail("self-update is not available on this host: %s", status.Reason)
		return
	}
	target, _ := models.NormalizeReleaseVersion(cmd.Version)
	if err := CheckUpgradePolicy(a.Version, target); err != nil {
		fail("%v", err)
		return
	}
	dir := a.dir()
	if req, _ := dir.ReadRequest(); req != nil {
		fail("upgrade %s is still waiting for the privileged applier", req.UpgradeID)
		return
	}
	if p, _ := a.rootDir().ReadPending(); p != nil {
		fail("upgrade %s is still in progress", p.UpgradeID)
		return
	}
	asset, err := AssetName(target, a.GOOS, a.GOARCH)
	if err != nil {
		fail("%v", err)
		return
	}
	a.report(ctx, cmd.UpgradeID, models.UpgradeDownloading, "")
	log.Printf("Self-update %s: downloading %s", cmd.UpgradeID, asset)
	rel, err := a.Fetcher.Fetch(ctx, target, asset)
	if err != nil {
		fail("%v", err)
		return
	}
	// Verified here to fail fast with a clear error; the applier verifies the
	// staged copy again because it must not trust this process.
	if _, err := a.Trust.Verify(rel); err != nil {
		fail("release verification failed: %v", err)
		return
	}
	if err := dir.Stage(rel); err != nil {
		fail("%v", err)
		return
	}
	if err := dir.WriteRequest(Request{UpgradeID: cmd.UpgradeID, Version: target, FromVersion: a.Version, RequestedAt: time.Now().UTC()}); err != nil {
		dir.ClearStaged()
		fail("handing the release to the applier: %v", err)
		return
	}
	a.report(ctx, cmd.UpgradeID, models.UpgradeInstalled, "")
	if a.StartApplier != nil {
		if err := a.StartApplier(ctx); err != nil {
			_ = dir.RemoveRequest()
			dir.ClearStaged()
			fail("starting the applier: %v", err)
			return
		}
	}
	log.Printf("Self-update %s: %s verified and handed to the applier; the agent restarts next", cmd.UpgradeID, target)
	a.report(ctx, cmd.UpgradeID, models.UpgradeRestarting, "")
}

// simulate walks a dry-run agent through the upgrade without touching the
// binary or the service: the reported version flips to the target instead.
func (a *Agent) simulate(ctx context.Context, cmd models.UpgradeCommand) {
	target, _ := models.NormalizeReleaseVersion(cmd.Version)
	step := func() bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(200 * time.Millisecond):
			return true
		}
	}
	log.Printf("Self-update %s: dry-run upgrade to %s (nothing is downloaded or restarted)", cmd.UpgradeID, target)
	a.report(ctx, cmd.UpgradeID, models.UpgradeDownloading, "")
	if !step() {
		return
	}
	if a.DryRunFail == "verify" {
		a.report(ctx, cmd.UpgradeID, models.UpgradeFailed, "dry-run: simulated release verification failure")
		return
	}
	a.report(ctx, cmd.UpgradeID, models.UpgradeInstalled, "")
	if !step() {
		return
	}
	a.report(ctx, cmd.UpgradeID, models.UpgradeRestarting, "")
	if !step() {
		return
	}
	if a.DryRunFail == "rollback" {
		a.report(ctx, cmd.UpgradeID, models.UpgradeRolledBack, "dry-run: simulated health timeout, previous binary restored")
		return
	}
	a.mu.Lock()
	a.simulated = target
	a.mu.Unlock()
	a.report(ctx, cmd.UpgradeID, models.UpgradeDone, "")
	if a.AfterSimulatedRestart != nil {
		a.AfterSimulatedRestart()
	}
}

// HeartbeatOK is called after every successful heartbeat. When this process is
// the binary an applier just installed, it writes the health proof the applier
// is waiting for.
func (a *Agent) HeartbeatOK() {
	if a.DryRun {
		return
	}
	p, err := a.rootDir().ReadPending()
	if err != nil || p == nil || p.Version != a.Version {
		return
	}
	a.mu.Lock()
	done := a.healthyReported == p.UpgradeID
	a.mu.Unlock()
	if done {
		return
	}
	if err := a.dir().WriteHealthy(Healthy{UpgradeID: p.UpgradeID, Version: a.Version, At: time.Now().UTC()}); err != nil {
		log.Printf("Self-update %s: writing health proof failed: %v", p.UpgradeID, err)
		return
	}
	a.mu.Lock()
	a.healthyReported = p.UpgradeID
	a.mu.Unlock()
	log.Printf("Self-update %s: running %s and connected; health proof written", p.UpgradeID, a.Version)
}

// Watch relays the applier's verdict to the orchestrator and gives up on a
// request no applier claimed. It runs for the life of the agent.
func (a *Agent) Watch(ctx context.Context) {
	if a.DryRun {
		return
	}
	interval := a.PollInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	claimTimeout := a.ClaimTimeout
	if claimTimeout <= 0 {
		claimTimeout = 2 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		a.WatchOnce(ctx, claimTimeout)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// WatchOnce is one Watch iteration.
func (a *Agent) WatchOnce(ctx context.Context, claimTimeout time.Duration) {
	dir := a.dir()
	if res, err := a.rootDir().ReadResult(); err != nil {
		log.Printf("Self-update: unreadable applier result: %v", err)
	} else if res != nil && !alreadyReported(dir, res) {
		if a.Reporter != nil {
			err := a.Reporter.Report(ctx, models.UpgradeReport{UpgradeID: res.UpgradeID, State: res.State, Version: a.Version, Error: res.Error})
			if err != nil && !isRejected(err) {
				return
			}
		}
		log.Printf("Self-update %s finished: %s %s", res.UpgradeID, res.State, res.Error)
		// The result lives in the root-owned directory, which the agent cannot
		// clean up; remembering it keeps it from being reported again.
		err := dir.Ensure()
		if err == nil {
			err = dir.WriteReported(Reported{UpgradeID: res.UpgradeID, FinishedAt: res.FinishedAt})
		}
		if err != nil {
			log.Printf("Self-update %s: recording the reported result failed: %v", res.UpgradeID, err)
		}
	}
	req, err := dir.ReadRequest()
	if err != nil || req == nil {
		return
	}
	if time.Since(req.RequestedAt) < claimTimeout {
		return
	}
	_ = dir.RemoveRequest()
	dir.ClearStaged()
	msg := "the privileged applier never picked up the staged release; check that nurproxy-agent-update.path (or the launchd job) is installed and active"
	log.Printf("Self-update %s failed: %s", req.UpgradeID, msg)
	a.report(ctx, req.UpgradeID, models.UpgradeFailed, msg)
}

func alreadyReported(dir Dir, res *Result) bool {
	r, err := dir.ReadReported()
	return err == nil && r != nil && r.UpgradeID == res.UpgradeID && r.FinishedAt.Equal(res.FinishedAt)
}

func isRejected(err error) bool { return errors.Is(err, ErrReportRejected) }

// spawnApplier runs `<self> self-update-apply` detached, for root agents
// without a path trigger.
func (a *Agent) spawnApplier(context.Context) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "self-update-apply", "--data-dir", a.DataDir, "--service-manager", "openrc")
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

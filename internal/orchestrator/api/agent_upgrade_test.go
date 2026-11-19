package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/agenthub"
	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/auth"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

type upgradeEnv struct {
	t      *testing.T
	srv    *Server
	db     *db.DB
	hub    *agenthub.Hub
	cookie *http.Cookie
	tokens map[string]string
	events map[string]<-chan agenthub.Event
}

func newUpgradeEnv(t *testing.T, orchestratorVersion string) *upgradeEnv {
	t.Helper()
	srv, database := testServer(t)
	srv.version = orchestratorVersion
	hub := agenthub.New()
	srv.SetAgentHub(hub, nil)
	srv.upgrades.poll = 5 * time.Millisecond
	srv.upgrades.settleTimeout = time.Second
	return &upgradeEnv{t: t, srv: srv, db: database, hub: hub, cookie: setupAdmin(t, srv.Handler()),
		tokens: map[string]string{}, events: map[string]<-chan agenthub.Event{}}
}

// agent creates an adopted agent on version that reported self-update
// support; connected subscribes it to the hub.
func (e *upgradeEnv) agent(id, version string, connected bool) {
	e.t.Helper()
	e.legacyAgent(id, version, connected)
	if err := e.db.SetAgentSelfUpdateCapability(id, &models.SelfUpdateStatus{Supported: true, InstallKind: "standalone", ServiceManager: "systemd"}); err != nil {
		e.t.Fatal(err)
	}
}

// legacyAgent creates an adopted agent that never reported self-update
// support, like an agent from before 0.6.0.
func (e *upgradeEnv) legacyAgent(id, version string, connected bool) {
	e.t.Helper()
	token := "token-" + id
	if err := e.db.CreateAgent(&models.Agent{
		ID: id, Name: id, FQDN: id + ".example.com", TokenHash: auth.HashToken(token),
		Status: models.AgentStatusAdopted, DNSMode: models.DNSModeStatic,
	}); err != nil {
		e.t.Fatal(err)
	}
	e.tokens[id] = token
	if err := e.db.UpdateAgentVersion(id, version); err != nil {
		e.t.Fatal(err)
	}
	if connected {
		ch, unsubscribe := e.hub.Subscribe(id)
		e.t.Cleanup(unsubscribe)
		e.events[id] = ch
	}
}

func (e *upgradeEnv) admin(method, path string, body any) (int, string) {
	e.t.Helper()
	w := doRequest(e.t, e.srv.Handler(), method, path, body, e.cookie)
	return w.Code, w.Body.String()
}

func (e *upgradeEnv) report(agentID, upgradeID string, state models.AgentUpgradeState, version, errMsg string) int {
	e.t.Helper()
	w := doRequestWithAuth(e.t, e.srv.Handler(), "POST", "/api/v1/agents/"+agentID+"/upgrade/report",
		models.UpgradeReport{UpgradeID: upgradeID, State: state, Version: version, Error: errMsg}, e.tokens[agentID])
	return w.Code
}

func (e *upgradeEnv) heartbeat(agentID string, body map[string]any) {
	e.t.Helper()
	w := doRequestWithAuth(e.t, e.srv.Handler(), "POST", "/api/v1/agents/"+agentID+"/heartbeat", body, e.tokens[agentID])
	if w.Code != http.StatusOK {
		e.t.Fatalf("heartbeat: %d %s", w.Code, w.Body.String())
	}
}

// command waits for the upgrade command pushed to agentID.
func (e *upgradeEnv) command(agentID string) models.UpgradeCommand {
	e.t.Helper()
	select {
	case ev := <-e.events[agentID]:
		if ev.Type != agenthub.EventUpgrade {
			e.t.Fatalf("event %s, want upgrade", ev.Type)
		}
		var cmd models.UpgradeCommand
		if err := json.Unmarshal(ev.Data, &cmd); err != nil {
			e.t.Fatal(err)
		}
		return cmd
	case <-time.After(5 * time.Second):
		e.t.Fatalf("no upgrade command for %s", agentID)
	}
	return models.UpgradeCommand{}
}

func (e *upgradeEnv) upgrade(id string) *models.AgentUpgrade {
	e.t.Helper()
	up, err := e.db.GetAgentUpgrade(id)
	if err != nil {
		e.t.Fatal(err)
	}
	return up
}

func TestAgentUpgradeLifecycle(t *testing.T) {
	e := newUpgradeEnv(t, "1.3.0")
	e.agent("agent-1", "1.2.0", true)
	e.heartbeat("agent-1", map[string]any{"version": "1.2.0", "self_update": models.SelfUpdateStatus{Supported: true, InstallKind: "standalone", ServiceManager: "systemd"}})

	code, body := e.admin("POST", "/api/v1/agents/agent-1/upgrade", nil)
	if code != http.StatusAccepted {
		t.Fatalf("upgrade: %d %s", code, body)
	}
	var up models.AgentUpgrade
	if err := json.Unmarshal([]byte(body), &up); err != nil {
		t.Fatal(err)
	}
	if up.State != models.UpgradeRequested || up.TargetVersion != "1.3.0" || up.FromVersion != "1.2.0" || up.Trigger != models.UpgradeTriggerManual {
		t.Fatalf("upgrade %+v", up)
	}
	cmd := e.command("agent-1")
	if cmd.UpgradeID != up.ID || cmd.Version != "1.3.0" {
		t.Fatalf("command %+v", cmd)
	}

	if code, _ := e.admin("POST", "/api/v1/agents/agent-1/upgrade", map[string]string{"version": "1.3.0"}); code != http.StatusConflict {
		t.Fatalf("second upgrade while one runs: %d", code)
	}

	for _, st := range []models.AgentUpgradeState{models.UpgradeDownloading, models.UpgradeInstalled, models.UpgradeRestarting} {
		if code := e.report("agent-1", up.ID, st, "1.2.0", ""); code != http.StatusOK {
			t.Fatalf("report %s: %d", st, code)
		}
	}
	if code := e.report("agent-1", up.ID, models.UpgradeDownloading, "1.2.0", ""); code != http.StatusConflict {
		t.Fatalf("backwards report accepted: %d", code)
	}
	if code := e.report("agent-1", up.ID, models.UpgradeDone, "1.3.0", ""); code != http.StatusOK {
		t.Fatalf("done report: %d", code)
	}
	if got := e.upgrade(up.ID); got.State != models.UpgradeDone {
		t.Fatalf("state %s", got.State)
	}
	if code := e.report("agent-1", up.ID, models.UpgradeFailed, "1.3.0", "late"); code != http.StatusConflict {
		t.Fatalf("report after done accepted: %d", code)
	}

	// Another agent's token cannot report on this upgrade.
	e.agent("agent-2", "1.2.0", false)
	w := doRequestWithAuth(t, e.srv.Handler(), "POST", "/api/v1/agents/agent-2/upgrade/report",
		models.UpgradeReport{UpgradeID: up.ID, State: models.UpgradeFailed}, e.tokens["agent-2"])
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-agent report: %d", w.Code)
	}

	code, body = e.admin("GET", "/api/v1/agents", nil)
	if code != http.StatusOK {
		t.Fatal(body)
	}
	var agents []models.Agent
	if err := json.Unmarshal([]byte(body), &agents); err != nil {
		t.Fatal(err)
	}
	var listed *models.Agent
	for i := range agents {
		if agents[i].ID == "agent-1" {
			listed = &agents[i]
		}
	}
	if listed == nil || listed.Upgrade == nil || listed.Upgrade.State != models.UpgradeDone || listed.SelfUpdate == nil || !listed.SelfUpdate.Supported || listed.AutoUpgrade {
		t.Fatalf("listed agent %+v", listed)
	}
	code, body = e.admin("GET", "/api/v1/agents/agent-1/upgrades", nil)
	if code != http.StatusOK || !strings.Contains(body, up.ID) {
		t.Fatalf("history %d %s", code, body)
	}

	entries, _, err := e.db.ListAuditLog(100, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		if entry.EntityID == "agent-1" {
			seen[entry.Action] = true
		}
	}
	for _, action := range []string{"upgrade_requested", "upgrade_downloading", "upgrade_restarting", "upgrade_done"} {
		if !seen[action] {
			t.Errorf("audit lacks %s (have %v)", action, seen)
		}
	}
}

func TestAgentUpgradeRefusals(t *testing.T) {
	e := newUpgradeEnv(t, "1.3.0")
	e.agent("offline", "1.2.0", false)
	e.agent("packaged", "1.2.0", true)
	e.heartbeat("packaged", map[string]any{"version": "1.2.0", "self_update": models.SelfUpdateStatus{Supported: false, InstallKind: "deb", Reason: "installed from the deb package"}})
	e.agent("current", "1.3.0", true)
	e.agent("fine", "1.2.0", true)

	cases := []struct {
		path    string
		body    any
		code    int
		message string
	}{
		{"/api/v1/agents/offline/upgrade", nil, http.StatusConflict, "not connected"},
		{"/api/v1/agents/packaged/upgrade", nil, http.StatusConflict, "deb package"},
		{"/api/v1/agents/current/upgrade", nil, http.StatusConflict, "already runs"},
		{"/api/v1/agents/fine/upgrade", map[string]string{"version": "1.1.0"}, http.StatusConflict, "newer releases"},
		{"/api/v1/agents/fine/upgrade", map[string]string{"version": "latest"}, http.StatusBadRequest, "invalid version"},
		{"/api/v1/agents/fine/upgrade", map[string]string{"version": "1.3.0/../../x"}, http.StatusBadRequest, "invalid version"},
		{"/api/v1/agents/missing/upgrade", nil, http.StatusNotFound, "not found"},
	}
	for _, tc := range cases {
		code, body := e.admin("POST", tc.path, tc.body)
		if code != tc.code || !strings.Contains(body, tc.message) {
			t.Errorf("%s %v: %d %s", tc.path, tc.body, code, body)
		}
	}

	// Pre-releases need an explicit opt-in, as a requested version and as the
	// orchestrator's own default.
	if code, body := e.admin("POST", "/api/v1/agents/fine/upgrade", map[string]string{"version": "1.4.0-rc.1"}); code != http.StatusBadRequest || !strings.Contains(body, "pre-release") {
		t.Fatalf("pre-release without opt-in: %d %s", code, body)
	}
	if code, body := e.admin("POST", "/api/v1/agents/fine/upgrade", map[string]any{"version": "1.4.0-rc.1", "allow_prerelease": true}); code != http.StatusAccepted {
		t.Fatalf("pre-release with opt-in: %d %s", code, body)
	}
	rc := newUpgradeEnv(t, "1.4.0-rc.1")
	rc.agent("a", "1.2.0", true)
	if code, body := rc.admin("POST", "/api/v1/agents/a/upgrade", nil); code != http.StatusBadRequest || !strings.Contains(body, "pre-release") {
		t.Fatalf("pre-release default target: %d %s", code, body)
	}
	if code, body := rc.admin("POST", "/api/v1/agents/upgrade-outdated", nil); code != http.StatusBadRequest || !strings.Contains(body, "pre-release") {
		t.Fatalf("pre-release rollout: %d %s", code, body)
	}
	if code, body := rc.admin("PUT", "/api/v1/agents/a/auto-upgrade", map[string]bool{"enabled": true}); code != http.StatusOK {
		t.Fatalf("auto-upgrade: %d %s", code, body)
	}
	rc.srv.upgrades.autoUpgradeOnce(context.Background())
	select {
	case ev := <-rc.events["a"]:
		t.Fatalf("auto-upgrade installed a pre-release: %s", ev.Type)
	default:
	}

	dev := newUpgradeEnv(t, "dev")
	dev.agent("a", "1.2.0", true)
	if code, body := dev.admin("POST", "/api/v1/agents/a/upgrade", nil); code != http.StatusBadRequest || !strings.Contains(body, "not a release") {
		t.Fatalf("dev orchestrator default target: %d %s", code, body)
	}
}

func TestAgentUpgradeCompletionRules(t *testing.T) {
	e := newUpgradeEnv(t, "1.3.0")
	e.agent("a", "1.2.0", true)

	start := func() string {
		code, body := e.admin("POST", "/api/v1/agents/a/upgrade", nil)
		if code != http.StatusAccepted {
			t.Fatalf("upgrade: %d %s", code, body)
		}
		return e.command("a").UpgradeID
	}

	// A "done" from a binary that is not the target counts as failed.
	id := start()
	e.report("a", id, models.UpgradeRestarting, "1.2.0", "")
	e.report("a", id, models.UpgradeDone, "1.2.0", "")
	if got := e.upgrade(id); got.State != models.UpgradeFailed || !strings.Contains(got.Error, "runs") {
		t.Fatalf("got %+v", got)
	}

	// A heartbeat on the target version does not complete a restarting upgrade
	// while the applier may still roll back...
	id = start()
	e.report("a", id, models.UpgradeRestarting, "1.2.0", "")
	e.heartbeat("a", map[string]any{"version": "1.3.0"})
	if got := e.upgrade(id); got.State != models.UpgradeRestarting {
		t.Fatalf("heartbeat completed the upgrade before the applier committed: %+v", got)
	}
	// ...but does after the confirmation window, so a lost done report does not
	// leave it hanging.
	e.srv.upgrades.now = func() time.Time { return time.Now().Add(upgradeConfirmWindow + time.Second) }
	e.heartbeat("a", map[string]any{"version": "1.3.0"})
	e.srv.upgrades.now = time.Now
	if got := e.upgrade(id); got.State != models.UpgradeDone {
		t.Fatalf("heartbeat after the window did not complete the upgrade: %+v", got)
	}
	// A rollback the applier reports afterwards still wins over that done.
	if code := e.report("a", id, models.UpgradeRolledBack, "1.2.0", "the new agent did not report healthy"); code != http.StatusOK {
		t.Fatalf("rolled_back after done: HTTP %d", code)
	}
	if got := e.upgrade(id); got.State != models.UpgradeRolledBack {
		t.Fatalf("rolled_back did not override done: %+v", got)
	}
	if code := e.report("a", id, models.UpgradeDone, "1.3.0", ""); code != http.StatusConflict {
		t.Fatalf("done after rolled_back: HTTP %d", code)
	}

	// A rolled-back report keeps the agent's error.
	_ = e.db.UpdateAgentVersion("a", "1.2.0")
	id = start()
	e.report("a", id, models.UpgradeRolledBack, "1.2.0", "the new agent did not report healthy within 3m0s")
	if got := e.upgrade(id); got.State != models.UpgradeRolledBack || !strings.Contains(got.Error, "healthy") {
		t.Fatalf("got %+v", got)
	}

	// The sweeper fails an upgrade that stopped reporting.
	id = start()
	e.report("a", id, models.UpgradeRestarting, "1.2.0", "")
	e.srv.upgrades.now = func() time.Time { return time.Now().Add(time.Hour) }
	e.srv.upgrades.sweep()
	e.srv.upgrades.now = time.Now
	if got := e.upgrade(id); got.State != models.UpgradeFailed || !strings.Contains(got.Error, "did not come back") {
		t.Fatalf("sweeper: %+v", got)
	}
}

func TestUpgradeRolloutStopsOnFailure(t *testing.T) {
	e := newUpgradeEnv(t, "1.3.0")
	// Created in this order; the rollout follows it.
	e.agent("a1", "1.2.0", true)
	time.Sleep(1100 * time.Millisecond) // created_at has second resolution
	e.agent("a2", "1.2.0", true)
	time.Sleep(1100 * time.Millisecond)
	e.agent("a3", "1.1.0", true)
	e.agent("current", "1.3.0", true)
	e.agent("offline", "1.0.0", false)

	code, body := e.admin("POST", "/api/v1/agents/upgrade-outdated", nil)
	if code != http.StatusAccepted {
		t.Fatalf("rollout: %d %s", code, body)
	}
	if code, _ := e.admin("POST", "/api/v1/agents/upgrade-outdated", nil); code != http.StatusConflict {
		t.Fatalf("second rollout while one runs: %d", code)
	}

	// a1 upgrades fine and comes back on the target.
	cmd := e.command("a1")
	e.report("a1", cmd.UpgradeID, models.UpgradeRestarting, "1.2.0", "")
	e.report("a1", cmd.UpgradeID, models.UpgradeDone, "1.3.0", "")
	e.heartbeat("a1", map[string]any{"version": "1.3.0"})

	// a2 is only asked after a1 is healthy, and rolls back.
	cmd = e.command("a2")
	e.report("a2", cmd.UpgradeID, models.UpgradeRolledBack, "1.2.0", "health timeout")

	var rollout *UpgradeRollout
	deadline := time.Now().Add(5 * time.Second)
	for {
		rollout = e.srv.upgrades.snapshot()
		if rollout.State != "running" || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if rollout.State != "failed" || !strings.Contains(rollout.Error, "health timeout") {
		t.Fatalf("rollout %+v", rollout)
	}
	states := map[string]string{}
	for _, ra := range rollout.Agents {
		states[ra.AgentID] = ra.State
	}
	want := map[string]string{"a1": rolloutDone, "a2": rolloutFailed, "a3": rolloutSkipped, "offline": rolloutSkipped}
	for id, st := range want {
		if states[id] != st {
			t.Errorf("%s: %s, want %s (all %v)", id, states[id], st, states)
		}
	}
	if _, listed := states["current"]; listed {
		t.Error("an agent already on the target was planned")
	}
	select {
	case ev := <-e.events["a3"]:
		t.Fatalf("a3 got %s after the rollout stopped", ev.Type)
	default:
	}
	code, body = e.admin("GET", "/api/v1/agents/upgrade-rollout", nil)
	if code != http.StatusOK || !strings.Contains(body, `"state":"failed"`) {
		t.Fatalf("rollout status %d %s", code, body)
	}
}

func TestAutoUpgradeIsOptInAndDoesNotRetry(t *testing.T) {
	e := newUpgradeEnv(t, "1.3.0")
	e.agent("a", "1.2.0", true)
	ctx := context.Background()

	e.srv.upgrades.autoUpgradeOnce(ctx)
	select {
	case ev := <-e.events["a"]:
		t.Fatalf("upgrade %s pushed without opt-in", ev.Type)
	default:
	}

	if code, body := e.admin("PUT", "/api/v1/agents/a/auto-upgrade", map[string]bool{"enabled": true}); code != http.StatusOK {
		t.Fatalf("auto-upgrade: %d %s", code, body)
	}
	e.srv.upgrades.autoUpgradeOnce(ctx)
	cmd := e.command("a")
	if got := e.upgrade(cmd.UpgradeID); got.Trigger != models.UpgradeTriggerAuto {
		t.Fatalf("trigger %s", got.Trigger)
	}
	e.report("a", cmd.UpgradeID, models.UpgradeFailed, "1.2.0", "download failed")
	deadline := time.Now().Add(2 * time.Second)
	for !e.srv.upgrades.tryAcquire() {
		if time.Now().After(deadline) {
			t.Fatal("auto-upgrade never released the coordinator")
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.srv.upgrades.release()

	e.srv.upgrades.autoUpgradeOnce(ctx)
	select {
	case ev := <-e.events["a"]:
		t.Fatalf("auto-upgrade retried a failed target: %s", ev.Type)
	default:
	}
}

// An agent that never reported self-update support (any agent before 0.6.0
// ignores the upgrade event) is refused up front and skipped by a rollout,
// instead of timing out as a failed upgrade that stops the rollout.
func TestAgentUpgradeRefusesAgentWithoutCapability(t *testing.T) {
	e := newUpgradeEnv(t, "1.3.0")
	e.legacyAgent("old", "0.5.1", true)
	code, body := e.admin("POST", "/api/v1/agents/old/upgrade", nil)
	if code != http.StatusConflict || !strings.Contains(body, "has not reported self-update support") {
		t.Fatalf("upgrade of legacy agent: %d %s", code, body)
	}
	if code, body := e.admin("POST", "/api/v1/agents/upgrade-outdated", nil); code != http.StatusConflict {
		t.Fatalf("rollout with only a legacy agent: %d %s", code, body)
	}
	select {
	case ev := <-e.events["old"]:
		t.Fatalf("legacy agent got an event: %+v", ev)
	default:
	}
}

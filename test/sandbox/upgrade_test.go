//go:build sandbox

package sandbox

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestSandboxAgentUpgrade drives agent self-update (#73) through the dry
// stack: an orchestrator stamped 0.9.0 and agents stamped 0.8.0 that simulate
// the upgrade (no download, no restart). It covers a single operator-requested
// upgrade to done and an "upgrade all outdated" rollout that stops at the first
// rolled-back agent.
func TestSandboxAgentUpgrade(t *testing.T) {
	root := repoRoot(t)
	out := t.TempDir()
	build := func(name, tags, version, pkg string) string {
		bin := filepath.Join(out, name)
		args := []string{"build"}
		if tags != "" {
			args = append(args, "-tags", tags)
		}
		args = append(args, "-ldflags", "-X main.version="+version, "-o", bin, pkg)
		cmd := exec.Command("go", args...)
		cmd.Dir = root
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("building %s: %v\n%s", pkg, err, output)
		}
		return bin
	}
	orchBin := build("nurproxy-orch", "headless", "0.9.0", "./cmd/nurproxy")
	agentBin := build("nurproxy-agent", "", "0.8.0", "./cmd/nurproxy-agent")

	dataRoot := t.TempDir()
	orchPort := freePort(t)
	base := fmt.Sprintf("http://127.0.0.1:%d", orchPort)
	orch := startProcess(t, orchBin, []string{"-port", fmt.Sprint(orchPort), "-data-dir", filepath.Join(dataRoot, "orch")}, "NP_DRY_RUN=true")
	defer orch.stop()
	waitFor(t, 60*time.Second, func() bool { return httpOK(base + "/api/v1/health") })

	jar, _ := cookiejar.New(nil)
	cli := &http.Client{Jar: jar}
	postJSON(t, cli, base+"/api/v1/auth/setup", map[string]string{"password": adminPassword}, nil)
	var keyResp struct {
		APIKey string `json:"api_key"`
	}
	postJSON(t, cli, base+"/api/v1/api-key", map[string]string{}, &keyResp)
	api := &apiClient{base: base, key: keyResp.APIKey, t: t}

	type agentView struct {
		ID            string `json:"id"`
		FQDN          string `json:"fqdn"`
		Version       string `json:"version"`
		VersionStatus string `json:"version_status"`
		SelfUpdate    *struct {
			Supported bool `json:"supported"`
			DryRun    bool `json:"dry_run"`
		} `json:"self_update"`
		Upgrade *struct {
			ID    string `json:"id"`
			State string `json:"state"`
			Error string `json:"error"`
		} `json:"upgrade"`
	}
	listAgents := func() map[string]agentView {
		var agents []agentView
		api.get("/api/v1/agents", &agents)
		byFQDN := map[string]agentView{}
		for _, a := range agents {
			byFQDN[a.FQDN] = a
		}
		return byFQDN
	}

	// edge2 fails its restart (simulated rollback); it registers before edge3,
	// so the rollout reaches it first.
	ids := map[string]string{}
	for _, spec := range []struct{ fqdn, fail string }{
		{"edge1.upgrade.test", ""},
		{"edge2.upgrade.test", "rollback"},
		{"edge3.upgrade.test", ""},
	} {
		env := []string{"NP_DRY_RUN=true"}
		if spec.fail != "" {
			env = append(env, "NP_DRY_RUN_UPDATE_FAIL="+spec.fail)
		}
		agent := startProcess(t, agentBin, []string{
			"-orchestrator", base, "-fqdn", spec.fqdn, "-api-port", fmt.Sprint(freePort(t)),
			"-data-dir", filepath.Join(dataRoot, spec.fqdn),
		}, env...)
		defer agent.stop()
		waitFor(t, 15*time.Second, func() bool { _, ok := listAgents()[spec.fqdn]; return ok })
		ids[spec.fqdn] = listAgents()[spec.fqdn].ID
		api.put("/api/v1/agents/"+ids[spec.fqdn]+"/adopt", map[string]any{"name": spec.fqdn}, nil)
		time.Sleep(1100 * time.Millisecond) // distinct created_at seconds keep the rollout order stable
	}

	// Every agent heartbeats its self-update capability and shows as outdated.
	waitFor(t, 30*time.Second, func() bool {
		for _, a := range listAgents() {
			if a.SelfUpdate == nil || !a.SelfUpdate.Supported || !a.SelfUpdate.DryRun || a.VersionStatus != "outdated" {
				return false
			}
		}
		return true
	})

	// --- single upgrade: requested -> ... -> done, agent reports 0.9.0 --------
	var up struct {
		ID            string `json:"id"`
		TargetVersion string `json:"target_version"`
	}
	api.post("/api/v1/agents/"+ids["edge1.upgrade.test"]+"/upgrade", map[string]string{}, &up)
	if up.TargetVersion != "0.9.0" {
		t.Fatalf("default target %q, want the orchestrator's 0.9.0", up.TargetVersion)
	}
	waitFor(t, 30*time.Second, func() bool {
		a := listAgents()["edge1.upgrade.test"]
		return a.Upgrade != nil && a.Upgrade.ID == up.ID && a.Upgrade.State == "done" && a.Version == "0.9.0" && a.VersionStatus == "current"
	})

	// --- rollout: edge2 rolls back, the rollout stops before edge3 -----------
	api.post("/api/v1/agents/upgrade-outdated", map[string]string{}, nil)
	var rollout struct {
		Rollout *struct {
			State  string `json:"state"`
			Error  string `json:"error"`
			Agents []struct {
				AgentID string `json:"agent_id"`
				State   string `json:"state"`
			} `json:"agents"`
		} `json:"rollout"`
	}
	waitFor(t, 60*time.Second, func() bool {
		api.get("/api/v1/agents/upgrade-rollout", &rollout)
		return rollout.Rollout != nil && rollout.Rollout.State != "running"
	})
	if rollout.Rollout.State != "failed" {
		t.Fatalf("rollout ended %q, want failed (edge2 rolls back)", rollout.Rollout.State)
	}
	states := map[string]string{}
	for _, a := range rollout.Rollout.Agents {
		states[a.AgentID] = a.State
	}
	if states[ids["edge2.upgrade.test"]] != "failed" || states[ids["edge3.upgrade.test"]] != "skipped" {
		t.Fatalf("rollout agent states %v", states)
	}
	if _, planned := states[ids["edge1.upgrade.test"]]; planned {
		t.Fatal("rollout planned an agent that is already current")
	}
	agents := listAgents()
	if e2 := agents["edge2.upgrade.test"]; e2.Upgrade == nil || e2.Upgrade.State != "rolled_back" || e2.Version != "0.8.0" {
		t.Fatalf("edge2 after rollback: %+v", e2)
	}
	if e3 := agents["edge3.upgrade.test"]; e3.Upgrade != nil || e3.Version != "0.8.0" {
		t.Fatalf("edge3 was touched after the rollout stopped: %+v", e3)
	}

	// The audit log records the upgrade lifecycle.
	var audit struct {
		Entries []struct {
			EntityID string `json:"entity_id"`
			Action   string `json:"action"`
		} `json:"entries"`
	}
	api.get("/api/v1/audit-log?limit=1000", &audit)
	seen := map[string]bool{}
	for _, e := range audit.Entries {
		seen[e.Action] = true
	}
	for _, action := range []string{"upgrade_requested", "upgrade_done", "upgrade_rolled_back", "upgrade_rollout_started", "upgrade_rollout_failed"} {
		if !seen[action] {
			t.Errorf("audit log lacks %s", action)
		}
	}
}

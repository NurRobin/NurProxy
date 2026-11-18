//go:build sandbox

package sandbox

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSandboxFailover drives multi-agent failover (#74) through the dry
// stack: a domain on edge1 with a backup server on edge2. Stopping edge1
// moves the CNAME to edge2, restarting it moves the record back after the
// failback delay. Timings are shortened through the settings API.
func TestSandboxFailover(t *testing.T) {
	root := repoRoot(t)
	bin := buildBinaries(t, root)
	orchPort := freePort(t)
	dataRoot := t.TempDir()
	base := fmt.Sprintf("http://127.0.0.1:%d", orchPort)
	orchArgs := []string{"-port", fmt.Sprintf("%d", orchPort), "-data-dir", filepath.Join(dataRoot, "orch")}

	orch := startProcess(t, bin.orch, orchArgs, "NP_DRY_RUN=true")
	waitFor(t, 60*time.Second, func() bool { return httpOK(base + "/api/v1/health") })

	jar, _ := cookiejar.New(nil)
	cli := &http.Client{Jar: jar}
	postJSON(t, cli, base+"/api/v1/auth/setup", map[string]string{"password": adminPassword}, nil)
	var keyResp struct {
		APIKey string `json:"api_key"`
	}
	postJSON(t, cli, base+"/api/v1/api-key", map[string]string{}, &keyResp)
	api := &apiClient{base: base, key: keyResp.APIKey, t: t}

	// Short timings. The reconcile interval is read when the orchestrator
	// starts, so it restarts once with them in place.
	for key, value := range map[string]string{
		"reconciler_interval":     "5",
		"agent_offline_timeout":   "30", // above the 20 s stream keepalive
		"failover_grace":          "0",
		"failover_failback_delay": "10",
		"failover_settle":         "10",
	} {
		api.put("/api/v1/settings/"+key, map[string]string{"value": value}, nil)
	}
	orch.stop()
	orch = startProcess(t, bin.orch, orchArgs, "NP_DRY_RUN=true")
	defer func() { orch.stop() }()
	waitFor(t, 60*time.Second, func() bool { return httpOK(base + "/api/v1/health") })

	var prov struct {
		ID string `json:"id"`
	}
	api.post("/api/v1/providers", map[string]any{
		"type": "cloudflare", "name": "CF-dry",
		"config": map[string]string{"api_token": "dummy-dry-token"},
	}, &prov)
	var zone struct {
		ID string `json:"id"`
	}
	api.post("/api/v1/zones", map[string]string{"provider_id": prov.ID, "name": "sandbox.test"}, &zone)

	startAgent := func(n int) *process {
		return startProcess(t, bin.agent, []string{
			"-dry-run", "-orchestrator", base,
			"-fqdn", fmt.Sprintf("edge%d.sandbox.test", n),
			"-api-port", fmt.Sprintf("%d", freePort(t)),
			"-data-dir", filepath.Join(dataRoot, fmt.Sprintf("agent%d", n)),
		})
	}
	adopt := func(n int) string {
		fqdn := fmt.Sprintf("edge%d.sandbox.test", n)
		var id string
		waitFor(t, 15*time.Second, func() bool {
			var agents []struct {
				ID   string `json:"id"`
				FQDN string `json:"fqdn"`
			}
			api.get("/api/v1/agents", &agents)
			for _, a := range agents {
				if a.FQDN == fqdn {
					id = a.ID
					return true
				}
			}
			return false
		})
		api.put("/api/v1/agents/"+id+"/adopt", map[string]any{"name": fmt.Sprintf("edge%d", n), "zone_ids": []string{zone.ID}}, nil)
		return id
	}
	agent1 := startAgent(1)
	defer func() { agent1.stop() }()
	agent1ID := adopt(1)
	agent2 := startAgent(2)
	defer agent2.stop()
	agent2ID := adopt(2)

	var srv1, srv2 struct {
		ID string `json:"id"`
	}
	api.post("/api/v1/agents/"+agent1ID+"/servers", map[string]string{"name": "app-a", "address": "10.0.0.5"}, &srv1)
	api.post("/api/v1/agents/"+agent2ID+"/servers", map[string]string{"name": "app-b", "address": "10.0.0.6"}, &srv2)
	var domain struct {
		ID int64 `json:"id"`
	}
	api.post("/api/v1/domains", map[string]any{
		"subdomain": "ha", "zone_id": zone.ID, "server_id": srv1.ID, "port": 8080, "ssl_mode": "central",
	}, &domain)
	api.put(fmt.Sprintf("/api/v1/domains/%d/backups", domain.ID), map[string]any{"server_ids": []string{srv2.ID}}, nil)

	type failoverStatus struct {
		ActiveServerID string `json:"active_server_id"`
		Switches       int    `json:"switches"`
		Candidates     []struct {
			ServerID string `json:"server_id"`
			Healthy  bool   `json:"healthy"`
		} `json:"candidates"`
	}
	status := func() failoverStatus {
		var st failoverStatus
		api.get(fmt.Sprintf("/api/v1/domains/%d/failover", domain.ID), &st)
		return st
	}
	// sawAudit reports whether the audit log has an entry with action whose
	// details contain want.
	sawAudit := func(action, want string) bool {
		var audit struct {
			Entries []struct {
				Action  string `json:"action"`
				Details string `json:"details"`
			} `json:"entries"`
		}
		api.get("/api/v1/audit-log?limit=200", &audit)
		for _, e := range audit.Entries {
			if e.Action == action && strings.Contains(e.Details, want) {
				return true
			}
		}
		return false
	}

	// Converged: the CNAME points at edge1, and edge2 holds the standby route.
	waitFor(t, 60*time.Second, func() bool {
		var d struct {
			DNSRecordID string `json:"dns_record_id"`
		}
		api.get(fmt.Sprintf("/api/v1/domains/%d", domain.ID), &d)
		return d.DNSRecordID != "" && sawAudit("dns_created", "ha.sandbox.test -> edge1.sandbox.test")
	})
	if st := status(); st.ActiveServerID != srv1.ID || len(st.Candidates) != 2 {
		t.Fatalf("before failover: %+v", st)
	}
	waitFor(t, 45*time.Second, func() bool {
		var arts []struct {
			ID      string `json:"id"`
			AgentID string `json:"agent_id"`
		}
		api.get("/api/v1/artifacts?agent_id="+agent2ID, &arts)
		for _, a := range arts {
			if a.AgentID == agent2ID && strings.HasPrefix(a.ID, fmt.Sprintf("dom-%d-sb-", domain.ID)) {
				return true
			}
		}
		return false
	})

	// Primary down: after the offline timeout the record moves to edge2.
	agent1.stop()
	waitFor(t, 75*time.Second, func() bool {
		return status().ActiveServerID == srv2.ID && sawAudit("dns_updated", "edge1.sandbox.test -> edge2.sandbox.test")
	})
	if !sawAudit("failover", "edge2.sandbox.test") {
		t.Fatal("no failover audit entry")
	}

	// Primary back: after the failback delay the record returns to edge1.
	agent1 = startAgent(1)
	waitFor(t, 60*time.Second, func() bool {
		return status().ActiveServerID == srv1.ID && sawAudit("dns_updated", "edge2.sandbox.test -> edge1.sandbox.test")
	})
	if !sawAudit("failback", "edge1.sandbox.test") {
		t.Fatal("no failback audit entry")
	}
	if st := status(); st.Switches != 2 {
		t.Fatalf("switches = %d, want 2", st.Switches)
	}
}

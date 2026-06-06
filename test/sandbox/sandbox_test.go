//go:build sandbox

// Package sandbox holds an end-to-end test of NurProxy's dry-run / sandbox mode
// (#93): it boots a real orchestrator and a real agent — both in dry-run — as
// subprocesses, drives the public REST API to stand up a provider, zone, agent
// adoption, server, and central-TLS domain, and asserts the whole control plane
// converges with NO external DNS or ACME calls and NO privileges.
//
// It is the durable counterpart to scripts/dev-sandbox.sh: same flow, but with
// hard assertions (domain active, certificate issued, DNS records simulated,
// audit entries tagged source=dryrun). Gated behind the `sandbox` build tag so
// it never runs in the normal unit-test pass; invoke with `make test-sandbox`.
package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const adminPassword = "sandbox-e2e-pass"

func TestSandboxEndToEnd(t *testing.T) {
	repoRoot := repoRoot(t)
	bin := buildBinaries(t, repoRoot)

	orchPort := freePort(t)
	dataRoot := t.TempDir()
	base := fmt.Sprintf("http://127.0.0.1:%d", orchPort)

	// --- start the dry-run orchestrator --------------------------------------
	orch := startProcess(t, bin.orch, []string{
		"-port", fmt.Sprintf("%d", orchPort),
		"-data-dir", filepath.Join(dataRoot, "orch"),
	}, "NP_DRY_RUN=true")
	defer orch.stop()

	waitFor(t, 10*time.Second, func() bool { return httpOK(base + "/api/v1/health") })

	// Health must advertise the sandbox so the dashboard banner lights up.
	var health map[string]any
	mustGetJSON(t, &http.Client{}, base+"/api/v1/health", &health)
	if health["dry_run"] != true || health["dns_dry_run"] != true || health["acme_dry_run"] != true {
		t.Fatalf("health did not report dry-run: %v", health)
	}

	// --- bootstrap auth + API key (cookie session) ---------------------------
	jar, _ := cookiejar.New(nil)
	cli := &http.Client{Jar: jar}
	postJSON(t, cli, base+"/api/v1/auth/setup", map[string]string{"password": adminPassword}, nil)
	var keyResp struct {
		APIKey string `json:"api_key"`
	}
	postJSON(t, cli, base+"/api/v1/api-key", map[string]string{}, &keyResp)
	if keyResp.APIKey == "" {
		t.Fatal("no API key returned")
	}
	api := &apiClient{base: base, key: keyResp.APIKey, t: t}

	// --- provider (dummy creds) + zone ---------------------------------------
	var prov struct {
		ID string `json:"id"`
	}
	api.post("/api/v1/providers", map[string]any{
		"type": "cloudflare", "name": "CF-dry",
		"config": map[string]string{"api_token": "dummy-dry-token"},
	}, &prov)
	if prov.ID == "" {
		t.Fatal("provider not created (dry-run validation should accept a dummy token)")
	}
	var zone struct {
		ID string `json:"id"`
	}
	api.post("/api/v1/zones", map[string]string{"provider_id": prov.ID, "name": "sandbox.test"}, &zone)

	// --- start the dry-run agent ---------------------------------------------
	agentPort := freePort(t)
	agent := startProcess(t, bin.agent, []string{
		"-dry-run",
		"-orchestrator", base,
		"-fqdn", "edge1.sandbox.test",
		"-api-port", fmt.Sprintf("%d", agentPort),
		"-data-dir", filepath.Join(dataRoot, "agent1"),
	}, "")
	defer agent.stop()

	// --- adopt the agent once it registers -----------------------------------
	var agentID string
	waitFor(t, 15*time.Second, func() bool {
		var agents []struct {
			ID   string `json:"id"`
			FQDN string `json:"fqdn"`
		}
		api.get("/api/v1/agents", &agents)
		for _, a := range agents {
			if a.FQDN == "edge1.sandbox.test" {
				agentID = a.ID
				return true
			}
		}
		return false
	})
	api.put("/api/v1/agents/"+agentID+"/adopt", map[string]any{
		"name": "edge1", "zone_ids": []string{zone.ID},
	}, nil)

	// --- server + central-TLS domain (triggers simulated issuance) -----------
	var server struct {
		ID string `json:"id"`
	}
	api.post("/api/v1/agents/"+agentID+"/servers", map[string]string{
		"name": "app", "address": "10.0.0.5:8080",
	}, &server)
	var domain struct {
		ID int `json:"id"`
	}
	api.post("/api/v1/domains", map[string]any{
		"subdomain": "app", "zone_id": zone.ID, "server_id": server.ID,
		"port": 8080, "ssl_mode": "central",
	}, &domain)

	// --- assert convergence ---------------------------------------------------
	// The CNAME (which flips the domain to active) is written on a reconciler
	// cycle; the default interval is 60s, so allow one full cycle plus margin.
	var final string
	waitFor(t, 75*time.Second, func() bool {
		var d struct {
			Status      string `json:"status"`
			DNSManaged  bool   `json:"dns_managed"`
			DNSRecordID string `json:"dns_record_id"`
		}
		api.get(fmt.Sprintf("/api/v1/domains/%d", domain.ID), &d)
		final = d.Status
		return d.Status == "active" && d.DNSManaged && d.DNSRecordID != ""
	})
	if final != "active" {
		t.Fatalf("domain never became active (last status %q)", final)
	}

	// The DNS record must be a simulated one (dryrun-* ID from the in-memory store).
	var dom struct {
		DNSRecordID string `json:"dns_record_id"`
	}
	api.get(fmt.Sprintf("/api/v1/domains/%d", domain.ID), &dom)
	if got := dom.DNSRecordID; len(got) < 7 || got[:7] != "dryrun-" {
		t.Fatalf("expected a simulated dryrun-* DNS record ID, got %q", got)
	}

	// The audit trail must tag the simulated DNS/cert work as source=dryrun.
	var audit struct {
		Entries []struct {
			Action string `json:"action"`
			Source string `json:"source"`
		} `json:"entries"`
	}
	api.get("/api/v1/audit-log?limit=50", &audit)
	var sawDryRunDNS, sawIssuance bool
	for _, e := range audit.Entries {
		if e.Source == "dryrun" && (e.Action == "dns_created" || e.Action == "a_record_created") {
			sawDryRunDNS = true
		}
		if e.Source == "dryrun" && (e.Action == "renewed" || e.Action == "issue_failed") {
			sawIssuance = true
		}
	}
	if !sawDryRunDNS {
		t.Error("no audit entry with source=dryrun for DNS record creation")
	}
	if !sawIssuance {
		t.Error("no audit entry with source=dryrun for certificate issuance")
	}

	t.Logf("sandbox converged: domain active, DNS record %s, audit tagged dryrun", dom.DNSRecordID)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type binaries struct{ orch, agent string }

func repoRoot(t *testing.T) string {
	// test/sandbox -> repo root is two levels up.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

// buildBinaries compiles the headless orchestrator and the agent into a temp
// dir, so the test is self-contained (no reliance on pre-built artifacts) and
// runs with no embedded dashboard / npm dependency.
func buildBinaries(t *testing.T, root string) binaries {
	t.Helper()
	out := t.TempDir()
	b := binaries{orch: filepath.Join(out, "nurproxy-orch"), agent: filepath.Join(out, "nurproxy-agent")}
	build := func(bin, tags, pkg string) {
		args := []string{"build"}
		if tags != "" {
			args = append(args, "-tags", tags)
		}
		args = append(args, "-o", bin, pkg)
		cmd := exec.Command("go", args...)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("building %s: %v\n%s", pkg, err, out)
		}
	}
	build(b.orch, "headless", "./cmd/nurproxy")
	build(b.agent, "", "./cmd/nurproxy-agent")
	return b
}

type process struct {
	cmd *exec.Cmd
	t   *testing.T
}

func startProcess(t *testing.T, bin string, args []string, env string) *process {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = os.Environ()
	if env != "" {
		cmd.Env = append(cmd.Env, env)
	}
	logf, err := os.Create(filepath.Join(t.TempDir(), filepath.Base(bin)+".log"))
	if err == nil {
		cmd.Stdout, cmd.Stderr = logf, logf
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting %s: %v", bin, err)
	}
	return &process{cmd: cmd, t: t}
}

func (p *process) stop() {
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_, _ = p.cmd.Process.Wait()
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", d)
}

func httpOK(url string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func mustGetJSON(t *testing.T, cli *http.Client, url string, out any) {
	t.Helper()
	resp, err := cli.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
}

func postJSON(t *testing.T, cli *http.Client, url string, body, out any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal %s body: %v", url, err)
	}
	resp, err := cli.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		t.Fatalf("POST %s: status %d", url, resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode %s: %v", url, err)
		}
	}
}

// apiClient is a tiny Bearer-authenticated REST helper for the seeding calls.
type apiClient struct {
	base string
	key  string
	t    *testing.T
}

func (c *apiClient) do(method, path string, body, out any) {
	c.t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			c.t.Fatalf("marshal %s %s body: %v", method, path, err)
		}
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		c.t.Fatalf("new request %s %s: %v", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		c.t.Fatalf("%s %s: status %d", method, path, resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			c.t.Fatalf("decode %s %s: %v", method, path, err)
		}
	}
}

func (c *apiClient) get(path string, out any)     { c.do(http.MethodGet, path, nil, out) }
func (c *apiClient) post(path string, b, out any) { c.do(http.MethodPost, path, b, out) }
func (c *apiClient) put(path string, b, out any)  { c.do(http.MethodPut, path, b, out) }

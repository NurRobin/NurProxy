package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	agentconfig "github.com/NurRobin/NurProxy/internal/agent/config"
)

// claimResponse is the orchestrator's reply to POST .../admin-ops/claim (§19):
// the op id, its type, and the op-type-specific payload (left raw so the switch
// on op_type decodes it into the right typed struct).
type claimResponse struct {
	ID      string          `json:"id"`
	OpType  string          `json:"op_type"`
	Payload json.RawMessage `json:"payload"`
}

// setProxyModePayload mirrors models.SetProxyModePayload plus an optional
// proxy_binary the payload may carry (§19). Decoded from claimResponse.Payload
// when op_type == set_proxy_mode.
type setProxyModePayload struct {
	ProxyMode      string   `json:"proxy_mode"`
	ProxyType      string   `json:"proxy_type"`
	ProxyConfigDir string   `json:"proxy_config_dir"`
	ProxyBinary    string   `json:"proxy_binary"`
	ProxyReloadCmd string   `json:"proxy_reload_cmd"`
	ProxyTestCmd   string   `json:"proxy_test_cmd"`
	ProxyService   string   `json:"proxy_service"`
	ProxyLogPaths  []string `json:"proxy_log_paths"`
}

// reconfigureResult mirrors the local agent API's POST /admin/reconfigure
// response (§19): the human message plus optional remediation the operator runs
// to grant the agent file-write/reload rights.
type reconfigureResult struct {
	OK          bool                `json:"ok"`
	Message     string              `json:"message"`
	Remediation *remediationPayload `json:"remediation,omitempty"`
}

type remediationPayload struct {
	Steps       []remediationStepPayload `json:"steps"`
	SudoersLine string                   `json:"sudoers_line"`
}

type remediationStepPayload struct {
	Title    string   `json:"title"`
	Commands []string `json:"commands"`
}

// errCodeNotFound signals the orchestrator returned 404 on claim (wrong,
// expired, or already-used code) — a clean non-fatal user error.
var errCodeNotFound = errors.New("code not found")

// cmdApply handles `nurproxy-agent apply <CODE>`. It claims a pending admin
// change from the orchestrator using the host's local identity, persists it to
// agent.yaml, hot-applies it via the local agent API, prints any permission
// remediation, and acks the result (§19).
func cmdApply(args []string) {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	dataDir := fs.String("data-dir", "/var/lib/nurproxy-agent", "Data directory")
	orchestrator := fs.String("orchestrator", "", "Orchestrator URL (overrides runtime.json/agent.yaml)")
	apiPort := fs.Int("api-port", 0, "Agent API port (overrides runtime.json/agent.yaml)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nurproxy-agent apply <CODE> [--data-dir DIR] [--orchestrator URL] [--api-port N]")
		fs.PrintDefaults()
	}
	// Separate the positional <CODE> from the flags. Go's flag package stops
	// parsing at the first non-flag token, so `apply <CODE> --orchestrator X`
	// would otherwise drop every flag. Pull a leading positional, then parse the
	// rest; if the code came after the flags instead, recover it from fs.Arg(0).
	var code string
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		code = args[0]
		rest = args[1:]
	}
	_ = fs.Parse(rest)
	if code == "" && fs.NArg() > 0 {
		code = fs.Arg(0)
	}
	if code == "" {
		fmt.Fprintln(os.Stderr, "error: apply requires a confirmation code, e.g. `nurproxy-agent apply XXXX-XXXX`")
		os.Exit(2)
	}
	code = normalizeCode(code)

	if err := runApply(*dataDir, *orchestrator, *apiPort, code); err != nil {
		if errors.Is(err, errCodeNotFound) {
			fmt.Fprintln(os.Stderr, "error: no matching pending change — wrong, expired, or already-used code")
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// normalizeCode trims and upper-cases the confirmation code so casing/spacing
// from a copy-paste doesn't cause a spurious 404.
func normalizeCode(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

// runApply performs the claim → persist → hot-apply → ack flow. It returns
// errCodeNotFound for a 404 claim and a wrapped error for hard failures
// (unreadable identity, unwritable config, transport errors on the claim/ack).
func runApply(dataDir, orchestratorFlag string, apiPortFlag int, code string) error {
	// Resolution order: explicit flags > runtime.json > agent.yaml.
	ri, err := agentconfig.LoadRuntimeInfo(dataDir)
	if err != nil {
		return fmt.Errorf("reading runtime.json: %w", err)
	}
	// agent.yaml is a best-effort fallback for orchestrator/api-port. Loading it
	// here does NOT validate required fields (we read the raw file), so a host
	// that supplies identity via env still resolves.
	fileOrch, fileAPIPort := readConfigFallback(dataDir)

	orchestrator := firstNonEmpty(orchestratorFlag, ri.OrchestratorURL, fileOrch)
	if orchestrator == "" {
		return fmt.Errorf("could not resolve orchestrator URL (pass --orchestrator, or run apply on a host that has started the agent at least once)")
	}
	orchestrator = strings.TrimRight(orchestrator, "/")

	apiPort := apiPortFlag
	if apiPort == 0 {
		apiPort = ri.APIPort
	}
	if apiPort == 0 {
		apiPort = fileAPIPort
	}
	if apiPort == 0 {
		apiPort = 8780
	}

	token, err := readDataFile(dataDir, "token")
	if err != nil {
		return fmt.Errorf("reading agent token from %s: %w", filepath.Join(dataDir, "token"), err)
	}
	agentID, err := readDataFile(dataDir, "agent-id")
	if err != nil {
		return fmt.Errorf("reading agent id from %s: %w", filepath.Join(dataDir, "agent-id"), err)
	}
	// Prefer the runtime-recorded agent id if the file somehow disagrees; the file
	// is authoritative, so only fall back to runtime.json when the file is blank.
	if agentID == "" {
		agentID = ri.AgentID
	}
	if agentID == "" {
		return fmt.Errorf("could not resolve agent id (no %s and no runtime.json)", filepath.Join(dataDir, "agent-id"))
	}

	client := &http.Client{Timeout: 30 * time.Second}
	ctx := context.Background()

	// Step 2: claim.
	claim, err := claimAdminOp(ctx, client, orchestrator, agentID, token, code)
	if err != nil {
		return err
	}

	// Step 3: future-proof op-type switch.
	if claim.OpType != "set_proxy_mode" {
		fmt.Printf("unsupported op %q — this agent build does not know how to apply it\n", claim.OpType)
		// Ack so the orchestrator stops showing it pending; report we couldn't apply.
		_ = ackAdminOp(ctx, client, orchestrator, agentID, token, claim.ID, false, "unsupported op "+claim.OpType)
		return nil
	}

	var p setProxyModePayload
	if err := json.Unmarshal(claim.Payload, &p); err != nil {
		return fmt.Errorf("decoding set_proxy_mode payload: %w", err)
	}

	// Step 4: persist into agent.yaml (survives restart, preserves other keys).
	if _, err := agentconfig.ApplyProxyConfig(dataDir, agentconfig.ProxyConfigUpdate{
		Mode:      p.ProxyMode,
		Type:      p.ProxyType,
		ConfigDir: p.ProxyConfigDir,
		Binary:    p.ProxyBinary,
		ReloadCmd: p.ProxyReloadCmd,
		TestCmd:   p.ProxyTestCmd,
		Service:   p.ProxyService,
		LogPaths:  p.ProxyLogPaths,
	}); err != nil {
		return fmt.Errorf("persisting proxy config: %w", err)
	}
	fmt.Printf("saved to %s\n", filepath.Join(dataDir, "agent.yaml"))

	// Step 5: hot-apply via the local agent API.
	res, reachable, err := reconfigureLocal(ctx, apiPort, token, p)

	var ackOK bool
	var ackResult string

	if !reachable {
		fmt.Println("the running agent is not reachable on the local API — the saved config will take effect on next start")
		if err != nil {
			fmt.Printf("  (%v)\n", err)
		}
		ackOK = false
		ackResult = "saved to agent.yaml; agent not running, will apply on next start"
	} else if err != nil {
		// Reachable but the call/decoding failed — treat as a soft failure but still ack.
		fmt.Printf("the agent rejected the live reconfigure: %v\n", err)
		ackOK = false
		ackResult = "saved to agent.yaml; live reconfigure failed: " + err.Error()
	} else {
		// Step 6: print the human result + any remediation.
		printReconfigureResult(res)
		ackOK = res.OK
		if res.OK && res.Remediation == nil {
			ackResult = "applied; permissions OK"
		} else if res.OK {
			ackResult = "applied; missing write/reload — see remediation"
		} else {
			ackResult = "applied with warnings; " + res.Message
		}
	}

	// Step 7: ack the orchestrator.
	if err := ackAdminOp(ctx, client, orchestrator, agentID, token, claim.ID, ackOK, ackResult); err != nil {
		return fmt.Errorf("acking admin op: %w", err)
	}

	// Step 8: success — even if permissions still need granting (non-fatal).
	return nil
}

// claimAdminOp POSTs the confirmation code to the orchestrator and returns the
// op. A 404 maps to errCodeNotFound; other non-200s are hard errors.
func claimAdminOp(ctx context.Context, client *http.Client, orchestrator, agentID, token, code string) (*claimResponse, error) {
	body, _ := json.Marshal(map[string]string{"code": code})
	url := fmt.Sprintf("%s/api/v1/agents/%s/admin-ops/claim", orchestrator, agentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building claim request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("contacting orchestrator: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errCodeNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("claim failed with status %d", resp.StatusCode)
	}

	var cr claimResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return nil, fmt.Errorf("decoding claim response: %w", err)
	}
	return &cr, nil
}

// ackAdminOp POSTs the apply outcome back to the orchestrator.
func ackAdminOp(ctx context.Context, client *http.Client, orchestrator, agentID, token, opID string, ok bool, result string) error {
	body, _ := json.Marshal(map[string]interface{}{"ok": ok, "result": result})
	url := fmt.Sprintf("%s/api/v1/agents/%s/admin-ops/%s/ack", orchestrator, agentID, opID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building ack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("contacting orchestrator: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ack failed with status %d", resp.StatusCode)
	}
	return nil
}

// reconfigureLocal POSTs to the local agent API to hot-switch the proxy backend.
// The bool return reports whether the local agent was reachable: a connection
// error (agent not running) yields reachable=false so the caller can fall back
// to "applies on next start" rather than treating it as a hard failure.
func reconfigureLocal(ctx context.Context, apiPort int, token string, p setProxyModePayload) (reconfigureResult, bool, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"proxy_mode":       p.ProxyMode,
		"proxy_type":       p.ProxyType,
		"proxy_config_dir": p.ProxyConfigDir,
		"proxy_binary":     p.ProxyBinary,
		"proxy_reload_cmd": p.ProxyReloadCmd,
		"proxy_test_cmd":   p.ProxyTestCmd,
		"proxy_service":    p.ProxyService,
		"proxy_log_paths":  p.ProxyLogPaths,
	})
	url := fmt.Sprintf("http://127.0.0.1:%d/admin/reconfigure", apiPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return reconfigureResult{}, false, fmt.Errorf("building reconfigure request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// Connection refused / no listener: the agent isn't running locally.
		return reconfigureResult{}, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return reconfigureResult{}, true, fmt.Errorf("local agent returned status %d", resp.StatusCode)
	}

	var res reconfigureResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return reconfigureResult{}, true, fmt.Errorf("decoding reconfigure response: %w", err)
	}
	return res, true, nil
}

// printReconfigureResult prints the human-readable outcome of a hot-switch: the
// message and, if permissions are missing, the copy-paste remediation (§19 hard
// requirement).
func printReconfigureResult(res reconfigureResult) {
	if res.Message != "" {
		fmt.Println(res.Message)
	}
	if res.Remediation == nil {
		return
	}
	fmt.Println()
	fmt.Println("To grant the agent the required permissions, run:")
	for _, step := range res.Remediation.Steps {
		fmt.Println()
		if step.Title != "" {
			fmt.Printf("  %s\n", step.Title)
		}
		for _, cmd := range step.Commands {
			fmt.Printf("    %s\n", cmd)
		}
	}
	if res.Remediation.SudoersLine != "" {
		fmt.Println()
		fmt.Println("  Scoped sudoers line (/etc/sudoers.d/nurproxy-agent):")
		fmt.Printf("    echo '%s' | sudo tee /etc/sudoers.d/nurproxy-agent && sudo visudo -c\n", res.Remediation.SudoersLine)
	}
}

// readDataFile reads and trims a single-line file (token, agent-id) from the
// data dir. A missing file is an error for the token/id (the host isn't adopted).
func readDataFile(dataDir, name string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dataDir, name))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// readConfigFallback reads orchestrator + api_port from agent.yaml without
// validating required fields, for the resolution fallback. Errors are swallowed
// (best-effort): a missing/garbage file just yields empties.
func readConfigFallback(dataDir string) (orchestrator string, apiPort int) {
	cfg, err := agentconfig.LoadRaw(dataDir)
	if err != nil || cfg == nil {
		return "", 0
	}
	return cfg.OrchestratorURL, cfg.APIPort
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

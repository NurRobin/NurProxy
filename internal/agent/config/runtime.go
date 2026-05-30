package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// RuntimeInfo records the runtime facts a freshly-started agent knows but that
// don't live in agent.yaml as the source of truth: its resolved orchestrator
// URL, the local API port it bound, and its adopted agent ID. The CLI reads
// this so `nurproxy-agent apply <code>` works zero-arg after install (§19),
// without re-deriving identity from env/flags. It is written non-destructively
// on every startup and is purely a convenience cache — never authoritative.
type RuntimeInfo struct {
	OrchestratorURL string `json:"orchestrator_url"`
	APIPort         int    `json:"api_port"`
	AgentID         string `json:"agent_id"`
}

// SaveRuntimeInfo writes <dataDir>/runtime.json (0600), creating the data dir if
// needed. Tiny, non-destructive: it only records the current runtime facts.
func SaveRuntimeInfo(dataDir string, ri RuntimeInfo) error {
	if dataDir == "" {
		return fmt.Errorf("data dir is required to save runtime.json")
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("creating data directory: %w", err)
	}
	data, err := json.MarshalIndent(ri, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling runtime.json: %w", err)
	}
	path := filepath.Join(dataDir, "runtime.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// LoadRuntimeInfo reads <dataDir>/runtime.json. A missing file yields a zero
// RuntimeInfo and no error, so callers can layer it under explicit flags and
// agent.yaml without special-casing a fresh install.
func LoadRuntimeInfo(dataDir string) (RuntimeInfo, error) {
	path := filepath.Join(dataDir, "runtime.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return RuntimeInfo{}, nil
		}
		return RuntimeInfo{}, err
	}
	var ri RuntimeInfo
	if err := json.Unmarshal(data, &ri); err != nil {
		return RuntimeInfo{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	return ri, nil
}

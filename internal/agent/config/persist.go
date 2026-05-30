package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Save writes cfg to <dataDir>/agent.yaml as YAML (0600). It creates the data
// dir if needed. This is the persisted source of truth the agent reloads on
// startup (Load reads the same file), so a CLI-driven change survives restarts.
func Save(cfg *Config, dataDir string) error {
	if dataDir == "" {
		return fmt.Errorf("data dir is required to save agent.yaml")
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("creating data directory: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling agent.yaml: %w", err)
	}
	path := filepath.Join(dataDir, "agent.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// LoadRaw reads <dataDir>/agent.yaml into a Config WITHOUT applying defaults,
// env, flags, or required-field validation. It is for callers (e.g. the apply
// CLI) that need the on-disk values as a best-effort fallback for identity
// resolution and must not fail just because orchestrator/fqdn aren't in the
// file. A missing file yields (nil, nil).
func LoadRaw(dataDir string) (*Config, error) {
	return loadFile(filepath.Join(dataDir, "agent.yaml"))
}

// ProxyConfigUpdate carries the proxy_* fields of an admin change (§19). It is
// the subset of Config a set_proxy_mode op may alter; everything else in
// agent.yaml (orchestrator, fqdn, ports, …) is preserved untouched.
type ProxyConfigUpdate struct {
	Mode      string
	Type      string
	ConfigDir string
	Binary    string
	ReloadCmd string
	TestCmd   string
	Service   string
	LogPaths  []string
}

// ApplyProxyConfig persists a proxy-mode change to <dataDir>/agent.yaml without
// clobbering the rest of the file (§19). It loads the existing agent.yaml (or
// starts from a minimal config if none exists), overwrites only the proxy_*
// fields from p, writes the file back, and returns the merged Config. The
// returned config is NOT validated for required fields (orchestrator/fqdn) —
// those may legitimately be supplied via env/flags at runtime — so this never
// rejects a host that configures identity outside the file.
func ApplyProxyConfig(dataDir string, p ProxyConfigUpdate) (*Config, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("data dir is required to apply proxy config")
	}

	path := filepath.Join(dataDir, "agent.yaml")
	existing, err := loadFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading existing config: %w", err)
	}

	// Start from defaults, layer the existing file (if any) over them, then apply
	// the proxy_* changes. Defaults keep ports sane if the file omitted them.
	cfg := defaults()
	if existing != nil {
		mergeFile(&cfg, existing)
	}
	cfg.DataDir = dataDir

	cfg.ProxyMode = ProxyMode(p.Mode)
	cfg.ProxyType = p.Type
	cfg.ProxyConfigDir = p.ConfigDir
	cfg.ProxyBinary = p.Binary
	cfg.ProxyReloadCmd = p.ReloadCmd
	cfg.ProxyTestCmd = p.TestCmd
	cfg.ProxyService = p.Service
	cfg.ProxyLogPaths = p.LogPaths

	if err := Save(&cfg, dataDir); err != nil {
		return nil, err
	}
	return &cfg, nil
}

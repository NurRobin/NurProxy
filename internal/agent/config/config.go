package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ProxyMode selects how the agent manages a reverse proxy on its host (§2).
type ProxyMode string

const (
	// ProxyModeBuiltIn runs the bundled Caddy via its admin API — today's
	// zero-config default path.
	ProxyModeBuiltIn ProxyMode = "built-in"
	// ProxyModeExisting manages an already-installed nginx/apache/caddy via
	// on-disk config files + reload (opt-in, guided setup).
	ProxyModeExisting ProxyMode = "existing"
)

// Config holds the resolved agent configuration.
type Config struct {
	OrchestratorURL string `yaml:"orchestrator"`
	FQDN            string `yaml:"fqdn"`
	DataDir         string `yaml:"data_dir"`
	APIPort         int    `yaml:"api_port"`
	CaddyAdminPort  int    `yaml:"caddy_admin_port"`

	// ProxyMode selects built-in (bundled Caddy, default) vs existing (manage an
	// installed proxy on disk), per §2/§9.
	ProxyMode ProxyMode `yaml:"proxy_mode"`
	// ProxyType is the existing proxy's kind (caddy | nginx | apache); only
	// meaningful when ProxyMode is "existing" (§9).
	ProxyType string `yaml:"proxy_type"`
	// ProxyBinary overrides the detected proxy binary path (§9).
	ProxyBinary string `yaml:"proxy_binary"`
	// ProxyConfigDir overrides the detected config directory (§9).
	ProxyConfigDir string `yaml:"proxy_config_dir"`
	// ProxyReloadCmd overrides the service reload command (§9).
	ProxyReloadCmd string `yaml:"proxy_reload_cmd"`
	// ProxyTestCmd overrides the config-validate command (e.g. `nginx -t`) (§9).
	ProxyTestCmd string `yaml:"proxy_test_cmd"`
	// ProxyLogPaths are the error/access logs to surface in the dashboard (§9,
	// §15). Parsed from a comma-separated flag/env value or a YAML list.
	ProxyLogPaths []string `yaml:"proxy_log_paths"`
	// ProxyService is the service unit (systemd/openrc/launchd) used for reloads
	// (§9).
	ProxyService string `yaml:"proxy_service"`
}

// Flags carries the command-line flag values into Load. Each field mirrors a
// flag; an empty / zero value means "flag not set", so the layered priority
// (flags > env > config file > defaults) can skip it.
type Flags struct {
	Orchestrator string
	FQDN         string
	DataDir      string
	APIPort      int
	CaddyPort    int

	ProxyMode      string
	ProxyType      string
	ProxyBinary    string
	ProxyConfigDir string
	ProxyReloadCmd string
	ProxyTestCmd   string
	ProxyLogPaths  string // comma-separated
	ProxyService   string
}

// defaults returns a Config with default values applied.
func defaults() Config {
	return Config{
		DataDir:        "/var/lib/nurproxy-agent",
		APIPort:        8780,
		CaddyAdminPort: 2019,
		ProxyMode:      ProxyModeBuiltIn,
	}
}

// Load merges configuration from flags, environment variables, a YAML config
// file, and defaults. Priority: flags > env > config file > defaults.
func Load(f Flags) (*Config, error) {
	cfg := defaults()

	// Determine data dir early so we can find the config file.
	// We need data dir from flags first, then env, then keep default.
	dataDir := cfg.DataDir
	if f.DataDir != "" {
		dataDir = f.DataDir
	}
	if v := os.Getenv("NP_DATA_DIR"); v != "" {
		dataDir = v
	}
	// Flag still takes priority over env; re-apply if flag was set.
	if f.DataDir != "" {
		dataDir = f.DataDir
	}

	// Load config file if it exists.
	configPath := filepath.Join(dataDir, "agent.yaml")
	fileCfg, err := loadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("loading config file %s: %w", configPath, err)
	}

	// Layer 1: config file over defaults.
	if fileCfg != nil {
		mergeFile(&cfg, fileCfg)
	}

	// Layer 2: environment variables over config file.
	mergeEnv(&cfg)

	// Layer 3: flags over everything.
	mergeFlags(&cfg, f)

	// Validate required fields.
	if cfg.OrchestratorURL == "" {
		return nil, fmt.Errorf("orchestrator URL is required (flag --orchestrator or env NP_ORCHESTRATOR)")
	}
	if cfg.FQDN == "" {
		return nil, fmt.Errorf("FQDN is required (flag --fqdn or env NP_FQDN)")
	}
	if cfg.ProxyMode != ProxyModeBuiltIn && cfg.ProxyMode != ProxyModeExisting {
		return nil, fmt.Errorf("invalid proxy_mode %q (must be %q or %q)", cfg.ProxyMode, ProxyModeBuiltIn, ProxyModeExisting)
	}

	return &cfg, nil
}

func loadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}
	return &cfg, nil
}

func mergeFile(dst *Config, src *Config) {
	if src.OrchestratorURL != "" {
		dst.OrchestratorURL = src.OrchestratorURL
	}
	if src.FQDN != "" {
		dst.FQDN = src.FQDN
	}
	if src.DataDir != "" {
		dst.DataDir = src.DataDir
	}
	if src.APIPort != 0 {
		dst.APIPort = src.APIPort
	}
	if src.CaddyAdminPort != 0 {
		dst.CaddyAdminPort = src.CaddyAdminPort
	}
	if src.ProxyMode != "" {
		dst.ProxyMode = src.ProxyMode
	}
	if src.ProxyType != "" {
		dst.ProxyType = src.ProxyType
	}
	if src.ProxyBinary != "" {
		dst.ProxyBinary = src.ProxyBinary
	}
	if src.ProxyConfigDir != "" {
		dst.ProxyConfigDir = src.ProxyConfigDir
	}
	if src.ProxyReloadCmd != "" {
		dst.ProxyReloadCmd = src.ProxyReloadCmd
	}
	if src.ProxyTestCmd != "" {
		dst.ProxyTestCmd = src.ProxyTestCmd
	}
	if len(src.ProxyLogPaths) > 0 {
		dst.ProxyLogPaths = src.ProxyLogPaths
	}
	if src.ProxyService != "" {
		dst.ProxyService = src.ProxyService
	}
}

func mergeEnv(cfg *Config) {
	if v := os.Getenv("NP_ORCHESTRATOR"); v != "" {
		cfg.OrchestratorURL = v
	}
	if v := os.Getenv("NP_FQDN"); v != "" {
		cfg.FQDN = v
	}
	if v := os.Getenv("NP_DATA_DIR"); v != "" {
		cfg.DataDir = v
	}
	if v := os.Getenv("NP_API_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.APIPort = port
		}
	}
	if v := os.Getenv("NP_PROXY_MODE"); v != "" {
		cfg.ProxyMode = ProxyMode(v)
	}
	if v := os.Getenv("NP_PROXY_TYPE"); v != "" {
		cfg.ProxyType = v
	}
	if v := os.Getenv("NP_PROXY_BINARY"); v != "" {
		cfg.ProxyBinary = v
	}
	if v := os.Getenv("NP_PROXY_CONFIG_DIR"); v != "" {
		cfg.ProxyConfigDir = v
	}
	if v := os.Getenv("NP_PROXY_RELOAD_CMD"); v != "" {
		cfg.ProxyReloadCmd = v
	}
	if v := os.Getenv("NP_PROXY_TEST_CMD"); v != "" {
		cfg.ProxyTestCmd = v
	}
	if v := os.Getenv("NP_PROXY_LOG_PATHS"); v != "" {
		cfg.ProxyLogPaths = parseLogPaths(v)
	}
	if v := os.Getenv("NP_PROXY_SERVICE"); v != "" {
		cfg.ProxyService = v
	}
}

func mergeFlags(cfg *Config, f Flags) {
	if f.Orchestrator != "" {
		cfg.OrchestratorURL = f.Orchestrator
	}
	if f.FQDN != "" {
		cfg.FQDN = f.FQDN
	}
	if f.DataDir != "" {
		cfg.DataDir = f.DataDir
	}
	if f.APIPort != 0 {
		cfg.APIPort = f.APIPort
	}
	if f.CaddyPort != 0 {
		cfg.CaddyAdminPort = f.CaddyPort
	}
	if f.ProxyMode != "" {
		cfg.ProxyMode = ProxyMode(f.ProxyMode)
	}
	if f.ProxyType != "" {
		cfg.ProxyType = f.ProxyType
	}
	if f.ProxyBinary != "" {
		cfg.ProxyBinary = f.ProxyBinary
	}
	if f.ProxyConfigDir != "" {
		cfg.ProxyConfigDir = f.ProxyConfigDir
	}
	if f.ProxyReloadCmd != "" {
		cfg.ProxyReloadCmd = f.ProxyReloadCmd
	}
	if f.ProxyTestCmd != "" {
		cfg.ProxyTestCmd = f.ProxyTestCmd
	}
	if f.ProxyLogPaths != "" {
		cfg.ProxyLogPaths = parseLogPaths(f.ProxyLogPaths)
	}
	if f.ProxyService != "" {
		cfg.ProxyService = f.ProxyService
	}
}

// parseLogPaths splits a comma-separated log-path list (flag/env form) into a
// trimmed slice, dropping empty entries. A blank input yields a nil slice.
func parseLogPaths(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

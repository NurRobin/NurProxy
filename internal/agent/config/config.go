package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Config holds the resolved agent configuration.
type Config struct {
	OrchestratorURL string `yaml:"orchestrator"`
	FQDN            string `yaml:"fqdn"`
	DataDir         string `yaml:"data_dir"`
	APIPort         int    `yaml:"api_port"`
	CaddyAdminPort  int    `yaml:"caddy_admin_port"`
}

// defaults returns a Config with default values applied.
func defaults() Config {
	return Config{
		DataDir:        "/var/lib/nurproxy-agent",
		APIPort:        8780,
		CaddyAdminPort: 2019,
	}
}

// Load merges configuration from flags, environment variables, a YAML config
// file, and defaults. Priority: flags > env > config file > defaults.
func Load(flagOrchestrator, flagFQDN, flagDataDir string, flagAPIPort, flagCaddyPort int) (*Config, error) {
	cfg := defaults()

	// Determine data dir early so we can find the config file.
	// We need data dir from flags first, then env, then keep default.
	dataDir := cfg.DataDir
	if flagDataDir != "" {
		dataDir = flagDataDir
	}
	if v := os.Getenv("NP_DATA_DIR"); v != "" {
		dataDir = v
	}
	// Flag still takes priority over env; re-apply if flag was set.
	if flagDataDir != "" {
		dataDir = flagDataDir
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
	mergeFlags(&cfg, flagOrchestrator, flagFQDN, flagDataDir, flagAPIPort, flagCaddyPort)

	// Validate required fields.
	if cfg.OrchestratorURL == "" {
		return nil, fmt.Errorf("orchestrator URL is required (flag --orchestrator or env NP_ORCHESTRATOR)")
	}
	if cfg.FQDN == "" {
		return nil, fmt.Errorf("FQDN is required (flag --fqdn or env NP_FQDN)")
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
}

func mergeFlags(cfg *Config, orchestrator, fqdn, dataDir string, apiPort, caddyPort int) {
	if orchestrator != "" {
		cfg.OrchestratorURL = orchestrator
	}
	if fqdn != "" {
		cfg.FQDN = fqdn
	}
	if dataDir != "" {
		cfg.DataDir = dataDir
	}
	if apiPort != 0 {
		cfg.APIPort = apiPort
	}
	if caddyPort != 0 {
		cfg.CaddyAdminPort = caddyPort
	}
}

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	dir := t.TempDir()

	// Provide required fields via flags, let everything else default.
	cfg, err := Load("http://orchestrator:8080", "agent.example.com", dir, 0, 0)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.OrchestratorURL != "http://orchestrator:8080" {
		t.Errorf("OrchestratorURL = %q, want %q", cfg.OrchestratorURL, "http://orchestrator:8080")
	}
	if cfg.FQDN != "agent.example.com" {
		t.Errorf("FQDN = %q, want %q", cfg.FQDN, "agent.example.com")
	}
	if cfg.DataDir != dir {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, dir)
	}
	if cfg.APIPort != 8780 {
		t.Errorf("APIPort = %d, want %d", cfg.APIPort, 8780)
	}
	if cfg.CaddyAdminPort != 2019 {
		t.Errorf("CaddyAdminPort = %d, want %d", cfg.CaddyAdminPort, 2019)
	}
}

func TestLoadFromConfigFile(t *testing.T) {
	dir := t.TempDir()

	configContent := `orchestrator: http://from-file:9090
fqdn: file.example.com
api_port: 9999
caddy_admin_port: 3030
`
	if err := os.WriteFile(filepath.Join(dir, "agent.yaml"), []byte(configContent), 0644); err != nil {
		t.Fatalf("writing config file: %v", err)
	}

	// Pass empty flags except data dir (needed to find the file).
	cfg, err := Load("", "", dir, 0, 0)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.OrchestratorURL != "http://from-file:9090" {
		t.Errorf("OrchestratorURL = %q, want %q", cfg.OrchestratorURL, "http://from-file:9090")
	}
	if cfg.FQDN != "file.example.com" {
		t.Errorf("FQDN = %q, want %q", cfg.FQDN, "file.example.com")
	}
	if cfg.APIPort != 9999 {
		t.Errorf("APIPort = %d, want %d", cfg.APIPort, 9999)
	}
	if cfg.CaddyAdminPort != 3030 {
		t.Errorf("CaddyAdminPort = %d, want %d", cfg.CaddyAdminPort, 3030)
	}
}

func TestLoadEnvOverridesFile(t *testing.T) {
	dir := t.TempDir()

	configContent := `orchestrator: http://from-file:9090
fqdn: file.example.com
`
	if err := os.WriteFile(filepath.Join(dir, "agent.yaml"), []byte(configContent), 0644); err != nil {
		t.Fatalf("writing config file: %v", err)
	}

	t.Setenv("NP_ORCHESTRATOR", "http://from-env:7070")
	t.Setenv("NP_FQDN", "env.example.com")

	cfg, err := Load("", "", dir, 0, 0)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.OrchestratorURL != "http://from-env:7070" {
		t.Errorf("OrchestratorURL = %q, want %q", cfg.OrchestratorURL, "http://from-env:7070")
	}
	if cfg.FQDN != "env.example.com" {
		t.Errorf("FQDN = %q, want %q", cfg.FQDN, "env.example.com")
	}
}

func TestLoadFlagOverridesEnv(t *testing.T) {
	dir := t.TempDir()

	t.Setenv("NP_ORCHESTRATOR", "http://from-env:7070")
	t.Setenv("NP_FQDN", "env.example.com")

	cfg, err := Load("http://from-flag:6060", "flag.example.com", dir, 1234, 5678)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.OrchestratorURL != "http://from-flag:6060" {
		t.Errorf("OrchestratorURL = %q, want %q", cfg.OrchestratorURL, "http://from-flag:6060")
	}
	if cfg.FQDN != "flag.example.com" {
		t.Errorf("FQDN = %q, want %q", cfg.FQDN, "flag.example.com")
	}
	if cfg.APIPort != 1234 {
		t.Errorf("APIPort = %d, want %d", cfg.APIPort, 1234)
	}
	if cfg.CaddyAdminPort != 5678 {
		t.Errorf("CaddyAdminPort = %d, want %d", cfg.CaddyAdminPort, 5678)
	}
}

func TestLoadMissingRequired(t *testing.T) {
	dir := t.TempDir()

	// No orchestrator.
	_, err := Load("", "", dir, 0, 0)
	if err == nil {
		t.Fatal("expected error for missing orchestrator, got nil")
	}

	// Orchestrator but no FQDN.
	_, err = Load("http://orch:8080", "", dir, 0, 0)
	if err == nil {
		t.Fatal("expected error for missing FQDN, got nil")
	}
}

func TestLoadEnvAPIPort(t *testing.T) {
	dir := t.TempDir()

	t.Setenv("NP_API_PORT", "4444")

	cfg, err := Load("http://orch:8080", "test.example.com", dir, 0, 0)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.APIPort != 4444 {
		t.Errorf("APIPort = %d, want %d", cfg.APIPort, 4444)
	}
}

func TestLoadNoConfigFile(t *testing.T) {
	dir := t.TempDir()

	// No config file at all — should still work with flags.
	cfg, err := Load("http://orch:8080", "test.example.com", dir, 0, 0)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.OrchestratorURL != "http://orch:8080" {
		t.Errorf("OrchestratorURL = %q, want %q", cfg.OrchestratorURL, "http://orch:8080")
	}
}

func TestLoadEnvDataDir(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	// Write config to dir2.
	configContent := `orchestrator: http://from-file:9090
fqdn: file.example.com
`
	if err := os.WriteFile(filepath.Join(dir2, "agent.yaml"), []byte(configContent), 0644); err != nil {
		t.Fatalf("writing config file: %v", err)
	}

	// Set env to dir2, flag to dir1 (no config file there).
	t.Setenv("NP_DATA_DIR", dir2)

	// Flag data-dir takes priority for finding config file.
	// Since dir1 has no config, we should still get defaults + flag values.
	cfg, err := Load("http://flag:8080", "flag.example.com", dir1, 0, 0)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Flag should override env for data dir.
	if cfg.DataDir != dir1 {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, dir1)
	}
}

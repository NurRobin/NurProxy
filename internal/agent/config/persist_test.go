package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyProxyConfig(t *testing.T) {
	tests := []struct {
		name     string
		existing string // agent.yaml contents to seed; "" means no file
		update   ProxyConfigUpdate
		check    func(t *testing.T, cfg *Config, raw string)
	}{
		{
			name:     "creates file when none exists",
			existing: "",
			update: ProxyConfigUpdate{
				Mode:      "existing",
				Type:      "nginx",
				ConfigDir: "/etc/nginx",
				ReloadCmd: "nginx -s reload",
				TestCmd:   "nginx -t",
				Service:   "nginx",
				LogPaths:  []string{"/var/log/nginx/error.log"},
			},
			check: func(t *testing.T, cfg *Config, raw string) {
				if cfg.ProxyMode != ProxyModeExisting {
					t.Errorf("ProxyMode = %q, want existing", cfg.ProxyMode)
				}
				if cfg.ProxyType != "nginx" || cfg.ProxyConfigDir != "/etc/nginx" {
					t.Errorf("proxy fields not set: %+v", cfg)
				}
				if len(cfg.ProxyLogPaths) != 1 || cfg.ProxyLogPaths[0] != "/var/log/nginx/error.log" {
					t.Errorf("log paths = %v", cfg.ProxyLogPaths)
				}
			},
		},
		{
			name: "merges into existing file preserving other keys",
			existing: "orchestrator: https://orch.example\n" +
				"fqdn: edge1.example\n" +
				"api_port: 9999\n" +
				"caddy_admin_port: 2020\n" +
				"proxy_mode: built-in\n",
			update: ProxyConfigUpdate{
				Mode:      "existing",
				Type:      "apache",
				ConfigDir: "/etc/apache2",
			},
			check: func(t *testing.T, cfg *Config, raw string) {
				// Preserved identity/ports.
				if cfg.OrchestratorURL != "https://orch.example" {
					t.Errorf("orchestrator clobbered: %q", cfg.OrchestratorURL)
				}
				if cfg.FQDN != "edge1.example" {
					t.Errorf("fqdn clobbered: %q", cfg.FQDN)
				}
				if cfg.APIPort != 9999 {
					t.Errorf("api_port clobbered: %d", cfg.APIPort)
				}
				if cfg.CaddyAdminPort != 2020 {
					t.Errorf("caddy_admin_port clobbered: %d", cfg.CaddyAdminPort)
				}
				// Applied proxy change.
				if cfg.ProxyMode != ProxyModeExisting || cfg.ProxyType != "apache" {
					t.Errorf("proxy change not applied: %+v", cfg)
				}
				// Persisted to disk too.
				if !strings.Contains(raw, "orchestrator: https://orch.example") {
					t.Errorf("orchestrator missing from persisted file:\n%s", raw)
				}
				if !strings.Contains(raw, "proxy_type: apache") {
					t.Errorf("proxy_type missing from persisted file:\n%s", raw)
				}
			},
		},
		{
			name:     "switch back to built-in clears proxy fields",
			existing: "proxy_mode: existing\nproxy_type: nginx\nproxy_config_dir: /etc/nginx\n",
			update:   ProxyConfigUpdate{Mode: "built-in"},
			check: func(t *testing.T, cfg *Config, raw string) {
				if cfg.ProxyMode != ProxyModeBuiltIn {
					t.Errorf("ProxyMode = %q, want built-in", cfg.ProxyMode)
				}
				if cfg.ProxyType != "" || cfg.ProxyConfigDir != "" {
					t.Errorf("proxy fields not cleared: %+v", cfg)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.existing != "" {
				if err := os.WriteFile(filepath.Join(dir, "agent.yaml"), []byte(tt.existing), 0600); err != nil {
					t.Fatalf("seeding file: %v", err)
				}
			}

			cfg, err := ApplyProxyConfig(dir, tt.update)
			if err != nil {
				t.Fatalf("ApplyProxyConfig: %v", err)
			}
			if cfg.DataDir != dir {
				t.Errorf("DataDir = %q, want %q", cfg.DataDir, dir)
			}

			raw, err := os.ReadFile(filepath.Join(dir, "agent.yaml"))
			if err != nil {
				t.Fatalf("reading persisted file: %v", err)
			}

			tt.check(t, cfg, string(raw))

			// Re-loading the persisted file must reflect the same proxy mode.
			reloaded, err := LoadRaw(dir)
			if err != nil {
				t.Fatalf("LoadRaw: %v", err)
			}
			if reloaded.ProxyMode != cfg.ProxyMode {
				t.Errorf("reloaded ProxyMode = %q, want %q", reloaded.ProxyMode, cfg.ProxyMode)
			}
		})
	}
}

func TestSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{OrchestratorURL: "https://o", FQDN: "f", APIPort: 8780}
	if err := Save(cfg, dir); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := LoadRaw(dir)
	if err != nil {
		t.Fatalf("LoadRaw: %v", err)
	}
	if got.OrchestratorURL != "https://o" || got.FQDN != "f" || got.APIPort != 8780 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

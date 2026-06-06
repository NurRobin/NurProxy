package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	dir := t.TempDir()

	// Provide required fields via flags, let everything else default.
	cfg, err := Load(Flags{Orchestrator: "http://orchestrator:8080", FQDN: "agent.example.com", DataDir: dir})
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
	if cfg.ProxyMode != ProxyModeBuiltIn {
		t.Errorf("ProxyMode = %q, want %q", cfg.ProxyMode, ProxyModeBuiltIn)
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
	cfg, err := Load(Flags{DataDir: dir})
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

	cfg, err := Load(Flags{DataDir: dir})
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

	cfg, err := Load(Flags{Orchestrator: "http://from-flag:6060", FQDN: "flag.example.com", DataDir: dir, APIPort: 1234, CaddyPort: 5678})
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
	_, err := Load(Flags{DataDir: dir})
	if err == nil {
		t.Fatal("expected error for missing orchestrator, got nil")
	}

	// Orchestrator but no FQDN.
	_, err = Load(Flags{Orchestrator: "http://orch:8080", DataDir: dir})
	if err == nil {
		t.Fatal("expected error for missing FQDN, got nil")
	}
}

func TestLoadEnvAPIPort(t *testing.T) {
	dir := t.TempDir()

	t.Setenv("NP_API_PORT", "4444")

	cfg, err := Load(Flags{Orchestrator: "http://orch:8080", FQDN: "test.example.com", DataDir: dir})
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
	cfg, err := Load(Flags{Orchestrator: "http://orch:8080", FQDN: "test.example.com", DataDir: dir})
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
	cfg, err := Load(Flags{Orchestrator: "http://flag:8080", FQDN: "flag.example.com", DataDir: dir1})
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Flag should override env for data dir.
	if cfg.DataDir != dir1 {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, dir1)
	}
}

// TestLoadProxyKeys covers the §9 proxy backend config keys across all three
// sources (flag / env / yaml) plus their layered priority, the comma-list
// parsing of proxy_log_paths, and proxy_mode validation. It is table-driven: each
// case fully describes the inputs and the expected resolved Config fields.
func TestLoadProxyKeys(t *testing.T) {
	type want struct {
		mode      ProxyMode
		typ       string
		binary    string
		configDir string
		reloadCmd string
		testCmd   string
		logPaths  []string
		service   string
	}
	tests := []struct {
		name    string
		yaml    string
		env     map[string]string
		flags   Flags
		want    want
		wantErr bool
	}{
		{
			name: "all from flags",
			flags: Flags{
				ProxyMode:      "existing",
				ProxyType:      "nginx",
				ProxyBinary:    "/usr/sbin/nginx",
				ProxyConfigDir: "/etc/nginx/sites-available",
				ProxyReloadCmd: "nginx -s reload",
				ProxyTestCmd:   "nginx -t",
				ProxyLogPaths:  "/var/log/nginx/error.log, /var/log/nginx/access.log",
				ProxyService:   "nginx.service",
			},
			want: want{
				mode:      ProxyModeExisting,
				typ:       "nginx",
				binary:    "/usr/sbin/nginx",
				configDir: "/etc/nginx/sites-available",
				reloadCmd: "nginx -s reload",
				testCmd:   "nginx -t",
				logPaths:  []string{"/var/log/nginx/error.log", "/var/log/nginx/access.log"},
				service:   "nginx.service",
			},
		},
		{
			name: "all from env",
			env: map[string]string{
				"NP_PROXY_MODE":       "existing",
				"NP_PROXY_TYPE":       "apache",
				"NP_PROXY_BINARY":     "/usr/sbin/apache2",
				"NP_PROXY_CONFIG_DIR": "/etc/apache2/sites-available",
				"NP_PROXY_RELOAD_CMD": "apachectl graceful",
				"NP_PROXY_TEST_CMD":   "apachectl configtest",
				"NP_PROXY_LOG_PATHS":  "/var/log/apache2/error.log",
				"NP_PROXY_SERVICE":    "apache2.service",
			},
			want: want{
				mode:      ProxyModeExisting,
				typ:       "apache",
				binary:    "/usr/sbin/apache2",
				configDir: "/etc/apache2/sites-available",
				reloadCmd: "apachectl graceful",
				testCmd:   "apachectl configtest",
				logPaths:  []string{"/var/log/apache2/error.log"},
				service:   "apache2.service",
			},
		},
		{
			name: "all from yaml",
			yaml: `proxy_mode: existing
proxy_type: nginx
proxy_binary: /opt/nginx/sbin/nginx
proxy_config_dir: /opt/nginx/conf.d
proxy_reload_cmd: systemctl reload nginx
proxy_test_cmd: /opt/nginx/sbin/nginx -t
proxy_log_paths:
  - /opt/nginx/logs/error.log
  - /opt/nginx/logs/access.log
proxy_service: nginx
`,
			want: want{
				mode:      ProxyModeExisting,
				typ:       "nginx",
				binary:    "/opt/nginx/sbin/nginx",
				configDir: "/opt/nginx/conf.d",
				reloadCmd: "systemctl reload nginx",
				testCmd:   "/opt/nginx/sbin/nginx -t",
				logPaths:  []string{"/opt/nginx/logs/error.log", "/opt/nginx/logs/access.log"},
				service:   "nginx",
			},
		},
		{
			name: "flag overrides env overrides yaml",
			yaml: `proxy_type: caddy
proxy_binary: /yaml/caddy
`,
			env: map[string]string{
				"NP_PROXY_BINARY": "/env/caddy",
				"NP_PROXY_TYPE":   "nginx",
			},
			flags: Flags{ProxyType: "apache"},
			want: want{
				mode:   ProxyModeBuiltIn, // not set anywhere -> default
				typ:    "apache",         // flag wins
				binary: "/env/caddy",     // env wins over yaml, no flag
			},
		},
		{
			name:    "invalid proxy_mode rejected",
			flags:   Flags{ProxyMode: "bogus"},
			wantErr: true,
		},
		{
			name: "default mode when unset",
			want: want{mode: ProxyModeBuiltIn},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.yaml != "" {
				content := "orchestrator: http://orch:8080\nfqdn: a.example.com\n" + tt.yaml
				if err := os.WriteFile(filepath.Join(dir, "agent.yaml"), []byte(content), 0644); err != nil {
					t.Fatalf("writing config file: %v", err)
				}
			}
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			f := tt.flags
			f.DataDir = dir
			if f.Orchestrator == "" && tt.yaml == "" {
				f.Orchestrator = "http://orch:8080"
			}
			if f.FQDN == "" && tt.yaml == "" {
				f.FQDN = "a.example.com"
			}

			cfg, err := Load(f)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Load failed: %v", err)
			}

			if cfg.ProxyMode != tt.want.mode {
				t.Errorf("ProxyMode = %q, want %q", cfg.ProxyMode, tt.want.mode)
			}
			if cfg.ProxyType != tt.want.typ {
				t.Errorf("ProxyType = %q, want %q", cfg.ProxyType, tt.want.typ)
			}
			if cfg.ProxyBinary != tt.want.binary {
				t.Errorf("ProxyBinary = %q, want %q", cfg.ProxyBinary, tt.want.binary)
			}
			if cfg.ProxyConfigDir != tt.want.configDir {
				t.Errorf("ProxyConfigDir = %q, want %q", cfg.ProxyConfigDir, tt.want.configDir)
			}
			if cfg.ProxyReloadCmd != tt.want.reloadCmd {
				t.Errorf("ProxyReloadCmd = %q, want %q", cfg.ProxyReloadCmd, tt.want.reloadCmd)
			}
			if cfg.ProxyTestCmd != tt.want.testCmd {
				t.Errorf("ProxyTestCmd = %q, want %q", cfg.ProxyTestCmd, tt.want.testCmd)
			}
			if !reflect.DeepEqual(cfg.ProxyLogPaths, tt.want.logPaths) {
				t.Errorf("ProxyLogPaths = %v, want %v", cfg.ProxyLogPaths, tt.want.logPaths)
			}
			if cfg.ProxyService != tt.want.service {
				t.Errorf("ProxyService = %q, want %q", cfg.ProxyService, tt.want.service)
			}
		})
	}
}

func TestParseLogPaths(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "empty", in: "", want: nil},
		{name: "single", in: "/var/log/nginx/error.log", want: []string{"/var/log/nginx/error.log"}},
		{name: "multiple trimmed", in: " /a.log , /b.log ,/c.log", want: []string{"/a.log", "/b.log", "/c.log"}},
		{name: "blanks dropped", in: ", ,/only.log,", want: []string{"/only.log"}},
		{name: "only blanks", in: " , , ", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLogPaths(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseLogPaths(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestLoadDryRunDataDir(t *testing.T) {
	tmp := os.TempDir()

	// Dry-run via flag with no data-dir override → relocated to a writable,
	// per-FQDN temp dir (never the privileged default), so it runs unprivileged.
	cfg, err := Load(Flags{Orchestrator: "http://orch:8080", FQDN: "edge1.example.com", DryRun: true})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.DryRun {
		t.Fatal("DryRun not set")
	}
	if cfg.DataDir == defaults().DataDir {
		t.Fatalf("dry-run data dir was not relocated off the privileged default: %s", cfg.DataDir)
	}
	if filepath.Dir(cfg.DataDir) != filepath.Clean(tmp) {
		t.Fatalf("dry-run data dir not under temp: %s", cfg.DataDir)
	}
	if !strings.Contains(cfg.DataDir, "edge1.example.com") {
		t.Fatalf("dry-run data dir not scoped by FQDN: %s", cfg.DataDir)
	}

	// A second FQDN must get a distinct dir so multiple dry-run agents on one host
	// don't share identity/cert files.
	cfg2, err := Load(Flags{Orchestrator: "http://orch:8080", FQDN: "edge2.example.com", DryRun: true})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DataDir == cfg2.DataDir {
		t.Fatalf("two dry-run agents collided on the same data dir: %s", cfg.DataDir)
	}

	// An explicit data-dir is always respected, even in dry-run.
	dir := t.TempDir()
	cfg3, err := Load(Flags{Orchestrator: "http://orch:8080", FQDN: "edge3.example.com", DryRun: true, DataDir: dir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg3.DataDir != dir {
		t.Fatalf("explicit data dir not respected in dry-run: got %s want %s", cfg3.DataDir, dir)
	}
}

package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
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
	// APIBind is the agent API listen address. Loopback by default: the API is
	// the local control surface (CLI reconfigure, route sync, config dump) and
	// the production control plane is the agent-dialed stream. Widen it (e.g.
	// "0.0.0.0") only when the orchestrator must reach this agent inbound.
	APIBind        string `yaml:"api_bind"`
	CaddyAdminPort int    `yaml:"caddy_admin_port"`
	// CaddyHTTPPort and CaddyHTTPSPort are the ports the bundled Caddy serves
	// plain HTTP and HTTPS on. Zero means the standard 80/443. Non-standard
	// values let an unprivileged agent serve real traffic (the live sandbox).
	CaddyHTTPPort  int `yaml:"caddy_http_port"`
	CaddyHTTPSPort int `yaml:"caddy_https_port"`
	// CaddyListenHost restricts the bundled Caddy's HTTP/HTTPS listeners to one
	// address (e.g. "127.0.0.1"). Empty binds every interface.
	CaddyListenHost string `yaml:"caddy_listen_host"`

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

	// --- Custom engine (ProxyType == "custom") ---------------------------------
	// A proxy NurProxy has no native renderer for (HAProxy, Traefik, …). These are
	// LOCAL operator config only — the host operator owns the host — so a custom
	// engine is never defined over the network (§9).

	// ProxyTemplate is the inline Go text/template rendering one route into the
	// engine's native config (see generic.RouteContext). Takes precedence over
	// ProxyTemplateFile when both are set.
	ProxyTemplate string `yaml:"proxy_template"`
	// ProxyTemplateFile is a path to the template file, read at startup. Used when
	// ProxyTemplate is empty.
	ProxyTemplateFile string `yaml:"proxy_template_file"`
	// ProxyFileExt is the rendered per-route config file extension (default ".conf").
	ProxyFileExt string `yaml:"proxy_file_ext"`
	// ProxyCaps are the capability names the operator asserts their template
	// supports (e.g. "websocket", "force_https", "custom_headers", "path_rewrite",
	// "basic_auth", "ip_filter", "rate_limit", "central_tls"). Reverse proxy is
	// always implied. Empty means the safe default (reverse_proxy + central_tls).
	ProxyCaps []string `yaml:"proxy_caps"`
	// ProxyAllowedCommands are extra reload/test command binaries (basenames, e.g.
	// "haproxy") the operator allows past cmdguard for a custom engine. Service
	// managers (systemctl, …) and the native proxies are always allowed.
	ProxyAllowedCommands []string `yaml:"proxy_allowed_commands"`

	// DryRun runs the agent in sandbox mode (#93): the reverse proxy is simulated
	// entirely in-memory — no Caddy subprocess, no :80/:443 binding, no privileged
	// file ops — while registration, heartbeat, the stream, and route rendering all
	// run for real. Lets the full orchestrator↔agent loop run unprivileged anywhere.
	DryRun bool `yaml:"dry_run"`

	// UpdateMirror replaces GitHub releases as the download source for
	// self-update (<mirror>/v<version>/<file>). Releases are verified against
	// the release workflow's signature regardless of where they come from, so a
	// mirror needs no trust. Must be https.
	UpdateMirror string `yaml:"update_mirror"`
}

// Flags carries the command-line flag values into Load. Each field mirrors a
// flag; an empty / zero value means "flag not set", so the layered priority
// (flags > env > config file > defaults) can skip it.
type Flags struct {
	Orchestrator string
	FQDN         string
	DataDir      string
	APIPort      int
	APIBind      string
	CaddyPort    int

	CaddyHTTPPort   int
	CaddyHTTPSPort  int
	CaddyListenHost string

	ProxyMode      string
	ProxyType      string
	ProxyBinary    string
	ProxyConfigDir string
	ProxyReloadCmd string
	ProxyTestCmd   string
	ProxyLogPaths  string // comma-separated
	ProxyService   string

	// DryRun mirrors the -dry-run flag (sandbox mode). Only ever set to true; a
	// false value means "flag not set" so env/file can still enable it.
	DryRun bool
}

// defaults returns a Config with default values applied.
func defaults() Config {
	return Config{
		DataDir:        "/var/lib/nurproxy-agent",
		APIPort:        8780,
		APIBind:        "127.0.0.1",
		CaddyAdminPort: 2019,
		ProxyMode:      ProxyModeBuiltIn,
	}
}

// Load merges configuration from flags, environment variables, a YAML config
// file, and defaults. Priority: flags > env > config file > defaults.
func Load(f Flags) (*Config, error) {
	cfg := defaults()

	// Determine data dir early so we can find the config file.
	// Priority: flag > env > default.
	dataDir := cfg.DataDir
	if v := os.Getenv("NP_DATA_DIR"); v != "" {
		dataDir = v
	}
	if f.DataDir != "" {
		dataDir = f.DataDir
	}
	explicitDataDir := f.DataDir != "" || os.Getenv("NP_DATA_DIR") != ""

	// Dry-run ergonomics: the default data dir is a privileged system path
	// (/var/lib/...). When sandbox mode is requested via flag or env and the
	// operator did not pin a data dir, relocate to a writable, per-agent temp dir
	// *before* the config file is read — so an unreadable /var/lib never blocks an
	// unprivileged run, and multiple dry-run agents on one host don't collide on
	// shared identity/cert files. (Activation only via the config file in the
	// privileged default dir is a contradiction — writing it there needs the same
	// access — so resolving from flag/env here is sufficient.) An explicit
	// data-dir is always respected.
	if (f.DryRun || envBool("NP_DRY_RUN")) && !explicitDataDir {
		dataDir = dryRunDataDir(firstNonEmpty(f.FQDN, os.Getenv("NP_FQDN")))
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

	// Pin the resolved data dir: in the relocated dry-run case nothing above
	// should drag it back to the privileged default.
	if !explicitDataDir && (cfg.DryRun || f.DryRun) && cfg.DataDir == defaults().DataDir {
		cfg.DataDir = dataDir
	}

	// Validate required fields.
	if cfg.OrchestratorURL == "" {
		return nil, fmt.Errorf("orchestrator URL is required (flag --orchestrator or env NP_ORCHESTRATOR)")
	}
	if cfg.FQDN == "" {
		return nil, fmt.Errorf("FQDN is required (flag --fqdn or env NP_FQDN)")
	}
	for _, p := range []struct {
		name string
		port int
	}{{"caddy_http_port", cfg.CaddyHTTPPort}, {"caddy_https_port", cfg.CaddyHTTPSPort}} {
		if p.port < 0 || p.port > 65535 {
			return nil, fmt.Errorf("invalid %s %d (must be 1-65535, or 0 for the default)", p.name, p.port)
		}
	}
	httpPort, httpsPort := cfg.CaddyHTTPPort, cfg.CaddyHTTPSPort
	if httpPort == 0 {
		httpPort = 80
	}
	if httpsPort == 0 {
		httpsPort = 443
	}
	if httpPort == httpsPort {
		return nil, fmt.Errorf("caddy_http_port and caddy_https_port must differ (both %d, 0 means 80/443)", httpPort)
	}
	if err := validateListenHost(cfg.CaddyListenHost); err != nil {
		return nil, err
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
	if src.APIBind != "" {
		dst.APIBind = src.APIBind
	}
	if src.CaddyAdminPort != 0 {
		dst.CaddyAdminPort = src.CaddyAdminPort
	}
	if src.CaddyHTTPPort != 0 {
		dst.CaddyHTTPPort = src.CaddyHTTPPort
	}
	if src.CaddyHTTPSPort != 0 {
		dst.CaddyHTTPSPort = src.CaddyHTTPSPort
	}
	if src.CaddyListenHost != "" {
		dst.CaddyListenHost = src.CaddyListenHost
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
	if src.ProxyTemplate != "" {
		dst.ProxyTemplate = src.ProxyTemplate
	}
	if src.ProxyTemplateFile != "" {
		dst.ProxyTemplateFile = src.ProxyTemplateFile
	}
	if src.ProxyFileExt != "" {
		dst.ProxyFileExt = src.ProxyFileExt
	}
	if len(src.ProxyCaps) > 0 {
		dst.ProxyCaps = src.ProxyCaps
	}
	if len(src.ProxyAllowedCommands) > 0 {
		dst.ProxyAllowedCommands = src.ProxyAllowedCommands
	}
	if src.DryRun {
		dst.DryRun = true
	}
	if src.UpdateMirror != "" {
		dst.UpdateMirror = src.UpdateMirror
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
	if v := os.Getenv("NP_API_BIND"); v != "" {
		cfg.APIBind = v
	}
	if v := os.Getenv("NP_CADDY_HTTP_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.CaddyHTTPPort = port
		}
	}
	if v := os.Getenv("NP_CADDY_HTTPS_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.CaddyHTTPSPort = port
		}
	}
	if v := os.Getenv("NP_CADDY_LISTEN_HOST"); v != "" {
		cfg.CaddyListenHost = v
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
	if v := os.Getenv("NP_PROXY_TEMPLATE"); v != "" {
		cfg.ProxyTemplate = v
	}
	if v := os.Getenv("NP_PROXY_TEMPLATE_FILE"); v != "" {
		cfg.ProxyTemplateFile = v
	}
	if v := os.Getenv("NP_PROXY_FILE_EXT"); v != "" {
		cfg.ProxyFileExt = v
	}
	if v := os.Getenv("NP_PROXY_CAPS"); v != "" {
		cfg.ProxyCaps = parseLogPaths(v)
	}
	if v := os.Getenv("NP_PROXY_ALLOWED_COMMANDS"); v != "" {
		cfg.ProxyAllowedCommands = parseLogPaths(v)
	}
	if envBool("NP_DRY_RUN") {
		cfg.DryRun = true
	}
	if v := os.Getenv("NP_UPDATE_MIRROR"); v != "" {
		cfg.UpdateMirror = v
	}
}

// validateListenHost accepts an empty value, an IP address (IPv6 without
// brackets, since the port is joined later) or a DNS hostname; never a port.
func validateListenHost(host string) error {
	if host == "" {
		return nil
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if len(host) <= 253 {
		ok := true
		for _, label := range strings.Split(host, ".") {
			if !hostnameLabel.MatchString(label) {
				ok = false
				break
			}
		}
		if ok {
			return nil
		}
	}
	return fmt.Errorf("invalid caddy_listen_host %q (want an IP address or hostname without port or brackets)", host)
}

var hostnameLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// dryRunDataDir returns a writable, per-agent temp data dir for sandbox mode.
// Including the FQDN keeps multiple dry-run agents on one host isolated (separate
// token / identity / cert store) while staying stable across restarts of the
// same agent. An empty FQDN falls back to a shared name.
func dryRunDataDir(fqdn string) string {
	name := "nurproxy-agent-dry"
	if s := sanitizeForPath(fqdn); s != "" {
		name += "-" + s
	}
	return filepath.Join(os.TempDir(), name)
}

// sanitizeForPath reduces a string to a safe path segment (alphanumerics, dash,
// dot), so an FQDN can be embedded in a directory name.
func sanitizeForPath(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}

// firstNonEmpty returns the first non-empty argument, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// envBool reports whether an env var is set to a truthy value (1/true/yes/on).
func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
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
	if f.APIBind != "" {
		cfg.APIBind = f.APIBind
	}
	if f.CaddyPort != 0 {
		cfg.CaddyAdminPort = f.CaddyPort
	}
	if f.CaddyHTTPPort != 0 {
		cfg.CaddyHTTPPort = f.CaddyHTTPPort
	}
	if f.CaddyHTTPSPort != 0 {
		cfg.CaddyHTTPSPort = f.CaddyHTTPSPort
	}
	if f.CaddyListenHost != "" {
		cfg.CaddyListenHost = f.CaddyListenHost
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
	if f.DryRun {
		cfg.DryRun = true
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

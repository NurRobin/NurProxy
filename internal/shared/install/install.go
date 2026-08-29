// Package install provides native service installation for the NurProxy
// orchestrator and agent across operating systems. A Service describes the
// daemon in OS-neutral terms; a Manager (systemd, launchd, OpenRC, or FreeBSD
// rc.d) renders the host's service definition and wires it in. Detect() picks
// the right Manager for the running host.
//
// The render functions (RenderUnit/RenderEnv/RenderPlist/RenderOpenRC/
// RenderRCd) are pure and unit-tested; the Manager Install/Uninstall methods
// perform the privileged filesystem and service actions and require root.
package install

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

func ParseEnvironmentDataDir(r io.Reader) (string, bool, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	var logical string
	continuing := false
	var value string
	found := false
	for scanner.Scan() {
		line := scanner.Text()
		for _, ch := range line {
			if ch < 0x20 && ch != '\t' {
				return "", false, fmt.Errorf("EnvironmentFile contains a control character")
			}
		}
		logical += line
		if hasUnescapedTrailingBackslash(logical) {
			logical = logical[:len(logical)-1]
			continuing = true
			continue
		}
		continuing = false
		parsed, ok, err := parseEnvironmentDataDirLine(logical)
		logical = ""
		if err != nil {
			return "", false, err
		}
		if !ok {
			continue
		}
		if found {
			return "", false, fmt.Errorf("NP_DATA_DIR is defined more than once")
		}
		value, found = parsed, true
	}
	if err := scanner.Err(); err != nil {
		return "", false, err
	}
	if continuing {
		return "", false, fmt.Errorf("NP_DATA_DIR has an unterminated continuation")
	}
	return value, found, nil
}

func hasUnescapedTrailingBackslash(s string) bool {
	count := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		count++
	}
	return count%2 == 1
}

func parseEnvironmentDataDirLine(line string) (string, bool, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
		return "", false, nil
	}
	eq := strings.IndexByte(trimmed, '=')
	if eq < 0 {
		if strings.TrimSpace(trimmed) == "NP_DATA_DIR" {
			return "", true, fmt.Errorf("NP_DATA_DIR is missing =")
		}
		return "", false, nil
	}
	if strings.TrimSpace(trimmed[:eq]) != "NP_DATA_DIR" {
		return "", false, nil
	}
	raw := strings.TrimSpace(trimmed[eq+1:])
	if raw == "" {
		return "", true, fmt.Errorf("NP_DATA_DIR is empty")
	}
	quote := byte(0)
	if raw[0] == '\'' || raw[0] == '"' {
		quote = raw[0]
		raw = raw[1:]
	}
	var b strings.Builder
	closed := quote == 0
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if quote != 0 && ch == quote {
			if strings.TrimSpace(raw[i+1:]) != "" {
				return "", true, fmt.Errorf("NP_DATA_DIR has trailing characters after quote")
			}
			closed = true
			break
		}
		if ch == '\\' && quote != '\'' {
			i++
			if i >= len(raw) {
				return "", true, fmt.Errorf("NP_DATA_DIR has a trailing escape")
			}
			ch = raw[i]
		}
		if quote == 0 && (ch == '\'' || ch == '"') {
			return "", true, fmt.Errorf("NP_DATA_DIR has misplaced quoting")
		}
		if ch < 0x20 || ch == 0x7f {
			return "", true, fmt.Errorf("NP_DATA_DIR contains a control character")
		}
		b.WriteByte(ch)
	}
	if !closed {
		return "", true, fmt.Errorf("NP_DATA_DIR has an unterminated quote")
	}
	return b.String(), true, nil
}

// AgentProxyWritePaths are the proxy-backend trees the agent must be able to
// write/reload through ProtectSystem=strict: config under /etc, plus the log,
// cache and runtime dirs that nginx -t / -s reload (and apache/caddy) touch.
// Each is prefixed with "-" so systemd ignores a path absent on this host
// instead of refusing to start the unit — only the installed backend's dirs
// exist on any given box. This is what makes the dashboard's "config writable"
// and "reloadable" checks pass for a file-based backend; without it the mount
// stays read-only regardless of group/ownership, surfacing as EROFS.
var AgentProxyWritePaths = []string{
	"-/etc/nginx", "-/var/log/nginx", "-/var/lib/nginx", "-/var/cache/nginx",
	"-/etc/apache2", "-/etc/httpd", "-/var/log/apache2", "-/var/log/httpd",
	"-/etc/caddy", "-/var/lib/caddy", "-/var/log/caddy",
	"-/run",
}

// AgentCapabilities are the Linux capabilities the agent unit keeps. The agent
// runs as root but with a restricted bounding set, so it only holds what it
// needs:
//   - CAP_NET_BIND_SERVICE: the bundled Caddy binds :80/:443 without full root.
//   - CAP_DAC_OVERRIDE: in existing mode the agent drives a host nginx/Apache,
//     and `nginx -t` must read the proxy's TLS private keys (mode 0600, often
//     not owned by the agent) and write its log files (often owned by www-data).
//     Without it a root agent obeys the file-permission bits and the reload
//     self-test fails with "permission denied" on the key or log — even though
//     ReadWritePaths already made the mount writable (DAC and the read-only
//     mount are independent). The bundled-Caddy path does not need it, but the
//     unit is static and cannot know the mode at install time.
//   - CAP_CHOWN: `nginx -t` (started as root by the agent) runs ngx_create_paths,
//     which chown()s the temp dirs (client_body_temp_path etc.) to the worker
//     user. Changing a file's owner requires CAP_CHOWN; with it dropped, the
//     process falls under the normal chown() permission check and gets EPERM —
//     nginx attempts the chown unconditionally, even when the dir already has
//     the right owner — so every config test fails ("chown(...) failed (1:
//     Operation not permitted)") and no config can ever be applied.
var AgentCapabilities = []string{"CAP_NET_BIND_SERVICE", "CAP_DAC_OVERRIDE", "CAP_CHOWN"}

// Service describes a NurProxy service to install. The same descriptor is
// consumed by every Manager; fields without meaning on a given OS are ignored.
type Service struct {
	Name         string            // unit base name, e.g. "nurproxy" -> nurproxy.service
	Description  string            // human-readable description
	BinaryPath   string            // absolute path to the executable
	Args         []string          // extra ExecStart arguments
	User         string            // service user (e.g. "root")
	DataDir      string            // data directory (made ReadWritePaths)
	WritePaths   []string          // extra ReadWritePaths to punch through ProtectSystem=strict (e.g. proxy config/log/cache trees); prefix an entry with "-" to ignore it when absent
	EnvFile      string            // optional EnvironmentFile path (systemd)
	Env          map[string]string // environment variables for the service
	ConfigFile   string            // optional extra config file to write (e.g. agent.yaml)
	ConfigData   string            // contents of ConfigFile
	Capabilities []string          // ambient capabilities, e.g. CAP_NET_BIND_SERVICE (systemd-only)
	PrivateData  bool              // owner-only data dir (orchestrator); agent defaults retain service-user layout
}

// fprintf writes progress to the caller's writer; output errors are non-fatal.
func fprintf(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}

// UnitPath is where the systemd unit is written.
func (s Service) UnitPath() string {
	return filepath.Join("/etc/systemd/system", s.Name+".service")
}

// sortedKeys returns the keys of m in ascending order for deterministic output.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// RenderUnit renders a hardened systemd unit for the service. Output is
// deterministic so it can be diffed and tested.
func RenderUnit(s Service) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	w("[Unit]\n")
	w("Description=%s\n", s.Description)
	w("After=network-online.target\n")
	w("Wants=network-online.target\n\n")

	w("[Service]\n")
	w("Type=simple\n")
	if s.User != "" {
		w("User=%s\n", s.User)
	}
	if s.EnvFile != "" {
		w("EnvironmentFile=%s\n", s.EnvFile)
	}
	execStart := s.BinaryPath
	if len(s.Args) > 0 {
		execStart += " " + strings.Join(s.Args, " ")
	}
	w("ExecStart=%s\n", execStart)
	w("Restart=on-failure\n")
	w("RestartSec=5\n")
	w("UMask=0077\n")

	// Security hardening.
	w("NoNewPrivileges=true\n")
	w("ProtectSystem=strict\n")
	w("ProtectHome=true\n")
	w("PrivateTmp=true\n")
	w("ProtectControlGroups=true\n")
	w("ProtectKernelTunables=true\n")
	if s.DataDir != "" {
		w("ReadWritePaths=%s\n", s.DataDir)
	}
	// Proxy backends (nginx/apache/caddy) edit config under /etc and reload, which
	// writes log/cache/runtime files — all read-only under ProtectSystem=strict.
	// Punch exactly those trees through; the caller prefixes each with "-" so a
	// path absent on this host is ignored rather than failing the unit's start.
	if len(s.WritePaths) > 0 {
		w("ReadWritePaths=%s\n", strings.Join(s.WritePaths, " "))
	}
	if len(s.Capabilities) > 0 {
		caps := strings.Join(s.Capabilities, " ")
		w("AmbientCapabilities=%s\n", caps)
		w("CapabilityBoundingSet=%s\n", caps)
	}
	w("\n[Install]\n")
	w("WantedBy=multi-user.target\n")

	return b.String()
}

// RenderEnv renders an EnvironmentFile body with keys sorted for stable output.
func RenderEnv(env map[string]string) string {
	var b strings.Builder
	for _, k := range sortedKeys(env) {
		fmt.Fprintf(&b, "%s=%s\n", k, env[k])
	}
	return b.String()
}

func RenderDataDirDropIn(dataDir string) (string, error) {
	if !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir || dataDir == string(filepath.Separator) {
		return "", fmt.Errorf("data dir must be a canonical absolute non-root path")
	}
	for _, r := range dataDir {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '/' || r == '.' || r == '_' || r == '-' {
			continue
		}
		return "", fmt.Errorf("data dir contains an unsafe character")
	}
	for _, blocked := range []string{"/home", "/root", "/tmp", "/var/tmp", "/proc", "/sys", "/dev", "/run/user"} {
		if dataDir == blocked || strings.HasPrefix(dataDir, blocked+"/") {
			return "", fmt.Errorf("data dir %s is inaccessible under the packaged service sandbox", dataDir)
		}
	}
	return "[Service]\nReadWritePaths=\nReadWritePaths=" + dataDir + "\n", nil
}

func WriteDataDirDropIn(path, dataDir string) error {
	body, err := RenderDataDirDropIn(dataDir)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating drop-in directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".data-dir.conf-*")
	if err != nil {
		return fmt.Errorf("creating data-dir drop-in: %w", err)
	}
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(0o644); err != nil {
		return err
	}
	if _, err := tmp.WriteString(body); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("installing data-dir drop-in: %w", err)
	}
	committed = true
	return nil
}

// runTool runs an external service tool (systemctl, launchctl, rc-service,
// sysrc, …), streaming output. It is a no-op with a warning when the tool
// isn't present, so installs proceed up to the point of service activation on
// hosts without it.
func runTool(out io.Writer, bin string, args ...string) error {
	path, err := exec.LookPath(bin)
	if err != nil {
		fprintf(out, "! %s not found — skipping '%s %s' (configure the service manually)\n", bin, bin, strings.Join(args, " "))
		return nil
	}
	cmd := exec.Command(path, args...)
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", bin, strings.Join(args, " "), err)
	}
	return nil
}

// systemctl runs a systemctl command, streaming output.
func systemctl(out io.Writer, args ...string) error { return runTool(out, "systemctl", args...) }

// WriteEnvFile writes env to path (mode 0640), creating the parent directory.
// Used by the agent's `setup` command to fill an already-installed unit's
// EnvironmentFile without rewriting the unit itself.
func WriteEnvFile(path string, env map[string]string, out io.Writer) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(RenderEnv(env)), 0o640); err != nil {
		return fmt.Errorf("writing env file %s: %w", path, err)
	}
	fprintf(out, "• env file %s\n", path)
	return nil
}

// EnableService daemon-reloads systemd and enables+starts the named unit. It is
// the activation half of an install for a unit that already exists on disk.
func EnableService(name string, out io.Writer) error {
	if err := systemctl(out, "daemon-reload"); err != nil {
		return err
	}
	if err := systemctl(out, "enable", "--now", name); err != nil {
		return err
	}
	fprintf(out, "✓ %s enabled and started. Logs: journalctl -u %s -f\n", name, name)
	return nil
}

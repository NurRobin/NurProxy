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
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

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
var AgentCapabilities = []string{"CAP_NET_BIND_SERVICE", "CAP_DAC_OVERRIDE"}

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

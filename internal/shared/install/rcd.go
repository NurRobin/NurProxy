package install

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// rcdScriptPath is where the FreeBSD rc.d script is written.
func rcdScriptPath(name string) string { return filepath.Join("/usr/local/etc/rc.d", name) }

// rcdName sanitizes a service name into an rc(8)-safe identifier (no dashes),
// used for the script's name, rcvar, and pidfile.
func rcdName(name string) string { return strings.ReplaceAll(name, "-", "_") }

// RenderRCd renders a FreeBSD rc.d script for s. Our binaries run in the
// foreground, so daemon(8) backgrounds them and tracks the pidfile.
// Deterministic for testing.
func RenderRCd(s Service) string {
	rn := rcdName(s.Name)
	pidfile := fmt.Sprintf("/var/run/%s.pid", rn)

	// Build the daemon(8) command: env vars, then the binary and its args.
	parts := []string{"/usr/sbin/daemon", "-f", "-p", pidfile}
	if env := envPrefix(s.Env); len(env) > 0 {
		parts = append(parts, env...)
	}
	parts = append(parts, s.BinaryPath)
	parts = append(parts, s.Args...)

	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	w("#!/bin/sh\n\n")
	w("# PROVIDE: %s\n", rn)
	w("# REQUIRE: NETWORKING\n")
	w("# KEYWORD: shutdown\n\n")
	w(". /etc/rc.subr\n\n")
	w("name=%q\n", rn)
	w("rcvar=%q\n", rn+"_enable")
	w("pidfile=%q\n", pidfile)
	w("command=%q\n", parts[0])
	w("command_args=%q\n", strings.Join(parts[1:], " "))
	if s.User != "" {
		w("%s_user=%q\n", rn, s.User)
	}
	w("\nload_rc_config $name\n")
	w(": ${%s_enable:=\"NO\"}\n", rn)
	w("run_rc_command \"$1\"\n")
	return b.String()
}

// envPrefix renders sorted KEY=VALUE tokens passed to /usr/bin/env so the
// daemon inherits the service environment. Empty when there is no env.
func envPrefix(env map[string]string) []string {
	if len(env) == 0 {
		return nil
	}
	out := []string{"/usr/bin/env"}
	for _, k := range sortedKeys(env) {
		out = append(out, fmt.Sprintf("%s=%s", k, env[k]))
	}
	return out
}

// rcdManager installs services as FreeBSD rc.d scripts.
type rcdManager struct{}

func (rcdManager) Name() string { return "rc.d" }

func (rcdManager) Install(s Service, out io.Writer) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if err := ensureDataDir(s, out); err != nil {
		return err
	}

	path := rcdScriptPath(s.Name)
	if err := os.WriteFile(path, []byte(RenderRCd(s)), 0o755); err != nil {
		return fmt.Errorf("writing rc.d script %s: %w", path, err)
	}
	fprintf(out, "• rc.d script %s\n", path)

	// Enable in rc.conf and start. sysrc is the supported way to edit rc.conf.
	if err := runTool(out, "sysrc", rcdName(s.Name)+"_enable=YES"); err != nil {
		return err
	}
	if err := runTool(out, "service", s.Name, "start"); err != nil {
		return err
	}
	fprintf(out, "✓ %s installed and started.\n", s.Name)
	return nil
}

func (rcdManager) Uninstall(s Service, purge bool, out io.Writer) error {
	if err := requireRoot(); err != nil {
		return err
	}
	_ = runTool(out, "service", s.Name, "stop")
	_ = runTool(out, "sysrc", "-x", rcdName(s.Name)+"_enable")
	path := rcdScriptPath(s.Name)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing rc.d script: %w", err)
	}
	fprintf(out, "• removed rc.d script %s\n", path)
	return removeData(s, purge, out)
}

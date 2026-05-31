package install

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// openrcScriptPath is where the OpenRC service script is written.
func openrcScriptPath(name string) string { return filepath.Join("/etc/init.d", name) }

// RenderOpenRC renders an OpenRC service script for s. Deterministic for
// testing. It supervises the daemon so it restarts on failure.
func RenderOpenRC(s Service) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	w("#!/sbin/openrc-run\n\n")
	w("name=%q\n", s.Name)
	if s.Description != "" {
		w("description=%q\n", s.Description)
	}
	w("command=%q\n", s.BinaryPath)
	if len(s.Args) > 0 {
		w("command_args=%q\n", strings.Join(s.Args, " "))
	}
	if s.User != "" {
		w("command_user=%q\n", s.User)
	}
	w("supervisor=\"supervise-daemon\"\n")
	w("respawn_delay=5\n")
	if s.DataDir != "" {
		w("output_log=%q\n", filepath.Join(s.DataDir, s.Name+".log"))
		w("error_log=%q\n", filepath.Join(s.DataDir, s.Name+".err.log"))
	}
	for _, k := range sortedKeys(s.Env) {
		w("export %s=%q\n", k, s.Env[k])
	}
	w("\ndepend() {\n\tneed net\n\tafter firewall\n}\n")
	return b.String()
}

// openrcManager installs services as OpenRC scripts (Alpine and friends).
type openrcManager struct{}

func (openrcManager) Name() string { return "openrc" }

func (openrcManager) Install(s Service, out io.Writer) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if err := ensureDataDir(s, out); err != nil {
		return err
	}

	path := openrcScriptPath(s.Name)
	if err := os.WriteFile(path, []byte(RenderOpenRC(s)), 0o755); err != nil {
		return fmt.Errorf("writing init script %s: %w", path, err)
	}
	fprintf(out, "• init script %s\n", path)

	if err := runTool(out, "rc-update", "add", s.Name, "default"); err != nil {
		return err
	}
	if err := runTool(out, "rc-service", s.Name, "start"); err != nil {
		return err
	}
	fprintf(out, "✓ %s installed and started. Logs: %s\n", s.Name, filepath.Join(s.DataDir, s.Name+".log"))
	return nil
}

func (openrcManager) Uninstall(s Service, purge bool, out io.Writer) error {
	if err := requireRoot(); err != nil {
		return err
	}
	_ = runTool(out, "rc-service", s.Name, "stop")
	_ = runTool(out, "rc-update", "del", s.Name, "default")
	path := openrcScriptPath(s.Name)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing init script: %w", err)
	}
	fprintf(out, "• removed init script %s\n", path)
	return removeData(s, purge, out)
}

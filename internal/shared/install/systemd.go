package install

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// systemdManager installs services as hardened systemd units. It is the default
// manager on Linux hosts that have systemctl.
type systemdManager struct{}

func (systemdManager) Name() string { return "systemd" }

// Install writes the data dir, env/config files, and unit, then daemon-reloads
// and enables+starts the service. Must run as root.
func (systemdManager) Install(s Service, out io.Writer) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if err := ensureDataDir(s, out); err != nil {
		return err
	}

	if s.EnvFile != "" {
		if err := os.MkdirAll(filepath.Dir(s.EnvFile), 0o755); err != nil {
			return fmt.Errorf("creating env dir: %w", err)
		}
		if err := os.WriteFile(s.EnvFile, []byte(RenderEnv(s.Env)), 0o640); err != nil {
			return fmt.Errorf("writing env file %s: %w", s.EnvFile, err)
		}
		fprintf(out, "• env file %s\n", s.EnvFile)
	}

	if err := os.WriteFile(s.UnitPath(), []byte(RenderUnit(s)), 0o644); err != nil {
		return fmt.Errorf("writing unit %s: %w", s.UnitPath(), err)
	}
	fprintf(out, "• unit %s\n", s.UnitPath())

	if err := systemctl(out, "daemon-reload"); err != nil {
		return err
	}
	if err := systemctl(out, "enable", "--now", s.Name); err != nil {
		return err
	}
	fprintf(out, "✓ %s installed and started. Logs: journalctl -u %s -f\n", s.Name, s.Name)
	return nil
}

// Uninstall stops and disables the service and removes its unit, then cleans up
// data when purge is set. Must run as root.
func (systemdManager) Uninstall(s Service, purge bool, out io.Writer) error {
	if err := requireRoot(); err != nil {
		return err
	}

	// Best-effort stop/disable — keep going even if the unit is already gone.
	_ = systemctl(out, "disable", "--now", s.Name)

	if err := os.Remove(s.UnitPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing unit: %w", err)
	}
	fprintf(out, "• removed unit %s\n", s.UnitPath())
	_ = systemctl(out, "daemon-reload")

	return removeData(s, purge, out)
}

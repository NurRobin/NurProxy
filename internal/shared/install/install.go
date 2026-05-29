// Package install provides systemd service installation for the NurProxy
// orchestrator and agent: it renders a hardened unit file plus a config/env
// file, lays out the data directory, and wires the service into systemd.
//
// Rendering (RenderUnit/RenderEnv) is pure and unit-tested; Install/Uninstall
// perform the privileged filesystem and systemctl actions and require root.
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

// Service describes a NurProxy systemd service to install.
type Service struct {
	Name         string            // unit base name, e.g. "nurproxy" -> nurproxy.service
	Description  string            // [Unit] Description
	BinaryPath   string            // absolute path to the executable
	Args         []string          // extra ExecStart arguments
	User         string            // service user (e.g. "root")
	DataDir      string            // data directory (made ReadWritePaths)
	EnvFile      string            // optional EnvironmentFile path
	Env          map[string]string // contents of EnvFile
	ConfigFile   string            // optional extra config file to write (e.g. agent.yaml)
	ConfigData   string            // contents of ConfigFile
	Capabilities []string          // ambient capabilities, e.g. CAP_NET_BIND_SERVICE
}

// fprintf writes progress to the caller's writer; output errors are non-fatal.
func fprintf(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}

// UnitPath is where the systemd unit is written.
func (s Service) UnitPath() string {
	return filepath.Join("/etc/systemd/system", s.Name+".service")
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
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, env[k])
	}
	return b.String()
}

// Install lays out the service: it creates the data directory, writes the
// config/env file and the unit, then daemon-reloads and enables+starts it.
// Must run as root.
func Install(s Service, out io.Writer) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("install must run as root (try: sudo %s install ...)", filepath.Base(os.Args[0]))
	}

	if s.DataDir != "" {
		if err := os.MkdirAll(s.DataDir, 0o750); err != nil {
			return fmt.Errorf("creating data dir %s: %w", s.DataDir, err)
		}
		fprintf(out, "• data dir %s\n", s.DataDir)
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

	if s.ConfigFile != "" {
		if err := os.MkdirAll(filepath.Dir(s.ConfigFile), 0o750); err != nil {
			return fmt.Errorf("creating config dir: %w", err)
		}
		if err := os.WriteFile(s.ConfigFile, []byte(s.ConfigData), 0o640); err != nil {
			return fmt.Errorf("writing config file %s: %w", s.ConfigFile, err)
		}
		fprintf(out, "• config %s\n", s.ConfigFile)
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

// Uninstall stops and disables the service and removes its unit. When purge is
// true it also removes the data dir, env file, and config file. Must run as root.
func Uninstall(s Service, purge bool, out io.Writer) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("uninstall must run as root (try: sudo %s uninstall ...)", filepath.Base(os.Args[0]))
	}

	// Best-effort stop/disable — keep going even if the unit is already gone.
	_ = systemctl(out, "disable", "--now", s.Name)

	if err := os.Remove(s.UnitPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing unit: %w", err)
	}
	fprintf(out, "• removed unit %s\n", s.UnitPath())
	_ = systemctl(out, "daemon-reload")

	if purge {
		for _, p := range []string{s.EnvFile, s.ConfigFile, s.DataDir} {
			if p == "" {
				continue
			}
			if err := os.RemoveAll(p); err != nil && !os.IsNotExist(err) {
				fprintf(out, "! could not remove %s: %v\n", p, err)
				continue
			}
			fprintf(out, "• removed %s\n", p)
		}
	} else {
		fprintf(out, "• kept data dir %s (use --purge to remove)\n", s.DataDir)
	}
	fprintf(out, "✓ %s uninstalled.\n", s.Name)
	return nil
}

// systemctl runs a systemctl command, streaming output. It is a no-op (with a
// warning) when systemctl isn't present, so installs work on non-systemd hosts
// up to the point of service activation.
func systemctl(out io.Writer, args ...string) error {
	path, err := exec.LookPath("systemctl")
	if err != nil {
		fprintf(out, "! systemctl not found — skipping '%s' (enable the service manually)\n", strings.Join(args, " "))
		return nil
	}
	cmd := exec.Command(path, args...)
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

package install

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Manager installs and removes a Service using a host's native service system.
type Manager interface {
	// Install lays out files and registers + starts the service.
	Install(s Service, out io.Writer) error
	// Uninstall stops and removes the service; purge also deletes its data.
	Uninstall(s Service, purge bool, out io.Writer) error
	// Name identifies the mechanism (systemd, launchd, openrc, rc.d, none).
	Name() string
}

// Detect picks the service manager for the current host. Linux prefers systemd,
// falling back to OpenRC (Alpine) and finally a no-op that only lays out files.
func Detect() Manager {
	switch runtime.GOOS {
	case "darwin":
		return launchdManager{}
	case "freebsd":
		return rcdManager{}
	default: // linux and other unixes
		if _, err := exec.LookPath("systemctl"); err == nil {
			return systemdManager{}
		}
		if hasOpenRC() {
			return openrcManager{}
		}
		return noopManager{}
	}
}

// Install installs s using the manager detected for this host.
func Install(s Service, out io.Writer) error { return Detect().Install(s, out) }

// Uninstall removes s using the manager detected for this host.
func Uninstall(s Service, purge bool, out io.Writer) error { return Detect().Uninstall(s, purge, out) }

// hasOpenRC reports whether the host uses OpenRC (Alpine and friends).
func hasOpenRC() bool {
	if _, err := exec.LookPath("rc-update"); err == nil {
		return true
	}
	if fi, err := os.Stat("/sbin/openrc-run"); err == nil && !fi.IsDir() {
		return true
	}
	return false
}

// requireRoot returns an error if not running as the POSIX superuser.
func requireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("install must run as root (try: sudo %s install ...)", filepath.Base(os.Args[0]))
	}
	return nil
}

// ensureDataDir creates the data directory and writes the config file
// (e.g. agent.yaml) — the OS-neutral filesystem prep shared by every manager.
// Both are handed to Service.User: the installer runs as root, so without the
// chown a non-root service user cannot write its data dir (or read its config)
// and the service dies at first boot.
func ensureDataDir(s Service, out io.Writer) error {
	if s.DataDir != "" {
		mode := os.FileMode(0o750)
		if s.PrivateData {
			mode = 0o700
		}
		if err := os.MkdirAll(s.DataDir, mode); err != nil {
			return fmt.Errorf("creating data dir %s: %w", s.DataDir, err)
		}
		if s.PrivateData {
			if err := restrictPrivateDataDir(s, s.DataDir); err != nil {
				return fmt.Errorf("restricting data dir %s: %w", s.DataDir, err)
			}
		} else if err := chownForServiceUser(s, s.DataDir); err != nil {
			return err
		}
		fprintf(out, "• data dir %s\n", s.DataDir)
	}
	if s.ConfigFile != "" {
		confDir := filepath.Dir(s.ConfigFile)
		_, statErr := os.Stat(confDir)
		confDirCreated := os.IsNotExist(statErr)
		if err := os.MkdirAll(confDir, 0o750); err != nil {
			return fmt.Errorf("creating config dir: %w", err)
		}
		if err := os.WriteFile(s.ConfigFile, []byte(s.ConfigData), 0o640); err != nil {
			return fmt.Errorf("writing config file %s: %w", s.ConfigFile, err)
		}
		// The config file must be readable by the service user (mode 0640); its
		// parent is only re-owned when this install created it, so a shared
		// pre-existing directory keeps its ownership.
		paths := []string{s.ConfigFile}
		if confDirCreated {
			paths = append(paths, confDir)
		}
		if err := chownForServiceUser(s, paths...); err != nil {
			return err
		}
		fprintf(out, "• config %s\n", s.ConfigFile)
	}
	return nil
}

func restrictPrivateDataDir(s Service, path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("opening without following links: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Fchmod(fd, 0o700); err != nil {
		return err
	}
	uid, gid, change, err := serviceUserIDs(s)
	if err != nil {
		return err
	}
	if change {
		if err := unix.Fchown(fd, uid, gid); err != nil {
			return fmt.Errorf("chowning %s to %s: %w", path, s.User, err)
		}
	}
	return nil
}

// chownForServiceUser hands paths to Service.User so a non-root service can
// use the files the (root) installer laid out. Root or an unset user needs no
// change.
func chownForServiceUser(s Service, paths ...string) error {
	uid, gid, change, err := serviceUserIDs(s)
	if err != nil {
		return err
	}
	if !change {
		return nil
	}
	for _, p := range paths {
		if err := os.Chown(p, uid, gid); err != nil {
			return fmt.Errorf("chowning %s to %s: %w", p, s.User, err)
		}
	}
	return nil
}

func serviceUserIDs(s Service) (uid, gid int, change bool, err error) {
	if s.User == "" || s.User == "root" {
		return 0, 0, false, nil
	}
	u, err := user.Lookup(s.User)
	if err != nil {
		return 0, 0, false, fmt.Errorf("looking up service user %q (create the user first, or install without --user): %w", s.User, err)
	}
	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, false, fmt.Errorf("parsing uid %q of service user %s: %w", u.Uid, s.User, err)
	}
	gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, false, fmt.Errorf("parsing gid %q of service user %s: %w", u.Gid, s.User, err)
	}
	return uid, gid, true, nil
}

// removeData deletes the env file, config file, and (with purge) the data dir,
// then prints the closing line. Shared by every manager's Uninstall.
func removeData(s Service, purge bool, out io.Writer) error {
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
	} else if s.DataDir != "" {
		fprintf(out, "• kept data dir %s (use --purge to remove)\n", s.DataDir)
	}
	fprintf(out, "✓ %s uninstalled.\n", s.Name)
	return nil
}

// noopManager lays out files but cannot register a service; it tells the user
// how to start the daemon by hand.
type noopManager struct{}

func (noopManager) Name() string { return "none" }

func (noopManager) Install(s Service, out io.Writer) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if err := ensureDataDir(s, out); err != nil {
		return err
	}
	cmd := strings.Join(append([]string{s.BinaryPath}, s.Args...), " ")
	fprintf(out, "! no supported service manager found — laid out files only.\n")
	fprintf(out, "  Start it manually (and wire it into your init system): %s\n", cmd)
	return nil
}

func (noopManager) Uninstall(s Service, purge bool, out io.Writer) error {
	return removeData(s, purge, out)
}

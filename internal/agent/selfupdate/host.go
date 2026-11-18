package selfupdate

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/runtimeenv"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// Install kinds reported in models.SelfUpdateStatus.InstallKind.
const (
	InstallStandalone = "standalone"
	InstallDeb        = "deb"
	InstallRPM        = "rpm"
	InstallPacman     = "pacman"
	InstallHomebrew   = "homebrew"
	InstallContainer  = "container"
	InstallUsrBin     = "package-path"
	InstallDryRun     = "dry-run"
)

// Trigger files installed by `nurproxy-agent self-update-enable`. Their
// presence is the host-level opt-in: without them no privileged process acts on
// a staged upgrade.
const (
	SystemdTriggerPath = "/etc/systemd/system/nurproxy-agent-update.path"
	LaunchdTriggerPath = "/Library/LaunchDaemons/de.nurrobin.nurproxy-agent-update.plist"
)

// Host is what decides whether this agent may replace its own binary.
type Host struct {
	GOOS           string
	Version        string
	Executable     string
	IsRoot         bool
	Init           string // runtimeenv.Init* or ""
	InContainer    bool
	PackageOwner   string // one of the Install* package kinds, or ""
	TriggerPresent bool
	DryRun         bool
	// UnsafeExecutable says why the root applier would refuse to run
	// Executable (see CheckRootOwnedBinary), or is empty.
	UnsafeExecutable string
}

// DetectHost inspects the running agent. It only reads.
func DetectHost(version string, env runtimeenv.Env, dryRun bool) Host {
	h := Host{GOOS: runtime.GOOS, Version: version, IsRoot: env.IsRoot, Init: env.Init, DryRun: dryRun}
	if dryRun {
		return h
	}
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		h.Executable = exe
		if err := CheckRootOwnedBinary(exe); err != nil {
			h.UnsafeExecutable = err.Error()
		}
	}
	h.InContainer = inContainer(os.Getenv, fileExists, readFile)
	h.PackageOwner = packageOwner(h.Executable, packageProbes{
		readFile: readFile, glob: filepath.Glob, run: runQuiet,
	})
	switch h.Init {
	case runtimeenv.InitSystemd:
		h.TriggerPresent = fileExists(SystemdTriggerPath)
	case runtimeenv.InitLaunchd:
		h.TriggerPresent = fileExists(LaunchdTriggerPath)
	case runtimeenv.InitOpenRC:
		// OpenRC has no path trigger; a root agent starts the applier itself.
		h.TriggerPresent = h.IsRoot
	}
	return h
}

// Status turns the host facts into the operator-facing verdict.
func (h Host) Status() models.SelfUpdateStatus {
	st := models.SelfUpdateStatus{ServiceManager: h.Init, DryRun: h.DryRun}
	if h.DryRun {
		st.Supported, st.InstallKind = true, InstallDryRun
		return st
	}
	switch {
	case h.InContainer:
		st.InstallKind = InstallContainer
		st.Reason = "the agent runs in a container; pull the new image tag and recreate the container instead"
	case h.PackageOwner == InstallHomebrew:
		st.InstallKind = h.PackageOwner
		st.Reason = "installed with Homebrew; upgrade with: brew upgrade nurproxy-agent"
	case h.PackageOwner == InstallDeb || h.PackageOwner == InstallRPM:
		st.InstallKind = h.PackageOwner
		st.Reason = fmt.Sprintf("installed from the %s package; upgrade it with the package manager so the package database stays correct", h.PackageOwner)
	case h.PackageOwner == InstallPacman:
		st.InstallKind = h.PackageOwner
		st.Reason = "installed from the AUR package; upgrade it with your AUR helper or pacman"
	case h.PackageOwner == InstallUsrBin:
		st.InstallKind = h.PackageOwner
		st.Reason = "the binary lives in /usr/bin, which belongs to the package manager; upgrade with the package manager"
	case h.Executable == "":
		st.InstallKind = "unknown"
		st.Reason = "cannot determine the agent's own executable path"
	default:
		st.InstallKind = InstallStandalone
		if _, err := AssetName("0.0.0", h.GOOS, runtime.GOARCH); err != nil {
			st.Reason = err.Error()
			return st
		}
		if _, ok := models.NormalizeReleaseVersion(h.Version); !ok {
			st.Reason = fmt.Sprintf("this is a development build (version %q); only release builds can self-update", h.Version)
			return st
		}
		if h.UnsafeExecutable != "" {
			st.Reason = h.UnsafeExecutable
			return st
		}
		switch h.Init {
		case runtimeenv.InitSystemd, runtimeenv.InitLaunchd:
			if !h.TriggerPresent {
				st.Reason = "the self-update trigger is not installed on this host; run: sudo nurproxy-agent self-update-enable"
				return st
			}
		case runtimeenv.InitOpenRC:
			if !h.IsRoot {
				st.Reason = "under OpenRC self-update needs the agent to run as root; upgrade this host manually"
				return st
			}
		default:
			st.Reason = "the agent is not running under systemd, OpenRC or launchd, so nothing could restart it after an upgrade"
			return st
		}
		st.Supported = true
	}
	return st
}

// inContainer recognizes Docker, Podman and Kubernetes. LXC system containers
// are not matched: they run a normal init and behave like a host.
func inContainer(getenv func(string) string, exists func(string) bool, read func(string) ([]byte, error)) bool {
	switch getenv("container") {
	case "docker", "podman", "oci":
		return true
	}
	if exists("/.dockerenv") || exists("/run/.containerenv") {
		return true
	}
	if data, err := read("/proc/1/cgroup"); err == nil {
		s := string(data)
		for _, marker := range []string{"/docker/", "/docker-", "/kubepods", "/containerd/", "libpod"} {
			if strings.Contains(s, marker) {
				return true
			}
		}
	}
	return false
}

type packageProbes struct {
	readFile func(string) ([]byte, error)
	glob     func(string) ([]string, error)
	run      func(name string, args ...string) bool
}

// packageOwner reports which package manager owns exe, if any. Overwriting a
// package-owned file would leave the package database describing a binary that
// no longer exists, so any positive answer refuses self-update.
func packageOwner(exe string, p packageProbes) string {
	if exe == "" {
		return ""
	}
	for _, marker := range []string{"/Cellar/", "/Caskroom/", "/opt/homebrew/", "/home/linuxbrew/", "/usr/local/Homebrew/"} {
		if strings.Contains(exe, marker) {
			return InstallHomebrew
		}
	}
	if lists, _ := p.glob("/var/lib/dpkg/info/nurproxy-agent*.list"); len(lists) > 0 {
		for _, list := range lists {
			if data, err := p.readFile(list); err == nil && containsLine(data, exe) {
				return InstallDeb
			}
		}
	}
	if p.run("rpm", "-qf", "--quiet", exe) {
		return InstallRPM
	}
	if p.run("pacman", "-Qqo", exe) {
		return InstallPacman
	}
	if filepath.Dir(exe) == "/usr/bin" {
		return InstallUsrBin
	}
	return ""
}

func containsLine(data []byte, want string) bool {
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == want {
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }

// runQuiet runs a package-manager query and reports whether it exited 0. A
// missing tool counts as "no".
func runQuiet(name string, args ...string) bool {
	path, err := exec.LookPath(name)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, path, args...).Run() == nil
}

func goarch() string { return runtime.GOARCH }

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/NurRobin/NurProxy/internal/agent/helper"
	"github.com/NurRobin/NurProxy/internal/agent/runtimeenv"
	"github.com/NurRobin/NurProxy/internal/agent/selfupdate"
	"github.com/NurRobin/NurProxy/internal/shared/install"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// cmdSelfUpdateApply is the privileged applier. It is started by the trigger
// that `self-update-enable` installs (or, on OpenRC, by a root agent) and
// replaces the binary it was itself started from.
func cmdSelfUpdateApply(args []string) {
	fs := flag.NewFlagSet("self-update-apply", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Agent data directory holding self-update/ (required)")
	manager := fs.String("service-manager", "", "systemd, launchd or openrc")
	unit := fs.String("unit", "", "Agent unit, launchd label or OpenRC service (default per manager)")
	_ = fs.Parse(args)
	if fs.NArg() != 0 || *dataDir == "" || !filepath.IsAbs(*dataDir) {
		log.Fatalf("self-update-apply: --data-dir must be an absolute path and no positional arguments are accepted")
	}
	if os.Geteuid() != 0 {
		log.Fatalf("self-update-apply must run as root")
	}
	service, err := selfupdate.NewService(*manager, *unit, nil)
	if err != nil {
		log.Fatalf("self-update-apply: %v", err)
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		log.Fatalf("self-update-apply: cannot resolve own executable: %v", err)
	}
	trust, err := selfupdate.DefaultTrust()
	if err != nil {
		log.Fatalf("self-update-apply: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	applier := &selfupdate.Applier{
		Dir: selfupdate.StateDir(*dataDir), BinaryPath: exe, CurrentVersion: version, Trust: trust,
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Service: service,
		RefreshBuildID: func(buildID string) error {
			_, err := helper.RefreshRootConfigBuildID(helper.DefaultRootConfigPath, buildID)
			return err
		},
	}
	res, err := applier.Run(ctx)
	if err != nil {
		log.Fatalf("self-update-apply: %v", err)
	}
	if res == nil {
		return
	}
	log.Printf("self-update %s: %s %s", res.UpgradeID, res.State, res.Error)
	if res.State != models.UpgradeDone {
		os.Exit(1)
	}
}

type selfUpdateTarget struct {
	bin, dataDir, unit string
}

func parseSelfUpdateFlags(name string, args []string) selfUpdateTarget {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	dataDir := fs.String("data-dir", "/var/lib/nurproxy-agent", "The agent's data directory (as passed to the agent service)")
	unit := fs.String("unit", "", "Agent systemd unit or launchd label to restart (default: nurproxy-agent.service / de.nurrobin.nurproxy-agent)")
	bin := fs.String("bin", selfPath(), "The agent binary the service runs")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		log.Fatalf("%s accepts no positional arguments", name)
	}
	if os.Geteuid() != 0 {
		log.Fatalf("%s must run as root (try: sudo nurproxy-agent %s)", name, name)
	}
	resolved, err := filepath.EvalSymlinks(*bin)
	if err != nil {
		log.Fatalf("%s: %v", name, err)
	}
	return selfUpdateTarget{bin: resolved, dataDir: filepath.Clean(*dataDir), unit: *unit}
}

// cmdSelfUpdateEnable installs the root trigger that lets this host's agent
// apply operator-requested upgrades. It is the host-level opt-in.
func cmdSelfUpdateEnable(args []string) {
	t := parseSelfUpdateFlags("self-update-enable", args)
	host := selfupdate.DetectHost(version, runtimeenv.Detect(), false)
	host.Executable = t.bin
	host.TriggerPresent = true
	if st := host.Status(); !st.Supported && st.InstallKind != selfupdate.InstallStandalone {
		log.Fatalf("self-update-enable refused: %s", st.Reason)
	}
	switch install.Detect().Name() {
	case "systemd":
		unit := t.unit
		if unit == "" {
			unit = selfupdate.DefaultSystemdUnit
		}
		pathUnit, serviceUnit, err := install.RenderSelfUpdateUnits(t.bin, t.dataDir, unit)
		if err != nil {
			log.Fatalf("self-update-enable: %v", err)
		}
		pathFile, serviceFile := install.SelfUpdateUnitPaths()
		writeRootFile(serviceFile, serviceUnit)
		writeRootFile(pathFile, pathUnit)
		run("systemctl", "daemon-reload")
		run("systemctl", "enable", "--now", install.SelfUpdatePathUnit)
		fmt.Printf("Self-update enabled: %s watches %s\n", install.SelfUpdatePathUnit, filepath.Join(t.dataDir, "self-update"))
	case "launchd":
		label := t.unit
		if label == "" {
			label = install.AgentLaunchdLabel()
		}
		plist, err := install.RenderSelfUpdatePlist(t.bin, t.dataDir, label)
		if err != nil {
			log.Fatalf("self-update-enable: %v", err)
		}
		path := install.SelfUpdateLaunchdPlistPath()
		writeRootFile(path, plist)
		run("launchctl", "bootstrap", "system", path)
		fmt.Printf("Self-update enabled: launchd job %s watches %s\n", path, filepath.Join(t.dataDir, "self-update"))
	case "openrc":
		fmt.Println("OpenRC has no path trigger. Self-update works when the agent itself runs as root; otherwise upgrade manually.")
	default:
		log.Fatalf("self-update-enable: no supported service manager (systemd, launchd, OpenRC) found")
	}
}

// cmdSelfUpdateDisable removes the trigger installed by self-update-enable.
func cmdSelfUpdateDisable(args []string) {
	_ = parseSelfUpdateFlags("self-update-disable", args)
	switch install.Detect().Name() {
	case "systemd":
		_ = exec.Command("systemctl", "disable", "--now", install.SelfUpdatePathUnit).Run()
		pathFile, serviceFile := install.SelfUpdateUnitPaths()
		for _, f := range []string{pathFile, serviceFile} {
			if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
				log.Fatalf("self-update-disable: %v", err)
			}
		}
		run("systemctl", "daemon-reload")
	case "launchd":
		path := install.SelfUpdateLaunchdPlistPath()
		_ = exec.Command("launchctl", "bootout", "system", path).Run()
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Fatalf("self-update-disable: %v", err)
		}
	}
	fmt.Println("Self-update disabled on this host.")
}

func writeRootFile(path, content string) {
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		log.Fatalf("writing %s: %v", path, err)
	}
	fmt.Printf("• %s\n", path)
}

func run(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("%s: %v", name, err)
	}
}

package selfupdate

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Service restarts the agent through the host's service manager.
type Service interface {
	// Restart restarts the agent so the binary on disk is executed again.
	Restart(ctx context.Context) error
	Name() string
}

// CommandRunner runs an external command; tests replace it.
type CommandRunner func(ctx context.Context, name string, args ...string) error

func execRunner(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Default unit/label names, matching `nurproxy-agent install` and packaging.
const (
	DefaultSystemdUnit   = "nurproxy-agent.service"
	DefaultHelperUnit    = "nurproxy-agent-helper.service"
	DefaultLaunchdLabel  = "de.nurrobin.nurproxy-agent"
	DefaultOpenRCService = "nurproxy-agent"
)

// NewService returns the controller for manager ("systemd", "launchd" or
// "openrc"). name is the unit, label or service; empty picks the default.
func NewService(manager, name string, run CommandRunner) (Service, error) {
	if run == nil {
		run = execRunner
	}
	switch manager {
	case "systemd":
		if name == "" {
			name = DefaultSystemdUnit
		}
		return systemdService{unit: name, helper: DefaultHelperUnit, run: run}, nil
	case "launchd":
		if name == "" {
			name = DefaultLaunchdLabel
		}
		return launchdService{label: name, run: run}, nil
	case "openrc":
		if name == "" {
			name = DefaultOpenRCService
		}
		return openrcService{name: name, run: run}, nil
	default:
		return nil, fmt.Errorf("unsupported service manager %q (systemd, launchd or openrc)", manager)
	}
}

type systemdService struct {
	unit, helper string
	run          CommandRunner
}

func (s systemdService) Name() string { return "systemd" }

// Restart restarts the agent unit and, if it is running, the root helper: the
// helper is started from the same binary and refuses an agent whose build
// differs from its own.
func (s systemdService) Restart(ctx context.Context) error {
	if err := s.run(ctx, "systemctl", "restart", s.unit); err != nil {
		return err
	}
	_ = s.run(ctx, "systemctl", "try-restart", s.helper)
	return nil
}

type launchdService struct {
	label string
	run   CommandRunner
}

func (s launchdService) Name() string { return "launchd" }

func (s launchdService) Restart(ctx context.Context) error {
	return s.run(ctx, "launchctl", "kickstart", "-k", "system/"+s.label)
}

type openrcService struct {
	name string
	run  CommandRunner
}

func (s openrcService) Name() string { return "openrc" }

func (s openrcService) Restart(ctx context.Context) error {
	return s.run(ctx, "rc-service", s.name, "restart")
}

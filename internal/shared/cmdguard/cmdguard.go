// Package cmdguard validates proxy command/binary overrides that arrive over
// the network (the orchestrator's set_proxy_mode admin op, the agent's
// /admin/reconfigure endpoint). The agent executes the reload/test command —
// elevated via scoped sudo when unprivileged — so accepting raw command strings
// from the control plane would turn "manage proxies" into arbitrary command
// execution on every adopted host. Local configuration (CLI flags, agent.yaml,
// NP_PROXY_* env) is NOT routed through this guard: the host operator already
// owns the host.
package cmdguard

import (
	"fmt"
	"path/filepath"
	"strings"
)

// proxyBinaries are the recognized proxy binaries an override may name: the
// detection kinds the agent manages plus their conventional control wrappers.
var proxyBinaries = map[string]bool{
	"nginx":      true,
	"caddy":      true,
	"httpd":      true,
	"apachectl":  true,
	"apache2":    true,
	"apache2ctl": true,
}

// serviceManagers are the init-system wrappers a reload/test override may
// invoke (e.g. "systemctl reload nginx").
var serviceManagers = map[string]bool{
	"systemctl":  true,
	"service":    true,
	"rc-service": true,
	"launchctl":  true,
}

// ValidateProxyBinary checks a network-supplied proxy binary override: it must
// be an absolute path to a recognized proxy binary. Empty means "use the
// detected default" and is always fine.
func ValidateProxyBinary(path string) error {
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("proxy binary %q must be an absolute path", path)
	}
	if !proxyBinaries[filepath.Base(path)] {
		return fmt.Errorf("proxy binary %q is not a recognized proxy (allowed: %s)", path, allowedList(proxyBinaries))
	}
	return nil
}

// ValidateProxyCommand checks a network-supplied reload/test command override.
// The command is exec'd directly (no shell), so the gate is its first token: it
// must be a recognized proxy binary or service manager. sudo is rejected — the
// agent decides its own elevation, and a sudo prefix would let the rest of the
// line name any command.
func ValidateProxyCommand(field, cmd string) error {
	if cmd == "" {
		return nil
	}
	tokens := strings.Fields(cmd)
	if len(tokens) == 0 {
		return nil
	}
	base := filepath.Base(tokens[0])
	if base == "sudo" {
		return fmt.Errorf("%s must not invoke sudo (the agent elevates itself when needed)", field)
	}
	if !proxyBinaries[base] && !serviceManagers[base] {
		return fmt.Errorf("%s starts with %q, which is not a recognized proxy or service manager (allowed: %s, %s)",
			field, tokens[0], allowedList(proxyBinaries), allowedList(serviceManagers))
	}
	return nil
}

// ValidateConfigDir checks a network-supplied config-dir override: it must be
// an absolute path (the agent renders managed vhost files into it).
func ValidateConfigDir(dir string) error {
	if dir == "" {
		return nil
	}
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("proxy config dir %q must be an absolute path", dir)
	}
	return nil
}

func allowedList(set map[string]bool) string {
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	// Deterministic order for error messages and tests.
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return strings.Join(names, "/")
}

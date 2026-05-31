package permcheck

import (
	"fmt"
	"path/filepath"
	"strings"
)

// defaultGroup is the OS group NurProxy uses to grant the agent write access to
// a proxy's config dir via group ownership (§12/§19), so writing never needs
// sudo — only the test+reload commands do.
const defaultGroup = "nurproxy"

// sudoersPath is the drop-in file the scoped, NOPASSWD sudoers line is installed
// to (§19). A dedicated /etc/sudoers.d file keeps the grant auditable and easy
// to remove, and never touches the main /etc/sudoers.
const sudoersPath = "/etc/sudoers.d/nurproxy-agent"

// defaultUnit is the systemd unit the drop-in targets when the agent could not
// resolve its own unit name.
const defaultUnit = "nurproxy-agent.service"

// DefaultSandboxWritePaths are the proxy config/log/cache/runtime trees a systemd
// unit must expose via ReadWritePaths so the agent can write config and reload
// (which appends logs) under ProtectSystem=strict. Each is "-" prefixed so a path
// absent on this host is ignored rather than failing the unit's start — only the
// installed backend's dirs exist on any given box. Used when RemediationOptions
// supplies no backend-specific SandboxWritePaths.
var DefaultSandboxWritePaths = []string{
	"-/etc/nginx", "-/var/log/nginx", "-/var/lib/nginx", "-/var/cache/nginx",
	"-/etc/apache2", "-/etc/httpd", "-/var/log/apache2", "-/var/log/httpd",
	"-/etc/caddy", "-/var/lib/caddy", "-/var/log/caddy",
	"-/run",
}

// RemediationOptions describes what the agent needs in order to manage and
// reload a file-based proxy on this host. It is the input to BuildRemediation,
// which turns it into copy-paste operator commands (§19 hard requirement: show
// the exact least-privilege grants, never blanket sudo). All fields are plain
// strings/paths: BuildRemediation only assembles command text, it never touches
// the host.
type RemediationOptions struct {
	// Backend names the proxy backend ("nginx" | "apache"), for clearer titles.
	Backend string
	// User is the OS user the agent runs as (e.g. os/user.Current().Username). It
	// is the user added to the owning group and named in the sudoers line.
	User string
	// Group owns the config dir so the agent can write without sudo. Defaults to
	// "nurproxy" when empty.
	Group string
	// Dirs are the config directories that must be group-writable (a backend's
	// ProbeDirs). No dirs means the write grant is omitted.
	Dirs []string
	// TestCmd is the resolved validate command incl. binary+args, e.g.
	// "/usr/sbin/nginx -t". Empty omits it from the sudoers line.
	TestCmd string
	// ReloadCmd is the resolved reload command, e.g. "/usr/sbin/nginx -s reload".
	// Empty omits it from the sudoers line.
	ReloadCmd string
	// RunAsRoot reports whether the agent runs as root. As root, group ownership
	// and sudo do not apply: under systemd the sandbox drop-in is the whole fix,
	// so the group + sudoers steps are omitted.
	RunAsRoot bool
	// InitSystem names the service manager ("systemd", …) or "". "systemd" adds a
	// ReadWritePaths drop-in step, since ProtectSystem= makes the config/log/
	// runtime dirs read-only mounts regardless of file permissions.
	InitSystem string
	// UnitName is the agent's service unit (e.g. "nurproxy-agent.service"), used to
	// target the systemd drop-in. Defaults to "nurproxy-agent.service" when empty.
	UnitName string
	// SandboxWritePaths overrides the ReadWritePaths entries for the systemd drop-in.
	// Empty uses DefaultSandboxWritePaths (union'd with Dirs), which covers the
	// common nginx/apache/caddy trees with "-" prefixes so absent paths are ignored.
	SandboxWritePaths []string
}

// RemediationStep is one ordered chunk of the fix: a human title plus the exact
// shell lines to run. Commands are ready to copy-paste; the agent never runs
// them — a human with local shell presence does (§19 trust boundary).
type RemediationStep struct {
	// Title is the human description of what this step grants.
	Title string
	// Commands are the copy-paste shell lines, in run order.
	Commands []string
}

// Remediation is the full set of least-privilege grants to make a file-based
// proxy manageable by the agent (§19). Steps are ordered: group/ownership first
// (so the agent can write config), then the scoped sudoers entry (so it can
// test+reload). SudoersLine is surfaced separately so callers (CLI, UI) can show
// the exact /etc/sudoers.d/nurproxy-agent content on its own.
type Remediation struct {
	// Steps are the ordered remediation steps; empty when nothing is needed.
	Steps []RemediationStep
	// SudoersLine is the exact content of /etc/sudoers.d/nurproxy-agent, or empty
	// when no test/reload command was supplied.
	SudoersLine string
}

// BuildRemediation assembles the least-privilege operator commands to grant the
// agent the rights it lacks (§19). It is pure and deterministic: it only builds
// strings, never mutates the host, and never panics on empty input — a step
// whose inputs are empty is simply omitted (no Dirs → no write step; no commands
// → no sudoers step). The two grants mirror §12:
//
//   - WRITE via group ownership + setgid, so the agent never needs sudo to write
//     config (and new files inherit the group).
//   - TEST+RELOAD via a single scoped, NOPASSWD /etc/sudoers.d/nurproxy-agent
//     line naming exactly the two commands — never blanket sudo.
func BuildRemediation(opts RemediationOptions) Remediation {
	group := opts.Group
	if group == "" {
		group = defaultGroup
	}
	user := opts.User

	var rem Remediation

	// Step 0 (systemd only): open the unit's filesystem sandbox. ProtectSystem=
	// makes the proxy's config/log/runtime dirs read-only mounts regardless of file
	// permissions, so this drop-in is required under systemd — and for a root agent
	// it is the COMPLETE fix (group ownership and sudo do not apply to root).
	if opts.InitSystem == InitSystemdName {
		paths := nonEmpty(opts.SandboxWritePaths)
		if len(paths) == 0 {
			paths = DefaultSandboxWritePaths
		}
		// Make sure the dirs that actually failed are covered, even a custom config
		// dir not in the default list. "-" prefix keeps every entry optional.
		paths = dedupeStrings(append(optionalPaths(nonEmpty(opts.Dirs)), paths...))
		// A root agent also needs CAP_DAC_OVERRIDE in the drop-in: the hardened unit
		// drops it, so root obeys file bits and cannot read the proxy's TLS keys
		// (0600) or write its logs (often non-root-owned). Non-root agents get the
		// group + sudoers grants below instead, never a capability.
		rem.Steps = append(rem.Steps, systemdSandboxStep(opts.UnitName, paths, opts.RunAsRoot))
		if opts.RunAsRoot {
			return rem
		}
	}

	// As root without systemd there is no group/ownership or sudo grant that
	// applies; the sandbox step above (if any) is all we can offer.
	if opts.RunAsRoot {
		return rem
	}

	// Step 1: make the config dir group-writable, no sudo for the agent itself.
	dirs := nonEmpty(opts.Dirs)
	if len(dirs) > 0 {
		cmds := []string{
			fmt.Sprintf("sudo groupadd -f %s", group),
		}
		if user != "" {
			cmds = append(cmds, fmt.Sprintf("sudo usermod -aG %s %s", group, user))
		}
		for _, dir := range dirs {
			cmds = append(cmds,
				fmt.Sprintf("sudo chgrp -R %s %s", group, dir),
				fmt.Sprintf("sudo chmod -R g+w %s", dir),
				// setgid so files the agent creates inherit the owning group.
				fmt.Sprintf("sudo chmod g+s %s", dir),
			)
		}
		rem.Steps = append(rem.Steps, RemediationStep{
			Title:    "Make the config directory writable (group ownership, no sudo for the agent)",
			Commands: cmds,
		})
	}

	// Step 2: scoped, NOPASSWD sudoers for exactly the test + reload commands.
	cmdList := nonEmpty([]string{opts.TestCmd, opts.ReloadCmd})
	if len(cmdList) > 0 && user != "" {
		line := fmt.Sprintf("%s ALL=(root) NOPASSWD: %s", user, strings.Join(cmdList, ", "))
		rem.SudoersLine = line

		title := "Allow the agent to test + reload the proxy (scoped sudoers, NOPASSWD for exactly these commands)"
		install := []string{
			fmt.Sprintf("echo '%s' | sudo tee %s", line, sudoersPath),
			fmt.Sprintf("sudo chmod 0440 %s", sudoersPath),
			"sudo visudo -c",
		}
		// Warn (as a single comment line operators see) if any command path is not
		// absolute: sudoers should name absolute paths so the grant is unambiguous.
		// One note covers all of them — listing the same advice per command is noise.
		var notes []string
		var bare []string
		for _, c := range cmdList {
			if !isAbsCommand(c) {
				bare = append(bare, commandBinary(c))
			}
		}
		if len(bare) > 0 {
			notes = append(notes, fmt.Sprintf("# note: use absolute paths in the sudoers line for: %s", strings.Join(dedupeStrings(bare), ", ")))
		}
		rem.Steps = append(rem.Steps, RemediationStep{
			Title:    title,
			Commands: append(notes, install...),
		})
	}

	return rem
}

// systemdSandboxStep builds the drop-in that opens the unit's sandbox. It always
// grants the proxy's dirs via ReadWritePaths (the read-only mount); when withCaps
// is set (a root agent) it also restores CAP_DAC_OVERRIDE, since the hardened unit
// drops it and root then cannot read the proxy's TLS keys or write its logs. It
// writes a numbered drop-in (so it composes with the shipped unit instead of
// replacing it), daemon-reloads, and restarts the agent. Copy-paste ready; the
// agent never runs them.
func systemdSandboxStep(unit string, paths []string, withCaps bool) RemediationStep {
	if unit == "" {
		unit = defaultUnit
	} else if !strings.HasSuffix(unit, ".service") {
		unit += ".service"
	}
	dropinDir := fmt.Sprintf("/etc/systemd/system/%s.d", unit)

	lines := []string{"ReadWritePaths=" + strings.Join(paths, " ")}
	title := "Open the service sandbox so the agent can write + reload the proxy (systemd ReadWritePaths drop-in)"
	if withCaps {
		lines = append(lines,
			"AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE",
			"CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE",
		)
		title = "Open the service sandbox so the root agent can read the proxy's keys + write its config/logs (systemd drop-in)"
	}
	// strings joined with a literal \n so the single-quoted printf renders the
	// multi-line drop-in body when the operator runs it.
	body := strings.Join(lines, `\n`)

	return RemediationStep{
		Title: title,
		Commands: []string{
			fmt.Sprintf("sudo mkdir -p %s", dropinDir),
			fmt.Sprintf("printf '[Service]\\n%s\\n' | sudo tee %s/10-nurproxy-writepaths.conf", body, dropinDir),
			"sudo systemctl daemon-reload",
			fmt.Sprintf("sudo systemctl restart %s", unit),
		},
	}
}

// optionalPaths prefixes each path with "-" (systemd's "ignore if absent" marker)
// unless it already carries one, so a path missing on this host never fails the
// unit's start.
func optionalPaths(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		if strings.HasPrefix(p, "-") {
			out = append(out, p)
			continue
		}
		out = append(out, "-"+p)
	}
	return out
}

// nonEmpty returns the input with empty strings dropped, preserving order. It
// never returns nil-vs-empty surprises: an all-empty input yields a zero-length
// slice the callers treat as "skip this step".
func nonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// dedupeStrings returns the input with duplicate values removed, preserving
// first-seen order.
func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// commandBinary returns the first whitespace-separated field of a command
// string (the binary), or the whole string when it has no args.
func commandBinary(cmd string) string {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return cmd
	}
	return fields[0]
}

// isAbsCommand reports whether a command string's binary is an absolute path.
func isAbsCommand(cmd string) bool {
	return filepath.IsAbs(commandBinary(cmd))
}

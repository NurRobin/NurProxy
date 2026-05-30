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

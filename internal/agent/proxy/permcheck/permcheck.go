// Package permcheck is the agent's startup permission probe for file-based proxy
// backends (§12). Existing-mode (nginx/apache) needs two privileges the built-in
// Caddy admin-API path never did:
//
//   - WRITE the proxy's config files — granted via GROUP/OWNERSHIP (the agent
//     user in a group that owns the config dir, or a NurProxy-owned include dir),
//     never sudo.
//   - RELOAD the service — the only real privilege, granted via a NARROWLY-SCOPED
//     sudoers entry (NOPASSWD for exactly the test + reload commands), never
//     blanket sudo.
//
// The probe checks both at startup and returns a structured Result. It NEVER
// mutates real config (it writes and removes a throwaway probe file) and NEVER
// panics or exits — a denied permission is a degraded-but-connected state, just
// like today's bind-failure handling: the agent reports a clear, actionable
// health error and keeps heartbeating so the operator can fix it from the
// dashboard. Wiring the Result into the agent's health.State is the caller's job;
// this package only diagnoses.
//
// It is deliberately split from the backends so the diagnosis is pure and
// table-testable: the filesystem write probe runs against a t.TempDir, and the
// reload probe takes an injectable command runner.
package permcheck

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// probeFileName is the throwaway file the write probe creates and immediately
// removes in each directory. The .nurproxy-permcheck suffix (no .conf) means a
// stray file — should removal ever fail — is never auto-included by nginx conf.d
// or apache conf.d globbing.
const probeFileName = ".nurproxy-permcheck"

// InitSystemdName is the Options.InitSystem value (matching runtimeenv.InitSystemd)
// that switches messages and remediation onto the systemd-sandbox path. It is a
// plain string, not an import of runtimeenv, so permcheck stays dependency-free
// and purely table-testable.
const InitSystemdName = "systemd"

// TestRunner runs the backend's config-validate command (nginx -t / apachectl
// configtest). It is the same shape as the backends' Runner.Test, injected so the
// reload-privilege probe is unit-testable without a real proxy or sudo. The probe
// only needs to know whether the command runs at all (exit + output), not whether
// the live config is valid — a config error is not a permission error.
type TestRunner interface {
	// Test runs the validate command and returns its combined output and an error
	// if the command itself failed (could not execute, was denied, or the config
	// is invalid). The probe inspects the output/error to tell a permission denial
	// apart from a mere config-invalid result.
	Test(ctx context.Context) (output string, err error)
}

// Result is the outcome of the startup permission probe (§12). It is advisory
// data: the caller decides how to surface it (typically health.SetError). A
// degraded Result never means "crash"; it means "report and keep running".
type Result struct {
	// CanWrite reports whether the agent can create/write/remove files in the
	// probed config directories (the group/ownership grant, §12).
	CanWrite bool
	// CanReload reports whether the validate/reload command ran without a
	// permission denial (the scoped-sudoers grant, §12). A config-invalid result
	// still counts as CanReload=true — the command ran, the privilege is present.
	CanReload bool
	// WriteError is the actionable message when CanWrite is false, empty otherwise.
	WriteError string
	// ReloadError is the actionable message when CanReload is false, empty
	// otherwise.
	ReloadError string
}

// OK reports whether both privileges are present (write + reload).
func (r Result) OK() bool { return r.CanWrite && r.CanReload }

// HealthError renders the probe's actionable message for the agent's health
// state, or "" when both privileges are present. It is what the caller feeds to
// health.SetError so the dashboard shows a clear, fixable reason the agent is
// degraded — mirroring the bind-failure message. Both failures are reported
// together so the operator fixes everything in one pass.
func (r Result) HealthError() string {
	var parts []string
	if !r.CanWrite {
		parts = append(parts, r.WriteError)
	}
	if !r.CanReload {
		parts = append(parts, r.ReloadError)
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ")
}

// Options configures the probe (§12). Only the bits a given backend needs are
// set; an empty Dirs skips the write probe, a nil Runner skips the reload probe.
type Options struct {
	// Backend names the proxy backend for clearer messages (e.g. "nginx").
	Backend string
	// Dirs are the config directories that must be writable (e.g. nginx
	// sites-available + sites-enabled). Empty entries are ignored; duplicates are
	// fine. An empty slice skips the write probe (CanWrite reported true).
	Dirs []string
	// Runner runs the validate command for the reload-privilege probe. Nil skips
	// the reload probe (CanReload reported true) — used by the admin-API caddy path
	// that needs no service reload at all.
	Runner TestRunner
	// ReloadHint is the exact command the operator must allow via scoped sudoers
	// (e.g. "/usr/sbin/nginx -s reload"), woven into the ReloadError so the docs'
	// sudoers snippet is one copy-paste away. Optional.
	ReloadHint string
	// RunAsRoot reports whether the agent runs as root. When true the messages drop
	// the group-ownership / sudo advice (neither applies to root) and point at the
	// service sandbox instead — the actual blocker for a root agent.
	RunAsRoot bool
	// InitSystem names the service manager the agent runs under ("systemd", …) or
	// "" when run directly. "systemd" switches the messages to the unit-sandbox
	// (ProtectSystem=/ReadWritePaths) explanation, since that — not file
	// permissions — is what makes the config dir a read-only mount (EROFS).
	InitSystem string
	// UnitName is the agent's service unit (e.g. "nurproxy-agent.service"), woven
	// into the systemd remediation hint so `systemctl edit <unit>` is exact.
	UnitName string
}

// Probe runs the write and reload checks and returns a Result. It never panics
// and never exits: every failure path produces a degraded Result with an
// actionable message, so the caller can report-and-continue exactly like the
// bind-failure path. The probe is read-mostly: the write check creates and
// immediately removes a throwaway file; nothing in the live config is touched.
func Probe(ctx context.Context, opts Options) Result {
	res := Result{CanWrite: true, CanReload: true}

	if len(opts.Dirs) > 0 {
		if err := probeWrite(opts.Dirs); err != nil {
			res.CanWrite = false
			res.WriteError = writeMessage(opts, err)
		}
	}

	if opts.Runner != nil {
		if out, err := probeReload(ctx, opts.Runner); err != nil {
			res.CanReload = false
			res.ReloadError = reloadMessage(opts, err, out)
		}
	}

	return res
}

// probeWrite verifies the agent can create, write, and remove a throwaway file in
// every config directory (the group/ownership grant). It returns the first error
// encountered. A missing directory is reported as a distinct, actionable error
// (the operator may not have created the include dir yet) rather than a raw
// os.ErrNotExist.
func probeWrite(dirs []string) error {
	seen := make(map[string]struct{}, len(dirs))
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		if _, dup := seen[dir]; dup {
			continue
		}
		seen[dir] = struct{}{}

		info, err := os.Stat(dir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("config directory %q does not exist", dir)
			}
			return fmt.Errorf("cannot stat config directory %q: %w", dir, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("config path %q is not a directory", dir)
		}

		probe := filepath.Join(dir, probeFileName)
		// Create + write the probe file. A permission error here is the canonical
		// "agent user is not in the owning group" case.
		if err := os.WriteFile(probe, []byte("nurproxy permission probe\n"), 0o644); err != nil {
			return fmt.Errorf("cannot write to config directory %q: %w", dir, err)
		}
		// Always clean up, even if a later dir fails. A failed removal is itself a
		// permission problem worth surfacing.
		if err := os.Remove(probe); err != nil {
			return fmt.Errorf("cannot remove files in config directory %q: %w", dir, err)
		}
	}
	return nil
}

// probeReload runs the validate command and decides whether the failure (if any)
// is a PERMISSION denial versus a benign config-invalid result. Only a permission
// denial is a probe failure: a config-invalid result means the command ran fine
// (the privilege is present) and the operator's config simply needs fixing —
// that is the drift/apply path's job, not the permission probe's. A
// command-not-found / not-executable error is treated as a permission/setup
// problem. It returns the command's combined output in both cases so the caller
// can surface the proxy's real diagnostic (e.g. which key or log it could not
// open) instead of a bare "exit status 1".
func probeReload(ctx context.Context, r TestRunner) (string, error) {
	out, err := r.Test(ctx)
	if err == nil {
		return out, nil
	}
	if isPermissionDenied(err, out) {
		return out, err
	}
	// Command ran but the config is invalid (or some non-permission failure): the
	// reload privilege itself is present, so the probe passes. The config error is
	// surfaced elsewhere (Apply/Validate, §10), not here.
	return out, nil
}

// isPermissionDenied reports whether a validate-command failure is a privilege
// problem (missing sudoers, a dropped capability, an unreadable key) rather than
// a config-invalid result. It checks both the Go error (os.ErrPermission,
// exec.ErrNotFound surface as wrapped errors) and the command output for the
// usual denial phrasings ("permission denied", "a password is required",
// "not allowed", "sudo: ..."). It deliberately does NOT match a bare "no such
// file or directory": that string is far more often a config error (a missing
// include or cert) than a missing binary, which exec.ErrNotFound and "executable
// file not found" already catch. Matching is conservative: anything not clearly a
// denial is treated as a benign config error so we never over-report.
func isPermissionDenied(err error, output string) bool {
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	hay := strings.ToLower(err.Error() + "\n" + output)
	for _, needle := range []string{
		"permission denied",
		"operation not permitted",
		"a password is required",
		"a terminal is required",
		"sudo: no tty present",
		"is not allowed to execute",
		"not in the sudoers file",
		"command not found",
		"executable file not found",
	} {
		if strings.Contains(hay, needle) {
			return true
		}
	}
	return false
}

// writeMessage builds the actionable health message for a failed write probe.
// Which fix it points at depends on the runtime context: a read-only filesystem
// under systemd is the unit sandbox (ProtectSystem=), fixed with a ReadWritePaths
// drop-in — NOT group ownership; a root agent is never a group/ownership problem;
// otherwise the §12 group/ownership grant is the fix.
func writeMessage(opts Options, err error) string {
	b := backendLabel(opts.Backend)
	const tail = "See the least-privilege setup docs. The agent stays connected; existing config is untouched."

	if isReadOnlyFS(err) && opts.InitSystem == InitSystemdName {
		return fmt.Sprintf(
			"%s config is not writable: %v — this is the systemd unit's filesystem sandbox "+
				"(ProtectSystem=), not a file-permission problem: it makes the config dir a read-only mount. "+
				"Grant write by adding the proxy's dirs to ReadWritePaths in a %s drop-in, then restart. %s",
			b, err, unitLabel(opts.UnitName), tail)
	}
	if opts.RunAsRoot {
		return fmt.Sprintf(
			"%s config is not writable: %v — the agent runs as root, so this is not a group/ownership "+
				"problem; check the service sandbox (ProtectSystem=/ReadWritePaths) or an immutable/read-only "+
				"mount. %s",
			b, err, tail)
	}
	return fmt.Sprintf(
		"%s config is not writable: %v — add the agent user to the group that owns the config dir "+
			"(or point it at a NurProxy-owned include dir). %s",
		b, err, tail)
}

// reloadMessage builds the actionable health message for a failed reload probe.
// For a root agent the fix is never sudo: under systemd the unit sandbox can
// block the reload two independent ways — a read-only mount (ProtectSystem=,
// fixed with ReadWritePaths) and a dropped capability (CapabilityBoundingSet
// without CAP_DAC_OVERRIDE, so root obeys file bits and cannot read the proxy's
// TLS keys or write its logs). Both are named. For an unprivileged agent it is
// the §12 scoped-sudoers grant; when a ReloadHint is set the exact command is
// included. The proxy's own output is appended in every case, since the bare
// exit status hides which key or log actually failed.
func reloadMessage(opts Options, err error, output string) string {
	b := backendLabel(opts.Backend)
	const tail = "See the least-privilege setup docs. The agent stays connected; existing config is untouched."

	var msg string
	switch {
	case opts.RunAsRoot && opts.InitSystem == InitSystemdName:
		msg = fmt.Sprintf(
			"%s cannot be reloaded: %v — the agent runs as root, so this is not a sudo problem. The systemd "+
				"unit's sandbox blocks the validate/reload two ways: a read-only mount (add the proxy's config, "+
				"log and runtime dirs to ReadWritePaths) and a dropped capability (add CAP_DAC_OVERRIDE so root "+
				"may read the TLS keys and write the logs). Apply both in a %s drop-in, then restart. %s",
			b, err, unitLabel(opts.UnitName), tail)
	case opts.RunAsRoot:
		msg = fmt.Sprintf(
			"%s cannot be reloaded: %v — the agent runs as root; this is not a sudo problem. Check that it can "+
				"read the proxy's TLS keys and write its logs (file ownership/permissions), and verify the reload "+
				"command path. %s",
			b, err, tail)
	default:
		cmd := ""
		if opts.ReloadHint != "" {
			cmd = fmt.Sprintf(" (NOPASSWD for exactly %q and the matching test command)", opts.ReloadHint)
		}
		msg = fmt.Sprintf(
			"%s cannot be reloaded: %v — grant a narrowly-scoped sudoers entry%s, not blanket sudo. %s",
			b, err, cmd, tail)
	}
	return msg + proxyOutputSuffix(output)
}

// proxyOutputSuffix renders the proxy's own validate output for the health
// message, trimmed and capped so a verbose config dump never floods the
// dashboard. Empty output adds nothing.
func proxyOutputSuffix(output string) string {
	out := strings.TrimSpace(output)
	if out == "" {
		return ""
	}
	const max = 600
	if len(out) > max {
		out = "…" + out[len(out)-max:]
	}
	return " Proxy output: " + out
}

// isReadOnlyFS reports whether a write failure is an EROFS (read-only filesystem)
// — the systemd-sandbox tell — rather than a DAC permission denial. Matched on
// the error text (portable across OSes, consistent with isPermissionDenied)
// rather than syscall.EROFS, which is not defined on every build target.
func isReadOnlyFS(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "read-only file system")
}

// unitLabel returns a unit name for a `systemctl edit`-style hint, defaulting to
// a generic phrase when the agent could not resolve its own unit.
func unitLabel(unit string) string {
	if unit == "" {
		return "systemctl edit (the agent unit)"
	}
	return "systemctl edit " + unit
}

// backendLabel returns a human label for a backend name, defaulting to "proxy".
func backendLabel(backend string) string {
	if backend == "" {
		return "proxy"
	}
	return backend
}

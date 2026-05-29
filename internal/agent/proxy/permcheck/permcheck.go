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
			res.WriteError = writeMessage(opts.Backend, err)
		}
	}

	if opts.Runner != nil {
		if err := probeReload(ctx, opts.Runner); err != nil {
			res.CanReload = false
			res.ReloadError = reloadMessage(opts.Backend, opts.ReloadHint, err)
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
// problem.
func probeReload(ctx context.Context, r TestRunner) error {
	out, err := r.Test(ctx)
	if err == nil {
		return nil
	}
	if isPermissionDenied(err, out) {
		return err
	}
	// Command ran but the config is invalid (or some non-permission failure): the
	// reload privilege itself is present, so the probe passes. The config error is
	// surfaced elsewhere (Apply/Validate, §10), not here.
	return nil
}

// isPermissionDenied reports whether a validate-command failure is a privilege
// problem (the scoped sudoers entry is missing or wrong) rather than a
// config-invalid result. It checks both the Go error (os.ErrPermission,
// exec.ErrNotFound surface as wrapped errors) and the command output for the
// usual denial phrasings ("permission denied", "a password is required",
// "not allowed", "sudo: ..."). Matching is conservative: anything not clearly a
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
		"no such file or directory",
		"executable file not found",
	} {
		if strings.Contains(hay, needle) {
			return true
		}
	}
	return false
}

// writeMessage builds the actionable health message for a failed write probe,
// pointing the operator at the group/ownership fix (§12), not sudo.
func writeMessage(backend string, err error) string {
	b := backendLabel(backend)
	return fmt.Sprintf(
		"%s config is not writable: %v — add the agent user to the group that owns the config dir "+
			"(or point it at a NurProxy-owned include dir). See the least-privilege setup docs. "+
			"The agent stays connected; existing config is untouched.",
		b, err)
}

// reloadMessage builds the actionable health message for a failed reload probe,
// pointing the operator at the scoped-sudoers fix (§12), not blanket sudo. When a
// ReloadHint is set the exact command to allow is included so the docs' sudoers
// snippet is a copy-paste away.
func reloadMessage(backend, hint string, err error) string {
	b := backendLabel(backend)
	cmd := ""
	if hint != "" {
		cmd = fmt.Sprintf(" (NOPASSWD for exactly %q and the matching test command)", hint)
	}
	return fmt.Sprintf(
		"%s cannot be reloaded: %v — grant a narrowly-scoped sudoers entry%s, not blanket sudo. "+
			"See the least-privilege setup docs. The agent stays connected; existing config is untouched.",
		b, err, cmd)
}

// backendLabel returns a human label for a backend name, defaulting to "proxy".
func backendLabel(backend string) string {
	if backend == "" {
		return "proxy"
	}
	return backend
}

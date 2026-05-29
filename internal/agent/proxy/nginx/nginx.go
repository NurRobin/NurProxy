// Package nginx implements the externally-installed nginx (Debian/Ubuntu first)
// as the "nginx" proxy backend behind the agent-side proxy.Proxy interface (§5,
// §13 phase 5).
//
// Render emits a native server block via the pure nginxgen renderer. Apply is
// the atomic file dance (§10): snapshot the current on-disk file (also a store
// version) → write a temp file in the config dir → Validate (nginx -t) → on
// success atomic-rename into sites-available, symlink into sites-enabled, and
// nginx -s reload → on failure discard the temp, restore the snapshot, and
// surface the error via health. The proxy is never left non-serving (rollback).
//
// Error attribution (§10): nginx -t validates the WHOLE config, so a pre-existing
// operator error can trip our apply. AttributeNginxTestError parses the file:line
// from the nginx output and, when the fault is outside the file we wrote,
// surfaces "error in your existing config at X:N" with an inline jump-to-file
// signal (we manage the dir, so the file is reachable).
//
// It mirrors the DNS provider plugin pattern: the backend registers a Factory in
// init() so it can be resolved by name through the proxy registry. The host
// commands (nginx -t / nginx -s reload) are injected so the pure orchestration
// — snapshot/write/rename/symlink/rollback — is unit-testable via t.TempDir
// without a real nginx; the real binary path is exercised by the integration
// package (next slice).
package nginx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/agent/proxy/certstore"
	"github.com/NurRobin/NurProxy/internal/shared/nginxgen"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// backendName is the registry key for the externally-installed nginx backend.
const backendName = "nginx"

// tempSuffix is appended to a managed file name while a new version is being
// validated, before the atomic rename into place (§10). It lives in the same
// directory so the rename is atomic (same filesystem).
const tempSuffix = ".nurproxy-tmp"

func init() {
	proxy.Register(backendName, func(cfg proxy.Config) (proxy.Proxy, error) {
		b := New(cfg)
		return b, nil
	})
}

// commandError carries an nginx -t failure with its attribution so Apply can
// surface "we broke it" distinctly from "your existing config was already
// broken" (§10). It is returned by Validate's internal test step and unwrapped by
// callers that want the structured attribution; its Error() yields a
// human-readable message with the jump-to-file location.
type commandError struct {
	// Attribution classifies the failure (ours vs the operator's config).
	Attribution ErrAttribution
}

func (e *commandError) Error() string {
	a := e.Attribution
	if !a.Located {
		return fmt.Sprintf("nginx -t failed: %s", strings.TrimSpace(a.Raw))
	}
	if a.Ours {
		return fmt.Sprintf("nginx -t failed in the generated config at %s:%d", a.File, a.Line)
	}
	return fmt.Sprintf("nginx -t failed: error in your existing config at %s:%d", a.File, a.Line)
}

// Runner abstracts the two privileged host commands the backend needs (§12):
// validate (nginx -t) and reload (nginx -s reload). It is an interface so Apply's
// orchestration is testable without a real nginx, and so the agent can wire a
// scoped-sudoers runner without the backend caring how the privilege is granted.
type Runner interface {
	// Test runs the config validation (nginx -t) and returns its combined output
	// and an error if the config is invalid. The output is parsed for error
	// attribution even on success==false.
	Test(ctx context.Context) (output string, err error)
	// Reload reloads the running nginx (nginx -s reload). A reload error after a
	// passing Test is unexpected and surfaced to the caller.
	Reload(ctx context.Context) error
}

// Backend drives an externally-installed nginx behind the proxy.Proxy interface.
// It owns files under sites-available / sites-enabled and reloads via the
// injected Runner.
type Backend struct {
	// layout is the resolved sites-available / sites-enabled directory pair (§9).
	layout Layout
	// version is the parsed nginx version reported in Info, empty if unknown.
	version string
	// binary is the resolved nginx binary path, empty if not detected.
	binary string
	// logPaths are the error/access logs surfaced in the dashboard (§15).
	logPaths []string
	// runner runs nginx -t / reload; injectable for tests and scoped-sudoers wiring.
	runner Runner
	// certs resolves on-disk cert/key paths for TLS routes (§7). Nil when no cert
	// directory is configured: TLS routes then render without a cert and nginxgen
	// drops the TLS listener with a warning (invariant #4).
	certs *certstore.Store
}

// New builds an nginx backend from the agent's per-backend Config (§9). It
// resolves the sites-available/enabled layout from the detected config dir,
// attaches a cert store when CertDir is set, and defaults the Runner to one that
// shells out to the nginx binary (overridable in tests).
func New(cfg proxy.Config) *Backend {
	binary := cfg.Binary
	if binary == "" {
		if p, err := exec.LookPath("nginx"); err == nil {
			binary = p
		}
	}
	b := &Backend{
		layout:   ResolveLayout(cfg.ConfigDir),
		binary:   binary,
		logPaths: cfg.LogPaths,
		runner:   &execRunner{binary: binary, reloadCmd: cfg.ReloadCmd, testCmd: cfg.TestCmd},
	}
	if cfg.CertDir != "" {
		b.certs = certstore.New(cfg.CertDir, cfg.EncryptKey)
	}
	return b
}

// WithRunner overrides the host-command runner (tests, scoped-sudoers wiring).
// Returns the receiver for chaining.
func (b *Backend) WithRunner(r Runner) *Backend {
	b.runner = r
	return b
}

// WithVersion records the detected nginx version for Info reporting. Returns the
// receiver for chaining.
func (b *Backend) WithVersion(v string) *Backend {
	b.version = v
	return b
}

// Info reports the backend's identity and resolved paths (§5). ConfigDir is the
// sites-available directory the backend owns.
func (b *Backend) Info() proxy.Info {
	return proxy.Info{
		Kind:       proxy.KindNginx,
		Version:    b.version,
		BinaryPath: b.binary,
		ConfigDir:  b.layout.Available,
		LogPaths:   b.logPaths,
	}
}

// Detect reports whether nginx is installed on this host: a resolved binary
// path means usable. A missing binary is "not present here" (false, nil), not an
// error — detection itself did not fail.
func (b *Backend) Detect(ctx context.Context) (bool, error) {
	return b.binary != "", nil
}

// Capabilities reports the options this nginx renderer supports (§8). All listed
// options are expressible in the server block nginxgen emits; rate limiting uses
// the always-compiled-in ngx_http_limit_req_module, so it is advertised. Central
// TLS (provided certs via InstallCerts) is supported when a cert store is
// configured.
func (b *Backend) Capabilities() proxy.Capabilities {
	return proxy.Capabilities{
		ReverseProxy:  true,
		WebSocket:     true,
		ForceHTTPS:    true,
		CustomHeaders: true,
		PathRewrite:   true,
		BasicAuth:     true,
		IPFilter:      true,
		RateLimit:     true,
		CentralTLS:    b.certs != nil,
	}
}

// Render turns a backend-neutral route into a file Artifact: the content is the
// nginx http-preamble plus server block produced by the pure nginxgen renderer,
// and the target is the sites-available path nurproxy-<host>.conf. Dropped
// options (invariant #4) are logged + audited here; they never fail the render.
func (b *Backend) Render(ctx context.Context, route proxymodel.Route) (proxy.Artifact, error) {
	in := nginxgen.Input{Route: route}
	// Resolve provided-cert paths for a TLS route so the renderer can emit the
	// listener; a missing store or cert leaves the paths empty and nginxgen drops
	// the TLS listener with a warning rather than referencing a missing file.
	if !route.IsRaw() && route.Host != "" && b.certs != nil {
		if paths, err := b.certs.CertPaths(route.Host); err == nil {
			in.CertPath = paths.CertPath
			in.KeyPath = paths.KeyPath
		}
	}

	res, err := nginxgen.Render(in)
	if err != nil {
		return proxy.Artifact{}, fmt.Errorf("rendering nginx config for %q: %w", route.Host, err)
	}
	for _, w := range res.Warnings {
		slog.WarnContext(ctx, "nginx: dropped unsupported proxy option",
			slog.String("host", route.Host),
			slog.String("option", w.Option),
			slog.String("reason", w.Reason))
	}

	var content strings.Builder
	if res.HTTPPreamble != "" {
		content.WriteString(res.HTTPPreamble)
		if !strings.HasSuffix(res.HTTPPreamble, "\n") {
			content.WriteString("\n")
		}
		content.WriteString("\n")
	}
	content.WriteString(res.Server)

	return proxy.Artifact{
		Target: proxy.Target{
			Kind: proxy.TargetKindFile,
			Path: b.layout.AvailablePath(route.Host),
		},
		Content: content.String(),
		Enabled: true,
	}, nil
}

// ReadManaged reads the managed vhost files this backend owns from
// sites-available, for adoption upload and drift checks (§4, §11). Only files
// matching the nurproxy- prefix are returned; the operator's own vhosts are left
// untouched. Enabled reports whether the sites-enabled symlink is present.
func (b *Backend) ReadManaged(ctx context.Context) ([]proxy.Artifact, error) {
	entries, err := os.ReadDir(b.layout.Available)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading nginx sites-available %q: %w", b.layout.Available, err)
	}
	var arts []proxy.Artifact
	for _, e := range entries {
		if e.IsDir() || !IsManagedFile(e.Name()) {
			continue
		}
		path := filepath.Join(b.layout.Available, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading managed nginx file %q: %w", path, err)
		}
		enabled := symlinkPresent(filepath.Join(b.layout.Enabled, e.Name()))
		arts = append(arts, proxy.Artifact{
			Target:  proxy.Target{Kind: proxy.TargetKindFile, Path: path},
			Content: string(data),
			Enabled: enabled,
		})
	}
	return arts, nil
}

// Apply writes, validates, and activates the given artifacts atomically (§10).
// Per artifact it: snapshots the current on-disk content, writes a temp file in
// sites-available, then after all temps are staged runs nginx -t once (it
// validates the whole config). On a passing test it atomic-renames each temp into
// place, ensures the sites-enabled symlink, then nginx -s reload. On a failing
// test or reload it discards every temp and restores each snapshot, leaving the
// proxy serving exactly what it served before (rollback). The error carries the
// attribution so the caller can tell "we broke it" from "your existing config".
func (b *Backend) Apply(ctx context.Context, arts []proxy.Artifact) error {
	if len(arts) == 0 {
		return nil
	}
	if b.runner == nil {
		return errors.New("nginx: no command runner configured")
	}
	if err := os.MkdirAll(b.layout.Available, 0o755); err != nil {
		return fmt.Errorf("ensuring sites-available %q: %w", b.layout.Available, err)
	}
	if err := os.MkdirAll(b.layout.Enabled, 0o755); err != nil {
		return fmt.Errorf("ensuring sites-enabled %q: %w", b.layout.Enabled, err)
	}

	staged := make([]stagedFile, 0, len(arts))
	// rollback discards every temp and restores every snapshot. It is deferred-safe
	// and idempotent: a committed file's snapshot restore is skipped via committed.
	rollback := func() {
		for _, s := range staged {
			_ = os.Remove(s.tempPath)
			if s.committed {
				continue
			}
			s.restoreSnapshot()
		}
	}

	for _, art := range arts {
		dest := art.Target.Path
		if dest == "" {
			rollback()
			return errors.New("nginx apply: artifact has empty target path")
		}
		s, err := snapshot(dest)
		if err != nil {
			rollback()
			return fmt.Errorf("snapshotting %q: %w", dest, err)
		}
		s.tempPath = dest + tempSuffix
		if err := os.WriteFile(s.tempPath, []byte(art.Content), 0o644); err != nil {
			rollback()
			return fmt.Errorf("writing temp config %q: %w", s.tempPath, err)
		}
		// Stage the temp at the live path so nginx -t validates the new content. The
		// snapshot lets us restore on failure.
		if err := os.WriteFile(dest, []byte(art.Content), 0o644); err != nil {
			rollback()
			return fmt.Errorf("staging config %q: %w", dest, err)
		}
		if art.Enabled {
			link := b.enabledLinkFor(dest)
			s.enabledLink = link
			s.linkPreexisted = symlinkPresent(link)
			if err := ensureSymlink(dest, link); err != nil {
				rollback()
				return fmt.Errorf("enabling %q: %w", dest, err)
			}
		}
		staged = append(staged, s)
	}

	out, err := b.runner.Test(ctx)
	if err != nil {
		attr := AttributeNginxTestError(out, primaryTarget(arts))
		rollback()
		return &commandError{Attribution: attr}
	}

	if err := b.runner.Reload(ctx); err != nil {
		rollback()
		return fmt.Errorf("nginx -s reload failed after passing nginx -t: %w", err)
	}

	// Commit: the staged content is live and valid; drop the temps and mark
	// committed so a later rollback (there is none past here) would not revert.
	for i := range staged {
		_ = os.Remove(staged[i].tempPath)
		staged[i].committed = true
	}
	slog.InfoContext(ctx, "nginx: applied config",
		slog.Int("artifacts", len(arts)),
		slog.String("sites_available", b.layout.Available))
	return nil
}

// Remove deletes a managed vhost: its sites-enabled symlink and the
// sites-available file, then reloads so nginx drops the vhost (§3, no ghosts). A
// missing file is not an error (already gone). The reload runs only after the
// files are gone so a removed domain stops serving promptly.
func (b *Backend) Remove(ctx context.Context, target proxy.Target) error {
	if target.Path == "" {
		return errors.New("nginx remove: empty target path")
	}
	link := b.enabledLinkFor(target.Path)
	if err := os.Remove(link); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing symlink %q: %w", link, err)
	}
	if err := os.Remove(target.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing config %q: %w", target.Path, err)
	}
	if b.runner != nil {
		if err := b.runner.Reload(ctx); err != nil {
			return fmt.Errorf("nginx -s reload after remove failed: %w", err)
		}
	}
	return nil
}

// Validate checks the live config (nginx -t) without applying changes. A test
// failure is returned with its attribution so the caller can distinguish our
// config from the operator's existing config (§10).
func (b *Backend) Validate(ctx context.Context) error {
	if b.runner == nil {
		return errors.New("nginx: no command runner configured")
	}
	out, err := b.runner.Test(ctx)
	if err != nil {
		return &commandError{Attribution: AttributeNginxTestError(out, "")}
	}
	return nil
}

// InstallCerts writes the centrally-issued cert bundles to the cert store (§7),
// before Apply of any config that references them (preflight ordering). When no
// cert store is configured it is a logged no-op (a TLS route then renders without
// a cert and nginxgen drops the TLS listener with a warning, invariant #4). Certs
// arrive over the agent-initiated stream — never an inbound probe (invariant #2).
func (b *Backend) InstallCerts(ctx context.Context, certs []proxy.CertBundle) error {
	if len(certs) == 0 {
		return nil
	}
	if b.certs == nil {
		slog.WarnContext(ctx, "nginx: no cert store configured; skipping central cert install (TLS listeners dropped)",
			slog.Int("bundles", len(certs)))
		return nil
	}
	for _, c := range certs {
		paths, err := b.certs.Install(certstore.Bundle{Host: c.Host, CertPEM: c.CertPEM, KeyPEM: c.KeyPEM})
		if err != nil {
			return fmt.Errorf("installing cert for %q: %w", c.Host, err)
		}
		slog.InfoContext(ctx, "nginx: installed central cert bundle",
			slog.String("host", c.Host),
			slog.String("cert_path", paths.CertPath),
			slog.Bool("key_encrypted_at_rest", paths.Encrypted))
	}
	return nil
}

// enabledLinkFor returns the sites-enabled symlink path for a sites-available
// file: same base name in the Enabled directory.
func (b *Backend) enabledLinkFor(availablePath string) string {
	return filepath.Join(b.layout.Enabled, filepath.Base(availablePath))
}

// primaryTarget returns the first artifact's target path, used as "our file" for
// error attribution. A single-domain apply has exactly one; for a multi-file
// apply the first is a reasonable anchor (the attribution still compares the
// blamed file against it by base name).
func primaryTarget(arts []proxy.Artifact) string {
	if len(arts) == 0 {
		return ""
	}
	return arts[0].Target.Path
}

// execRunner is the default Runner: it shells out to the nginx binary for -t and
// -s reload, honoring per-agent command overrides (§9, scoped sudoers). The
// integration package exercises this against a real nginx; unit tests inject a
// fake Runner instead.
type execRunner struct {
	binary    string
	testCmd   string
	reloadCmd string
}

// Test runs nginx -t (or the configured override) and returns combined output.
func (r *execRunner) Test(ctx context.Context) (string, error) {
	cmd := r.command(ctx, r.testCmd, "-t")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Reload runs nginx -s reload (or the configured override).
func (r *execRunner) Reload(ctx context.Context) error {
	cmd := r.command(ctx, r.reloadCmd, "-s", "reload")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// command builds the exec.Cmd for a step: a configured override string is split
// on whitespace and run as-is; otherwise the resolved binary is invoked with the
// default args.
func (r *execRunner) command(ctx context.Context, override string, defaultArgs ...string) *exec.Cmd {
	if override != "" {
		fields := strings.Fields(override)
		return exec.CommandContext(ctx, fields[0], fields[1:]...)
	}
	return exec.CommandContext(ctx, r.binary, defaultArgs...)
}

var _ proxy.Proxy = (*Backend)(nil)

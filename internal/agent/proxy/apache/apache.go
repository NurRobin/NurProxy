// Package apache implements the externally-installed Apache httpd as the
// "apache" proxy backend behind the agent-side proxy.Proxy interface (§5, §13
// phase 6).
//
// Render emits a native <VirtualHost> block via the pure apachegen renderer.
// Apply is the atomic file dance (§10): snapshot the current on-disk file (also
// a store version) → write a temp file in the config dir → Validate (apachectl
// configtest) → on success atomic-rename into the config dir, symlink into
// sites-enabled (Debian) or leave it in conf.d (RHEL), and reload → on failure
// discard the temp, restore the snapshot, and surface the error. The proxy is
// never left non-serving (rollback).
//
// It supports both Apache directory conventions (§9): Debian/Ubuntu
// sites-available + sites-enabled (symlink activation, like a2ensite) and
// RHEL/Fedora conf.d (flat, every *.conf auto-included — no enable step). The
// Layout resolved from the detected config dir decides which.
//
// Error attribution (§10): apachectl configtest validates the WHOLE config, so a
// pre-existing operator error can trip our apply. AttributeConfigtestError
// parses the file:line from the output and, when the fault is outside the file
// we wrote, surfaces "error in your existing config at X:N".
//
// It mirrors the nginx backend and the DNS provider plugin pattern: the backend
// registers a Factory in init() so it can be resolved by name through the proxy
// registry. The host commands (apachectl configtest / reload) are injected so
// the pure orchestration is unit-testable via t.TempDir without a real apache;
// the real binary path is exercised by the integration tests.
package apache

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
	"github.com/NurRobin/NurProxy/internal/shared/apachegen"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// backendName is the registry key for the externally-installed apache backend.
const backendName = "apache"

// tempSuffix is appended to a managed file name while a new version is being
// validated, before the atomic rename into place (§10). It lives in the same
// directory so the rename is atomic (same filesystem). It deliberately does NOT
// end in .conf so a stray temp on the RHEL conf.d layout is never auto-included
// by Apache mid-apply.
const tempSuffix = ".nurproxy-tmp"

func init() {
	proxy.Register(backendName, func(cfg proxy.Config) (proxy.Proxy, error) {
		return New(cfg), nil
	})
}

// commandError carries an apachectl configtest failure with its attribution so
// Apply can surface "we broke it" distinctly from "your existing config was
// already broken" (§10). Its Error() yields a human-readable message with the
// jump-to-file location.
type commandError struct {
	// Attribution classifies the failure (ours vs the operator's config).
	Attribution ErrAttribution
}

func (e *commandError) Error() string {
	a := e.Attribution
	if !a.Located {
		return fmt.Sprintf("apachectl configtest failed: %s", strings.TrimSpace(a.Raw))
	}
	if a.Ours {
		return fmt.Sprintf("apachectl configtest failed in the generated config at %s:%d", a.File, a.Line)
	}
	return fmt.Sprintf("apachectl configtest failed: error in your existing config at %s:%d", a.File, a.Line)
}

// Runner abstracts the two privileged host commands the backend needs (§12):
// validate (apachectl configtest) and reload (apachectl graceful / systemctl
// reload). It is an interface so Apply's orchestration is testable without a real
// apache, and so the agent can wire a scoped-sudoers runner without the backend
// caring how the privilege is granted.
type Runner interface {
	// Test runs the config validation (apachectl configtest) and returns its
	// combined output and an error if the config is invalid. The output is parsed
	// for error attribution even on failure.
	Test(ctx context.Context) (output string, err error)
	// Reload reloads the running apache (apachectl graceful). A reload error after
	// a passing Test is unexpected and surfaced to the caller.
	Reload(ctx context.Context) error
}

// Backend drives an externally-installed Apache behind the proxy.Proxy
// interface. It owns files under sites-available / conf.d and reloads via the
// injected Runner.
type Backend struct {
	// layout is the resolved sites-available/sites-enabled (Debian) or conf.d
	// (RHEL) directory layout (§9).
	layout Layout
	// version is the parsed apache version reported in Info, empty if unknown.
	version string
	// binary is the resolved apachectl/httpd binary path, empty if not detected.
	binary string
	// logPaths are the error/access logs surfaced in the dashboard (§15).
	logPaths []string
	// runner runs configtest / reload; injectable for tests and scoped-sudoers
	// wiring.
	runner Runner
	// certs resolves on-disk cert/key paths for TLS routes (§7). Nil when no cert
	// directory is configured: TLS routes then render without a cert and apachegen
	// drops the TLS listener with a warning (invariant #4).
	certs *certstore.Store
}

// New builds an apache backend from the agent's per-backend Config (§9). It
// resolves the directory layout from the detected config dir, attaches a cert
// store when CertDir is set, and defaults the Runner to one that shells out to
// the apachectl binary (overridable in tests).
func New(cfg proxy.Config) *Backend {
	binary := cfg.Binary
	if binary == "" {
		for _, cand := range []string{"apachectl", "apache2ctl", "httpd", "apache2"} {
			if p, err := exec.LookPath(cand); err == nil {
				binary = p
				break
			}
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

// WithVersion records the detected apache version for Info reporting. Returns the
// receiver for chaining.
func (b *Backend) WithVersion(v string) *Backend {
	b.version = v
	return b
}

// Info reports the backend's identity and resolved paths (§5). ConfigDir is the
// Available directory the backend owns (sites-available or conf.d).
func (b *Backend) Info() proxy.Info {
	return proxy.Info{
		Kind:       proxy.KindApache,
		Version:    b.version,
		BinaryPath: b.binary,
		ConfigDir:  b.layout.Available,
		LogPaths:   b.logPaths,
	}
}

// Detect reports whether apache is installed on this host: a resolved binary
// path means usable. A missing binary is "not present here" (false, nil), not an
// error — detection itself did not fail.
func (b *Backend) Detect(ctx context.Context) (bool, error) {
	return b.binary != "", nil
}

// Capabilities reports the options this apache renderer supports (§8). All listed
// options are expressible in the VirtualHost apachegen emits. Per-client rate
// limiting is NOT supported (Apache core has no equivalent — mod_ratelimit only
// throttles bandwidth), so it is advertised false and dropped during Render with
// a warning. Central TLS (provided certs via InstallCerts) is supported when a
// cert store is configured.
func (b *Backend) Capabilities() proxy.Capabilities {
	return proxy.Capabilities{
		ReverseProxy:  true,
		WebSocket:     true,
		ForceHTTPS:    true,
		CustomHeaders: true,
		PathRewrite:   true,
		BasicAuth:     true,
		IPFilter:      true,
		RateLimit:     false,
		CentralTLS:    b.certs != nil,
	}
}

// Render turns a backend-neutral route into a file Artifact: the content is the
// Apache VirtualHost block produced by the pure apachegen renderer, and the
// target is the config path nurproxy-<host>.conf. Dropped options (invariant #4)
// are logged here and carried back in the apply-ACK so the orchestrator audits
// each one; they never fail the render.
func (b *Backend) Render(ctx context.Context, route proxymodel.Route) (proxy.Artifact, error) {
	in := apachegen.Input{Route: route}
	// Resolve provided-cert paths for a TLS route so the renderer can emit the
	// listener; a missing store or cert leaves the paths empty and apachegen drops
	// the TLS listener with a warning rather than referencing a missing file.
	if !route.IsRaw() && route.Host != "" && b.certs != nil {
		if paths, err := b.certs.CertPaths(route.Host); err == nil {
			in.CertPath = paths.CertPath
			in.KeyPath = paths.KeyPath
		}
	}
	// Materialize the htpasswd file for a basic-auth route so basic auth works
	// instead of being dropped (§6). The intent carries the bcrypt entry; a write
	// failure leaves AuthFile empty and apachegen degrades to a warning (invariant #4).
	if !route.IsRaw() && route.Host != "" && route.BasicAuth != nil &&
		route.BasicAuth.Username != "" && route.BasicAuth.PasswordHash != "" {
		if authPath, err := b.writeHtpasswd(route.Host, route.BasicAuth.Username, route.BasicAuth.PasswordHash); err != nil {
			slog.WarnContext(ctx, "apache: could not write htpasswd; basic auth will be dropped",
				slog.String("host", route.Host), slog.Any("err", err))
		} else {
			in.AuthFile = authPath
		}
	}

	res, err := apachegen.Render(in)
	if err != nil {
		return proxy.Artifact{}, fmt.Errorf("rendering apache config for %q: %w", route.Host, err)
	}
	warnings := make([]string, 0, len(res.Warnings))
	for _, w := range res.Warnings {
		slog.WarnContext(ctx, "apache: dropped unsupported proxy option",
			slog.String("host", route.Host),
			slog.String("option", w.Option),
			slog.String("reason", w.Reason))
		warnings = append(warnings, w.String())
	}

	var content strings.Builder
	if res.Preamble != "" {
		content.WriteString(res.Preamble)
		if !strings.HasSuffix(res.Preamble, "\n") {
			content.WriteString("\n")
		}
		content.WriteString("\n")
	}
	content.WriteString(res.VHost)

	return proxy.Artifact{
		Target: proxy.Target{
			Kind: proxy.TargetKindFile,
			Path: b.layout.AvailablePath(route.Host),
		},
		Content:  content.String(),
		Enabled:  true,
		Warnings: warnings,
	}, nil
}

// ReadManaged reads the vhost files in the Available dir for adoption upload and
// drift checks (§4, §11). It reads ALL files (no whitelist): Existing-mode
// adoption tracks the operator's hand-written vhosts too — there is nothing to
// guard against by scoping, because NurProxy never auto-overwrites a file without
// an explicit Accept. Files NurProxy generated (the nurproxy- prefix) are
// returned with Adopted=false for drift comparison; every other file is an
// operator-authored config, returned with Adopted=true so the orchestrator
// stores it as Source: manual, version 1. Enabled reports whether an entry is
// present in sites-enabled (Debian) — by symlink or copied file — or, on the RHEL
// conf.d layout, whether the file is present at all (presence == enabled).
func (b *Backend) ReadManaged(ctx context.Context) ([]proxy.Artifact, error) {
	entries, err := os.ReadDir(b.layout.Available)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading apache config dir %q: %w", b.layout.Available, err)
	}
	var arts []proxy.Artifact
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Skip our own in-flight temp files and per-vhost htpasswd sidecars.
		if strings.HasSuffix(name, tempSuffix) || strings.HasSuffix(name, htpasswdSuffix) {
			continue
		}
		path := filepath.Join(b.layout.Available, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading apache config %q: %w", path, err)
		}
		enabled := true
		if !b.layout.IsConfD() {
			enabled = activationPresent(filepath.Join(b.layout.Enabled, name))
		}
		arts = append(arts, proxy.Artifact{
			Target:  proxy.Target{Kind: proxy.TargetKindFile, Path: path},
			Content: string(data),
			Enabled: enabled,
			Adopted: !IsManagedFile(name),
		})
	}
	return arts, nil
}

// Apply writes, validates, and activates the given artifacts atomically (§10).
// Per artifact it: snapshots the current on-disk content, writes a temp file in
// the config dir, stages the new content at the live path, then after all temps
// are staged runs apachectl configtest once (it validates the whole config). On a
// passing test it ensures the sites-enabled symlink (Debian only; conf.d needs
// none), then reloads. On a failing test or reload it discards every temp and
// restores each snapshot, leaving the proxy serving exactly what it served
// before (rollback). The error carries the attribution so the caller can tell
// "we broke it" from "your existing config".
func (b *Backend) Apply(ctx context.Context, arts []proxy.Artifact) error {
	if len(arts) == 0 {
		return nil
	}
	if b.runner == nil {
		return errors.New("apache: no command runner configured")
	}
	if err := os.MkdirAll(b.layout.Available, 0o755); err != nil {
		return fmt.Errorf("ensuring apache config dir %q: %w", b.layout.Available, err)
	}
	if !b.layout.IsConfD() {
		if err := os.MkdirAll(b.layout.Enabled, 0o755); err != nil {
			return fmt.Errorf("ensuring sites-enabled %q: %w", b.layout.Enabled, err)
		}
	}

	staged := make([]*stagedFile, 0, len(arts))
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
			return errors.New("apache apply: artifact has empty target path")
		}
		s, err := snapshot(dest)
		if err != nil {
			rollback()
			return fmt.Errorf("snapshotting %q: %w", dest, err)
		}
		s.tempPath = dest + tempSuffix
		// Register the staged file in the rollback set BEFORE overwriting the live
		// path, so any later failure in this iteration (e.g. a symlink clash on a
		// copied sites-enabled file) still restores dest's prior content rather than
		// leaving the new config live. staged holds pointers so the symlink fields
		// set below are visible to rollback.
		sp := &s
		staged = append(staged, sp)
		if err := os.WriteFile(sp.tempPath, []byte(art.Content), 0o644); err != nil {
			rollback()
			return fmt.Errorf("writing temp config %q: %w", sp.tempPath, err)
		}
		// Stage the temp at the live path so configtest validates the new content.
		// The snapshot lets us restore on failure.
		if err := os.WriteFile(dest, []byte(art.Content), 0o644); err != nil {
			rollback()
			return fmt.Errorf("staging config %q: %w", dest, err)
		}
		// Debian: ensure the sites-enabled symlink. RHEL conf.d: presence is enough.
		if art.Enabled && !b.layout.IsConfD() {
			link := b.enabledLinkFor(dest)
			sp.enabledLink = link
			sp.linkPreexisted = symlinkPresent(link)
			if err := ensureSymlink(dest, link); err != nil {
				rollback()
				return fmt.Errorf("enabling %q: %w", dest, err)
			}
		}
	}

	out, err := b.runner.Test(ctx)
	if err != nil {
		attr := AttributeConfigtestError(out, primaryTarget(arts))
		rollback()
		return &commandError{Attribution: attr}
	}

	if err := b.runner.Reload(ctx); err != nil {
		rollback()
		return fmt.Errorf("apache reload failed after passing configtest: %w", err)
	}

	// Commit: the staged content is live and valid; drop the temps and mark
	// committed so a later rollback (there is none past here) would not revert.
	for i := range staged {
		_ = os.Remove(staged[i].tempPath)
		staged[i].committed = true
	}
	slog.InfoContext(ctx, "apache: applied config",
		slog.Int("artifacts", len(arts)),
		slog.String("config_dir", b.layout.Available),
		slog.Bool("confd_layout", b.layout.IsConfD()))
	return nil
}

// Remove deletes a managed vhost: its sites-enabled symlink (Debian) and the
// config file, then reloads so apache drops the vhost (§3, no ghosts). A missing
// file is not an error (already gone). The reload runs only after the files are
// gone so a removed domain stops serving promptly.
func (b *Backend) Remove(ctx context.Context, target proxy.Target) error {
	if target.Path == "" {
		return errors.New("apache remove: empty target path")
	}
	if !b.layout.IsConfD() {
		link := b.enabledLinkFor(target.Path)
		if err := os.Remove(link); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing symlink %q: %w", link, err)
		}
	}
	if err := os.Remove(target.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing config %q: %w", target.Path, err)
	}
	if auth := strings.TrimSuffix(target.Path, confSuffix) + htpasswdSuffix; auth != target.Path {
		_ = os.Remove(auth)
	}
	// Scrub the host's centrally-issued cert/key artifacts (incl. any decrypted
	// .key.plain) so a removed domain leaves no private key on disk.
	b.removeCerts(ctx, target.Path)
	if b.runner != nil {
		if err := b.runner.Reload(ctx); err != nil {
			return fmt.Errorf("apache reload after remove failed: %w", err)
		}
	}
	return nil
}

// removeCerts deletes the cert store artifacts for the host a managed config
// path belongs to. Managed files are named nurproxy-<base>.conf where <base> is
// the cert store's sanitized host; an operator-authored config (no nurproxy-
// prefix) has no NurProxy-issued cert, so it is skipped. A nil cert store (no
// CertDir configured) is a no-op. Errors are logged, not fatal: failing to
// scrub a stale key must not block the domain removal/reload.
func (b *Backend) removeCerts(ctx context.Context, configPath string) {
	if b.certs == nil {
		return
	}
	name := filepath.Base(configPath)
	if !IsManagedFile(name) {
		return
	}
	base := strings.TrimSuffix(strings.TrimPrefix(name, managedPrefix), confSuffix)
	if err := b.certs.Remove(base); err != nil {
		slog.WarnContext(ctx, "apache: could not remove cert artifacts for removed vhost",
			slog.String("config", configPath), slog.Any("err", err))
	}
}

// Prune removes every NurProxy-generated vhost (the nurproxy- prefix) in the
// config dir whose path is not in keep, then reloads once if anything was removed
// (§3, no ghost vhosts on domain delete). applyIntents calls it with the full
// desired set received over the agent's dial-out stream, so a deleted domain's
// file is gone on the next push without an inbound probe (invariant #2). Operator
// configs (no nurproxy- prefix) are never touched.
func (b *Backend) Prune(ctx context.Context, keep []proxy.Target) (int, error) {
	wanted := make(map[string]bool, len(keep))
	for _, t := range keep {
		if t.Path != "" {
			wanted[t.Path] = true
		}
	}
	entries, err := os.ReadDir(b.layout.Available)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("reading apache config dir %q: %w", b.layout.Available, err)
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !IsManagedFile(name) || strings.HasSuffix(name, tempSuffix) {
			continue
		}
		path := filepath.Join(b.layout.Available, name)
		if wanted[path] {
			continue
		}
		if !b.layout.IsConfD() {
			link := b.enabledLinkFor(path)
			if err := os.Remove(link); err != nil && !errors.Is(err, os.ErrNotExist) {
				return removed, fmt.Errorf("removing orphan symlink %q: %w", link, err)
			}
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, fmt.Errorf("removing orphan config %q: %w", path, err)
		}
		_ = os.Remove(strings.TrimSuffix(path, confSuffix) + htpasswdSuffix)
		// Scrub the orphaned vhost's centrally-issued cert/key artifacts so a
		// deleted domain leaves no decrypted private key behind.
		b.removeCerts(ctx, path)
		removed++
	}
	if removed > 0 && b.runner != nil {
		if err := b.runner.Reload(ctx); err != nil {
			return removed, fmt.Errorf("apache reload after prune failed: %w", err)
		}
	}
	return removed, nil
}

// Validate checks the live config (apachectl configtest) without applying
// changes. A test failure is returned with its attribution so the caller can
// distinguish our config from the operator's existing config (§10).
func (b *Backend) Validate(ctx context.Context) error {
	if b.runner == nil {
		return errors.New("apache: no command runner configured")
	}
	out, err := b.runner.Test(ctx)
	if err != nil {
		return &commandError{Attribution: AttributeConfigtestError(out, "")}
	}
	return nil
}

// InstallCerts writes the centrally-issued cert bundles to the cert store (§7),
// before Apply of any config that references them (preflight ordering). When no
// cert store is configured it is a logged no-op (a TLS route then renders without
// a cert and apachegen drops the TLS listener with a warning, invariant #4).
// Certs arrive over the agent-initiated stream — never an inbound probe
// (invariant #2).
func (b *Backend) InstallCerts(ctx context.Context, certs []proxy.CertBundle) error {
	if len(certs) == 0 {
		return nil
	}
	if b.certs == nil {
		slog.WarnContext(ctx, "apache: no cert store configured; skipping central cert install (TLS listeners dropped)",
			slog.Int("bundles", len(certs)))
		return nil
	}
	for _, c := range certs {
		paths, err := b.certs.Install(certstore.Bundle{Host: c.Host, CertPEM: c.CertPEM, KeyPEM: c.KeyPEM})
		if err != nil {
			return fmt.Errorf("installing cert for %q: %w", c.Host, err)
		}
		slog.InfoContext(ctx, "apache: installed central cert bundle",
			slog.String("host", c.Host),
			slog.String("cert_path", paths.CertPath),
			slog.Bool("key_encrypted_at_rest", paths.Encrypted))
	}
	return nil
}

// enabledLinkFor returns the sites-enabled symlink path for a config file: same
// base name in the Enabled directory. Only meaningful on the Debian layout.
func (b *Backend) enabledLinkFor(availablePath string) string {
	return filepath.Join(b.layout.Enabled, filepath.Base(availablePath))
}

// htpasswdSuffix names the per-vhost basic-auth file the agent maintains beside the
// managed config (not a .conf, so Apache's Include glob never loads it and
// ReadManaged/Prune treat it as auxiliary).
const htpasswdSuffix = ".htpasswd"

// authFilePath is the htpasswd path for a host's managed vhost.
func (b *Backend) authFilePath(host string) string {
	return strings.TrimSuffix(b.layout.AvailablePath(host), confSuffix) + htpasswdSuffix
}

// writeHtpasswd writes "user:hash" to the host's htpasswd file and returns its path.
func (b *Backend) writeHtpasswd(host, user, hash string) (string, error) {
	if err := os.MkdirAll(b.layout.Available, 0o755); err != nil {
		return "", fmt.Errorf("ensuring config dir %q: %w", b.layout.Available, err)
	}
	path := b.authFilePath(host)
	if err := os.WriteFile(path, []byte(fmt.Sprintf("%s:%s\n", user, hash)), 0o644); err != nil {
		return "", fmt.Errorf("writing htpasswd %q: %w", path, err)
	}
	return path, nil
}

// ResolvedCommands returns the exact configtest and reload command strings this
// backend will run (binary+args), so a later slice can feed permcheck's
// remediation builder the scoped-sudoers commands without re-deriving them. It
// mirrors execRunner.command: a per-agent override is returned verbatim;
// otherwise the resolved binary is joined with the default args (configtest,
// graceful). When the runner is not the default execRunner (e.g. a test fake)
// the defaults are derived from the backend's resolved binary.
func (b *Backend) ResolvedCommands() (test string, reload string) {
	if r, ok := b.runner.(*execRunner); ok {
		// Return the privileged command the agent actually runs via sudo, binary
		// resolved to an absolute path (a scoped sudoers entry must name absolute
		// commands and must match what the agent invokes).
		tn, ta := r.spec(r.testCmd, []string{"configtest"})
		rn, ra := r.spec(r.reloadCmd, []string{"graceful"})
		return joinCommand(tn, ta), joinCommand(rn, ra)
	}
	bin := b.binary
	if bin == "" {
		bin = "apachectl"
	}
	return bin + " configtest", bin + " graceful"
}

// primaryTarget returns the first artifact's target path, used as "our file" for
// error attribution.
func primaryTarget(arts []proxy.Artifact) string {
	if len(arts) == 0 {
		return ""
	}
	return arts[0].Target.Path
}

// ProbeDirs reports the directories the agent must be able to write to manage
// apache (§12): the Available dir always, plus sites-enabled on the Debian
// layout (the a2ensite symlink dir). The RHEL conf.d layout has no separate
// enable dir, so only the one directory is returned. The startup permission
// probe (permcheck) writes a throwaway file in each to confirm the
// group/ownership grant before any real apply.
func (b *Backend) ProbeDirs() []string {
	if b.layout.IsConfD() {
		return []string{b.layout.Available}
	}
	return []string{b.layout.Available, b.layout.Enabled}
}

// Runner exposes the backend's configtest/reload runner so the startup
// permission probe can confirm the scoped-sudoers reload grant (§12) without the
// backend depending on the probe package. It satisfies permcheck.TestRunner.
func (b *Backend) Runner() Runner { return b.runner }

// ReloadHint returns the reload command the operator must allow via a scoped
// sudoers entry (§12), woven into the probe's actionable health message. It is
// the per-agent override when set, else the default apachectl graceful reload.
func (b *Backend) ReloadHint() string {
	if r, ok := b.runner.(*execRunner); ok && r.reloadCmd != "" {
		return r.reloadCmd
	}
	bin := b.binary
	if bin == "" {
		bin = "apachectl"
	}
	return bin + " graceful"
}

// execRunner is the default Runner: it shells out to the apachectl binary for
// configtest and graceful reload, honoring per-agent command overrides (§9,
// scoped sudoers). The integration tests exercise this against a real apache;
// unit tests inject a fake Runner instead.
type execRunner struct {
	binary    string
	testCmd   string
	reloadCmd string
}

// Test runs apachectl configtest (or the configured override) and returns
// combined output.
func (r *execRunner) Test(ctx context.Context) (string, error) {
	cmd := r.command(ctx, r.testCmd, "configtest")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Reload runs apachectl graceful (or the configured override). A graceful reload
// re-reads config without dropping active connections.
func (r *execRunner) Reload(ctx context.Context) error {
	cmd := r.command(ctx, r.reloadCmd, "graceful")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// command builds the exec.Cmd for a step. It resolves the privileged command
// (see spec) and, when the agent runs unprivileged, invokes it through `sudo -n`
// so a scoped, passwordless sudoers entry (the §12 remediation) grants exactly
// these commands instead of requiring the whole agent to run as root.
func (r *execRunner) command(ctx context.Context, override string, defaultArgs ...string) *exec.Cmd {
	name, args := r.spec(override, defaultArgs)
	if elevateNeeded() && filepath.Base(name) != "sudo" {
		args = append([]string{"-n", name}, args...)
		name = "sudo"
	}
	return exec.CommandContext(ctx, name, args...)
}

// spec resolves a step to its (name, args) WITHOUT sudo: a per-agent override
// wins (split on whitespace), otherwise the resolved binary + default args. A
// bare override binary is resolved to an absolute path (skipping "sudo" and
// already-absolute paths) so it matches a scoped sudoers entry. Single source of
// truth for both execution (which wraps it in sudo) and ResolvedCommands (the
// remediation).
func (r *execRunner) spec(override string, defaultArgs []string) (name string, args []string) {
	if override != "" {
		fields := strings.Fields(override)
		name, args = fields[0], fields[1:]
		if name != "sudo" && !filepath.IsAbs(name) {
			if abs, err := exec.LookPath(name); err == nil {
				name = abs
			}
		}
		return name, args
	}
	name = r.binary
	if name == "" {
		name = "apachectl"
	}
	return name, defaultArgs
}

// elevateNeeded reports whether privileged proxy commands should run via sudo:
// true only for a non-root POSIX user. Geteuid() is 0 for root and -1 on Windows
// (both return false), so the command runs directly there. NURPROXY_NO_SUDO=1
// disables the sudo wrapper (agent already privileged / external elevation).
func elevateNeeded() bool {
	if os.Getenv("NURPROXY_NO_SUDO") == "1" {
		return false
	}
	return os.Geteuid() > 0
}

// joinCommand renders a (name, args) pair into a single command string for the
// remediation's sudoers line.
func joinCommand(name string, args []string) string {
	if len(args) == 0 {
		return name
	}
	return name + " " + strings.Join(args, " ")
}

var _ proxy.Proxy = (*Backend)(nil)

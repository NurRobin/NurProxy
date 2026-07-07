// Package generic implements a template-driven proxy backend for engines
// NurProxy has no native renderer for (HAProxy, Traefik, lighttpd, …), exposed
// as the "custom" backend behind the agent-side proxy.Proxy interface (§5, §9).
//
// Unlike the nginx/apache/caddy backends — which render a fixed, audited config
// shape — this backend renders each route through an operator-supplied Go
// text/template. Because that template plus the reload/test commands are
// arbitrary code the agent executes, a custom engine is configured ONLY from
// local agent config (agent.yaml / NP_PROXY_* / flags): the host operator, who
// already owns the host, opts in. It is never auto-detected and never defined
// over the network (the orchestrator's set_proxy_mode / the agent's
// /admin/reconfigure stay restricted to the native engines via cmdguard).
//
// The file dance mirrors nginx's atomic apply (§10) in a conf.d shape (one
// rendered file per route in a single directory, no sites-enabled symlink):
// snapshot → write temp + stage live → validate (optional test command) →
// reload → on failure restore every snapshot so the proxy is never left
// non-serving.
package generic

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/agent/proxy/certstore"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// backendName is the registry key for the operator-defined custom engine.
const backendName = "custom"

// managedPrefix namespaces the files this backend owns in the config dir, so
// Prune/Remove never touch an operator's hand-written config.
const managedPrefix = "nurproxy-"

// tempSuffix is appended to a managed file while a new version is validated,
// before it is committed (same dir → atomic rename / safe overwrite).
const tempSuffix = ".nurproxy-tmp"

// defaultFileExt is used when the operator does not set proxy_file_ext.
const defaultFileExt = ".conf"

func init() {
	proxy.Register(backendName, func(cfg proxy.Config) (proxy.Proxy, error) {
		return New(cfg)
	})
}

// RouteContext is the data a custom engine's template receives for one route. It
// offers flat convenience fields for the common case plus the full Route for
// advanced templates.
type RouteContext struct {
	// Host is the public FQDN this route serves.
	Host string
	// TLS reports whether the public listener terminates TLS (policy central or
	// self-acme). False for plaintext (policy off).
	TLS bool
	// Policy is the TLS policy string ("central" | "self-acme" | "off").
	Policy string
	// CertPath / KeyPath are the on-disk cert + key for a central-TLS route,
	// resolved from the agent cert store. Empty when not central or not yet
	// installed — the template should guard with {{ if .CertPath }}.
	CertPath string
	KeyPath  string
	// Scheme is the upstream scheme ("http" | "https").
	Scheme string
	// UpstreamHost / UpstreamPort / UpstreamAddr describe the backend target.
	UpstreamHost string
	UpstreamPort int
	UpstreamAddr string
	// ForceHTTPS / WebSocket mirror the route options for convenience.
	ForceHTTPS bool
	WebSocket  bool
	// Route is the complete backend-neutral intent, for anything the flat fields
	// above don't cover (headers, path rules, timeouts, IP rules, rate limit).
	Route proxymodel.Route
}

// Runner runs the custom engine's validate (optional) and reload commands.
// Abstracted so Apply's orchestration is testable without a real engine.
type Runner interface {
	// Test validates the config. ok is false with a nil error when no test
	// command is configured (the engine has no validate step); callers then skip
	// validation and apply directly.
	Test(ctx context.Context) (ok bool, output string, err error)
	// Reload reloads the running engine so it picks up the new config.
	Reload(ctx context.Context) error
}

// Backend drives an operator-defined engine behind proxy.Proxy.
type Backend struct {
	configDir string
	fileExt   string
	binary    string
	logPaths  []string
	tmpl      *template.Template
	caps      proxy.Capabilities
	runner    Runner
	certs     *certstore.Store
}

// New builds the custom backend from local agent Config (§9). It requires a
// non-empty Template and a non-empty ReloadCmd — without a way to render and to
// reload, NurProxy could not manage the engine. A TestCmd is optional (not every
// engine has a validate step).
func New(cfg proxy.Config) (*Backend, error) {
	if strings.TrimSpace(cfg.Template) == "" {
		return nil, errors.New("custom proxy: a config template is required (proxy_template)")
	}
	if strings.TrimSpace(cfg.ReloadCmd) == "" {
		return nil, errors.New("custom proxy: a reload command is required (proxy_reload_cmd)")
	}
	if strings.TrimSpace(cfg.ConfigDir) == "" {
		return nil, errors.New("custom proxy: a config directory is required (proxy_config_dir)")
	}
	tmpl, err := template.New("custom-route").Option("missingkey=zero").Parse(cfg.Template)
	if err != nil {
		return nil, fmt.Errorf("custom proxy: parsing template: %w", err)
	}
	ext := cfg.FileExt
	if ext == "" {
		ext = defaultFileExt
	}
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	caps := defaultCaps()
	if cfg.DeclaredCaps != nil {
		caps = *cfg.DeclaredCaps
		caps.ReverseProxy = true // baseline is always present
	}
	b := &Backend{
		configDir: cfg.ConfigDir,
		fileExt:   ext,
		binary:    cfg.Binary,
		logPaths:  cfg.LogPaths,
		tmpl:      tmpl,
		caps:      caps,
		runner:    &execRunner{testCmd: cfg.TestCmd, reloadCmd: cfg.ReloadCmd},
	}
	if cfg.CertDir != "" {
		b.certs = certstore.New(cfg.CertDir, cfg.EncryptKey)
	}
	return b, nil
}

// defaultCaps is the safe baseline for a custom engine that declares nothing:
// reverse proxy and central TLS only. The operator opts into the rest, asserting
// their template expresses it.
func defaultCaps() proxy.Capabilities {
	return proxy.Capabilities{ReverseProxy: true, CentralTLS: true}
}

// WithRunner overrides the command runner (tests). Returns the receiver.
func (b *Backend) WithRunner(r Runner) *Backend { b.runner = r; return b }

// Info reports the backend identity. Kind is "custom"; ConfigDir is the directory
// the rendered per-route files live in.
func (b *Backend) Info() proxy.Info {
	return proxy.Info{
		Kind:       proxy.KindCustom,
		BinaryPath: b.binary,
		ConfigDir:  b.configDir,
		LogPaths:   b.logPaths,
	}
}

// Detect always reports present: a custom engine is an explicit operator choice
// (proxy_type=custom with a template), not something to sniff for. Runtime
// command failures surface through Apply/Validate and the health report.
func (b *Backend) Detect(_ context.Context) (bool, error) { return true, nil }

// Capabilities reports the operator-declared capability matrix (§8). CentralTLS
// additionally requires a configured cert store.
func (b *Backend) Capabilities() proxy.Capabilities {
	c := b.caps
	c.CentralTLS = c.CentralTLS && b.certs != nil
	return c
}

// managedPath returns the rendered-config path for a host: a namespaced file in
// the config dir, with the host sanitized to the same base the cert store uses
// so cert scrubbing on Remove/Prune lines up.
func (b *Backend) managedPath(host string) string {
	return filepath.Join(b.configDir, managedPrefix+certstore.SanitizeHost(host)+b.fileExt)
}

// isManaged reports whether a file name is one this backend generated.
func (b *Backend) isManaged(name string) bool {
	return strings.HasPrefix(name, managedPrefix) && strings.HasSuffix(name, b.fileExt)
}

// Render turns a route into a file Artifact by executing the operator template.
// A raw route tagged for "custom" is used verbatim (the per-backend escape
// hatch, §6); a raw route tagged for a different backend is refused.
func (b *Backend) Render(_ context.Context, route proxymodel.Route) (proxy.Artifact, error) {
	if route.IsRaw() {
		if route.Raw.Backend != backendName {
			return proxy.Artifact{}, fmt.Errorf("custom proxy: raw config tagged for %q, not %q", route.Raw.Backend, backendName)
		}
		return proxy.Artifact{
			Target:  proxy.Target{Kind: proxy.TargetKindFile, Path: b.managedPath(route.Host)},
			Content: route.Raw.Content,
			Enabled: true,
		}, nil
	}

	policy := route.TLS.Policy
	if policy == "" {
		policy = proxymodel.TLSPolicyCentral
	}
	ctx := RouteContext{
		Host:         route.Host,
		TLS:          policy != proxymodel.TLSPolicyOff,
		Policy:       string(policy),
		Scheme:       string(route.EffectiveScheme()),
		UpstreamHost: route.Upstream.Addr,
		UpstreamPort: route.Upstream.Port,
		UpstreamAddr: upstreamAddr(route.Upstream),
		ForceHTTPS:   route.ForceHTTPS,
		WebSocket:    route.WebSocket,
		Route:        route,
	}
	// Resolve provided-cert paths for a central-TLS route; a missing store or
	// cert leaves them empty and the template guards with {{ if .CertPath }}.
	if route.Host != "" && policy == proxymodel.TLSPolicyCentral && b.certs != nil {
		if paths, err := b.certs.CertPaths(route.Host); err == nil {
			ctx.CertPath = paths.CertPath
			ctx.KeyPath = paths.KeyPath
		}
	}

	var sb strings.Builder
	if err := b.tmpl.Execute(&sb, ctx); err != nil {
		return proxy.Artifact{}, fmt.Errorf("custom proxy: rendering template for %q: %w", route.Host, err)
	}
	return proxy.Artifact{
		Target:  proxy.Target{Kind: proxy.TargetKindFile, Path: b.managedPath(route.Host)},
		Content: sb.String(),
		Enabled: true,
	}, nil
}

// upstreamAddr renders host[:port] for the template's convenience field.
func upstreamAddr(u proxymodel.Upstream) string {
	if u.Port == 0 {
		return u.Addr
	}
	return fmt.Sprintf("%s:%d", u.Addr, u.Port)
}

// ReadManaged reads every config file in the dir for adoption + drift (§4, §11).
// Files this backend generated (managed prefix + ext) are returned Adopted=false
// for drift tracking; every other file is an operator-authored config returned
// Adopted=true (stored as Source: manual, never auto-overwritten).
func (b *Backend) ReadManaged(_ context.Context) ([]proxy.Artifact, error) {
	entries, err := os.ReadDir(b.configDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("custom proxy: reading config dir %q: %w", b.configDir, err)
	}
	var arts []proxy.Artifact
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, tempSuffix) {
			continue
		}
		path := filepath.Join(b.configDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("custom proxy: reading %q: %w", path, err)
		}
		arts = append(arts, proxy.Artifact{
			Target:  proxy.Target{Kind: proxy.TargetKindFile, Path: path},
			Content: string(data),
			Enabled: true,
			Adopted: !b.isManaged(name),
		})
	}
	return arts, nil
}

// staged tracks one file through the atomic apply so a failure can restore it.
type stagedFile struct {
	dest      string
	tempPath  string
	existed   bool
	prior     []byte
	committed bool
}

func (s *stagedFile) restore() {
	if !s.existed {
		_ = os.Remove(s.dest)
		return
	}
	_ = os.WriteFile(s.dest, s.prior, 0o644)
}

// Apply writes, validates, and activates the artifacts atomically (§10): per file
// it snapshots the current content, writes a temp, and stages the new content
// live; then it runs the test command once (if configured) and reloads. On any
// failure it restores every snapshot so the engine keeps serving its prior
// config (rollback).
func (b *Backend) Apply(ctx context.Context, arts []proxy.Artifact) error {
	if len(arts) == 0 {
		return nil
	}
	if b.runner == nil {
		return errors.New("custom proxy: no command runner configured")
	}
	if err := os.MkdirAll(b.configDir, 0o755); err != nil {
		return fmt.Errorf("custom proxy: ensuring config dir %q: %w", b.configDir, err)
	}

	staged := make([]*stagedFile, 0, len(arts))
	rollback := func() {
		for _, s := range staged {
			_ = os.Remove(s.tempPath)
			if !s.committed {
				s.restore()
			}
		}
	}

	for _, art := range arts {
		dest := art.Target.Path
		if dest == "" {
			rollback()
			return errors.New("custom proxy: artifact has empty target path")
		}
		s := &stagedFile{dest: dest, tempPath: dest + tempSuffix}
		if prior, err := os.ReadFile(dest); err == nil {
			s.existed, s.prior = true, prior
		} else if !errors.Is(err, os.ErrNotExist) {
			rollback()
			return fmt.Errorf("custom proxy: snapshotting %q: %w", dest, err)
		}
		staged = append(staged, s)
		if err := os.WriteFile(s.tempPath, []byte(art.Content), 0o644); err != nil {
			rollback()
			return fmt.Errorf("custom proxy: writing temp %q: %w", s.tempPath, err)
		}
		if err := os.WriteFile(dest, []byte(art.Content), 0o644); err != nil {
			rollback()
			return fmt.Errorf("custom proxy: staging %q: %w", dest, err)
		}
	}

	ok, out, err := b.runner.Test(ctx)
	if err != nil {
		rollback()
		return fmt.Errorf("custom proxy: config test failed: %w: %s", err, strings.TrimSpace(out))
	}
	_ = ok // ok==false simply means "no test command configured"; staging already done

	if err := b.runner.Reload(ctx); err != nil {
		rollback()
		return fmt.Errorf("custom proxy: reload failed: %w", err)
	}

	for _, s := range staged {
		_ = os.Remove(s.tempPath)
		s.committed = true
	}
	slog.InfoContext(ctx, "custom proxy: applied config", slog.Int("artifacts", len(arts)), slog.String("config_dir", b.configDir))
	return nil
}

// Remove deletes a managed config file, scrubs its central cert artifacts, and
// reloads so the engine drops the vhost (§3). A missing file is not an error.
func (b *Backend) Remove(ctx context.Context, target proxy.Target) error {
	if target.Path == "" {
		return errors.New("custom proxy: empty target path")
	}
	if err := os.Remove(target.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("custom proxy: removing %q: %w", target.Path, err)
	}
	b.removeCerts(ctx, target.Path)
	if b.runner != nil {
		if err := b.runner.Reload(ctx); err != nil {
			return fmt.Errorf("custom proxy: reload after remove failed: %w", err)
		}
	}
	return nil
}

// Prune removes every managed file not in keep, scrubs their certs, and reloads
// once if anything was removed (§3, no ghost vhosts). Operator-authored files are
// never touched.
func (b *Backend) Prune(ctx context.Context, keep []proxy.Target) (int, error) {
	wanted := make(map[string]bool, len(keep))
	for _, t := range keep {
		if t.Path != "" {
			wanted[t.Path] = true
		}
	}
	entries, err := os.ReadDir(b.configDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("custom proxy: reading config dir %q: %w", b.configDir, err)
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !b.isManaged(name) || strings.HasSuffix(name, tempSuffix) {
			continue
		}
		path := filepath.Join(b.configDir, name)
		if wanted[path] {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, fmt.Errorf("custom proxy: removing orphan %q: %w", path, err)
		}
		b.removeCerts(ctx, path)
		removed++
	}
	if removed > 0 && b.runner != nil {
		if err := b.runner.Reload(ctx); err != nil {
			return removed, fmt.Errorf("custom proxy: reload after prune failed: %w", err)
		}
	}
	return removed, nil
}

// removeCerts scrubs the cert store artifacts for a managed file's host. The
// file name is nurproxy-<base><ext> where <base> is the cert store's sanitized
// host, so Remove(base) (which re-sanitizes idempotently) hits the right files.
// Operator-authored files have no NurProxy cert and are skipped.
func (b *Backend) removeCerts(ctx context.Context, path string) {
	if b.certs == nil {
		return
	}
	name := filepath.Base(path)
	if !b.isManaged(name) {
		return
	}
	base := strings.TrimSuffix(strings.TrimPrefix(name, managedPrefix), b.fileExt)
	if err := b.certs.Remove(base); err != nil {
		slog.WarnContext(ctx, "custom proxy: could not scrub cert artifacts", slog.String("path", path), slog.Any("err", err))
	}
}

// Validate runs the engine's test command (if any) without applying changes.
func (b *Backend) Validate(ctx context.Context) error {
	if b.runner == nil {
		return errors.New("custom proxy: no command runner configured")
	}
	ok, out, err := b.runner.Test(ctx)
	if err != nil {
		return fmt.Errorf("custom proxy: config test failed: %w: %s", err, strings.TrimSpace(out))
	}
	if !ok {
		return nil // no test command configured
	}
	return nil
}

// InstallCerts writes central cert bundles to the cert store (§7) before any
// referencing config is applied. A nil store is a logged no-op (TLS routes then
// render without a cert; the template guards with {{ if .CertPath }}).
func (b *Backend) InstallCerts(ctx context.Context, certs []proxy.CertBundle) error {
	if len(certs) == 0 {
		return nil
	}
	if b.certs == nil {
		slog.WarnContext(ctx, "custom proxy: no cert store configured; skipping central cert install", slog.Int("bundles", len(certs)))
		return nil
	}
	for _, c := range certs {
		paths, err := b.certs.Install(certstore.Bundle{Host: c.Host, CertPEM: c.CertPEM, KeyPEM: c.KeyPEM, MaterializePlain: c.MaterializeKey})
		if err != nil {
			return fmt.Errorf("custom proxy: installing cert for %q: %w", c.Host, err)
		}
		slog.InfoContext(ctx, "custom proxy: installed central cert bundle", slog.String("host", c.Host), slog.String("cert_path", paths.CertPath))
	}
	return nil
}

// execRunner is the default Runner: it shells out to the operator-configured
// test/reload commands, elevating via `sudo -n` when the agent runs unprivileged
// (the §12 scoped-sudoers model, same as the native backends).
type execRunner struct {
	testCmd   string
	reloadCmd string
}

func (r *execRunner) Test(ctx context.Context) (bool, string, error) {
	if strings.TrimSpace(r.testCmd) == "" {
		return false, "", nil
	}
	out, err := r.run(ctx, r.testCmd)
	return true, out, err
}

func (r *execRunner) Reload(ctx context.Context) error {
	out, err := r.run(ctx, r.reloadCmd)
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(out))
	}
	return nil
}

func (r *execRunner) run(ctx context.Context, cmdline string) (string, error) {
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return "", errors.New("empty command")
	}
	name, args := fields[0], fields[1:]
	if name != "sudo" && !filepath.IsAbs(name) {
		if abs, err := exec.LookPath(name); err == nil {
			name = abs
		}
	}
	if elevateNeeded() && filepath.Base(name) != "sudo" {
		args = append([]string{"-n", name}, args...)
		name = "sudo"
	}
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// elevateNeeded mirrors the native backends: run privileged proxy commands via
// sudo only when the agent is a non-root POSIX user; NURPROXY_NO_SUDO=1 disables.
func elevateNeeded() bool {
	if os.Getenv("NURPROXY_NO_SUDO") == "1" {
		return false
	}
	return os.Geteuid() > 0
}

var _ proxy.Proxy = (*Backend)(nil)

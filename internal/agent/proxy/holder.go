package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"sync"

	"github.com/NurRobin/NurProxy/internal/agent/proxy/permcheck"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// caddyOps is the superset of concrete admin-API primitives the agent's local
// API and stream drive on the bundled-Caddy backend (EnsureServer / ClearRoutes /
// AddRoute / RemoveRoute / GetConfig / Render / InstallCerts / EnsureServerTLS).
// The bundled *proxy/caddy.Backend satisfies it. The Holder forwards to whatever
// current backend satisfies it; a current backend that does not (e.g. a file
// backend after a hot-switch to Existing mode) makes these primitives safe no-ops
// — the route push to a file backend does not go through the admin-API path, so
// the Holder must not panic or break when the live backend lacks them.
//
// It is unexported because nothing outside this package needs to name it: the
// Holder itself implements every method, so it slots in wherever the bundled
// caddy backend was passed before, with zero behavior change while the current
// backend is still the caddy backend (invariant #1).
type caddyOps interface {
	EnsureServer(ctx context.Context) error
	ClearRoutes(ctx context.Context) error
	AddRoute(ctx context.Context, route json.RawMessage) error
	RemoveRoute(ctx context.Context, routeID string) error
	GetConfig(ctx context.Context) (json.RawMessage, error)
	Render(ctx context.Context, route proxymodel.Route) (Artifact, error)
	InstallCerts(ctx context.Context, certs []CertBundle) error
	EnsureServerTLS(ctx context.Context, intents []TLSIntent) error
}

// Holder is the agent's mutable, mutex-guarded reverse-proxy backend slot (§19
// hot-switch). The stream, the local agent API, and the heartbeat all consult the
// Holder instead of a fixed caddy backend, so the agent can swap its live backend
// — built-in Caddy ↔ an existing nginx/apache — with NO process restart and no
// dropped stream.
//
// Transparency is the hard invariant (#1): the Holder forwards every call to the
// current backend under an RLock. While nobody calls Reconfigure, the current
// backend is the same bundled caddy backend that was passed before, so behavior
// is byte-for-byte identical — the Holder is a pure pass-through layer.
type Holder struct {
	mu      sync.RWMutex
	current Proxy
	// mode is the agent's CURRENT live reverse-proxy mode ("built-in" | "existing"),
	// updated atomically with current on every Reconfigure. The heartbeat reports it
	// (§19) so the dashboard reflects a hot-switch instead of always assuming built-in.
	mode string
}

// NewHolder seeds the Holder with the agent's initial backend (the bundled caddy
// backend at startup) and its mode. The seed must satisfy the concrete admin-API
// primitives the agent API/stream drive (the bundled *caddy.Backend does); the
// compile-time assertion lives at the call site in main.go where the concrete
// type is known. An empty mode is normalized to "built-in".
func NewHolder(initial Proxy, mode string) *Holder {
	if mode == "" {
		mode = "built-in"
	}
	return &Holder{current: initial, mode: mode}
}

// Current returns the active backend. The heartbeat reads Current().Capabilities()
// so the reported matrix tracks a hot-switch (e.g. caddy → nginx) on the next beat.
func (h *Holder) Current() Proxy {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.current
}

// Mode returns the agent's current live reverse-proxy mode ("built-in" |
// "existing"). The heartbeat reports it each beat so the orchestrator/dashboard
// reflect a §19 hot-switch (or a restart that honored a persisted existing mode).
func (h *Holder) Mode() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.mode
}

// ---- proxy.Proxy forwarding (the Holder is itself a Proxy) -------------------

// Info forwards to the current backend.
func (h *Holder) Info() Info {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.current.Info()
}

// Detect forwards to the current backend.
func (h *Holder) Detect(ctx context.Context) (bool, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.current.Detect(ctx)
}

// Capabilities forwards to the current backend.
func (h *Holder) Capabilities() Capabilities {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.current.Capabilities()
}

// Render forwards to the current backend.
func (h *Holder) Render(ctx context.Context, route proxymodel.Route) (Artifact, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.current.Render(ctx, route)
}

// ReadManaged forwards to the current backend.
func (h *Holder) ReadManaged(ctx context.Context) ([]Artifact, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.current.ReadManaged(ctx)
}

// Apply forwards to the current backend.
func (h *Holder) Apply(ctx context.Context, arts []Artifact) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.current.Apply(ctx, arts)
}

// Remove forwards to the current backend.
func (h *Holder) Remove(ctx context.Context, target Target) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.current.Remove(ctx, target)
}

// Prune forwards to the current backend.
func (h *Holder) Prune(ctx context.Context, keep []Target) (int, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.current.Prune(ctx, keep)
}

// Validate forwards to the current backend.
func (h *Holder) Validate(ctx context.Context) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.current.Validate(ctx)
}

// InstallCerts forwards to the current backend. The admin-API caddy backend and
// the file backends both implement InstallCerts (it is part of proxy.Proxy), so
// this always reaches a real implementation.
func (h *Holder) InstallCerts(ctx context.Context, certs []CertBundle) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.current.InstallCerts(ctx, certs)
}

// ---- caddyOps forwarding (admin-API primitives the API/stream drive) ---------
//
// These are NOT part of proxy.Proxy; they are the concrete primitives the bundled
// caddy backend exposes (EnsureServer/ClearRoutes/AddRoute/RemoveRoute/GetConfig/
// EnsureServerTLS). When the current backend implements caddyOps (the bundled
// caddy backend does), the call forwards verbatim — byte-for-byte unchanged. When
// it does not (a file backend after a hot-switch), the call is a safe no-op: the
// admin-API route path simply does not apply to a file backend, and the Holder
// must never panic or surface a spurious error that would break the live path.

// EnsureServer forwards to the current backend's admin-API primitive, or is a
// no-op when the current backend is not admin-API driven.
func (h *Holder) EnsureServer(ctx context.Context) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if c, ok := h.current.(caddyOps); ok {
		return c.EnsureServer(ctx)
	}
	return nil
}

// ClearRoutes forwards to the current backend's admin-API primitive, or is a
// no-op when the current backend is not admin-API driven.
func (h *Holder) ClearRoutes(ctx context.Context) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if c, ok := h.current.(caddyOps); ok {
		return c.ClearRoutes(ctx)
	}
	return nil
}

// AddRoute forwards to the current backend's admin-API primitive, or is a no-op
// when the current backend is not admin-API driven.
func (h *Holder) AddRoute(ctx context.Context, route json.RawMessage) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if c, ok := h.current.(caddyOps); ok {
		return c.AddRoute(ctx, route)
	}
	return nil
}

// RemoveRoute forwards to the current backend's admin-API primitive, or is a
// no-op when the current backend is not admin-API driven.
func (h *Holder) RemoveRoute(ctx context.Context, routeID string) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if c, ok := h.current.(caddyOps); ok {
		return c.RemoveRoute(ctx, routeID)
	}
	return nil
}

// GetConfig forwards to the current backend's admin-API primitive. A backend
// without an admin API returns an empty JSON object rather than an error, so the
// agent's read-only config dump never breaks after a hot-switch.
func (h *Holder) GetConfig(ctx context.Context) (json.RawMessage, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if c, ok := h.current.(caddyOps); ok {
		return c.GetConfig(ctx)
	}
	return json.RawMessage("{}"), nil
}

// EnsureServerTLS forwards to the current backend's admin-API primitive, or is a
// no-op when the current backend is not admin-API driven.
func (h *Holder) EnsureServerTLS(ctx context.Context, intents []TLSIntent) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if c, ok := h.current.(caddyOps); ok {
		return c.EnsureServerTLS(ctx, intents)
	}
	return nil
}

// ---- Reconfigure (hot-switch) ------------------------------------------------

// ReconfigureRequest carries the target proxy configuration for a hot-switch
// (§19). It mirrors the per-agent backend settings (§9) the operator confirms in
// the dashboard and the agent persists to agent.yaml. Mode "built-in" switches
// back to the bundled Caddy; Mode "existing" switches to a file backend (Type:
// nginx | apache | caddy).
type ReconfigureRequest struct {
	// Mode is "built-in" (bundled Caddy) or "existing" (a host-installed proxy).
	Mode string
	// Type is the existing backend name (nginx | apache | caddy); ignored for
	// built-in.
	Type string
	// ConfigDir overrides the detected config directory (empty = OS default).
	ConfigDir string
	// Binary overrides the detected proxy binary path (empty = autodetect).
	Binary string
	// ReloadCmd overrides the service reload command (empty = backend default).
	ReloadCmd string
	// TestCmd overrides the config-validate command (empty = backend default).
	TestCmd string
	// Service is the service unit name (systemd/openrc/launchd) for reloads.
	Service string
	// LogPaths are the error/access log paths to surface in the dashboard (§15).
	LogPaths []string
}

// healthSetter is the minimal slice of the agent's health.State the Holder needs
// to report a hot-switch outcome (§12/§19: a failing probe is non-fatal, health
// explains). Passing it as a small interface keeps the proxy package free of an
// import on the agent's health package (no import cycle).
type healthSetter interface {
	SetError(msg string)
	SetCaddyRunning(running bool)
}

// ReconfigureDeps gives the Holder what it needs to hot-switch without importing
// concrete agent packages (no import cycle): a health setter, a way to stop the
// bundled Caddy subprocess when leaving built-in, the agent's OS user for the
// remediation commands, and a factory to rebuild the bundled caddy backend when
// switching back to built-in.
type ReconfigureDeps struct {
	// Health receives the actionable outcome message (non-fatal on a failing probe).
	Health healthSetter
	// StopCaddy stops the bundled Caddy subprocess when leaving built-in mode, so
	// the host's nginx/apache can own :80/:443. Optional: nil means "nothing to
	// stop" (e.g. Caddy never started). A stop error is reported, never fatal.
	StopCaddy func() error
	// OSUser is the OS user the agent runs as, named in the remediation (group
	// membership + scoped sudoers line). Empty omits the user from those commands.
	OSUser string
	// CaddyFactory rebuilds the bundled caddy backend for a switch back to built-in.
	// Optional: nil means built-in→built-in / switch-back cannot rebuild the backend
	// (the Holder keeps the current one and explains via health).
	CaddyFactory func() Proxy
	// CertDir is the agent's cert store directory; passed into a hot-switched file
	// backend (nginx/apache) so InstallCerts can write central bundles and Render
	// can reference them (§7). Without it an existing-mode agent has no cert store
	// and silently drops every central TLS listener. Empty disables central TLS.
	CertDir string
	// CertKey is the agent-local AES-256 key the file backend uses to encrypt cert
	// private keys at rest (paired with CertDir). Empty stores keys as plaintext.
	CertKey []byte
}

// ReconfigureResult is the structured outcome of a hot-switch, returned so the
// local API can relay it to the operator (§19): OK + a human message, plus the
// least-privilege Remediation when an Existing-mode probe found missing grants.
type ReconfigureResult struct {
	// OK reports whether the switch landed with all privileges present. A false OK
	// with a non-nil Remediation is the "applied-with-warnings" state (§19): the
	// backend was swapped, but the operator must grant the listed rights.
	OK bool
	// Message is the human-readable outcome for the dashboard/CLI.
	Message string
	// Remediation lists the least-privilege grants to run when an Existing-mode
	// probe found missing rights; nil when nothing is needed (or for built-in).
	Remediation *permcheck.Remediation
}

// fileBackend is the subset of a file-based backend (nginx/apache) the hot-switch
// permission probe needs (§12): the dirs that must be writable, the reload hint,
// and the resolved test/reload commands for the remediation. Both nginx.Backend
// and apache.Backend satisfy it. Defining it here (as in main.go) keeps the
// backends decoupled from this package.
type fileBackend interface {
	ProbeDirs() []string
	ReloadHint() string
	ResolvedCommands() (test string, reload string)
}

// extractRunner pulls a file backend's validate-command runner for the reload-
// privilege probe (§12). nginx.Backend.Runner() and apache.Backend.Runner() each
// return their own concrete Runner type (which satisfies permcheck.TestRunner),
// but Go interface method signatures are invariant — a static
// `interface{ Runner() permcheck.TestRunner }` assertion would NOT match a
// `Runner() nginx.Runner` method. The proxy package also cannot import nginx/
// apache (they import it — import cycle). So we reflect: call the zero-arg
// Runner() method and assert its result to permcheck.TestRunner. A backend with no
// Runner() method (an admin-API backend) yields nil, which the probe treats as
// "skip the reload check". This keeps the backends decoupled and cycle-free.
func extractRunner(be Proxy) permcheck.TestRunner {
	v := reflect.ValueOf(be)
	m := v.MethodByName("Runner")
	if !m.IsValid() || m.Type().NumIn() != 0 || m.Type().NumOut() != 1 {
		return nil
	}
	out := m.Call(nil)
	if r, ok := out[0].Interface().(permcheck.TestRunner); ok {
		return r
	}
	return nil
}

// Reconfigure hot-switches the live backend with no process restart (§19). It is
// deliberately fail-soft: every error path sets a clear, actionable health message
// and returns a ReconfigureResult — it NEVER returns an error that could crash the
// agent or break the running path (invariant #1, mirrors the never-die-on-host-
// problems posture). The backend swap itself happens under the write lock so an
// in-flight forwarded call either sees the old or the new backend, never a torn
// state.
func (h *Holder) Reconfigure(ctx context.Context, req ReconfigureRequest, deps ReconfigureDeps) ReconfigureResult {
	switch req.Mode {
	case "existing":
		return h.reconfigureExisting(ctx, req, deps)
	case "built-in":
		return h.reconfigureBuiltIn(deps)
	default:
		msg := fmt.Sprintf("reconfigure: unknown proxy mode %q (expected built-in or existing)", req.Mode)
		log.Printf("WARNING: %s", msg)
		if deps.Health != nil {
			deps.Health.SetError(msg)
		}
		return ReconfigureResult{OK: false, Message: msg}
	}
}

// reconfigureExisting builds the requested file backend, stops the bundled Caddy
// (so the host proxy can own the ports), runs the §12 permission probe, swaps the
// holder atomically, and reports the outcome. A failing probe is non-fatal: the
// swap still happens (the agent now manages the host proxy), health explains what
// to grant, and the Remediation carries the exact commands.
func (h *Holder) reconfigureExisting(ctx context.Context, req ReconfigureRequest, deps ReconfigureDeps) ReconfigureResult {
	if req.Type == "" {
		msg := "reconfigure: proxy mode existing requires a proxy type (nginx | apache | caddy)"
		log.Printf("WARNING: %s", msg)
		if deps.Health != nil {
			deps.Health.SetError(msg)
		}
		return ReconfigureResult{OK: false, Message: msg}
	}

	be, err := Get(req.Type, Config{
		Type:      req.Type,
		Binary:    req.Binary,
		ConfigDir: req.ConfigDir,
		ReloadCmd: req.ReloadCmd,
		TestCmd:   req.TestCmd,
		Service:   req.Service,
		LogPaths:  req.LogPaths,
		// Wire the agent's cert store so the file backend can install + reference
		// central TLS bundles (§7); without this an existing-mode agent drops TLS.
		CertDir:    deps.CertDir,
		EncryptKey: deps.CertKey,
	})
	if err != nil {
		msg := fmt.Sprintf("reconfigure: %q is not a known proxy backend — cannot switch to it: %v", req.Type, err)
		log.Printf("WARNING: %s", msg)
		if deps.Health != nil {
			deps.Health.SetError(msg)
		}
		return ReconfigureResult{OK: false, Message: msg}
	}

	// Run the §12 permission probe + remediation BEFORE swapping the live backend.
	// The probe never mutates real config and never panics; a denial is reported,
	// never fatal.
	probe, rem := h.probeExisting(ctx, req.Type, deps.OSUser, be)

	// Leaving built-in: stop the bundled Caddy so the host proxy can bind :80/:443.
	// A stop error is reported but never aborts the switch.
	if deps.StopCaddy != nil {
		if err := deps.StopCaddy(); err != nil {
			log.Printf("WARNING: reconfigure: failed to stop bundled Caddy: %v (continuing — host proxy now owns the ports)", err)
		}
	}

	// Swap the live backend atomically, recording the new live mode so the next
	// heartbeat reports "existing" (§19).
	h.mu.Lock()
	h.current = be
	h.mode = "existing"
	h.mu.Unlock()
	// The bundled Caddy subprocess is stopped; it is no longer "running" in the
	// built-in sense. Health is now governed by the file backend's probe.
	if deps.Health != nil {
		deps.Health.SetCaddyRunning(false)
	}

	if probe.OK() {
		msg := fmt.Sprintf("switched to existing %s — config is writable and reloadable", req.Type)
		log.Printf("reconfigure: %s", msg)
		if deps.Health != nil {
			deps.Health.SetError("")
		}
		return ReconfigureResult{OK: true, Message: msg}
	}

	// Applied-with-warnings: the backend is live but a grant is missing. Surface the
	// actionable health error + the exact remediation (§19), never crash.
	msg := probe.HealthError()
	log.Printf("WARNING: reconfigure: switched to existing %s but permission probe failed: %s", req.Type, msg)
	if deps.Health != nil {
		deps.Health.SetError(msg)
	}
	return ReconfigureResult{OK: false, Message: msg, Remediation: rem}
}

// ProbePermissions runs the §12 permission self-test against the CURRENT backend
// and returns the structured result, the targeted remediation (nil when nothing
// is missing), the config dirs that were checked, and whether a probe actually
// ran. checked is false for a built-in / admin-API backend (no file-write or
// service-reload privilege to probe) — the caller reports no permission block in
// that case. It never mutates real config and never panics; it is safe to call on
// every heartbeat so a granted permission clears on the next beat without a
// restart. osUser is named in the remediation commands (group membership +
// scoped sudoers).
func (h *Holder) ProbePermissions(ctx context.Context, osUser string) (res permcheck.Result, rem *permcheck.Remediation, dirs []string, checked bool) {
	be := h.Current()
	fb, ok := be.(fileBackend)
	if !ok {
		return permcheck.Result{CanWrite: true, CanReload: true}, nil, nil, false
	}
	res, rem = h.probeExisting(ctx, string(be.Info().Kind), osUser, be)
	return res, rem, fb.ProbeDirs(), true
}

// probeExisting runs the §12 write+reload permission probe over the backend's
// ProbeDirs/Runner/ReloadHint and builds the least-privilege remediation from its
// ResolvedCommands. A backend that exposes no file/reload hooks (an admin-API
// backend, e.g. external caddy) needs no probe: it returns an all-clear Result and
// nil remediation. It never panics and never touches real config.
func (h *Holder) probeExisting(ctx context.Context, backend, osUser string, be Proxy) (permcheck.Result, *permcheck.Remediation) {
	fb, ok := be.(fileBackend)
	if !ok {
		// Admin-API backend: no file write / service reload privilege to probe.
		return permcheck.Result{CanWrite: true, CanReload: true}, nil
	}

	runner := extractRunner(be)

	res := permcheck.Probe(ctx, permcheck.Options{
		Backend:    backend,
		Dirs:       fb.ProbeDirs(),
		Runner:     runner,
		ReloadHint: fb.ReloadHint(),
	})
	if res.OK() {
		return res, nil
	}

	// Build the remediation for ONLY the grants that are actually missing, so the
	// dashboard shows exactly what to fix — not the full blob. A present write grant
	// omits the group/ownership step (empty Dirs), a present reload grant omits the
	// scoped-sudoers step (empty commands). BuildRemediation already drops a step
	// whose inputs are empty.
	test, reload := fb.ResolvedCommands()
	opts := permcheck.RemediationOptions{
		Backend: backend,
		User:    osUser,
		Group:   "nurproxy",
	}
	if !res.CanWrite {
		opts.Dirs = fb.ProbeDirs()
	}
	if !res.CanReload {
		opts.TestCmd = test
		opts.ReloadCmd = reload
	}
	rem := permcheck.BuildRemediation(opts)
	return res, &rem
}

// reconfigureBuiltIn switches back to the bundled Caddy (§19). It is best-effort:
// it rebuilds the caddy backend via the factory and swaps it in, but the Holder
// cannot itself (re)start the Caddy subprocess from here — that lifecycle lives in
// main. If the subprocess is not running, the rebuilt admin-API backend will fall
// back to the in-memory mock and health is set to explain that a full restart is
// needed to serve traffic via built-in again. built-in→built-in with no factory is
// a no-op.
func (h *Holder) reconfigureBuiltIn(deps ReconfigureDeps) ReconfigureResult {
	if deps.CaddyFactory == nil {
		msg := "switch to built-in: no caddy factory wired — restart the agent in built-in mode to serve via the bundled Caddy"
		log.Printf("WARNING: reconfigure: %s", msg)
		if deps.Health != nil {
			deps.Health.SetError(msg)
		}
		return ReconfigureResult{OK: false, Message: msg}
	}

	be := deps.CaddyFactory()
	h.mu.Lock()
	h.current = be
	h.mode = "built-in"
	h.mu.Unlock()

	// The Holder cannot restart the Caddy subprocess; note that to the operator so
	// they know a process restart is required for built-in to actually serve.
	msg := "switched backend to built-in (bundled Caddy) — restart the agent process if the bundled Caddy subprocess is not running so it can bind :80/:443"
	log.Printf("reconfigure: %s", msg)
	if deps.Health != nil {
		deps.Health.SetError(msg)
	}
	return ReconfigureResult{OK: true, Message: msg}
}

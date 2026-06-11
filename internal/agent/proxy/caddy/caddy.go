// Package caddy implements the bundled Caddy as the "caddy" proxy backend
// behind the agent-side proxy.Proxy interface (§5), in admin-API mode.
//
// Render emits Caddy route JSON via caddygen; Apply posts the routes to the
// Caddy admin API (EnsureServer → ClearRoutes → AddRoute), exactly mirroring
// the historical agent behavior so the built-in Caddy path is byte-for-byte
// unchanged (invariant #1). Validate round-trips the live config through the
// admin API. The backend never writes config files: built-in Caddy is driven
// entirely through its localhost admin API, so there is no atomic-file dance.
//
// It mirrors the DNS provider plugin pattern: the backend registers a Factory
// in init() so it can be resolved by name through the proxy registry. The agent
// also constructs it directly with New around the already-wired admin client so
// the existing mock-fallback logic (no caddy binary → in-memory mock) is
// preserved unchanged.
package caddy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	agentcaddy "github.com/NurRobin/NurProxy/internal/agent/caddy"
	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/agent/proxy/certstore"
	"github.com/NurRobin/NurProxy/internal/shared/caddygen"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// backendName is the registry key for the bundled Caddy backend.
const backendName = "caddy"

// rateLimitModule is the Caddy module ID provided by the caddy-ratelimit plugin
// (https://github.com/mholt/caddy-ratelimit). Its presence in `caddy
// list-modules` is what tells us rate limiting is actually compiled into this
// build, rather than assuming it (§8 module probing).
const rateLimitModule = "http.handlers.rate_limit"

func init() {
	proxy.Register(backendName, func(cfg proxy.Config) (proxy.Proxy, error) {
		b := New(agentcaddy.NewClient(cfg.AdminPort))
		if cfg.CertDir != "" {
			b.certs = certstore.New(cfg.CertDir, cfg.EncryptKey)
		}
		return b, nil
	})
}

// Backend drives the bundled Caddy through its admin API behind the proxy.Proxy
// interface. It wraps an *agentcaddy.Client (real or mock); all proxy
// operations route through that single client so behavior is identical to the
// pre-interface agent.
type Backend struct {
	client *agentcaddy.Client
	// certs writes centrally-issued cert bundles to disk for InstallCerts (§7),
	// encrypting private keys at rest on the agent. Nil when no cert directory is
	// configured, in which case InstallCerts is a logged no-op (built-in Caddy can
	// still self-ACME as the fallback, §7).
	certs *certstore.Store
	// listModules returns the module IDs compiled into the live caddy binary,
	// used by Capabilities to probe optional modules (e.g. caddy-ratelimit). It is
	// a field so tests can inject captured `caddy list-modules` output without a
	// real binary; the default shells out to the caddy binary (§8). An error or a
	// missing binary yields a nil list — the probe degrades gracefully.
	listModules func(ctx context.Context) ([]string, error)
}

// New wraps an already-constructed admin-API client (real or mock) as a Proxy
// backend. The agent uses this so the mock-fallback decision (no caddy binary)
// is made once at startup and preserved here.
func New(client *agentcaddy.Client) *Backend {
	b := &Backend{client: client}
	b.listModules = listInstalledModules
	return b
}

// WithCertStore attaches a cert store so InstallCerts writes centrally-issued
// bundles to disk (encrypting keys at rest). The agent's main wiring uses this so
// the mock-fallback client construction stays in one place while still enabling
// central TLS. Returns the receiver for chaining.
func (b *Backend) WithCertStore(s *certstore.Store) *Backend {
	b.certs = s
	return b
}

// Info reports the backend's static identity. The bundled Caddy is admin-API
// driven, so it advertises no managed binary or config dir on disk.
func (b *Backend) Info() proxy.Info {
	return proxy.Info{
		Kind: proxy.Kind(backendName),
	}
}

// Detect reports whether this backend is usable. The bundled Caddy is always
// available to the agent — when no caddy binary is present the client runs in
// the in-memory mock mode rather than being absent — so detection is true.
func (b *Backend) Detect(ctx context.Context) (bool, error) {
	return true, nil
}

// Capabilities reports the options the bundled Caddy supports (§8). The core
// reverse-proxy, header, rewrite, auth, IP-filter and TLS features are part of
// standard Caddy, so they are always true. Rate limiting is the one
// module-dependent option: it requires the caddy-ratelimit plugin, so we probe
// the live binary's module list (§8 module probing) and report RateLimit only
// when http.handlers.rate_limit is actually compiled in. A probe failure (no
// binary, mock mode, command error) reports RateLimit=false rather than guessing
// true — the dashboard greys it out and the renderer drops it with an audited
// warning rather than emitting config the binary can't load.
func (b *Backend) Capabilities() proxy.Capabilities {
	return proxy.Capabilities{
		ReverseProxy:  true,
		WebSocket:     true,
		ForceHTTPS:    true,
		CustomHeaders: true,
		PathRewrite:   true,
		BasicAuth:     true,
		IPFilter:      true,
		RateLimit:     b.hasRateLimitModule(),
		CentralTLS:    true,
	}
}

// hasRateLimitModule probes whether the caddy-ratelimit module is compiled into
// the live binary. It tolerates the absence of a prober or any probe error by
// reporting false (no rate-limit support advertised).
func (b *Backend) hasRateLimitModule() bool {
	if b.listModules == nil {
		return false
	}
	mods, err := b.listModules(context.Background())
	if err != nil {
		return false
	}
	return moduleListHas(mods, rateLimitModule)
}

// moduleListHas reports whether want is present in the module ID list. It is a
// pure helper so the probe-parsing path is table-driven testable.
func moduleListHas(mods []string, want string) bool {
	for _, m := range mods {
		if m == want {
			return true
		}
	}
	return false
}

// parseListModules extracts module IDs from `caddy list-modules` output. Caddy
// prints one module ID per line, with an optional trailing summary section
// separated by a blank line (e.g. "  Standard modules: 123"); those non-module
// lines are skipped. It is a pure function so it can be unit-tested against
// captured output, no caddy binary required.
func parseListModules(out string) []string {
	var mods []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Summary/section lines contain spaces or colons; real module IDs are a
		// single dotted token (e.g. "http.handlers.rate_limit").
		if strings.ContainsAny(line, " \t:") {
			continue
		}
		mods = append(mods, line)
	}
	return mods
}

// listInstalledModules shells out to `caddy list-modules` and parses the result.
// A missing binary or a command error yields a nil list (no modules probed), so
// Capabilities degrades to "no optional modules" rather than failing.
func listInstalledModules(ctx context.Context) ([]string, error) {
	bin, err := exec.LookPath("caddy")
	if err != nil {
		return nil, fmt.Errorf("caddy binary not found: %w", err)
	}
	out, err := exec.CommandContext(ctx, bin, "list-modules").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("running caddy list-modules: %w", err)
	}
	return parseListModules(string(out)), nil
}

// Render turns a backend-neutral route into a caddy-route Artifact: the content
// is the Caddy route JSON produced by caddygen (the pure renderer), and the
// target is the virtual caddy-route handle keyed by the route's admin-API @id.
func (b *Backend) Render(ctx context.Context, route proxymodel.Route) (proxy.Artifact, error) {
	raw, err := caddygen.GenerateRoute(route)
	if err != nil {
		return proxy.Artifact{}, fmt.Errorf("rendering caddy route: %w", err)
	}
	return proxy.Artifact{
		Target: proxy.Target{
			Kind: proxy.TargetKindCaddyRoute,
			Path: routeTarget(raw),
		},
		Content: string(raw),
		Enabled: true,
	}, nil
}

// ReadManaged returns the routes currently live in Caddy as artifacts, for
// adoption upload and drift checks (§4, §11).
func (b *Backend) ReadManaged(ctx context.Context) ([]proxy.Artifact, error) {
	routes, err := b.client.ListRoutes(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading managed caddy routes: %w", err)
	}
	arts := make([]proxy.Artifact, 0, len(routes))
	for _, r := range routes {
		arts = append(arts, proxy.Artifact{
			Target: proxy.Target{
				Kind: proxy.TargetKindCaddyRoute,
				Path: routeTarget(r),
			},
			Content: string(r),
			Enabled: true,
		})
	}
	return arts, nil
}

// Apply replaces the live route set with the given caddy-route artifacts. It
// reproduces the historical agent sequence exactly — EnsureServer, then clear
// all routes, then add each — so the built-in Caddy path is byte-for-byte
// unchanged. The admin API is transactional per call; there is no temp-file
// rollback (that dance is for file backends, §10).
//
// EnsureServer errors are returned (the caller, e.g. the stream, surfaces them
// via health), while ClearRoutes failures are non-fatal and skipped, matching
// the prior behavior. A failed AddRoute aborts with an error naming the host.
func (b *Backend) Apply(ctx context.Context, arts []proxy.Artifact) error {
	if err := b.client.EnsureServer(ctx); err != nil {
		return fmt.Errorf("ensuring caddy server: %w", err)
	}
	_ = b.client.ClearRoutes(ctx)

	for _, art := range arts {
		raw := json.RawMessage(art.Content)
		if err := b.client.AddRoute(ctx, raw); err != nil {
			return fmt.Errorf("adding caddy route %q: %w", art.Target.Path, err)
		}
	}
	return nil
}

// EnsureServer creates the Caddy HTTP server if absent (admin-API config path).
// It is exposed so the agent stream can preserve its existing health reporting:
// a failure here is the classic "ports 80/443 already in use" case, surfaced
// distinctly from per-route add failures. This is the same primitive Apply uses
// internally; the stream calls it directly only to keep that error attribution
// byte-for-byte identical.
func (b *Backend) EnsureServer(ctx context.Context) error {
	return b.client.EnsureServer(ctx)
}

// ClearRoutes removes all live routes. Like the historical agent path, callers
// treat a failure here as non-fatal (the subsequent route adds reconcile state).
func (b *Backend) ClearRoutes(ctx context.Context) error {
	return b.client.ClearRoutes(ctx)
}

// AddRoute posts a single rendered route to the admin API. Exposed so the stream
// can apply routes one-by-one and report per-host success/failure exactly as
// before; the wire format still pushes Caddy route JSON in this phase.
func (b *Backend) AddRoute(ctx context.Context, route json.RawMessage) error {
	return b.client.AddRoute(ctx, route)
}

// GetConfig returns the full live Caddy config from the admin API. Exposed for
// the agent's read-only config dump endpoint.
func (b *Backend) GetConfig(ctx context.Context) (json.RawMessage, error) {
	return b.client.GetConfig(ctx)
}

// RemoveRoute deletes a single live route by its admin-API @id. Exposed for the
// agent's per-domain route deletion endpoint. Before deleting the route it
// resolves the route's public host from the live config and scrubs that host's
// centrally-issued cert/key artifacts (incl. any decrypted .key.plain) so a
// removed domain leaves no private key on disk — mirroring the nginx/apache
// backends. The cert scrub runs first (while the route is still readable, so the
// host can be recovered); failing to scrub a key is logged, not fatal, and never
// blocks the route deletion.
func (b *Backend) RemoveRoute(ctx context.Context, routeID string) error {
	b.scrubCertsForRoute(ctx, routeID)
	return b.client.RemoveRoute(ctx, routeID)
}

// Prune scrubs the cert store for hosts whose routes are no longer in the desired
// set. The live route set itself is reconciled by Apply (ClearRoutes then re-add),
// so there is no orphaned on-disk vhost to delete (unlike the file backends) — but
// the centrally-issued cert/key artifacts (incl. any decrypted .key.plain) for a
// removed domain would otherwise linger on disk, negating the at-rest encryption.
// So Prune lists the live routes, and for every route whose target handle is NOT in
// keep it scrubs that host's cert material, mirroring how the nginx/apache backends
// scrub orphaned vhosts. It returns the count of hosts scrubbed. With no cert store
// configured there is nothing to scrub and it is a no-op.
func (b *Backend) Prune(ctx context.Context, keep []proxy.Target) (int, error) {
	if b.certs == nil {
		return 0, nil
	}
	wanted := make(map[string]bool, len(keep))
	for _, t := range keep {
		if id := routeIDFromTarget(t.Path); id != "" {
			wanted[id] = true
		}
	}
	routes, err := b.client.ListRoutes(ctx)
	if err != nil {
		return 0, fmt.Errorf("caddy prune: reading managed routes: %w", err)
	}
	scrubbed := 0
	for _, raw := range routes {
		id := routeID(raw)
		if id == "" || wanted[id] {
			continue
		}
		host := hostFromRoute(raw)
		if host == "" {
			continue
		}
		if err := b.certs.Remove(host); err != nil {
			slog.WarnContext(ctx, "caddy: could not remove cert artifacts for orphaned route",
				slog.String("route_id", id), slog.String("host", host), slog.Any("err", err))
			continue
		}
		scrubbed++
	}
	return scrubbed, nil
}

// Remove deletes a single route from the live config by its admin-API @id,
// derived from the target handle (§3, no ghost routes). Before deleting it scrubs
// the route's host cert/key artifacts (incl. any decrypted .key.plain) from the
// cert store so a removed domain leaves no private key on disk, mirroring the
// nginx/apache backends. The scrub is best-effort (logged, not fatal) and must not
// block the route removal.
func (b *Backend) Remove(ctx context.Context, target proxy.Target) error {
	id := routeIDFromTarget(target.Path)
	if id == "" {
		return fmt.Errorf("caddy remove: invalid target %q", target.Path)
	}
	b.scrubCertsForRoute(ctx, id)
	if err := b.client.RemoveRoute(ctx, id); err != nil {
		return fmt.Errorf("removing caddy route %q: %w", id, err)
	}
	return nil
}

// scrubCertsForRoute removes the cert store artifacts for the public host served
// by the live route with the given admin-API @id. The host is recovered from the
// route's host matcher in the live config (the @id is a slug, not the FQDN, so it
// cannot be reversed; reading the live route is the reliable source). A nil cert
// store (no CertDir configured) is a no-op. A route that cannot be read or carries
// no host matcher is skipped. Any unlink error is logged, not fatal: failing to
// scrub a stale key must not block the route removal.
func (b *Backend) scrubCertsForRoute(ctx context.Context, id string) {
	if b.certs == nil || id == "" {
		return
	}
	routes, err := b.client.ListRoutes(ctx)
	if err != nil {
		slog.WarnContext(ctx, "caddy: could not read routes to scrub cert artifacts",
			slog.String("route_id", id), slog.Any("err", err))
		return
	}
	for _, raw := range routes {
		if routeID(raw) != id {
			continue
		}
		host := hostFromRoute(raw)
		if host == "" {
			return
		}
		if err := b.certs.Remove(host); err != nil {
			slog.WarnContext(ctx, "caddy: could not remove cert artifacts for removed route",
				slog.String("route_id", id), slog.String("host", host), slog.Any("err", err))
		}
		return
	}
}

// hostFromRoute extracts the first public host from a Caddy route's host matcher
// (match[].host[]). Rendered NurProxy routes carry exactly one host (see caddygen),
// so the first entry is the route's FQDN. Returns empty when the route has no host
// matcher (e.g. a non-NurProxy or malformed route), in which case there is no
// associated cert to scrub.
func hostFromRoute(raw json.RawMessage) string {
	var partial struct {
		Match []struct {
			Host []string `json:"host"`
		} `json:"match"`
	}
	if err := json.Unmarshal(raw, &partial); err != nil {
		return ""
	}
	for _, m := range partial.Match {
		if len(m.Host) > 0 {
			return m.Host[0]
		}
	}
	return ""
}

// Validate checks the live config by reading it back through the admin API. A
// readable, well-formed config means Caddy accepted what was applied (the admin
// API rejects invalid config at PUT/POST time, so a successful round-trip is
// the admin-API equivalent of `caddy validate`).
func (b *Backend) Validate(ctx context.Context) error {
	cfg, err := b.client.GetConfig(ctx)
	if err != nil {
		return fmt.Errorf("validating caddy config: %w", err)
	}
	var v interface{}
	if err := json.Unmarshal(cfg, &v); err != nil {
		return fmt.Errorf("validating caddy config: malformed admin response: %w", err)
	}
	return nil
}

// InstallCerts writes the centrally-issued cert bundles to the backend's cert
// directory (§7), encrypting each private key at rest on the agent. It is the
// preflight step: the agent stream calls InstallCerts BEFORE Apply of any config
// that references the cert files, so a generated config never validates against a
// missing file (§5). Certs arrive over the agent-initiated stream — never an
// inbound probe (invariant #2).
//
// When no cert store is configured (no CertDir), it is a logged no-op: the
// built-in Caddy can self-ACME as the fallback (§7), so a missing store must not
// fail the whole apply (invariant #4). A per-bundle write error aborts InstallCerts
// (returning the error) so the stream withholds Apply rather than going live with
// a missing cert; the caller surfaces it via health.
func (b *Backend) InstallCerts(ctx context.Context, certs []proxy.CertBundle) error {
	if len(certs) == 0 {
		return nil
	}
	if b.certs == nil {
		slog.WarnContext(ctx, "caddy: no cert store configured; skipping central cert install (self-ACME fallback applies)",
			slog.Int("bundles", len(certs)))
		return nil
	}
	for _, c := range certs {
		paths, err := b.certs.Install(certstore.Bundle{
			Host:    c.Host,
			CertPEM: c.CertPEM,
			KeyPEM:  c.KeyPEM,
		})
		if err != nil {
			return fmt.Errorf("installing cert for %q: %w", c.Host, err)
		}
		slog.InfoContext(ctx, "caddy: installed central cert bundle",
			slog.String("host", c.Host),
			slog.String("cert_path", paths.CertPath),
			slog.Bool("key_encrypted_at_rest", paths.Encrypted))
	}
	return nil
}

// EnsureServerTLS configures the bundled Caddy's TLS strategy for the given set
// of host TLS intents (§7). It is the built-in counterpart of "run on provided
// certs": for every central-policy host it resolves the installed cert+key paths
// from the cert store and feeds them into Caddy's tls app, then disables (or
// scopes) Caddy's automatic_https accordingly. Self-ACME hosts are left to
// Caddy's own ACME (the explicit fallback for zones not in a configured DNS
// provider and orchestrator-down resilience); off hosts get no TLS material and
// are excluded from ACME.
//
// The TLS strategy decision is made by the pure caddygen.GenerateServerTLS so it
// is table-driven testable; this method only resolves cert paths and PUTs the
// result through the admin API. It must run AFTER InstallCerts (the cert files
// must exist) and is safe to call before route Apply.
//
// A central host whose cert is not yet installed is dropped from load_files with
// a logged + audited warning rather than failing the whole apply (invariant #4):
// it is still skipped from automatic_https (we do not want Caddy to ACME a host
// the orchestrator owns), so it simply has no cert until the next push installs
// one. When no cert store is configured the backend cannot serve provided certs;
// every host falls back to whatever policy GenerateServerTLS yields from paths
// left empty (no load_files), and Caddy self-ACME covers TLS.
func (b *Backend) EnsureServerTLS(ctx context.Context, intents []proxy.TLSIntent) error {
	// srv0 must exist (with its routes array) before ApplyTLS PUTs automatic_https
	// into it. A cert push can arrive before the first route apply, and ApplyTLS
	// assumes EnsureServer already ran; without this, srv0 ends up created with only
	// automatic_https and no routes, and the later AddRoute writes an object Caddy
	// rejects as a RouteList.
	if err := b.client.EnsureServer(ctx); err != nil {
		return fmt.Errorf("ensuring server before tls strategy: %w", err)
	}
	hosts := make([]caddygen.TLSHost, 0, len(intents))
	for _, in := range intents {
		h := caddygen.TLSHost{Host: in.Host, Policy: in.Policy}
		// Resolve provided-cert paths for the central path only.
		if in.Policy == proxymodel.TLSPolicySelfACME || in.Policy == proxymodel.TLSPolicyOff {
			hosts = append(hosts, h)
			continue
		}
		if b.certs == nil {
			// No cert store: cannot serve a provided cert. Leave paths empty;
			// GenerateServerTLS will still skip ACME for this host (the orchestrator
			// owns it) but load no file.
			slog.WarnContext(ctx, "caddy: no cert store; central host has no provided cert (self-ACME fallback applies)",
				slog.String("host", in.Host))
			hosts = append(hosts, h)
			continue
		}
		paths, err := b.certs.CertPaths(in.Host)
		if err != nil {
			// Cert not installed yet: drop the file, keep the host skipped from ACME.
			slog.WarnContext(ctx, "caddy: provided cert not available; dropping from tls load (apply continues)",
				slog.String("host", in.Host), slog.String("error", err.Error()))
			hosts = append(hosts, h)
			continue
		}
		h.CertPath = paths.CertPath
		h.KeyPath = paths.KeyPath
		hosts = append(hosts, h)
	}

	strategy := caddygen.GenerateServerTLS(hosts)
	loadFiles, err := json.Marshal(strategy.LoadFiles)
	if err != nil {
		return fmt.Errorf("marshaling tls load_files: %w", err)
	}
	autoHTTPS, err := json.Marshal(strategy.AutomaticHTTPS)
	if err != nil {
		return fmt.Errorf("marshaling automatic_https: %w", err)
	}
	var connPolicies json.RawMessage
	if len(strategy.ConnectionPolicies) > 0 {
		if connPolicies, err = json.Marshal(strategy.ConnectionPolicies); err != nil {
			return fmt.Errorf("marshaling tls_connection_policies: %w", err)
		}
	}
	if err := b.client.ApplyTLS(ctx, loadFiles, autoHTTPS, connPolicies); err != nil {
		return fmt.Errorf("applying caddy tls strategy: %w", err)
	}
	slog.InfoContext(ctx, "caddy: applied tls strategy",
		slog.Int("provided_certs", len(strategy.LoadFiles)),
		slog.Bool("automatic_https_disabled", strategy.AutomaticHTTPS.Disable),
		slog.Int("automatic_https_skip", len(strategy.AutomaticHTTPS.Skip)))
	return nil
}

// targetPrefix namespaces the virtual caddy-route target handle (§4): the
// admin-API @id is stored as "caddy:route:<id>".
const targetPrefix = "caddy:route:"

// routeTarget extracts a Caddy route's @id and wraps it as a virtual target
// handle. An un-IDed route (shouldn't happen for rendered routes) yields the
// bare prefix.
func routeTarget(raw json.RawMessage) string {
	return targetPrefix + routeID(raw)
}

// routeID parses the @id out of a Caddy route JSON, empty if absent.
func routeID(raw json.RawMessage) string {
	var partial struct {
		ID string `json:"@id"`
	}
	if err := json.Unmarshal(raw, &partial); err != nil {
		return ""
	}
	return partial.ID
}

// routeIDFromTarget recovers the admin-API @id from a virtual target handle.
func routeIDFromTarget(path string) string {
	if len(path) <= len(targetPrefix) || path[:len(targetPrefix)] != targetPrefix {
		return ""
	}
	return path[len(targetPrefix):]
}

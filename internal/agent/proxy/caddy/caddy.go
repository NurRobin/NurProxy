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

	agentcaddy "github.com/NurRobin/NurProxy/internal/agent/caddy"
	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/caddygen"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// backendName is the registry key for the bundled Caddy backend.
const backendName = "caddy"

func init() {
	proxy.Register(backendName, func(cfg proxy.Config) (proxy.Proxy, error) {
		return New(agentcaddy.NewClient(cfg.AdminPort)), nil
	})
}

// Backend drives the bundled Caddy through its admin API behind the proxy.Proxy
// interface. It wraps an *agentcaddy.Client (real or mock); all proxy
// operations route through that single client so behavior is identical to the
// pre-interface agent.
type Backend struct {
	client *agentcaddy.Client
}

// New wraps an already-constructed admin-API client (real or mock) as a Proxy
// backend. The agent uses this so the mock-fallback decision (no caddy binary)
// is made once at startup and preserved here.
func New(client *agentcaddy.Client) *Backend {
	return &Backend{client: client}
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

// Capabilities reports the options the bundled Caddy supports (§8). Rate
// limiting requires the caddy-ratelimit module; without live module probing we
// report it as available, matching what the renderer emits today (a rate_limit
// handler). Module probing is a later refinement.
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
		CentralTLS:    true,
	}
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
// agent's per-domain route deletion endpoint.
func (b *Backend) RemoveRoute(ctx context.Context, routeID string) error {
	return b.client.RemoveRoute(ctx, routeID)
}

// Remove deletes a single route from the live config by its admin-API @id,
// derived from the target handle (§3, no ghost routes).
func (b *Backend) Remove(ctx context.Context, target proxy.Target) error {
	id := routeIDFromTarget(target.Path)
	if id == "" {
		return fmt.Errorf("caddy remove: invalid target %q", target.Path)
	}
	if err := b.client.RemoveRoute(ctx, id); err != nil {
		return fmt.Errorf("removing caddy route %q: %w", id, err)
	}
	return nil
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

// InstallCerts is a no-op in the current phase: central TLS distribution to
// built-in Caddy (provided certs) lands in Phase 4 (§7). It is defined so the
// backend satisfies the interface; certs ride the agent-initiated stream, never
// an inbound probe.
func (b *Backend) InstallCerts(ctx context.Context, certs []proxy.CertBundle) error {
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

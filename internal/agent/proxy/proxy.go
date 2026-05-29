package proxy

import (
	"context"

	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// Proxy is the agent-side abstraction over a reverse-proxy backend (§5). It
// mirrors the DNS provider plugin pattern (internal/provider): one interface,
// multiple init()-registered implementations selected by name through the
// registry below.
//
// The bundled Caddy is the first implementation (admin-API mode): Render emits
// Caddy route JSON via caddygen and Apply posts it to the admin API. File
// backends (nginx, apache) render native config text and Apply performs the
// atomic write → validate → reload dance (§10).
//
// Contract notes:
//   - context.Context is always the first parameter; methods that touch the host
//     or a subprocess honor cancellation.
//   - Render is a thin wrapper over a pure renderer (caddygen/nginxgen): intent
//     in, native bytes out. The pure renderer is the table-driven testable core.
//   - Unsupported options for a backend are dropped during Render with a logged +
//     audited warning (§8); they never fail the whole apply.
//   - The agent always dials out; nothing here is ever probed inbound (§7). Certs
//     ride the agent-initiated stream and land via InstallCerts.
type Proxy interface {
	// Info reports the backend's static identity plus any detected host facts
	// (type, version, resolved paths). It is cheap and does not mutate state.
	Info() Info

	// Detect reports whether this backend is installed/usable on the host. A nil
	// error with false means "not present here"; an error means detection itself
	// failed.
	Detect(ctx context.Context) (bool, error)

	// Capabilities reports which proxy options this backend supports on this host
	// (§8), including module probing (e.g. caddy-ratelimit compiled in?). The
	// dashboard greys out unsupported options per the selected agent's backend.
	Capabilities() Capabilities

	// Render turns a backend-neutral route (intent) into a native Artifact
	// (target + content). It is a thin wrapper over the backend's pure renderer.
	Render(ctx context.Context, route proxymodel.Route) (Artifact, error)

	// ReadManaged reads the config artifacts in the backend's configured dirs,
	// used for both adoption upload and drift checks (§4, §11). For Existing-mode
	// adoption it reads ALL files (no whitelist — we never auto-overwrite, so
	// there is nothing to scope), tagging operator-authored files Adopted so the
	// orchestrator stores them as Source: manual, version 1. NurProxy-generated
	// files are returned with Adopted=false for drift comparison against their
	// accepted state.
	ReadManaged(ctx context.Context) ([]Artifact, error)

	// Apply writes, validates, and activates the given artifacts atomically
	// (§10). On failure it restores the prior state; the proxy is never left
	// non-serving.
	Apply(ctx context.Context, arts []Artifact) error

	// Remove deletes the artifact at the given target (e.g. a removed domain),
	// leaving no ghost vhosts (§3).
	Remove(ctx context.Context, target Target) error

	// Validate checks the live config without applying changes (nginx -t /
	// apachectl configtest / caddy validate).
	Validate(ctx context.Context) error

	// InstallCerts writes cert/key bundles to the backend's expected location
	// (§7), before Apply of any config that references them (preflight ordering).
	InstallCerts(ctx context.Context, certs []CertBundle) error
}

// Info is a backend's static identity plus detected host facts (§5). It is the
// agent-side counterpart to the read-only Detection and feeds the orchestrator's
// per-agent view.
type Info struct {
	// Kind is the backend type (caddy / nginx / apache).
	Kind Kind `json:"kind"`
	// Version is the parsed proxy version (e.g. "1.24.0"), empty if unknown.
	Version string `json:"version,omitempty"`
	// BinaryPath is the resolved proxy binary path, empty for admin-API-only
	// backends with no managed binary.
	BinaryPath string `json:"binary_path,omitempty"`
	// ConfigDir is the primary config directory this backend manages.
	ConfigDir string `json:"config_dir,omitempty"`
	// LogPaths are the error/access log paths surfaced in the dashboard (§15).
	LogPaths []string `json:"log_paths,omitempty"`
}

// Capabilities reports which proxy options a backend supports on this host (§8).
// A false field means the option is dropped during Render with an audited
// warning rather than silently honored.
type Capabilities struct {
	// ReverseProxy is the baseline; every backend supports it.
	ReverseProxy bool `json:"reverse_proxy"`
	// WebSocket reports connection-upgrade passthrough support.
	WebSocket bool `json:"websocket"`
	// ForceHTTPS reports HTTP→HTTPS redirect support.
	ForceHTTPS bool `json:"force_https"`
	// CustomHeaders reports request/response header injection support.
	CustomHeaders bool `json:"custom_headers"`
	// PathRewrite reports path strip/rewrite support.
	PathRewrite bool `json:"path_rewrite"`
	// BasicAuth reports HTTP basic-auth support.
	BasicAuth bool `json:"basic_auth"`
	// IPFilter reports IP allow/block support.
	IPFilter bool `json:"ip_filter"`
	// RateLimit reports per-client rate-limit support (module-dependent; probed
	// at Detect/Capabilities time, e.g. caddy-ratelimit / nginx limit_req).
	RateLimit bool `json:"rate_limit"`
	// CentralTLS reports support for orchestrator-provisioned (DNS-01) certs
	// installed via InstallCerts (§7).
	CentralTLS bool `json:"central_tls"`
}

// ToModel converts the agent-side Capabilities into the shared wire/storage
// model carried in the adoption + heartbeat payloads (§8). The agent dials out
// only; this is the shape the orchestrator persists on the agent row and exposes
// read-only so the dashboard can grey out unsupported options per backend.
func (c Capabilities) ToModel() *models.ProxyCapabilities {
	return &models.ProxyCapabilities{
		ReverseProxy:  c.ReverseProxy,
		WebSocket:     c.WebSocket,
		ForceHTTPS:    c.ForceHTTPS,
		CustomHeaders: c.CustomHeaders,
		PathRewrite:   c.PathRewrite,
		BasicAuth:     c.BasicAuth,
		IPFilter:      c.IPFilter,
		RateLimit:     c.RateLimit,
		CentralTLS:    c.CentralTLS,
	}
}

// TargetKind distinguishes a file-on-disk artifact from the built-in Caddy's
// virtual route (§4). It controls how Apply/Remove address the artifact.
type TargetKind string

const (
	// TargetKindFile is a config file on disk (nginx/apache, external caddy).
	TargetKindFile TargetKind = "file"
	// TargetKindCaddyRoute is the built-in Caddy's route JSON, addressed through
	// the admin API rather than a file path.
	TargetKindCaddyRoute TargetKind = "caddy-route"
)

// Target locates an artifact on the host (§4). For file backends Path is the
// file path; for built-in Caddy it is the virtual "caddy:route:<id>" handle.
type Target struct {
	// Kind selects file vs caddy-route addressing.
	Kind TargetKind `json:"kind"`
	// Path is the file path, or the virtual route handle for caddy-route.
	Path string `json:"path"`
}

// Artifact is a single rendered config unit: where it lives plus its native
// content (§4). For built-in Caddy the content is route JSON; for nginx/apache
// it is the native config block.
type Artifact struct {
	// Target locates the artifact on the host.
	Target Target `json:"target"`
	// Content is the native config text (or Caddy route JSON for built-in).
	Content string `json:"content"`
	// Enabled reports whether the artifact is active (e.g. nginx sites-enabled
	// symlink present); meaningless for caddy-route, where presence == enabled.
	Enabled bool `json:"enabled"`
	// Adopted reports that this artifact is an operator-authored config the
	// backend discovered on disk (NOT one NurProxy generated) during adoption
	// (§4). The orchestrator stores adopted artifacts as Source: manual, version
	// 1; we never auto-overwrite them. False means a NurProxy-managed (generated)
	// file, tracked for drift against its accepted state.
	Adopted bool `json:"adopted"`
	// Warnings lists the proxy options this backend dropped because it cannot
	// express them (invariant #4: unsupported options are dropped, never failing
	// the render). Each entry is a human-readable "<option>: <reason>". The agent
	// logs them locally and carries them back in the apply-ACK so the orchestrator
	// audits each drop (invariant #4's "logged + audited" half lives centrally,
	// since the audit log is on the orchestrator).
	Warnings []string `json:"warnings,omitempty"`
}

// TLSIntent is one host's public-listener TLS policy, used by the bundled Caddy
// backend to render its server TLS strategy (§7): central provided certs (load
// the installed bundle, disable Caddy ACME) vs self-ACME (let Caddy manage the
// cert) vs off. The backend resolves the on-disk cert paths from its cert store
// for the central path, so the caller only supplies the host and its policy.
type TLSIntent struct {
	// Host is the public FQDN this policy governs.
	Host string
	// Policy selects central provided certs (default), Caddy self-ACME (fallback),
	// or off (plaintext).
	Policy proxymodel.TLSPolicy
}

// CertBundle is a leaf certificate plus its private key (and chain) destined for
// a backend's cert store (§7). It is written by InstallCerts before the
// referencing config is applied (preflight ordering). Keys are sensitive: they
// arrive encrypted at rest and over the agent-initiated TLS stream.
type CertBundle struct {
	// Host is the FQDN the certificate covers, e.g. "app.example.com". Used to
	// derive on-disk file names.
	Host string `json:"host"`
	// CertPEM is the leaf certificate (plus chain) in PEM form.
	CertPEM []byte `json:"cert_pem"`
	// KeyPEM is the private key in PEM form (sensitive).
	KeyPEM []byte `json:"key_pem"`
}

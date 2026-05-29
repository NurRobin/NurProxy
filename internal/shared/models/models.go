package models

import "time"

// AgentStatus represents the lifecycle state of an agent.
type AgentStatus string

const (
	AgentStatusPending AgentStatus = "pending"
	AgentStatusAdopted AgentStatus = "adopted"
	AgentStatusOffline AgentStatus = "offline"
	AgentStatusError   AgentStatus = "error"
)

// DomainStatus represents the lifecycle state of a domain.
type DomainStatus string

const (
	DomainStatusPending  DomainStatus = "pending"
	DomainStatusActive   DomainStatus = "active"
	DomainStatusError    DomainStatus = "error"
	DomainStatusDeleting DomainStatus = "deleting"
)

// DNSMode indicates whether DNS records are static or use dynamic DNS.
type DNSMode string

const (
	DNSModeStatic DNSMode = "static"
	DNSModeDDNS   DNSMode = "ddns"
)

// SSLMode controls how TLS certificates are managed.
type SSLMode string

const (
	SSLModeAuto   SSLMode = "auto"
	SSLModeManual SSLMode = "manual"
	SSLModeOff    SSLMode = "off"
)

// Provider represents a DNS provider configuration (e.g. Cloudflare).
type Provider struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Name      string    `json:"name"`
	Config    string    `json:"-"` // encrypted, never in API responses
	IsDefault bool      `json:"is_default"`
	CreatedAt time.Time `json:"created_at"`
}

// Zone represents a DNS zone belonging to a provider.
type Zone struct {
	ID         string    `json:"id"`
	ProviderID string    `json:"provider_id"`
	ExternalID string    `json:"external_id"`
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at"`
}

// ProxyPortConflict identifies which process holds a listening port the built-in
// Caddy needs (:80/:443). It is what turns "Caddy can't bind" into the
// actionable "nginx is holding :443" signal (§2.1). It mirrors the agent-side
// proxy.PortConflict, carried over the wire in the adoption/heartbeat payload.
type ProxyPortConflict struct {
	Port    int    `json:"port"`
	Process string `json:"process,omitempty"`
	PID     int    `json:"pid,omitempty"`
}

// ProxyCapabilities reports which proxy options the agent's selected backend
// supports on this host (§8). It is the wire/storage counterpart of the
// agent-side proxy.Capabilities, carried in the adoption + heartbeat payloads and
// stored on the agent row. A false field means the dashboard greys out that
// option and the agent drops it during Render with a logged + audited warning,
// never failing the whole apply. Module-dependent fields (e.g. RateLimit) are
// resolved by probing at detection time (is caddy-ratelimit compiled in?).
type ProxyCapabilities struct {
	ReverseProxy  bool `json:"reverse_proxy"`
	WebSocket     bool `json:"websocket"`
	ForceHTTPS    bool `json:"force_https"`
	CustomHeaders bool `json:"custom_headers"`
	PathRewrite   bool `json:"path_rewrite"`
	BasicAuth     bool `json:"basic_auth"`
	IPFilter      bool `json:"ip_filter"`
	RateLimit     bool `json:"rate_limit"`
	CentralTLS    bool `json:"central_tls"`
}

// ProxyDetection is the agent's read-only Phase-0 detection result (§13.0, §2.1,
// §9): which proxy is installed on the host, its version, the discovered config
// dir / binary / log paths, and which process (if any) holds :80/:443. The agent
// dials out and carries this in its adoption + heartbeat payloads; the
// orchestrator persists it on the agent row and exposes it read-only so the
// dashboard can show "nginx 1.24 at /etc/nginx".
type ProxyDetection struct {
	// Installed reports whether a supported proxy binary was found on the host.
	Installed bool `json:"installed"`
	// Kind is the detected proxy type (caddy / nginx / apache), empty if none.
	Kind string `json:"kind,omitempty"`
	// Version is the parsed version string (e.g. "1.24.0"), empty if unknown.
	Version string `json:"version,omitempty"`
	// BinaryPath is the absolute path to the resolved proxy binary.
	BinaryPath string `json:"binary_path,omitempty"`
	// ConfigDir is the resolved primary config directory (§9 OS defaults).
	ConfigDir string `json:"config_dir,omitempty"`
	// LogPaths are the discovered error/access log paths (§9 OS defaults).
	LogPaths []string `json:"log_paths,omitempty"`
	// PortConflicts lists the holders of :80/:443 when those ports are occupied.
	PortConflicts []ProxyPortConflict `json:"port_conflicts,omitempty"`
}

// Agent represents a registered proxy agent.
type Agent struct {
	ID           string      `json:"id"`
	Name         string      `json:"name"`
	FQDN         string      `json:"fqdn"`
	APIURL       string      `json:"api_url"`
	TokenHash    string      `json:"-"`
	DNSMode      DNSMode     `json:"dns_mode"`
	DDNSInterval int         `json:"ddns_interval"`
	PublicIP     string      `json:"public_ip,omitempty"`
	DNSRecordID  string      `json:"dns_record_id,omitempty"`
	Status       AgentStatus `json:"status"`
	LastSeen     *time.Time  `json:"last_seen,omitempty"`
	Version      string      `json:"version,omitempty"`
	// CaddyRunning reports whether the agent's embedded Caddy is serving
	// traffic. It can be false (e.g. ports 80/443 are taken by another service)
	// while the agent itself is perfectly healthy and connected.
	CaddyRunning bool `json:"caddy_running"`
	// LastError is the most recent operational error the agent reported about
	// itself (e.g. a Caddy bind failure). Owned by the agent via heartbeat.
	LastError string `json:"last_error,omitempty"`
	// DNSError is an orchestrator-side problem managing this agent's DNS (e.g.
	// its FQDN is outside every assigned zone, so no A record can be created).
	// Owned by the reconciler. Kept separate from LastError so the two never
	// overwrite one another.
	DNSError string `json:"dns_error,omitempty"`
	// ProxyDetection is the agent's last-reported read-only detection result
	// (installed proxy + version + paths + bind-conflict holder, §13.0/§2.1/§9).
	// Owned by the agent via the adoption/heartbeat payload; the orchestrator only
	// stores and exposes it. Nil when the agent has not yet reported detection.
	ProxyDetection *ProxyDetection `json:"proxy_detection,omitempty"`
	// ProxyDetectedAt is when the orchestrator last received a detection report.
	ProxyDetectedAt *time.Time `json:"proxy_detected_at,omitempty"`
	// ProxyCapabilities is the agent's last-reported capability matrix (§8) for its
	// selected backend, including module probing (e.g. caddy-ratelimit present?).
	// Owned by the agent via the adoption/heartbeat payload; the orchestrator only
	// stores and exposes it so the dashboard can grey out unsupported options. Nil
	// when the agent has not yet reported capabilities.
	ProxyCapabilities *ProxyCapabilities `json:"proxy_capabilities,omitempty"`
	// AutoReconcileConfig is the opt-in per-agent policy that restores hands-off
	// behavior for config artifacts (§11): when true the reconciler automatically
	// re-applies generated artifacts over on-disk drift instead of flagging it for
	// review. Off by default — drift is a review, not a bulldoze. DNS
	// reconciliation stays automatic regardless of this flag.
	AutoReconcileConfig bool      `json:"auto_reconcile_config"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// Server represents a backend server managed by an agent.
type Server struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id"`
	Name      string    `json:"name"`
	Address   string    `json:"address"`
	Notes     string    `json:"notes,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// BasicAuthConfig holds credentials for HTTP basic authentication.
type BasicAuthConfig struct {
	Username string `json:"username"`
	Password string `json:"password"` // bcrypt hash
}

// RawConfig is the per-backend escape hatch for a domain's proxy config (§6).
// When set, the operator's raw native config is used verbatim instead of being
// rendered from the structured ProxyConfig fields. It replaces the old
// single-backend ProxyConfig.RawCaddy with a backend-tagged payload so the same
// escape hatch works for caddy, nginx, and apache.
type RawConfig struct {
	// Backend names the proxy this content targets ("caddy" | "nginx" |
	// "apache").
	Backend string `json:"backend,omitempty"`
	// Content is the raw native config text. For built-in Caddy this is route
	// JSON; for nginx/apache it is the native config block.
	Content string `json:"content,omitempty"`
}

// IsZero reports whether the raw escape hatch is unset (no override).
func (r RawConfig) IsZero() bool {
	return r.Backend == "" && r.Content == ""
}

// ProxyConfig holds per-domain reverse proxy settings.
type ProxyConfig struct {
	WebSocket             bool              `json:"websocket,omitempty"`
	ForceHTTPS            bool              `json:"force_https,omitempty"`
	MaxBodySize           string            `json:"max_body_size,omitempty"`
	CustomRequestHeaders  map[string]string `json:"custom_request_headers,omitempty"`
	CustomResponseHeaders map[string]string `json:"custom_response_headers,omitempty"`
	PathStrip             string            `json:"path_strip,omitempty"`
	PathRewrite           string            `json:"path_rewrite,omitempty"`
	UpstreamScheme        string            `json:"upstream_scheme,omitempty"` // "http" or "https"
	TimeoutRead           int               `json:"timeout_read,omitempty"`    // seconds
	TimeoutWrite          int               `json:"timeout_write,omitempty"`
	TimeoutIdle           int               `json:"timeout_idle,omitempty"`
	BasicAuth             *BasicAuthConfig  `json:"basic_auth,omitempty"`
	IPAllowlist           []string          `json:"ip_allowlist,omitempty"`
	IPBlocklist           []string          `json:"ip_blocklist,omitempty"`
	RateLimit             float64           `json:"rate_limit,omitempty"` // requests/second
	RawConfig             RawConfig         `json:"raw_config,omitempty"` // per-backend manual override (§6)
}

// Domain represents a proxied subdomain.
type Domain struct {
	ID           int64        `json:"id"`
	Subdomain    string       `json:"subdomain"`
	ZoneID       string       `json:"zone_id"`
	ServerID     string       `json:"server_id"`
	Port         int          `json:"port"`
	ProxyConfig  ProxyConfig  `json:"proxy_config"`
	ManualConfig bool         `json:"manual_config"`
	WebSocket    bool         `json:"websocket"`
	ForceHTTPS   bool         `json:"force_https"`
	SSLMode      SSLMode      `json:"ssl_mode"`
	DNSRecordID  string       `json:"dns_record_id,omitempty"`
	Status       DomainStatus `json:"status"`
	ErrorMsg     string       `json:"error_msg,omitempty"`
	LastSynced   *time.Time   `json:"last_synced,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

// FQDN returns the full domain name (subdomain + zone).
func (d Domain) FQDN(zoneName string) string {
	return d.Subdomain + "." + zoneName
}

// AuditSource categorizes which channel an audited action came through.
type AuditSource = string

const (
	AuditSourceUI     AuditSource = "ui"     // browser session (dashboard)
	AuditSourceAPI    AuditSource = "api"    // admin API key (REST)
	AuditSourceMCP    AuditSource = "mcp"    // MCP tool call
	AuditSourceAgent  AuditSource = "agent"  // an agent (token auth)
	AuditSourceSystem AuditSource = "system" // orchestrator itself (reconciler)
)

// AuditLogEntry records a single change event for audit purposes.
type AuditLogEntry struct {
	ID         int64  `json:"id"`
	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
	Action     string `json:"action"`
	Actor      string `json:"actor"`
	// Source is the channel the action came through (ui/api/mcp/agent/system).
	Source    string    `json:"source,omitempty"`
	Details   string    `json:"details,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// ArtifactSource records whether a managed config artifact is model-backed
// (rendered from a domain's intent) or hand-edited/adopted (§4, §6). Editing a
// generated artifact raw flips it to manual; a "reset to model" re-renders it.
type ArtifactSource = string

const (
	// ArtifactSourceGenerated means the content was rendered from a domain's
	// intent and can be re-rendered (DomainID is set).
	ArtifactSourceGenerated ArtifactSource = "generated"
	// ArtifactSourceManual means the content was hand-edited or adopted from an
	// existing on-disk config and must not be blindly re-rendered.
	ArtifactSourceManual ArtifactSource = "manual"
)

// ArtifactApplyState is the per-artifact lifecycle status surfaced in the UI
// without extra joins (§4, §15).
type ArtifactApplyState = string

const (
	// ArtifactStateLive means the on-disk content matches the accepted state.
	ArtifactStateLive ArtifactApplyState = "live"
	// ArtifactStateApplyFailed means the last apply (write/validate/reload)
	// failed; see LastError.
	ArtifactStateApplyFailed ArtifactApplyState = "apply_failed"
	// ArtifactStateDrifted means the on-disk content diverged from the accepted
	// state and is awaiting operator review (§11).
	ArtifactStateDrifted ArtifactApplyState = "drifted"
)

// TargetKind names where an artifact lives on the host (§4).
type TargetKind = string

const (
	// TargetKindFile is a config file on disk (nginx/apache/external caddy).
	TargetKindFile TargetKind = "file"
	// TargetKindCaddyRoute is the virtual target for built-in Caddy: the route
	// JSON applied via the admin API rather than a file on disk.
	TargetKindCaddyRoute TargetKind = "caddy-route"
)

// Target is where a managed config artifact lives on the host (§4). For file
// backends Path is the absolute file path; for built-in Caddy the artifact is a
// route in the admin API and Path is the virtual "caddy:route:<id>".
type Target struct {
	Kind TargetKind `json:"kind"`
	Path string     `json:"path"`
}

// ConfigArtifact is the unit of the central managed-config store (§4). The agent
// renders native config and round-trips it here so the orchestrator can version,
// diff, back up, roll back, and drift-review it across hosts (B1, §3). Built-in
// Caddy participates with Target.Kind == "caddy-route" and Content == route JSON.
type ConfigArtifact struct {
	ID      string `json:"id"`
	AgentID string `json:"agent_id"`
	// Backend names the proxy this artifact targets ("caddy" | "nginx" |
	// "apache").
	Backend string `json:"backend"`
	// Target is where the artifact lives on the host.
	Target Target `json:"target"`
	// Source is "generated" (model-backed) or "manual" (hand-edited/adopted).
	Source ArtifactSource `json:"source"`
	// DomainID is set when Source == generated, linking the artifact to the
	// domain whose intent produced it. Nil for manual/adopted artifacts.
	DomainID *int64 `json:"domain_id,omitempty"`
	// Content is the native config text (or Caddy route JSON for built-in).
	Content string `json:"content"`
	// Checksum is of the live/accepted content; the agent reports the on-disk
	// checksum on heartbeat and divergence flags drift (§11).
	Checksum string `json:"checksum"`
	// LiveVersion is the version number of the currently accepted content. It
	// matches a row in config_artifact_versions.
	LiveVersion int `json:"live_version"`
	// Enabled reflects whether the artifact is active on the host (e.g. an nginx
	// sites-enabled symlink is present).
	Enabled bool `json:"enabled"`
	// Drifted is true when on-disk content diverges from the accepted state and
	// the artifact awaits review (§11). Mirrors ApplyState == drifted.
	Drifted bool `json:"drifted"`
	// ApplyState is the lifecycle status (live | apply_failed | drifted).
	ApplyState ArtifactApplyState `json:"apply_state"`
	// LastError is the most recent apply/validate/reload error, if any.
	LastError string    `json:"last_error,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ConfigArtifactVersion is one entry in the append-only version history of a
// config artifact (§4, §11). A new version is written only on semantic change so
// re-serialization (Caddy) does not spawn phantom versions; history is never
// pruned.
type ConfigArtifactVersion struct {
	ID         int64  `json:"id"`
	ArtifactID string `json:"artifact_id"`
	// Version is the 1-indexed sequence number within the artifact's history.
	Version int `json:"version"`
	// Content is the full config text at this version (full content history).
	Content string `json:"content"`
	// Checksum is of Content, for cheap equality checks.
	Checksum string `json:"checksum"`
	// Source records whether this version was generated or manual at the time it
	// was written (e.g. an accepted drift is manual).
	Source ArtifactSource `json:"source"`
	// Actor and Note describe who/what wrote this version and why, for audit
	// (apply/accept/reject/rollback).
	Actor     string    `json:"actor,omitempty"`
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Setting is a key-value configuration pair.
type Setting struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Notifier represents a configured notification channel.
type Notifier struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Name      string    `json:"name"`
	Config    string    `json:"-"`
	Events    []string  `json:"events"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

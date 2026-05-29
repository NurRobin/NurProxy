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
	CreatedAt         time.Time          `json:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at"`
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

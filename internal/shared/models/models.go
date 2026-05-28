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
	Config    string    `json:"-"`          // encrypted, never in API responses
	ZoneID    string    `json:"zone_id"`
	ZoneName  string    `json:"zone_name"`
	IsDefault bool      `json:"is_default"`
	CreatedAt time.Time `json:"created_at"`
}

// Agent represents a registered proxy agent.
type Agent struct {
	ID           string      `json:"id"`
	Name         string      `json:"name"`
	FQDN         string      `json:"fqdn"`
	APIURL       string      `json:"api_url"`
	TokenHash    string      `json:"-"`
	ProviderID   string      `json:"provider_id,omitempty"`
	DNSMode      DNSMode     `json:"dns_mode"`
	DDNSInterval int         `json:"ddns_interval"`
	PublicIP     string      `json:"public_ip,omitempty"`
	DNSRecordID  string      `json:"dns_record_id,omitempty"`
	Status       AgentStatus `json:"status"`
	LastSeen     *time.Time  `json:"last_seen,omitempty"`
	Version      string      `json:"version,omitempty"`
	CreatedAt    time.Time   `json:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at"`
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
	TimeoutRead           int               `json:"timeout_read,omitempty"`   // seconds
	TimeoutWrite          int               `json:"timeout_write,omitempty"`
	TimeoutIdle           int               `json:"timeout_idle,omitempty"`
	BasicAuth             *BasicAuthConfig  `json:"basic_auth,omitempty"`
	IPAllowlist           []string          `json:"ip_allowlist,omitempty"`
	IPBlocklist           []string          `json:"ip_blocklist,omitempty"`
	RateLimit             float64           `json:"rate_limit,omitempty"` // requests/second
	RawCaddy              string            `json:"_raw_caddy,omitempty"` // manual override
}

// Domain represents a proxied subdomain.
type Domain struct {
	ID           int64        `json:"id"`
	Subdomain    string       `json:"subdomain"`
	ProviderID   string       `json:"provider_id"`
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

// AuditLogEntry records a single change event for audit purposes.
type AuditLogEntry struct {
	ID         int64     `json:"id"`
	EntityType string    `json:"entity_type"`
	EntityID   string    `json:"entity_id"`
	Action     string    `json:"action"`
	Actor      string    `json:"actor"`
	Details    string    `json:"details,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
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

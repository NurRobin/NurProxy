// Package proxymodel defines a backend-neutral representation of a single
// reverse-proxy route (one host → one upstream, with options).
//
// It is the "intent" model from the design (§3): the orchestrator stores intent
// independently of any rendered native config, and each backend renderer
// (caddygen, nginxgen, apachegen) consumes a Route and emits its own native
// output. Keeping the model backend-neutral is what makes a clean,
// model-backed config portable across hosts and even across proxy types — to
// move it you push the intent and the new host re-renders natively.
//
// Renderers are pure functions (intent in, bytes out); this package holds no
// rendering logic, only the data shape plus constructors and validation.
package proxymodel

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Scheme is the protocol used to reach the upstream backend.
type Scheme string

const (
	// SchemeHTTP talks plain HTTP to the upstream (the default).
	SchemeHTTP Scheme = "http"
	// SchemeHTTPS talks HTTPS to the upstream (TLS to the backend).
	SchemeHTTPS Scheme = "https"
)

// TLSPolicy selects how TLS for the public listener is provisioned for this
// route. The default is central provisioning (DNS-01 via the orchestrator, §7):
// the orchestrator issues the cert and ships the bundle to the agent.
type TLSPolicy string

const (
	// TLSPolicyCentral provisions the certificate centrally (DNS-01) and
	// distributes the bundle to the agent. This is the default and applies to
	// every backend, including built-in Caddy on provided certs (§7).
	TLSPolicyCentral TLSPolicy = "central"
	// TLSPolicySelfACME lets the backend obtain its own certificate (Caddy
	// self-ACME). Used as a fallback for zones not in a configured DNS provider
	// or for orchestrator-down resilience (§7).
	TLSPolicySelfACME TLSPolicy = "self-acme"
	// TLSPolicyOff disables TLS on the public listener (plain HTTP only).
	TLSPolicyOff TLSPolicy = "off"
)

// Upstream is a single backend the route forwards requests to.
type Upstream struct {
	// Addr is the upstream host or IP (no scheme, no port), e.g. "10.0.0.4" or
	// "backend.internal".
	Addr string
	// Port is the upstream TCP port, e.g. 8080.
	Port int
	// Scheme is the protocol used to reach the upstream. Empty is treated as
	// SchemeHTTP by renderers.
	Scheme Scheme
}

// Timeouts holds upstream timeouts in seconds. Zero means "unset" — the backend
// uses its own default. These are intent-level and each renderer maps them onto
// the closest valid native fields for its proxy.
type Timeouts struct {
	// Read bounds how long to wait for the upstream's response headers.
	Read int
	// Write bounds how long establishing/writing to the upstream may take.
	Write int
	// Idle bounds how long an idle upstream keep-alive connection is kept.
	Idle int
}

// BasicAuth enables HTTP basic authentication in front of the upstream.
type BasicAuth struct {
	// Username is the account name presented in the WWW-Authenticate challenge.
	Username string
	// PasswordHash is the bcrypt hash of the password. The plaintext password
	// never lives in the intent model.
	PasswordHash string
}

// RateLimit caps request throughput per client.
type RateLimit struct {
	// RequestsPerSecond is the sustained per-client rate. Zero means disabled.
	// Backends without a rate-limit module drop this option with an audited
	// warning (§8).
	RequestsPerSecond float64
}

// PathRules manipulate the request path before it reaches the upstream.
type PathRules struct {
	// StripPrefix removes this leading prefix from the request path, e.g.
	// "/api" so "/api/users" reaches the upstream as "/users". Empty disables.
	StripPrefix string
	// Rewrite replaces the entire request URI with this value. Empty disables.
	Rewrite string
}

// TLSConfig describes the public-listener TLS settings for the route.
type TLSConfig struct {
	// Policy selects how the certificate is provisioned (central by default).
	Policy TLSPolicy
	// Wildcard requests a wildcard certificate for the host's parent zone.
	// Opt-in only: a wildcard shared across agents means the same private key
	// on multiple hosts (§7).
	Wildcard bool
}

// RawConfig is the per-backend escape hatch (§6): when set, the operator's raw
// native config is used verbatim instead of rendering from the structured
// fields. This replaces the old single-backend ProxyConfig.RawCaddy with a
// backend-tagged payload, so the same escape hatch works for caddy, nginx, and
// apache.
type RawConfig struct {
	// Backend names the proxy this content targets ("caddy" | "nginx" |
	// "apache"). A renderer must refuse content tagged for a different backend.
	Backend string
	// Content is the raw native config text. For built-in Caddy this is route
	// JSON; for nginx/apache it is the native config block.
	Content string
}

// IsZero reports whether the raw escape hatch is unset (no override).
func (r RawConfig) IsZero() bool {
	return r.Backend == "" && r.Content == ""
}

// Route is the backend-neutral intent for proxying one host to one upstream.
//
// It is consumed by every backend renderer and is deliberately free of any
// native-config concept. Unsupported options for a given backend are dropped by
// that renderer with a logged + audited warning (§8) — they never fail the
// whole apply and they are never silently honored where unsupported.
type Route struct {
	// Host is the public FQDN this route serves, e.g. "app.example.com".
	Host string
	// Upstream is the backend this route forwards to.
	Upstream Upstream

	// WebSocket enables WebSocket/connection-upgrade passthrough to the
	// upstream.
	WebSocket bool
	// ForceHTTPS redirects plaintext HTTP requests to HTTPS.
	ForceHTTPS bool
	// MaxBodySize caps the request body size, as a human-readable size string
	// (e.g. "10MB"). Empty or "unlimited" disables the limit.
	MaxBodySize string

	// RequestHeaders are headers set on the request before it is forwarded to
	// the upstream (in addition to the standard forwarding headers each
	// renderer adds, e.g. X-Forwarded-Proto).
	RequestHeaders map[string]string
	// ResponseHeaders are headers set on the response returned to the client.
	ResponseHeaders map[string]string

	// Path manipulates the request path before forwarding.
	Path PathRules

	// Timeouts bounds upstream interactions (seconds; zero = backend default).
	Timeouts Timeouts

	// BasicAuth, when non-nil, gates the route behind HTTP basic auth.
	BasicAuth *BasicAuth
	// IPAllowlist, when non-empty, permits only these CIDR ranges; all others
	// receive 403.
	IPAllowlist []string
	// IPBlocklist denies these CIDR ranges with 403. Evaluated before the
	// allowlist.
	IPBlocklist []string

	// RateLimit caps per-client request throughput.
	RateLimit RateLimit

	// TLS selects the public-listener TLS policy for the route.
	TLS TLSConfig

	// Raw is the per-backend escape hatch. When non-zero, renderers for the
	// matching backend use Raw.Content verbatim and ignore the structured
	// fields above.
	Raw RawConfig
}

// EffectiveScheme returns the upstream scheme, defaulting to SchemeHTTP when
// unset.
func (r Route) EffectiveScheme() Scheme {
	if r.Upstream.Scheme == "" {
		return SchemeHTTP
	}
	return r.Upstream.Scheme
}

// IsRaw reports whether this route uses the raw escape hatch instead of the
// structured fields.
func (r Route) IsRaw() bool {
	return !r.Raw.IsZero()
}

// Validate checks that the Route is internally consistent enough to render.
//
// A raw route only needs a backend tag and content (its native config is the
// operator's responsibility, validated by the proxy itself, e.g. nginx -t). A
// structured route needs a host and a complete upstream. Validate does not
// reach out to any backend or host; it is a pure, cheap check.
func (r Route) Validate() error {
	if r.IsRaw() {
		if r.Raw.Backend == "" {
			return fmt.Errorf("raw config: backend is required")
		}
		if strings.TrimSpace(r.Raw.Content) == "" {
			return fmt.Errorf("raw config: content is required")
		}
		return nil
	}

	if r.Host == "" {
		return fmt.Errorf("host is required")
	}
	if r.Upstream.Addr == "" {
		return fmt.Errorf("upstream address is required")
	}
	if r.Upstream.Port <= 0 || r.Upstream.Port > 65535 {
		return fmt.Errorf("upstream port %d out of range (1-65535)", r.Upstream.Port)
	}
	switch r.EffectiveScheme() {
	case SchemeHTTP, SchemeHTTPS:
	default:
		return fmt.Errorf("invalid upstream scheme %q", r.Upstream.Scheme)
	}
	if r.RateLimit.RequestsPerSecond < 0 {
		return fmt.Errorf("rate limit must not be negative")
	}
	if r.BasicAuth != nil {
		if r.BasicAuth.Username == "" {
			return fmt.Errorf("basic auth: username is required")
		}
		if r.BasicAuth.PasswordHash == "" {
			return fmt.Errorf("basic auth: password hash is required")
		}
	}
	if !validHost(r.Host) {
		return fmt.Errorf("host %q is not a valid DNS name", r.Host)
	}
	if !validUpstreamAddr(r.Upstream.Addr) {
		return fmt.Errorf("upstream address %q is not a host name or IP address", r.Upstream.Addr)
	}
	return r.ValidateOptions()
}

var (
	hostLabelRe   = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$`)
	headerNameRe  = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	bodySizeRe    = regexp.MustCompile(`^\s*(?i:unlimited|[0-9]+(\.[0-9]+)?\s*[kmg]?b?)\s*$`)
	pathUnsafeSet = " \t\"'\\{};#"
)

// ValidateOptions checks the option values that renderers interpolate into
// native proxy configs: header names and values, body size, path rules, IP
// lists and basic-auth credentials. It does not require a host or upstream,
// so the orchestrator can check a domain's proxy settings on their own.
func (r Route) ValidateOptions() error {
	for kind, headers := range map[string]map[string]string{"request": r.RequestHeaders, "response": r.ResponseHeaders} {
		for name, value := range headers {
			if !headerNameRe.MatchString(name) {
				return fmt.Errorf("%s header name %q may only contain letters, digits, '-' and '_'", kind, name)
			}
			if !validHeaderValue(value) {
				return fmt.Errorf("%s header %s has a value with control characters or a backslash", kind, name)
			}
		}
	}
	if r.MaxBodySize != "" && !bodySizeRe.MatchString(r.MaxBodySize) {
		return fmt.Errorf("max body size %q is not a size like 10m, 1GB or unlimited", r.MaxBodySize)
	}
	for _, p := range []struct{ name, value string }{{"path strip prefix", r.Path.StripPrefix}, {"path rewrite", r.Path.Rewrite}} {
		if p.value != "" && (hasControl(p.value) || strings.ContainsAny(p.value, pathUnsafeSet)) {
			return fmt.Errorf("%s %q contains whitespace, quotes, braces, '#', ';' or a backslash", p.name, p.value)
		}
	}
	for _, list := range [][]string{r.IPAllowlist, r.IPBlocklist} {
		for _, entry := range list {
			if !validIPOrCIDR(entry) {
				return fmt.Errorf("IP list entry %q is not an IP address or CIDR range", entry)
			}
		}
	}
	if r.BasicAuth != nil {
		if hasControl(r.BasicAuth.Username) || strings.Contains(r.BasicAuth.Username, ":") {
			return fmt.Errorf("basic auth: username must not contain ':' or control characters")
		}
		if hasControl(r.BasicAuth.PasswordHash) {
			return fmt.Errorf("basic auth: password hash must not contain control characters")
		}
	}
	return nil
}

// validHost accepts a DNS name with an optional leading "*." wildcard label.
func validHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for i, label := range strings.Split(host, ".") {
		if i == 0 && label == "*" {
			continue
		}
		if !hostLabelRe.MatchString(label) {
			return false
		}
	}
	return true
}

// validUpstreamAddr accepts a DNS name or an IP address (IPv6 with or without
// brackets).
func validUpstreamAddr(addr string) bool {
	if net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")) != nil {
		return true
	}
	return !strings.HasPrefix(addr, "*") && validHost(addr)
}

func validIPOrCIDR(entry string) bool {
	if net.ParseIP(entry) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(entry)
	return err == nil
}

// validHeaderValue refuses control characters (CR, LF, NUL, ...) and
// backslashes. Backslash escaping differs between nginx and Apache, so a
// value that needs one cannot be rendered the same way everywhere.
func validHeaderValue(v string) bool {
	return !hasControl(v) && !strings.Contains(v, `\`)
}

func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

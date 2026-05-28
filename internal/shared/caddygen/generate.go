package caddygen

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// DomainConfig holds all settings needed to generate a Caddy route for a domain.
type DomainConfig struct {
	FQDN                  string
	UpstreamAddr          string // server address
	UpstreamPort          int
	WebSocket             bool
	ForceHTTPS            bool
	MaxBodySize           string
	CustomRequestHeaders  map[string]string
	CustomResponseHeaders map[string]string
	UpstreamScheme        string // "http" or "https", default "http"

	// Path manipulation.
	PathStrip   string // strip this prefix from the request path
	PathRewrite string // rewrite the request URI to this value

	// Upstream timeouts, in seconds (0 = unset).
	TimeoutRead  int
	TimeoutWrite int
	TimeoutIdle  int

	// Access control.
	BasicAuthUser string // if set with hash, enables HTTP basic auth
	BasicAuthHash string // bcrypt hash of the password
	IPAllowlist   []string
	IPBlocklist   []string

	// Rate limiting (requests/second per client). Requires the caddy-ratelimit
	// module on the agent's Caddy build. 0 = disabled.
	RateLimit float64

	RawCaddy string // if set, use this instead of generating
}

var slugRe = regexp.MustCompile(`[^a-zA-Z0-9-]`)

// ConfigFromDomain builds a DomainConfig from a stored domain, its resolved
// FQDN, and the upstream server address. It is the single source of truth for
// translating a domain's proxy settings into a Caddy route, shared by the
// reconciler and the API's config preview so they never diverge.
func ConfigFromDomain(d models.Domain, fqdn, upstreamAddr string) DomainConfig {
	cfg := DomainConfig{
		FQDN:                  fqdn,
		UpstreamAddr:          upstreamAddr,
		UpstreamPort:          d.Port,
		WebSocket:             d.WebSocket || d.ProxyConfig.WebSocket,
		ForceHTTPS:            d.ForceHTTPS || d.ProxyConfig.ForceHTTPS,
		MaxBodySize:           d.ProxyConfig.MaxBodySize,
		CustomRequestHeaders:  d.ProxyConfig.CustomRequestHeaders,
		CustomResponseHeaders: d.ProxyConfig.CustomResponseHeaders,
		UpstreamScheme:        d.ProxyConfig.UpstreamScheme,
		PathStrip:             d.ProxyConfig.PathStrip,
		PathRewrite:           d.ProxyConfig.PathRewrite,
		TimeoutRead:           d.ProxyConfig.TimeoutRead,
		TimeoutWrite:          d.ProxyConfig.TimeoutWrite,
		TimeoutIdle:           d.ProxyConfig.TimeoutIdle,
		IPAllowlist:           d.ProxyConfig.IPAllowlist,
		IPBlocklist:           d.ProxyConfig.IPBlocklist,
		RateLimit:             d.ProxyConfig.RateLimit,
		RawCaddy:              d.ProxyConfig.RawCaddy,
	}
	if d.ProxyConfig.BasicAuth != nil {
		cfg.BasicAuthUser = d.ProxyConfig.BasicAuth.Username
		cfg.BasicAuthHash = d.ProxyConfig.BasicAuth.Password
	}
	return cfg
}

// forbiddenResponse returns a static_response handler that replies 403.
func forbiddenResponse() StaticResponse {
	return StaticResponse{
		Handler:    "static_response",
		StatusCode: "403",
		Body:       "Forbidden",
	}
}

// slugify converts an FQDN into a safe ID string by replacing dots and special
// characters with dashes and collapsing consecutive dashes.
func slugify(fqdn string) string {
	s := strings.ToLower(fqdn)
	s = slugRe.ReplaceAllString(s, "-")
	// Collapse consecutive dashes
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	return s
}

// GenerateRoute produces a Caddy JSON route configuration from a DomainConfig.
// The returned json.RawMessage is ready to be sent to the Caddy admin API.
func GenerateRoute(cfg DomainConfig) (json.RawMessage, error) {
	// Manual override: return raw JSON directly.
	if cfg.RawCaddy != "" {
		// Validate that it is well-formed JSON.
		var raw json.RawMessage
		if err := json.Unmarshal([]byte(cfg.RawCaddy), &raw); err != nil {
			return nil, fmt.Errorf("invalid RawCaddy JSON: %w", err)
		}
		return raw, nil
	}

	if cfg.FQDN == "" {
		return nil, fmt.Errorf("FQDN is required")
	}
	if cfg.UpstreamAddr == "" {
		return nil, fmt.Errorf("UpstreamAddr is required")
	}
	if cfg.UpstreamPort == 0 {
		return nil, fmt.Errorf("UpstreamPort is required")
	}

	// Build the inner handlers for the main route (the request pipeline that
	// runs once access-control guards have passed).
	var innerHandlers []interface{}

	// Path manipulation (rewrite handler) runs first so downstream handlers and
	// the upstream see the modified path.
	if cfg.PathStrip != "" {
		innerHandlers = append(innerHandlers, map[string]interface{}{
			"handler":           "rewrite",
			"strip_path_prefix": cfg.PathStrip,
		})
	}
	if cfg.PathRewrite != "" {
		innerHandlers = append(innerHandlers, map[string]interface{}{
			"handler": "rewrite",
			"uri":     cfg.PathRewrite,
		})
	}

	// HTTP basic authentication.
	if cfg.BasicAuthUser != "" && cfg.BasicAuthHash != "" {
		innerHandlers = append(innerHandlers, map[string]interface{}{
			"handler": "authentication",
			"providers": map[string]interface{}{
				"http_basic": map[string]interface{}{
					"hash": map[string]interface{}{"algorithm": "bcrypt"},
					"accounts": []map[string]interface{}{
						{
							"username": cfg.BasicAuthUser,
							// Caddy expects the hashed password base64-encoded.
							"password": base64.StdEncoding.EncodeToString([]byte(cfg.BasicAuthHash)),
						},
					},
				},
			},
		})
	}

	// Rate limiting (requires the caddy-ratelimit module).
	if cfg.RateLimit > 0 {
		innerHandlers = append(innerHandlers, map[string]interface{}{
			"handler": "rate_limit",
			"rate_limits": map[string]interface{}{
				"default": map[string]interface{}{
					"key":        "{http.request.remote.host}",
					"window":     "1s",
					"max_events": int(cfg.RateLimit),
				},
			},
		})
	}

	// Body size limit handler (before reverse_proxy).
	if cfg.MaxBodySize != "" && cfg.MaxBodySize != "unlimited" {
		innerHandlers = append(innerHandlers, Handler{
			Handler: "request_body",
			MaxSize: cfg.MaxBodySize,
		})
	}

	// Build reverse_proxy handler.
	rp := ReverseProxy{
		Handler: "reverse_proxy",
		Upstreams: []Upstream{
			{Dial: fmt.Sprintf("%s:%d", cfg.UpstreamAddr, cfg.UpstreamPort)},
		},
	}

	// Default forwarding headers.
	requestHeaders := map[string][]string{
		"X-Forwarded-Proto": {"{http.request.scheme}"},
		"X-Real-IP":         {"{http.request.remote.host}"},
	}

	// Merge custom request headers.
	for k, v := range cfg.CustomRequestHeaders {
		requestHeaders[k] = []string{v}
	}

	rp.Headers = &HeaderOps{
		Request: &HeaderMod{Set: requestHeaders},
	}

	// Custom response headers.
	if len(cfg.CustomResponseHeaders) > 0 {
		respHeaders := make(map[string][]string, len(cfg.CustomResponseHeaders))
		for k, v := range cfg.CustomResponseHeaders {
			respHeaders[k] = []string{v}
		}
		rp.Headers.Response = &HeaderMod{Set: respHeaders}
	}

	// WebSocket support.
	if cfg.WebSocket {
		rp.FlushInterval = -1
	}

	// Upstream transport: needed when talking HTTPS to the backend or when any
	// upstream timeout is configured.
	if cfg.UpstreamScheme == "https" || cfg.TimeoutRead > 0 || cfg.TimeoutWrite > 0 || cfg.TimeoutIdle > 0 {
		t := &Transport{Protocol: "http"}
		if cfg.UpstreamScheme == "https" {
			t.TLS = &TLS{}
		}
		// Map our read/write/idle timeouts onto the closest valid Caddy http
		// transport fields.
		if cfg.TimeoutWrite > 0 {
			t.DialTimeout = fmt.Sprintf("%ds", cfg.TimeoutWrite)
		}
		if cfg.TimeoutRead > 0 {
			t.ResponseHeaderTimeout = fmt.Sprintf("%ds", cfg.TimeoutRead)
		}
		if cfg.TimeoutIdle > 0 {
			t.KeepAlive = &KeepAlive{IdleTimeout: fmt.Sprintf("%ds", cfg.TimeoutIdle)}
		}
		rp.Transport = t
	}

	innerHandlers = append(innerHandlers, rp)

	// Build the subroute's inner routes. IP allow/block guards run first as
	// terminal routes so blocked clients never reach the proxy.
	var innerRoutes []Route
	if len(cfg.IPBlocklist) > 0 {
		innerRoutes = append(innerRoutes, Route{
			Match:    []map[string]interface{}{{"remote_ip": map[string]interface{}{"ranges": cfg.IPBlocklist}}},
			Handle:   []interface{}{forbiddenResponse()},
			Terminal: true,
		})
	}
	if len(cfg.IPAllowlist) > 0 {
		// Deny everything that is NOT in the allowlist.
		innerRoutes = append(innerRoutes, Route{
			Match: []map[string]interface{}{{
				"not": []map[string]interface{}{
					{"remote_ip": map[string]interface{}{"ranges": cfg.IPAllowlist}},
				},
			}},
			Handle:   []interface{}{forbiddenResponse()},
			Terminal: true,
		})
	}
	innerRoutes = append(innerRoutes, Route{Handle: innerHandlers})

	// Build the subroute.
	subroute := Handler{
		Handler: "subroute",
		Routes:  innerRoutes,
	}

	// Build top-level handlers.
	var topHandlers []Handler

	// ForceHTTPS: redirect plaintext (HTTP) requests to HTTPS. The inner route
	// is matched on the "http" protocol and marked terminal so it ONLY fires on
	// non-TLS requests — otherwise an HTTPS request would also match and create
	// an infinite redirect loop.
	if cfg.ForceHTTPS {
		topHandlers = append(topHandlers, Handler{
			Handler: "subroute",
			Routes: []Route{
				{
					Match: []map[string]interface{}{{"protocol": "http"}},
					Handle: []interface{}{
						StaticResponse{
							Handler:    "static_response",
							StatusCode: "302",
							Headers: map[string][]string{
								"Location": {"https://{http.request.host}{http.request.uri}"},
							},
						},
					},
					Terminal: true,
				},
			},
		})
	}

	topHandlers = append(topHandlers, subroute)

	route := CaddyRoute{
		ID:       "domain-" + slugify(cfg.FQDN),
		Match:    []Match{{Host: []string{cfg.FQDN}}},
		Handle:   topHandlers,
		Terminal: true,
	}

	data, err := json.Marshal(route)
	if err != nil {
		return nil, fmt.Errorf("marshaling route: %w", err)
	}
	return json.RawMessage(data), nil
}

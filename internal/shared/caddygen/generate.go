package caddygen

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// backendCaddy is the backend tag the Caddy renderer recognizes on a raw
// escape-hatch payload (proxymodel.RawConfig.Backend).
const backendCaddy = "caddy"

var slugRe = regexp.MustCompile(`[^a-zA-Z0-9-]`)

// ConfigFromDomain builds a backend-neutral proxymodel.Route from a stored
// domain, its resolved FQDN, and the upstream server address. It is the single
// source of truth for translating a domain's proxy settings into proxy intent,
// shared by the reconciler and the API's config preview so they never diverge.
func ConfigFromDomain(d models.Domain, fqdn, upstreamAddr string) proxymodel.Route {
	route := proxymodel.Route{
		Host: fqdn,
		Upstream: proxymodel.Upstream{
			Addr:   upstreamAddr,
			Port:   d.Port,
			Scheme: proxymodel.Scheme(d.ProxyConfig.UpstreamScheme),
		},
		WebSocket:       d.WebSocket || d.ProxyConfig.WebSocket,
		ForceHTTPS:      d.ForceHTTPS || d.ProxyConfig.ForceHTTPS,
		MaxBodySize:     d.ProxyConfig.MaxBodySize,
		RequestHeaders:  d.ProxyConfig.CustomRequestHeaders,
		ResponseHeaders: d.ProxyConfig.CustomResponseHeaders,
		Path: proxymodel.PathRules{
			StripPrefix: d.ProxyConfig.PathStrip,
			Rewrite:     d.ProxyConfig.PathRewrite,
		},
		Timeouts: proxymodel.Timeouts{
			Read:  d.ProxyConfig.TimeoutRead,
			Write: d.ProxyConfig.TimeoutWrite,
			Idle:  d.ProxyConfig.TimeoutIdle,
		},
		IPAllowlist: d.ProxyConfig.IPAllowlist,
		IPBlocklist: d.ProxyConfig.IPBlocklist,
		RateLimit:   proxymodel.RateLimit{RequestsPerSecond: d.ProxyConfig.RateLimit},
		TLS:         proxymodel.TLSConfig{Policy: tlsPolicyFromDomain(d)},
	}
	if d.ProxyConfig.BasicAuth != nil {
		route.BasicAuth = &proxymodel.BasicAuth{
			Username:     d.ProxyConfig.BasicAuth.Username,
			PasswordHash: d.ProxyConfig.BasicAuth.Password,
		}
	}
	if !d.ProxyConfig.RawConfig.IsZero() {
		backend := d.ProxyConfig.RawConfig.Backend
		if backend == "" {
			backend = backendCaddy
		}
		route.Raw = proxymodel.RawConfig{Backend: backend, Content: d.ProxyConfig.RawConfig.Content}
	}
	return route
}

// TLSPolicyForDomain resolves a domain's public-listener TLS provisioning policy
// (§7) into the backend-neutral proxymodel.TLSPolicy, exported so the central
// issuer can decide which domains need a provided cert with exactly the same
// logic the renderers use (no divergence between "needs a cert" and "renders a
// TLS listener"). See tlsPolicyFromDomain for the resolution rules.
func TLSPolicyForDomain(d models.Domain) proxymodel.TLSPolicy {
	return tlsPolicyFromDomain(d)
}

// tlsPolicyFromDomain resolves a domain's public-listener TLS provisioning
// policy (§7) into the backend-neutral proxymodel.TLSPolicy. The explicit
// per-domain ProxyConfig.TLSPolicy wins; an empty policy defaults to central
// provisioning (DNS-01, built-in Caddy on provided certs) EXCEPT when the
// domain's SSLMode is "off", which disables TLS. "self-acme" selects the Caddy
// self-ACME fallback (zones not in a configured DNS provider, orchestrator-down
// resilience). An unrecognized value falls back to central rather than failing.
func tlsPolicyFromDomain(d models.Domain) proxymodel.TLSPolicy {
	switch proxymodel.TLSPolicy(d.ProxyConfig.TLSPolicy) {
	case proxymodel.TLSPolicySelfACME:
		return proxymodel.TLSPolicySelfACME
	case proxymodel.TLSPolicyOff:
		return proxymodel.TLSPolicyOff
	case proxymodel.TLSPolicyCentral:
		return proxymodel.TLSPolicyCentral
	}
	// No explicit policy: honor SSLMode off, otherwise central by default.
	if d.SSLMode == models.SSLModeOff {
		return proxymodel.TLSPolicyOff
	}
	return proxymodel.TLSPolicyCentral
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

// GenerateRoute produces a Caddy JSON route configuration from a backend-neutral
// proxymodel.Route. The returned json.RawMessage is ready to be sent to the
// Caddy admin API.
func GenerateRoute(route proxymodel.Route) (json.RawMessage, error) {
	// Manual override: return the raw Caddy JSON directly. The escape hatch is
	// honored only when tagged for the caddy backend (a payload tagged for
	// nginx/apache is not ours to emit).
	if route.IsRaw() {
		if route.Raw.Backend != backendCaddy {
			return nil, fmt.Errorf("raw config targets backend %q, not %q", route.Raw.Backend, backendCaddy)
		}
		// Validate that it is well-formed JSON.
		var raw json.RawMessage
		if err := json.Unmarshal([]byte(route.Raw.Content), &raw); err != nil {
			return nil, fmt.Errorf("invalid raw Caddy JSON: %w", err)
		}
		return raw, nil
	}

	if route.Host == "" {
		return nil, fmt.Errorf("host is required")
	}
	if route.Upstream.Addr == "" {
		return nil, fmt.Errorf("upstream address is required")
	}
	if route.Upstream.Port == 0 {
		return nil, fmt.Errorf("upstream port is required")
	}

	// Build the inner handlers for the main route (the request pipeline that
	// runs once access-control guards have passed).
	var innerHandlers []interface{}

	// Path manipulation (rewrite handler) runs first so downstream handlers and
	// the upstream see the modified path.
	if route.Path.StripPrefix != "" {
		innerHandlers = append(innerHandlers, map[string]interface{}{
			"handler":           "rewrite",
			"strip_path_prefix": route.Path.StripPrefix,
		})
	}
	if route.Path.Rewrite != "" {
		innerHandlers = append(innerHandlers, map[string]interface{}{
			"handler": "rewrite",
			"uri":     route.Path.Rewrite,
		})
	}

	// HTTP basic authentication.
	if route.BasicAuth != nil && route.BasicAuth.Username != "" && route.BasicAuth.PasswordHash != "" {
		innerHandlers = append(innerHandlers, map[string]interface{}{
			"handler": "authentication",
			"providers": map[string]interface{}{
				"http_basic": map[string]interface{}{
					"hash": map[string]interface{}{"algorithm": "bcrypt"},
					"accounts": []map[string]interface{}{
						{
							"username": route.BasicAuth.Username,
							// Caddy expects the hashed password base64-encoded.
							"password": base64.StdEncoding.EncodeToString([]byte(route.BasicAuth.PasswordHash)),
						},
					},
				},
			},
		})
	}

	// Rate limiting (requires the caddy-ratelimit module).
	if route.RateLimit.RequestsPerSecond > 0 {
		innerHandlers = append(innerHandlers, map[string]interface{}{
			"handler": "rate_limit",
			"rate_limits": map[string]interface{}{
				"default": map[string]interface{}{
					"key":        "{http.request.remote.host}",
					"window":     "1s",
					"max_events": int(route.RateLimit.RequestsPerSecond),
				},
			},
		})
	}

	// Body size limit handler (before reverse_proxy).
	if route.MaxBodySize != "" && route.MaxBodySize != "unlimited" {
		innerHandlers = append(innerHandlers, Handler{
			Handler: "request_body",
			MaxSize: route.MaxBodySize,
		})
	}

	// Build reverse_proxy handler.
	rp := ReverseProxy{
		Handler: "reverse_proxy",
		Upstreams: []Upstream{
			{Dial: fmt.Sprintf("%s:%d", route.Upstream.Addr, route.Upstream.Port)},
		},
	}

	// Default forwarding headers.
	requestHeaders := map[string][]string{
		"X-Forwarded-Proto": {"{http.request.scheme}"},
		"X-Real-IP":         {"{http.request.remote.host}"},
	}

	// Merge custom request headers.
	for k, v := range route.RequestHeaders {
		requestHeaders[k] = []string{v}
	}

	rp.Headers = &HeaderOps{
		Request: &HeaderMod{Set: requestHeaders},
	}

	// Custom response headers.
	if len(route.ResponseHeaders) > 0 {
		respHeaders := make(map[string][]string, len(route.ResponseHeaders))
		for k, v := range route.ResponseHeaders {
			respHeaders[k] = []string{v}
		}
		rp.Headers.Response = &HeaderMod{Set: respHeaders}
	}

	// WebSocket support.
	if route.WebSocket {
		rp.FlushInterval = -1
	}

	// Upstream transport: needed when talking HTTPS to the backend or when any
	// upstream timeout is configured.
	httpsUpstream := route.EffectiveScheme() == proxymodel.SchemeHTTPS
	if httpsUpstream || route.Timeouts.Read > 0 || route.Timeouts.Write > 0 || route.Timeouts.Idle > 0 {
		t := &Transport{Protocol: "http"}
		if httpsUpstream {
			t.TLS = &TLS{}
		}
		// Map our read/write/idle timeouts onto the closest valid Caddy http
		// transport fields.
		if route.Timeouts.Write > 0 {
			t.DialTimeout = fmt.Sprintf("%ds", route.Timeouts.Write)
		}
		if route.Timeouts.Read > 0 {
			t.ResponseHeaderTimeout = fmt.Sprintf("%ds", route.Timeouts.Read)
		}
		if route.Timeouts.Idle > 0 {
			t.KeepAlive = &KeepAlive{IdleTimeout: fmt.Sprintf("%ds", route.Timeouts.Idle)}
		}
		rp.Transport = t
	}

	innerHandlers = append(innerHandlers, rp)

	// Build the subroute's inner routes. IP allow/block guards run first as
	// terminal routes so blocked clients never reach the proxy.
	var innerRoutes []Route
	if len(route.IPBlocklist) > 0 {
		innerRoutes = append(innerRoutes, Route{
			Match:    []map[string]interface{}{{"remote_ip": map[string]interface{}{"ranges": route.IPBlocklist}}},
			Handle:   []interface{}{forbiddenResponse()},
			Terminal: true,
		})
	}
	if len(route.IPAllowlist) > 0 {
		// Deny everything that is NOT in the allowlist.
		innerRoutes = append(innerRoutes, Route{
			Match: []map[string]interface{}{{
				"not": []map[string]interface{}{
					{"remote_ip": map[string]interface{}{"ranges": route.IPAllowlist}},
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
	if route.ForceHTTPS {
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

	caddyRoute := CaddyRoute{
		ID:       "domain-" + slugify(route.Host),
		Match:    []Match{{Host: []string{route.Host}}},
		Handle:   topHandlers,
		Terminal: true,
	}

	data, err := json.Marshal(caddyRoute)
	if err != nil {
		return nil, fmt.Errorf("marshaling route: %w", err)
	}
	return json.RawMessage(data), nil
}

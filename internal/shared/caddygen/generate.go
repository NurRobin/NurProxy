package caddygen

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
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
	RawCaddy              string // if set, use this instead of generating
}

var slugRe = regexp.MustCompile(`[^a-zA-Z0-9-]`)

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

	// Build the inner handlers for the subroute.
	var innerHandlers []interface{}

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

	// HTTPS upstream transport.
	if cfg.UpstreamScheme == "https" {
		rp.Transport = &Transport{
			Protocol: "http",
			TLS:      &TLS{},
		}
	}

	innerHandlers = append(innerHandlers, rp)

	// Build the subroute.
	subroute := Handler{
		Handler: "subroute",
		Routes: []Route{
			{Handle: innerHandlers},
		},
	}

	// Build top-level handlers.
	var topHandlers []Handler

	// ForceHTTPS: add a static_response redirect for non-TLS requests as the
	// first top-level handler. Caddy's automatic HTTPS handles most cases, but
	// an explicit redirect makes the intent clear in the config.
	if cfg.ForceHTTPS {
		topHandlers = append(topHandlers, Handler{
			Handler: "subroute",
			Routes: []Route{
				{
					Handle: []interface{}{
						StaticResponse{
							Handler:    "static_response",
							StatusCode: "302",
							Headers: map[string][]string{
								"Location": {"https://{http.request.host}{http.request.uri}"},
							},
						},
					},
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

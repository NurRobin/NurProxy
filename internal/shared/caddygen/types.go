package caddygen

// CaddyRoute represents a top-level Caddy route with an ID for the admin API.
type CaddyRoute struct {
	ID       string    `json:"@id"`
	Match    []Match   `json:"match"`
	Handle   []Handler `json:"handle"`
	Terminal bool      `json:"terminal"`
}

// Match describes which requests a route applies to.
type Match struct {
	Host []string `json:"host"`
}

// Handler is a Caddy handler such as "subroute" or "request_body".
type Handler struct {
	Handler string  `json:"handler"`
	Routes  []Route `json:"routes,omitempty"`
	// For request_body handler
	MaxSize string `json:"max_size,omitempty"`
}

// Route is an inner route inside a subroute handler. Match and Terminal are
// optional and used for guard routes (e.g. IP allow/block lists).
type Route struct {
	Match    []map[string]interface{} `json:"match,omitempty"`
	Handle   []interface{}            `json:"handle"`
	Terminal bool                     `json:"terminal,omitempty"`
}

// ReverseProxy configures Caddy's reverse_proxy handler.
type ReverseProxy struct {
	Handler       string     `json:"handler"`
	Upstreams     []Upstream `json:"upstreams"`
	FlushInterval int        `json:"flush_interval,omitempty"`
	Headers       *HeaderOps `json:"headers,omitempty"`
	Transport     *Transport `json:"transport,omitempty"`
}

// Upstream is a single backend address for reverse_proxy.
type Upstream struct {
	Dial string `json:"dial"`
}

// HeaderOps groups request and response header modifications.
type HeaderOps struct {
	Request  *HeaderMod `json:"request,omitempty"`
	Response *HeaderMod `json:"response,omitempty"`
}

// HeaderMod describes header set operations.
type HeaderMod struct {
	Set map[string][]string `json:"set,omitempty"`
}

// Transport configures the upstream transport (e.g. TLS to backend) and its
// timeouts. Caddy parses the duration fields from strings such as "30s".
type Transport struct {
	Protocol              string     `json:"protocol"`
	TLS                   *TLS       `json:"tls,omitempty"`
	DialTimeout           string     `json:"dial_timeout,omitempty"`
	ResponseHeaderTimeout string     `json:"response_header_timeout,omitempty"`
	KeepAlive             *KeepAlive `json:"keep_alive,omitempty"`
}

// KeepAlive configures upstream connection keep-alive behavior.
type KeepAlive struct {
	IdleTimeout string `json:"idle_timeout,omitempty"`
}

// TLS enables TLS on the upstream transport. An empty struct means default settings.
type TLS struct{}

// StaticResponse configures Caddy's static_response handler.
type StaticResponse struct {
	Handler    string              `json:"handler"`
	StatusCode string              `json:"status_code"`
	Headers    map[string][]string `json:"headers,omitempty"`
	Body       string              `json:"body,omitempty"`
}

// Package nginxgen is the pure nginx renderer (§5, §13 phase 5): it turns a
// backend-neutral proxymodel.Route into a native nginx `server { ... }` block.
//
// Like caddygen, it is a pure function — intent in, bytes out — with no host,
// no I/O, and no nginx binary involved, so it is fully table-driven testable
// (§14). The agent's nginx backend calls Render, writes the result to
// sites-available, validates with `nginx -t`, and reloads (§10); none of that
// lives here.
//
// Unsupported options are never fatal. Where the Route carries something nginx
// (as rendered by this package) cannot express, the option is DROPPED and
// reported as a Warning rather than failing the whole render (invariant #4 /
// §8). The caller is responsible for logging + auditing each warning.
package nginxgen

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// backendNginx is the backend tag the nginx renderer recognizes on a raw
// escape-hatch payload (proxymodel.RawConfig.Backend).
const backendNginx = "nginx"

// Input bundles a Route with the host-resolved facts the pure renderer needs
// but that do not belong in the backend-neutral intent: the on-disk cert/key
// paths the agent already installed via InstallCerts (§7), and the htpasswd
// file path for basic auth. The agent fills these from its own layout before
// calling Render; the renderer only references them.
type Input struct {
	// Route is the backend-neutral proxy intent.
	Route proxymodel.Route
	// CertPath is the on-disk leaf+chain PEM path for the central provided-cert
	// path (§7). Required (non-empty) to emit a TLS listener; when empty on a
	// central-TLS route the TLS listener is dropped with a warning.
	CertPath string
	// KeyPath is the on-disk private-key path. Required alongside CertPath.
	KeyPath string
	// AuthFile is the path to the htpasswd file nginx reads for basic auth. The
	// agent writes the bcrypt entry from Route.BasicAuth to this file; the
	// renderer only references it via auth_basic_user_file. When BasicAuth is set
	// but AuthFile is empty, basic auth is dropped with a warning.
	AuthFile string
}

// Warning records a single Route option this renderer could not express in the
// nginx config it produced, so it was dropped (invariant #4 / §8). It is data,
// not a log line: the caller (agent backend) logs + audits it with the right
// context (agent, domain, actor). A non-fatal render can return many warnings.
type Warning struct {
	// Option is a stable identifier for the dropped option, e.g. "rate_limit".
	Option string
	// Reason is a human-readable explanation of why it was dropped.
	Reason string
}

func (w Warning) String() string { return fmt.Sprintf("%s: %s", w.Option, w.Reason) }

// Result is the rendered nginx artifact: the server block plus any http-context
// preamble it depends on, and the warnings for options that were dropped.
type Result struct {
	// HTTPPreamble holds directives that must live in nginx's http {} context,
	// OUTSIDE the server block — currently the limit_req_zone for rate limiting
	// (limit_req_zone is only valid at http scope). It is empty when the route
	// needs none. The agent places it in a shared http-context include.
	HTTPPreamble string
	// Server is the `server { ... }` block (one, or two when ForceHTTPS adds a
	// redirect server). Always present for a structured route; for a raw route it
	// is the operator's verbatim content.
	Server string
	// Warnings lists options dropped because this nginx renderer cannot express
	// them. Never nil-vs-empty significant; len 0 means a clean render.
	Warnings []Warning
}

// Render produces an nginx server block from a proxymodel.Route (§5). It is a
// pure function: deterministic, no I/O, order-stable output.
//
// A raw escape-hatch route tagged for nginx is returned verbatim (the operator
// owns it; nginx -t validates it later). A raw route tagged for another backend
// is an error — it is not ours to emit.
//
// Structured routes render the supported options (reverse proxy, websocket,
// force-https, custom req/resp headers, path strip/rewrite, basic auth, IP
// allow/block, rate limit, max body size, upstream scheme + timeouts, provided
// certs). Options nginx-as-rendered-here cannot express are dropped and
// reported in Result.Warnings — never an error (invariant #4).
func Render(in Input) (Result, error) {
	route := in.Route

	if route.IsRaw() {
		if route.Raw.Backend != backendNginx {
			return Result{}, fmt.Errorf("raw config targets backend %q, not %q", route.Raw.Backend, backendNginx)
		}
		return Result{Server: route.Raw.Content}, nil
	}

	if route.Host == "" {
		return Result{}, fmt.Errorf("host is required")
	}
	if route.Upstream.Addr == "" {
		return Result{}, fmt.Errorf("upstream address is required")
	}
	if route.Upstream.Port <= 0 || route.Upstream.Port > 65535 {
		return Result{}, fmt.Errorf("upstream port %d out of range (1-65535)", route.Upstream.Port)
	}

	var warnings []Warning
	warn := func(option, reason string) {
		warnings = append(warnings, Warning{Option: option, Reason: reason})
	}

	// Resolve TLS up front: it drives the listen directives and whether a
	// force-https redirect server is even meaningful.
	tlsEnabled, preamble := resolveTLS(in, warn)

	var preambleSb strings.Builder

	// limit_req zone lives in http context, keyed per route by host.
	zoneName := ""
	if route.RateLimit.RequestsPerSecond > 0 {
		zoneName = "nurproxy_" + slugify(route.Host)
		// nginx rate is an integer requests/second (r/s) or r/m; we use r/s and
		// floor sub-1 rates to r/m to avoid losing a fractional limit silently.
		rate := formatRate(route.RateLimit.RequestsPerSecond)
		fmt.Fprintf(&preambleSb, "limit_req_zone $binary_remote_addr zone=%s:10m rate=%s;\n", zoneName, rate)
	}

	var b strings.Builder

	// ForceHTTPS: a dedicated server that 301-redirects all :80 traffic to https.
	// Only meaningful when TLS is actually enabled; otherwise dropped with a
	// warning (redirecting to a non-existent https listener would break the site).
	if route.ForceHTTPS {
		if tlsEnabled {
			fmt.Fprintf(&b, "server {\n")
			fmt.Fprintf(&b, "    listen 80;\n")
			fmt.Fprintf(&b, "    listen [::]:80;\n")
			fmt.Fprintf(&b, "    server_name %s;\n", route.Host)
			fmt.Fprintf(&b, "    return 301 https://$host$request_uri;\n")
			fmt.Fprintf(&b, "}\n\n")
		} else {
			warn("force_https", "no TLS certificate available for this route; HTTP→HTTPS redirect dropped")
		}
	}

	// Main server block.
	fmt.Fprintf(&b, "server {\n")
	if tlsEnabled {
		fmt.Fprintf(&b, "    listen 443 ssl;\n")
		fmt.Fprintf(&b, "    listen [::]:443 ssl;\n")
		fmt.Fprintf(&b, "    http2 on;\n")
	} else {
		fmt.Fprintf(&b, "    listen 80;\n")
		fmt.Fprintf(&b, "    listen [::]:80;\n")
	}
	fmt.Fprintf(&b, "    server_name %s;\n", route.Host)

	if tlsEnabled {
		fmt.Fprintf(&b, "\n")
		fmt.Fprintf(&b, "    ssl_certificate %s;\n", in.CertPath)
		fmt.Fprintf(&b, "    ssl_certificate_key %s;\n", in.KeyPath)
	}

	// Max body size.
	if size := normalizeBodySize(route.MaxBodySize); size != "" {
		fmt.Fprintf(&b, "\n    client_max_body_size %s;\n", size)
	}

	// IP allow/block. nginx evaluates allow/deny top-to-bottom, first match wins.
	// Blocklist denies come first (explicit deny), then the allowlist (allow the
	// listed ranges, deny everyone else). Mirrors the caddy renderer's ordering.
	if len(route.IPBlocklist) > 0 || len(route.IPAllowlist) > 0 {
		b.WriteString("\n")
		for _, cidr := range route.IPBlocklist {
			fmt.Fprintf(&b, "    deny %s;\n", cidr)
		}
		if len(route.IPAllowlist) > 0 {
			for _, cidr := range route.IPAllowlist {
				fmt.Fprintf(&b, "    allow %s;\n", cidr)
			}
			fmt.Fprintf(&b, "    deny all;\n")
		}
	}

	// Basic auth references an htpasswd file the agent maintains.
	if route.BasicAuth != nil {
		if in.AuthFile != "" {
			fmt.Fprintf(&b, "\n    auth_basic \"%s\";\n", basicAuthRealm(route.Host))
			fmt.Fprintf(&b, "    auth_basic_user_file %s;\n", in.AuthFile)
		} else {
			warn("basic_auth", "no htpasswd file path provided; basic auth dropped")
		}
	}

	// Rate limit (limit_req referencing the http-context zone above).
	if route.RateLimit.RequestsPerSecond > 0 {
		fmt.Fprintf(&b, "\n    limit_req zone=%s burst=%d nodelay;\n", zoneName, rateBurst(route.RateLimit.RequestsPerSecond))
	}

	// Response headers are set with add_header at server scope so they apply to
	// proxied responses too (always_add via the "always" flag).
	if len(route.ResponseHeaders) > 0 {
		b.WriteString("\n")
		for _, k := range sortedKeys(route.ResponseHeaders) {
			fmt.Fprintf(&b, "    add_header %s %s always;\n", k, quoteHeaderValue(route.ResponseHeaders[k]))
		}
	}

	// The location block: path rules + reverse proxy + websocket + forwarded
	// headers + custom request headers + timeouts.
	b.WriteString("\n    location / {\n")

	// Path strip: nginx strips a prefix by including a trailing slash on both the
	// location and the proxy_pass URI. We approximate StripPrefix by rewriting the
	// URI before proxy_pass so the upstream sees the path without the prefix.
	if route.Path.StripPrefix != "" {
		prefix := "/" + strings.Trim(route.Path.StripPrefix, "/")
		fmt.Fprintf(&b, "        rewrite ^%s/?(.*)$ /$1 break;\n", regexpEscape(prefix))
	}
	if route.Path.Rewrite != "" {
		fmt.Fprintf(&b, "        rewrite ^.*$ %s break;\n", route.Path.Rewrite)
	}

	scheme := "http"
	if route.EffectiveScheme() == proxymodel.SchemeHTTPS {
		scheme = "https"
	}
	fmt.Fprintf(&b, "        proxy_pass %s://%s:%d;\n", scheme, route.Upstream.Addr, route.Upstream.Port)

	// Standard forwarding headers (mirrors caddy's defaults).
	fmt.Fprintf(&b, "        proxy_set_header Host $host;\n")
	fmt.Fprintf(&b, "        proxy_set_header X-Real-IP $remote_addr;\n")
	fmt.Fprintf(&b, "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
	fmt.Fprintf(&b, "        proxy_set_header X-Forwarded-Proto $scheme;\n")

	// WebSocket / connection upgrade passthrough.
	if route.WebSocket {
		fmt.Fprintf(&b, "        proxy_http_version 1.1;\n")
		fmt.Fprintf(&b, "        proxy_set_header Upgrade $http_upgrade;\n")
		fmt.Fprintf(&b, "        proxy_set_header Connection \"upgrade\";\n")
	}

	// Custom request headers (deterministic order).
	for _, k := range sortedKeys(route.RequestHeaders) {
		fmt.Fprintf(&b, "        proxy_set_header %s %s;\n", k, quoteHeaderValue(route.RequestHeaders[k]))
	}

	// Upstream timeouts. Map our read/write/idle intent onto nginx's proxy
	// timeout directives (seconds).
	if route.Timeouts.Write > 0 {
		fmt.Fprintf(&b, "        proxy_connect_timeout %ds;\n", route.Timeouts.Write)
		fmt.Fprintf(&b, "        proxy_send_timeout %ds;\n", route.Timeouts.Write)
	}
	if route.Timeouts.Read > 0 {
		fmt.Fprintf(&b, "        proxy_read_timeout %ds;\n", route.Timeouts.Read)
	}

	b.WriteString("    }\n")
	b.WriteString("}\n")

	return Result{
		HTTPPreamble: preambleSb.String() + preamble,
		Server:       b.String(),
		Warnings:     warnings,
	}, nil
}

// resolveTLS decides whether the main server gets a TLS listener and returns any
// extra http-context preamble the TLS policy needs. The central provided-cert
// path needs both cert+key paths; self-acme and off do not apply to nginx here.
func resolveTLS(in Input, warn func(option, reason string)) (tlsEnabled bool, preamble string) {
	switch in.Route.TLS.Policy {
	case proxymodel.TLSPolicyOff:
		return false, ""
	case proxymodel.TLSPolicySelfACME:
		// Self-ACME is a Caddy-only fallback (§7); nginx never does its own ACME in
		// this design. Drop to plaintext with a warning rather than emit a broken
		// TLS listener.
		warn("tls", "self-acme is not supported by the nginx backend; route served over plaintext HTTP")
		return false, ""
	default:
		// Central provided certs (the default). Need both files on disk.
		if in.CertPath == "" || in.KeyPath == "" {
			warn("tls", "no provided certificate available; route served over plaintext HTTP")
			return false, ""
		}
		if in.Route.TLS.Wildcard {
			// Not a drop — just surface the shared-key caveat (§7) so it is audited.
			warn("tls_wildcard", "wildcard certificate shares one private key across hosts (§7)")
		}
		return true, ""
	}
}

// formatRate renders a per-second request rate into an nginx limit_req_zone rate
// token. nginx only accepts integer r/s or r/m, so a sub-1 r/s rate is expressed
// in requests-per-minute to avoid rounding it down to zero.
func formatRate(rps float64) string {
	if rps >= 1 {
		return strconv.Itoa(int(rps)) + "r/s"
	}
	perMin := int(rps * 60)
	if perMin < 1 {
		perMin = 1
	}
	return strconv.Itoa(perMin) + "r/m"
}

// rateBurst derives a burst allowance from the sustained rate. A burst equal to
// the per-second rate (min 1) smooths brief spikes without changing the steady
// state, matching common nginx practice.
func rateBurst(rps float64) int {
	b := int(rps)
	if b < 1 {
		b = 1
	}
	return b
}

// normalizeBodySize maps the intent's human-readable size onto nginx's
// client_max_body_size token. nginx uses suffixes k/m/g (no "B"); "unlimited"
// maps to "0" (nginx's "no limit"). Empty stays empty (directive omitted).
func normalizeBodySize(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.EqualFold(s, "unlimited") {
		return "0"
	}
	lower := strings.ToLower(s)
	lower = strings.TrimSuffix(lower, "b")
	// nginx accepts k/m/g; collapse any whitespace.
	return strings.ReplaceAll(lower, " ", "")
}

// basicAuthRealm builds the WWW-Authenticate realm string for a host.
func basicAuthRealm(host string) string { return "Restricted: " + host }

// quoteHeaderValue wraps a header value in double quotes when it contains
// whitespace or a semicolon, which nginx would otherwise mis-tokenize. Embedded
// double quotes are backslash-escaped.
func quoteHeaderValue(v string) string {
	if v == "" {
		return `""`
	}
	if strings.ContainsAny(v, " \t;\"") {
		return `"` + strings.ReplaceAll(v, `"`, `\"`) + `"`
	}
	return v
}

// regexpEscape escapes the regex metacharacters that can appear in a URL path
// prefix so a literal prefix is matched literally in an nginx rewrite.
func regexpEscape(s string) string {
	const special = `.+*?()|[]{}^$\`
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(special, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// sortedKeys returns the map keys in deterministic (sorted) order so rendered
// output is byte-stable across runs.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// slugify converts an FQDN into a safe nginx identifier (zone names allow
// letters, digits, and underscores) by replacing every other character with an
// underscore and collapsing repeats.
func slugify(host string) string {
	var b strings.Builder
	prevUnderscore := false
	for _, r := range strings.ToLower(host) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevUnderscore = false
			continue
		}
		if !prevUnderscore {
			b.WriteByte('_')
			prevUnderscore = true
		}
	}
	return strings.Trim(b.String(), "_")
}

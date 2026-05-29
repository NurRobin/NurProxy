// Package apachegen is the pure Apache (httpd) renderer (§5, §13 phase 6): it
// turns a backend-neutral proxymodel.Route into a native Apache
// `<VirtualHost>` block built on mod_proxy.
//
// Like caddygen and nginxgen, it is a pure function — intent in, bytes out —
// with no host, no I/O, and no apache binary involved, so it is fully
// table-driven testable (§14). The agent's apache backend calls Render, writes
// the result into sites-available (Debian) or conf.d (RHEL), validates with
// `apachectl configtest`, and reloads (§10); none of that lives here.
//
// Unsupported options are never fatal. Where the Route carries something Apache
// (as rendered by this package) cannot express — notably per-client rate
// limiting, which core httpd has no equivalent for — the option is DROPPED and
// reported as a Warning rather than failing the whole render (invariant #4 /
// §8). The caller is responsible for logging + auditing each warning.
package apachegen

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// backendApache is the backend tag the apache renderer recognizes on a raw
// escape-hatch payload (proxymodel.RawConfig.Backend).
const backendApache = "apache"

// Input bundles a Route with the host-resolved facts the pure renderer needs
// but that do not belong in the backend-neutral intent: the on-disk cert/key
// paths the agent already installed via InstallCerts (§7), and the htpasswd
// file path for basic auth. The agent fills these from its own layout before
// calling Render; the renderer only references them.
type Input struct {
	// Route is the backend-neutral proxy intent.
	Route proxymodel.Route
	// CertPath is the on-disk leaf+chain PEM path for the central provided-cert
	// path (§7). Required (non-empty) to emit a TLS VirtualHost; when empty on a
	// central-TLS route the TLS listener is dropped with a warning.
	CertPath string
	// KeyPath is the on-disk private-key path. Required alongside CertPath.
	KeyPath string
	// AuthFile is the path to the htpasswd file Apache reads for basic auth. The
	// agent writes the bcrypt entry from Route.BasicAuth to this file; the
	// renderer only references it via AuthUserFile. When BasicAuth is set but
	// AuthFile is empty, basic auth is dropped with a warning.
	AuthFile string
}

// Warning records a single Route option this renderer could not express in the
// Apache config it produced, so it was dropped (invariant #4 / §8). It is data,
// not a log line: the caller (agent backend) logs + audits it with the right
// context (agent, domain, actor). A non-fatal render can return many warnings.
type Warning struct {
	// Option is a stable identifier for the dropped option, e.g. "rate_limit".
	Option string
	// Reason is a human-readable explanation of why it was dropped.
	Reason string
}

func (w Warning) String() string { return fmt.Sprintf("%s: %s", w.Option, w.Reason) }

// Result is the rendered Apache artifact: the VirtualHost block(s) plus any
// global-context preamble it depends on, and the warnings for dropped options.
type Result struct {
	// Preamble holds directives that must live in the server (global) context,
	// OUTSIDE the VirtualHost — currently the LoadModule hints are NOT emitted
	// (the operator's httpd already loads its modules); this is reserved for any
	// future global directive a route needs. It is empty for every current route.
	Preamble string
	// VHost is the `<VirtualHost>` block (one, or two when ForceHTTPS adds a
	// :80 redirect host). Always present for a structured route; for a raw route
	// it is the operator's verbatim content.
	VHost string
	// Warnings lists options dropped because this apache renderer cannot express
	// them. len 0 means a clean render.
	Warnings []Warning
}

// Render produces an Apache VirtualHost block from a proxymodel.Route (§5). It
// is a pure function: deterministic, no I/O, order-stable output.
//
// A raw escape-hatch route tagged for apache is returned verbatim (the operator
// owns it; apachectl configtest validates it later). A raw route tagged for
// another backend is an error — it is not ours to emit.
//
// Structured routes render the supported options (reverse proxy, websocket,
// force-https, custom req/resp headers, path strip/rewrite, basic auth, IP
// allow/block, max body size, upstream scheme + timeouts, provided certs).
// Options Apache-as-rendered-here cannot express (per-client rate limiting) are
// dropped and reported in Result.Warnings — never an error (invariant #4).
func Render(in Input) (Result, error) {
	route := in.Route

	if route.IsRaw() {
		if route.Raw.Backend != backendApache {
			return Result{}, fmt.Errorf("raw config targets backend %q, not %q", route.Raw.Backend, backendApache)
		}
		return Result{VHost: route.Raw.Content}, nil
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

	// Resolve TLS up front: it drives the listen port and whether a force-https
	// redirect host is even meaningful.
	tlsEnabled := resolveTLS(in, warn)

	// Apache core has no per-client rate limiting (mod_ratelimit only throttles
	// bandwidth, not request rate); drop it with a warning rather than emit a
	// directive that does not exist (invariant #4 / §8).
	if route.RateLimit.RequestsPerSecond > 0 {
		warn("rate_limit", "Apache core has no per-client request rate limiting; option dropped")
	}

	var b strings.Builder

	// ForceHTTPS: a dedicated :80 VirtualHost that redirects all traffic to
	// https. Only meaningful when TLS is actually enabled; otherwise dropped with
	// a warning (redirecting to a non-existent https listener would break the
	// site).
	if route.ForceHTTPS {
		if tlsEnabled {
			fmt.Fprintf(&b, "<VirtualHost *:80>\n")
			fmt.Fprintf(&b, "    ServerName %s\n", route.Host)
			fmt.Fprintf(&b, "    Redirect permanent / https://%s/\n", route.Host)
			fmt.Fprintf(&b, "</VirtualHost>\n\n")
		} else {
			warn("force_https", "no TLS certificate available for this route; HTTP→HTTPS redirect dropped")
		}
	}

	// Main VirtualHost.
	port := "80"
	if tlsEnabled {
		port = "443"
	}
	fmt.Fprintf(&b, "<VirtualHost *:%s>\n", port)
	fmt.Fprintf(&b, "    ServerName %s\n", route.Host)

	if tlsEnabled {
		fmt.Fprintf(&b, "\n")
		fmt.Fprintf(&b, "    SSLEngine on\n")
		fmt.Fprintf(&b, "    SSLCertificateFile %s\n", in.CertPath)
		fmt.Fprintf(&b, "    SSLCertificateKeyFile %s\n", in.KeyPath)
	}

	// Max body size (Apache uses bytes for LimitRequestBody; "0" = unlimited).
	if size := normalizeBodySize(route.MaxBodySize, warn); size != "" {
		fmt.Fprintf(&b, "\n    LimitRequestBody %s\n", size)
	}

	// IP allow/block. Apache 2.4 uses mod_authz_host's Require directives inside a
	// <RequireAll> so a blocklist (Require not ip) and an allowlist (Require ip)
	// compose. With only a blocklist, deny those and allow the rest; with an
	// allowlist, permit only the listed ranges.
	if len(route.IPBlocklist) > 0 || len(route.IPAllowlist) > 0 {
		b.WriteString("\n    <RequireAll>\n")
		if len(route.IPAllowlist) > 0 {
			fmt.Fprintf(&b, "        Require ip %s\n", strings.Join(route.IPAllowlist, " "))
		} else {
			// No allowlist: everyone is allowed except the blocked ranges below.
			b.WriteString("        Require all granted\n")
		}
		for _, cidr := range route.IPBlocklist {
			fmt.Fprintf(&b, "        Require not ip %s\n", cidr)
		}
		b.WriteString("    </RequireAll>\n")
	}

	// Basic auth references an htpasswd file the agent maintains. Apache scopes
	// auth to a <Location />; AuthType Basic + AuthUserFile + a Require valid-user
	// inside its own <RequireAll>-free block. When IP rules are present they live
	// at vhost scope above; auth here is independent.
	if route.BasicAuth != nil {
		if in.AuthFile != "" {
			b.WriteString("\n    <Location />\n")
			fmt.Fprintf(&b, "        AuthType Basic\n")
			fmt.Fprintf(&b, "        AuthName %s\n", quoteValue(basicAuthRealm(route.Host)))
			fmt.Fprintf(&b, "        AuthUserFile %s\n", in.AuthFile)
			fmt.Fprintf(&b, "        Require valid-user\n")
			b.WriteString("    </Location>\n")
		} else {
			warn("basic_auth", "no htpasswd file path provided; basic auth dropped")
		}
	}

	// Response headers via mod_headers (always set, even on proxied/error
	// responses, matching nginx's "always").
	if len(route.ResponseHeaders) > 0 {
		b.WriteString("\n")
		for _, k := range sortedKeys(route.ResponseHeaders) {
			fmt.Fprintf(&b, "    Header always set %s %s\n", k, quoteValue(route.ResponseHeaders[k]))
		}
	}

	// Custom request headers via mod_headers (set on the request before it is
	// proxied upstream).
	if len(route.RequestHeaders) > 0 {
		b.WriteString("\n")
		for _, k := range sortedKeys(route.RequestHeaders) {
			fmt.Fprintf(&b, "    RequestHeader set %s %s\n", k, quoteValue(route.RequestHeaders[k]))
		}
	}

	// Standard forwarding headers. Apache's mod_proxy_http sets X-Forwarded-For,
	// X-Forwarded-Host and X-Forwarded-Server automatically; we add
	// X-Forwarded-Proto explicitly to mirror nginx/caddy behavior.
	b.WriteString("\n")
	proto := "http"
	if tlsEnabled {
		proto = "https"
	}
	fmt.Fprintf(&b, "    RequestHeader set X-Forwarded-Proto %s\n", proto)

	// Preserve the original Host header to the upstream (mirrors nginx
	// "proxy_set_header Host $host"). Off by default in Apache, so set it on.
	b.WriteString("    ProxyPreserveHost On\n")

	upstreamScheme := "http"
	if route.EffectiveScheme() == proxymodel.SchemeHTTPS {
		upstreamScheme = "https"
	}
	upstreamBase := fmt.Sprintf("%s://%s:%d", upstreamScheme, route.Upstream.Addr, route.Upstream.Port)

	// Path handling. Apache expresses prefix strip / rewrite via mod_rewrite;
	// otherwise a plain ProxyPass at "/" forwards everything.
	switch {
	case route.Path.Rewrite != "":
		// Full URI rewrite then proxy: rewrite to the target path and hand to the
		// upstream via the [P] proxy flag.
		b.WriteString("\n    RewriteEngine On\n")
		fmt.Fprintf(&b, "    RewriteRule ^.*$ %s%s [P]\n", upstreamBase, route.Path.Rewrite)
		fmt.Fprintf(&b, "    ProxyPassReverse / %s/\n", upstreamBase)
	case route.Path.StripPrefix != "":
		// Strip a leading prefix before proxying: rewrite ^/prefix/(.*) to /$1 and
		// proxy that to the upstream root.
		prefix := "/" + strings.Trim(route.Path.StripPrefix, "/")
		b.WriteString("\n    RewriteEngine On\n")
		fmt.Fprintf(&b, "    RewriteRule ^%s/?(.*)$ %s/$1 [P]\n", regexpEscape(prefix), upstreamBase)
		fmt.Fprintf(&b, "    ProxyPassReverse / %s/\n", upstreamBase)
	default:
		b.WriteString("\n")
		// WebSocket: route Upgrade requests to ws(s):// via mod_rewrite + mod_proxy_wstunnel
		// BEFORE the plain ProxyPass, so the upgrade handshake is tunneled.
		if route.WebSocket {
			wsScheme := "ws"
			if upstreamScheme == "https" {
				wsScheme = "wss"
			}
			b.WriteString("    RewriteEngine On\n")
			b.WriteString("    RewriteCond %{HTTP:Upgrade} =websocket [NC]\n")
			fmt.Fprintf(&b, "    RewriteRule ^/?(.*)$ %s://%s:%d/$1 [P,L]\n", wsScheme, route.Upstream.Addr, route.Upstream.Port)
		}
		fmt.Fprintf(&b, "    ProxyPass / %s/", upstreamBase)
		// Upstream timeouts map onto ProxyPass connectiontimeout/timeout key=value
		// worker params (seconds).
		if route.Timeouts.Write > 0 {
			fmt.Fprintf(&b, " connectiontimeout=%d", route.Timeouts.Write)
		}
		if route.Timeouts.Read > 0 {
			fmt.Fprintf(&b, " timeout=%d", route.Timeouts.Read)
		}
		b.WriteString("\n")
		fmt.Fprintf(&b, "    ProxyPassReverse / %s/\n", upstreamBase)
	}

	b.WriteString("</VirtualHost>\n")

	return Result{
		VHost:    b.String(),
		Warnings: warnings,
	}, nil
}

// resolveTLS decides whether the VirtualHost gets a TLS listener (:443 +
// SSLEngine). The central provided-cert path needs both cert+key paths;
// self-acme is a Caddy-only fallback and off means plaintext (§7).
func resolveTLS(in Input, warn func(option, reason string)) (tlsEnabled bool) {
	switch in.Route.TLS.Policy {
	case proxymodel.TLSPolicyOff:
		return false
	case proxymodel.TLSPolicySelfACME:
		// Self-ACME is a Caddy-only fallback (§7); Apache never does its own ACME in
		// this design. Drop to plaintext with a warning rather than emit a broken
		// TLS listener.
		warn("tls", "self-acme is not supported by the apache backend; route served over plaintext HTTP")
		return false
	default:
		// Central provided certs (the default). Need both files on disk.
		if in.CertPath == "" || in.KeyPath == "" {
			warn("tls", "no provided certificate available; route served over plaintext HTTP")
			return false
		}
		if in.Route.TLS.Wildcard {
			// Not a drop — just surface the shared-key caveat (§7) so it is audited.
			warn("tls_wildcard", "wildcard certificate shares one private key across hosts (§7)")
		}
		return true
	}
}

// normalizeBodySize maps the intent's human-readable size onto Apache's
// LimitRequestBody, which takes a byte count (no k/m/g suffixes). "unlimited"
// maps to "0" (Apache's "no limit"). An unparseable size is dropped with a
// warning rather than emitting an invalid directive. Empty stays empty.
func normalizeBodySize(s string, warn func(option, reason string)) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.EqualFold(s, "unlimited") {
		return "0"
	}
	bytes, ok := parseSizeToBytes(s)
	if !ok {
		warn("max_body_size", fmt.Sprintf("could not parse size %q; LimitRequestBody dropped", s))
		return ""
	}
	return strconv.FormatInt(bytes, 10)
}

// parseSizeToBytes converts a human-readable size like "10MB", "512k", "1G", or
// a plain byte count into bytes. It accepts optional k/m/g (decimal, 1000-based
// to match common human intent) with an optional trailing "b". Returns ok=false
// for anything it cannot parse.
func parseSizeToBytes(s string) (int64, bool) {
	lower := strings.ToLower(strings.TrimSpace(s))
	lower = strings.TrimSuffix(lower, "b")
	if lower == "" {
		return 0, false
	}
	mult := int64(1)
	switch lower[len(lower)-1] {
	case 'k':
		mult = 1000
		lower = lower[:len(lower)-1]
	case 'm':
		mult = 1000 * 1000
		lower = lower[:len(lower)-1]
	case 'g':
		mult = 1000 * 1000 * 1000
		lower = lower[:len(lower)-1]
	}
	lower = strings.TrimSpace(lower)
	n, err := strconv.ParseInt(lower, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n * mult, true
}

// basicAuthRealm builds the AuthName realm string for a host.
func basicAuthRealm(host string) string { return "Restricted: " + host }

// quoteValue wraps an Apache directive argument in double quotes when it
// contains whitespace, which Apache would otherwise tokenize into multiple
// arguments. Embedded double quotes are backslash-escaped. An empty value is
// rendered as an explicit empty-string token.
func quoteValue(v string) string {
	if v == "" {
		return `""`
	}
	if strings.ContainsAny(v, " \t\"") {
		return `"` + strings.ReplaceAll(v, `"`, `\"`) + `"`
	}
	return v
}

// regexpEscape escapes the regex metacharacters that can appear in a URL path
// prefix so a literal prefix is matched literally in an Apache RewriteRule.
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

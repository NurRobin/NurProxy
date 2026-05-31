// Package nginxparse is the pure nginx config "mask" parser (§6, §13 phase 6):
// it best-effort parses an nginx config text into the backend-neutral
// proxymodel.Route ("the structured mask"), recognizing the server / reverse-
// proxy / SSL constructs that nginxgen emits and the common shapes operators
// hand-write.
//
// It is the inverse-ish of nginxgen: where nginxgen turns a Route into nginx
// text, nginxparse turns nginx text back into a Route — but it is deliberately
// asymmetric in spirit. The mask is a *view*, never a lossy owner (§6):
//
//   - It NEVER destroys text it does not understand. Every directive it could
//     not map onto a Route field is preserved verbatim in Result.Unparsed, in
//     source order, so a raw-fallback view can still show (and re-save) the
//     operator's exact bytes.
//   - It is best-effort. Result.OK reports whether the parse was *clean* (the
//     mask fully represents the config and a round-trip is safe). When OK is
//     false the caller must keep the raw text as the source of truth and offer
//     the mask read-only / advisory only.
//   - It is a pure function — no host, no I/O, no nginx binary — so it is fully
//     table-driven testable (§14): round-trip (parse∘render ≈ identity for the
//     features the mask supports) and unparseable-preserved.
//
// What it recognizes: one primary `server {}` block (the proxied vhost) plus an
// optional companion `server {}` that only does an HTTP→HTTPS 301 redirect
// (nginxgen's force-https pair). Inside the primary server it maps listen/ssl
// (TLS policy), server_name (Host), client_max_body_size (MaxBodySize),
// allow/deny (IP allow/block), auth_basic* (BasicAuth presence), limit_req
// (RateLimit), add_header (ResponseHeaders), and the location / block's
// proxy_pass (Upstream), proxy_set_header (RequestHeaders + websocket + the
// standard forwarded headers), rewrite (Path), and proxy_*_timeout (Timeouts).
package nginxparse

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// Result is the outcome of parsing an nginx config into the mask.
type Result struct {
	// Route is the structured mask recovered from the config. It is meaningful
	// only when OK is true; when OK is false it holds whatever fields could be
	// recovered (best-effort, advisory) and the caller must treat the raw text as
	// authoritative.
	Route proxymodel.Route
	// OK reports whether the parse was clean: a single recognized proxied server
	// (optionally with its force-https companion) whose every directive mapped
	// onto a Route field, leaving nothing in Unparsed. Only when OK is true is a
	// form⇄raw round-trip lossless for the supported feature set (§6).
	OK bool
	// Unparsed preserves, verbatim and in source order, every construct the
	// parser could not map onto a Route field — extra server blocks, unknown
	// top-level directives, unrecognized directives inside a recognized server,
	// etc. It is NEVER discarded: a raw-fallback view shows it so the operator's
	// bytes are never lost (§6 "text we can't parse is never destroyed").
	Unparsed []string
	// Notes explains, per item, why the parse is not clean (e.g. "unrecognized
	// directive 'gzip on'"). Advisory, for the UI to hint why the mask is
	// read-only. Order matches Unparsed where applicable.
	Notes []string
}

// known forwarded headers nginxgen always emits; recognized so they don't leak
// into RequestHeaders as if the operator set them, and so a clean round-trip is
// possible.
var standardForwardedHeaders = map[string]string{
	"Host":              "$host",
	"X-Real-IP":         "$remote_addr",
	"X-Forwarded-For":   "$proxy_add_x_forwarded_for",
	"X-Forwarded-Proto": "$scheme",
}

// websocket header set nginxgen emits for WebSocket passthrough.
var websocketHeaders = map[string]string{
	"Upgrade":    "$http_upgrade",
	"Connection": "upgrade",
}

// Parse turns nginx config text into the structured mask (§6). It never errors
// and never destroys input: anything it cannot recognize is preserved in
// Result.Unparsed, and Result.OK reports whether the mask is a faithful,
// round-trippable representation.
func Parse(content string) Result {
	res := Result{}

	blocks, leftover := splitTopLevel(content)
	// Any non-server top-level text (stray directives, comments outside blocks,
	// http{} wrappers) is preserved but marks the parse unclean.
	for _, l := range leftover {
		res.Unparsed = append(res.Unparsed, l)
		res.Notes = append(res.Notes, "top-level text outside a server block")
	}

	var servers []block
	for _, b := range blocks {
		if b.kind == "server" {
			servers = append(servers, b)
			continue
		}
		// A non-server block (http, upstream, map, ...) is preserved verbatim.
		res.Unparsed = append(res.Unparsed, b.raw)
		res.Notes = append(res.Notes, fmt.Sprintf("unrecognized %q block", b.kind))
	}

	if len(servers) == 0 {
		// Nothing we model; raw is the only truth.
		res.OK = false
		return res
	}

	// Classify each server: a "redirect" server (only force-https) vs a proxied
	// server (has a location with proxy_pass). The clean shape is exactly one
	// proxied server, optionally with one redirect companion.
	var proxied []block
	var redirects []block
	for _, s := range servers {
		if isRedirectServer(s) {
			redirects = append(redirects, s)
		} else {
			proxied = append(proxied, s)
		}
	}

	if len(proxied) != 1 {
		// Zero or several proxied servers: we can't pick a single mask. Preserve
		// everything raw.
		for _, s := range servers {
			res.Unparsed = append(res.Unparsed, s.raw)
		}
		if len(proxied) == 0 {
			res.Notes = append(res.Notes, "no proxied server block found")
		} else {
			res.Notes = append(res.Notes, fmt.Sprintf("%d proxied server blocks; mask models a single route", len(proxied)))
		}
		res.OK = false
		return res
	}

	clean := parseProxiedServer(proxied[0], &res)

	// A force-https companion is clean only when it is a pure 301 redirect for the
	// same host. More than one redirect server, or one for a different host, is
	// preserved raw.
	if len(redirects) == 1 && redirectMatches(redirects[0], res.Route.Host) {
		res.Route.ForceHTTPS = true
	} else {
		for _, rdr := range redirects {
			res.Unparsed = append(res.Unparsed, rdr.raw)
			res.Notes = append(res.Notes, "redirect server does not match a force-https companion")
			clean = false
		}
	}

	res.OK = clean && len(res.Unparsed) == 0
	return res
}

// parseProxiedServer maps a single proxied server block onto res.Route and
// returns whether every directive in it was recognized (so the mask is clean).
// Unrecognized directives are appended to res.Unparsed, never dropped.
func parseProxiedServer(s block, res *Result) bool {
	clean := true
	r := &res.Route
	tlsEnabled := false

	for _, d := range s.directives {
		switch d.name {
		case "listen":
			// listen 443 ssl / listen [::]:443 ssl / listen 80 — drives TLS policy.
			if strings.Contains(d.args, "ssl") || strings.Contains(d.args, "443") {
				tlsEnabled = true
			}
		case "http2":
			// Companion of the ssl listener; no Route field, but expected — ignore.
		case "server_name":
			r.Host = strings.TrimSpace(d.args)
		case "ssl_certificate", "ssl_certificate_key":
			tlsEnabled = true
		case "client_max_body_size":
			r.MaxBodySize = strings.TrimSpace(d.args)
		case "deny":
			r.IPBlocklist = appendUnlessAll(r.IPBlocklist, strings.TrimSpace(d.args))
		case "allow":
			r.IPAllowlist = append(r.IPAllowlist, strings.TrimSpace(d.args))
		case "auth_basic":
			// Presence of basic auth; we cannot recover the htpasswd contents, so we
			// record a placeholder BasicAuth and mark it advisory.
			if r.BasicAuth == nil {
				r.BasicAuth = &proxymodel.BasicAuth{}
			}
			res.Notes = append(res.Notes, "basic auth detected (credentials live in the htpasswd file, not the config)")
			clean = false
		case "auth_basic_user_file":
			// Companion of auth_basic; handled above.
		case "limit_req":
			// Rate limit references a zone defined in http context (not in this
			// server). We can detect its presence but not the exact rate from here.
			res.Notes = append(res.Notes, "rate limit detected (rate is defined by the limit_req_zone in http context)")
			clean = false
		case "add_header":
			k, v, ok := parseAddHeader(d.args)
			if !ok {
				res.Unparsed = append(res.Unparsed, d.raw)
				clean = false
				continue
			}
			if r.ResponseHeaders == nil {
				r.ResponseHeaders = map[string]string{}
			}
			r.ResponseHeaders[k] = v
		default:
			// Anything else at server scope (return, error_page, gzip, ...) is
			// preserved raw and makes the mask advisory.
			res.Unparsed = append(res.Unparsed, d.raw)
			res.Notes = append(res.Notes, fmt.Sprintf("unrecognized directive %q", d.name))
			clean = false
		}
	}

	r.TLS.Policy = proxymodel.TLSPolicyOff
	if tlsEnabled {
		r.TLS.Policy = proxymodel.TLSPolicyCentral
	}

	// The location / block holds the reverse-proxy intent.
	loc, ok := findRootLocation(s)
	if !ok {
		res.Notes = append(res.Notes, "no `location / {}` block found")
		return false
	}
	if !parseLocation(loc, res) {
		clean = false
	}
	return clean
}

// parseLocation maps the `location / {}` block onto the Route and returns
// whether it was fully recognized.
func parseLocation(loc block, res *Result) bool {
	clean := true
	r := &res.Route

	for _, d := range loc.directives {
		switch d.name {
		case "proxy_pass":
			if !parseProxyPass(strings.TrimSpace(d.args), r) {
				res.Unparsed = append(res.Unparsed, d.raw)
				res.Notes = append(res.Notes, "could not parse proxy_pass target")
				clean = false
			}
		case "proxy_set_header":
			if !parseProxySetHeader(d.args, r) {
				res.Unparsed = append(res.Unparsed, d.raw)
				clean = false
			}
		case "proxy_http_version":
			// Companion of websocket; recognized once Upgrade/Connection are seen.
		case "rewrite":
			if !parseRewrite(d.args, r) {
				res.Unparsed = append(res.Unparsed, d.raw)
				res.Notes = append(res.Notes, "unrecognized rewrite form")
				clean = false
			}
		case "proxy_connect_timeout", "proxy_send_timeout":
			if v, ok := parseSeconds(d.args); ok {
				r.Timeouts.Write = v
			}
		case "proxy_read_timeout":
			if v, ok := parseSeconds(d.args); ok {
				r.Timeouts.Read = v
			}
		default:
			res.Unparsed = append(res.Unparsed, d.raw)
			res.Notes = append(res.Notes, fmt.Sprintf("unrecognized directive %q in location", d.name))
			clean = false
		}
	}

	// Detect websocket: the two upgrade headers plus proxy_http_version 1.1.
	if hasWebSocketHeaders(r.RequestHeaders) {
		r.WebSocket = true
		delete(r.RequestHeaders, "Upgrade")
		delete(r.RequestHeaders, "Connection")
		if len(r.RequestHeaders) == 0 {
			r.RequestHeaders = nil
		}
	}

	if r.Upstream.Addr == "" {
		res.Notes = append(res.Notes, "no proxy_pass upstream found in location")
		clean = false
	}
	return clean
}

var proxyPassRe = regexp.MustCompile(`^(https?)://([^:/\s]+):(\d+)/?$`)

// parseProxyPass maps `proxy_pass http://addr:port;` onto the Upstream. Only the
// simple scheme://host:port form nginxgen emits is recognized; anything fancier
// (variables, upstream{} names, paths) falls back to raw.
func parseProxyPass(arg string, r *proxymodel.Route) bool {
	m := proxyPassRe.FindStringSubmatch(arg)
	if m == nil {
		return false
	}
	port, err := strconv.Atoi(m[3])
	if err != nil || port <= 0 || port > 65535 {
		return false
	}
	r.Upstream.Addr = m[2]
	r.Upstream.Port = port
	if m[1] == "https" {
		r.Upstream.Scheme = proxymodel.SchemeHTTPS
	} else {
		r.Upstream.Scheme = proxymodel.SchemeHTTP
	}
	return true
}

// parseProxySetHeader maps a `proxy_set_header Name Value;` onto either a
// recognized standard/forwarded/websocket header (ignored as boilerplate) or a
// custom RequestHeader. Returns false only if the directive is malformed.
func parseProxySetHeader(args string, r *proxymodel.Route) bool {
	k, v, ok := splitHeaderArgs(args)
	if !ok {
		return false
	}
	// Standard forwarded headers nginxgen always emits: recognized boilerplate.
	if std, isStd := standardForwardedHeaders[k]; isStd && std == v {
		return true
	}
	// Websocket headers: stash so the location pass can flip WebSocket and drop
	// them from the custom set.
	if ws, isWS := websocketHeaders[k]; isWS && (v == ws || v == `"`+ws+`"`) {
		if r.RequestHeaders == nil {
			r.RequestHeaders = map[string]string{}
		}
		r.RequestHeaders[k] = ws
		return true
	}
	if r.RequestHeaders == nil {
		r.RequestHeaders = map[string]string{}
	}
	r.RequestHeaders[k] = v
	return true
}

// hasWebSocketHeaders reports whether the request-header set carries the two
// upgrade headers nginxgen emits for WebSocket.
func hasWebSocketHeaders(h map[string]string) bool {
	return h["Upgrade"] == "$http_upgrade" && h["Connection"] == "upgrade"
}

var rewriteStripRe = regexp.MustCompile(`^\^(.*)/\?\(\.\*\)\$ /\$1 break$`)
var rewriteReplaceRe = regexp.MustCompile(`^\^\.\*\$ (\S+) break$`)

// parseRewrite recognizes the two rewrite forms nginxgen emits: the strip-prefix
// form and the whole-URI replace form. Other rewrites fall back to raw.
func parseRewrite(args string, r *proxymodel.Route) bool {
	args = strings.TrimSpace(args)
	if m := rewriteStripRe.FindStringSubmatch(args); m != nil {
		r.Path.StripPrefix = unescapeRegexp(m[1])
		return true
	}
	if m := rewriteReplaceRe.FindStringSubmatch(args); m != nil {
		r.Path.Rewrite = m[1]
		return true
	}
	return false
}

// parseSeconds parses an nginx time token like "30s" or "30" into seconds.
func parseSeconds(args string) (int, bool) {
	a := strings.TrimSpace(args)
	a = strings.TrimSuffix(a, "s")
	v, err := strconv.Atoi(a)
	if err != nil || v < 0 {
		return 0, false
	}
	return v, true
}

// parseAddHeader splits `add_header Name Value [always];` into name + value,
// dropping the trailing "always" flag nginxgen adds.
func parseAddHeader(args string) (string, string, bool) {
	args = strings.TrimSpace(args)
	args = strings.TrimSuffix(args, " always")
	return splitHeaderArgs(args)
}

// splitHeaderArgs splits "Name value with spaces" into the header name and its
// (possibly quoted) value.
func splitHeaderArgs(args string) (string, string, bool) {
	args = strings.TrimSpace(args)
	idx := strings.IndexAny(args, " \t")
	if idx < 0 {
		return "", "", false
	}
	name := args[:idx]
	value := strings.TrimSpace(args[idx+1:])
	value = unquote(value)
	if name == "" {
		return "", "", false
	}
	return name, value, true
}

// appendUnlessAll appends a CIDR to a list, skipping the "all" pseudo-token nginx
// uses to close an allowlist (it is implied by the allowlist, not a blocklist
// entry).
func appendUnlessAll(list []string, cidr string) []string {
	if cidr == "all" {
		return list
	}
	return append(list, cidr)
}

// unquote strips a single layer of double quotes and unescapes \" inside.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return strings.ReplaceAll(s[1:len(s)-1], `\"`, `"`)
	}
	return s
}

// unescapeRegexp reverses nginxgen.regexpEscape for a literal path prefix.
func unescapeRegexp(s string) string {
	var b strings.Builder
	escaped := false
	for _, r := range s {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

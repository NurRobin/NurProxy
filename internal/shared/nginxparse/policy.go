package nginxparse

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/NurRobin/NurProxy/internal/shared/nginxgen"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// ManagedPolicy names the values an nginx vhost must use verbatim before the
// privileged helper writes it: the route's host and the helper-owned
// certificate, key and htpasswd paths.
type ManagedPolicy struct {
	Host     string
	CertPath string
	KeyPath  string
	AuthPath string
}

// ValidateManaged reports whether a raw nginx config is a bounded single-route
// vhost the helper may write. The checks run on the statements as nginx's own
// tokenizer reads them, and every directive name and argument must match an
// explicit allowlist for its scope; anything else is refused. The error names
// the offending directive and its line, and is safe to show to the operator:
// it quotes directive names only, never argument values.
func ValidateManaged(content string, policy ManagedPolicy) error {
	blocks, directives, err := parsePolicyConfig(content, policy)
	if err != nil {
		return err
	}
	if len(directives) != 0 {
		return fmt.Errorf("line %d: top-level directives are not allowed in a raw nginx config, only server blocks", lineAt(content, directives[0].offset))
	}
	return validateServers(blocks, policyScope{ManagedPolicy: policy, content: content, raw: true})
}

// ValidateRendered reports whether a vhost the helper rendered itself with
// nginxgen stays inside the same allowlists as a raw config, plus the
// generator-only forms: basic auth and a rate limit with its http-context
// limit_req_zone. The helper runs it on every rendered file, so a generator
// bug cannot turn into an arbitrary root-written directive.
func ValidateRendered(content string, policy ManagedPolicy) error {
	blocks, directives, err := parsePolicyConfig(content, policy)
	if err != nil {
		return err
	}
	zone := ""
	for _, d := range directives {
		if d.comment || !plainName(d.tokens[0]) || d.tokens[0].value != "limit_req_zone" || zone != "" {
			return fmt.Errorf("line %d: rendered nginx configuration has unsupported top-level scope", lineAt(content, d.offset))
		}
		if zone = rateLimitZone(d.tokens[1:]); zone == "" {
			return fmt.Errorf("line %d: rendered nginx limit_req_zone has unsupported arguments", lineAt(content, d.offset))
		}
	}
	return validateServers(blocks, policyScope{ManagedPolicy: policy, content: content, zone: zone})
}

// parsePolicyConfig tokenizes content for a policy check and enforces the
// checks shared by raw and rendered configs.
func parsePolicyConfig(content string, policy ManagedPolicy) ([]block, []directive, error) {
	if strings.TrimSpace(policy.Host) == "" || strings.ContainsAny(policy.Host, " \t\r\n;/$") || !plainArgument(policy.Host) {
		return nil, nil, fmt.Errorf("managed nginx policy has no exact host")
	}
	for i := 0; i < len(content); i++ {
		if c := content[i]; (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			return nil, nil, fmt.Errorf("nginx configuration contains control characters")
		}
	}
	blocks, directives, err := parseConfig(content)
	if err != nil {
		return nil, nil, fmt.Errorf("nginx configuration is not valid nginx syntax")
	}
	if longestWordOrComment(content) > MaxWordBytes {
		return nil, nil, fmt.Errorf("nginx configuration has a word or comment longer than %d bytes", MaxWordBytes)
	}
	if len(blocks) == 0 {
		return nil, nil, fmt.Errorf("nginx configuration has no server block")
	}
	if len(blocks) > 2 {
		return nil, nil, fmt.Errorf("line %d: nginx configuration may hold at most two server blocks (the proxied server and its port-80 redirect)", lineAt(content, blocks[2].offset))
	}
	return blocks, directives, nil
}

// validateServers checks every top-level server block.
func validateServers(blocks []block, scope policyScope) error {
	proxied := 0
	for _, server := range blocks {
		if !header(server, "server") {
			return fmt.Errorf("line %d: nginx block %s is not allowed at top level, only server", scope.line(server.offset), blockName(server))
		}
		if len(server.blocks) == 0 {
			if err := validateRedirectServer(server, scope); err != nil {
				return err
			}
			continue
		}
		proxied++
		if err := validateProxiedServer(server, scope); err != nil {
			return err
		}
	}
	if proxied != 1 {
		return fmt.Errorf("nginx configuration must have exactly one proxied server (a server block with location /)")
	}
	return nil
}

// MaxWordBytes bounds every word (including its quotes) and every comment
// (from "#" to the end of the line). nginx's tokenizer reads a word or a
// comment into a 4096-byte buffer and fails `nginx -t` with "too long
// parameter" when one does not fit; the margin keeps admitted configs clear
// of that limit. Lines may be longer.
const MaxWordBytes = 4000

// longestWordOrComment returns the byte length of the longest word source or
// comment in a config that parseConfig accepted.
func longestWordOrComment(content string) int {
	longest := 0
	for i := 0; ; {
		st, err := readStatement(content, i)
		if err != nil {
			return longest
		}
		longest = max(longest, st.longestComment)
		for _, t := range st.tokens {
			longest = max(longest, len(t.source))
		}
		if st.end == endFile {
			return longest
		}
		i = st.next
	}
}

// policyScope is what argument rules may compare against.
type policyScope struct {
	ManagedPolicy
	// content is the checked config, for line numbers in errors.
	content string
	// raw is set for a hand-written config: the generator-only forms (basic
	// auth, which needs the helper-written htpasswd file) are refused.
	raw bool
	// zone is the rate-limit zone declared by a rendered config, or "".
	zone string
}

func (p policyScope) line(offset int) int { return lineAt(p.content, offset) }

// lineAt returns the 1-based line of a source offset.
func lineAt(content string, offset int) int {
	return strings.Count(content[:min(max(offset, 0), len(content))], "\n") + 1
}

// argRule checks a directive's arguments (nginx values, name excluded).
type argRule func(args []token, scope policyScope) bool

// tuningDirectives are the per-request tuning directives allowed both in the
// proxied server block and in its `location / {}`. None of them names a file,
// loads code or takes a variable that could change where nginx reads or
// writes; header values may reference variables, which only change the
// header text.
var tuningDirectives = map[string]argRule{
	"client_max_body_size":    func(a []token, _ policyScope) bool { return plainMatch(a, bodySizeRe) },
	"client_body_buffer_size": func(a []token, _ policyScope) bool { return sizeAtMost(a, maxBufferBytes) },
	"add_header": func(a []token, _ policyScope) bool {
		if len(a) == 3 && !plainOneOf(a[2:], "always") {
			return false
		}
		return (len(a) == 2 || len(a) == 3) && plainMatch(a[:1], headerNameRe) && headerValue(a[1])
	},
	"access_log": accessLogRule,
	"proxy_set_header": func(a []token, _ policyScope) bool {
		return len(a) == 2 && plainMatch(a[:1], headerNameRe) && headerValue(a[1])
	},
	"proxy_hide_header":       func(a []token, _ policyScope) bool { return plainMatch(a, headerNameRe) },
	"proxy_http_version":      func(a []token, _ policyScope) bool { return plainOneOf(a, "1.0", "1.1") },
	"proxy_connect_timeout":   func(a []token, _ policyScope) bool { return plainMatch(a, durationRe) },
	"proxy_send_timeout":      func(a []token, _ policyScope) bool { return plainMatch(a, durationRe) },
	"proxy_read_timeout":      func(a []token, _ policyScope) bool { return plainMatch(a, durationRe) },
	"proxy_buffering":         onOff,
	"proxy_request_buffering": onOff,
	"proxy_buffer_size":       func(a []token, _ policyScope) bool { return sizeAtMost(a, maxBufferBytes) },
	"proxy_busy_buffers_size": func(a []token, _ policyScope) bool { return sizeAtMost(a, maxBufferBytes) },
	"proxy_buffers": func(a []token, _ policyScope) bool {
		return len(a) == 2 && plainMatch(a[:1], countRe) && sizeAtMost(a[1:], maxBufferBytes)
	},
	"proxy_redirect":        func(a []token, _ policyScope) bool { return plainOneOf(a, "off") },
	"proxy_ssl_server_name": onOff,
	"gzip":                  onOff,
	"gzip_vary":             onOff,
	"gzip_comp_level":       func(a []token, _ policyScope) bool { return plainMatch(a, compLevelRe) },
	"gzip_min_length":       func(a []token, _ policyScope) bool { return sizeAtMost(a, 1<<30) },
	"gzip_types": func(a []token, _ policyScope) bool {
		return len(a) >= 1 && len(a) <= 32 && allPlain(a, func(v string) bool { return v == "*" || mimeTypeRe.MatchString(v) })
	},
	"gzip_proxied": func(a []token, _ policyScope) bool {
		return len(a) >= 1 && len(a) <= 9 && allPlain(a, func(v string) bool { return gzipProxiedValues[v] })
	},
}

// proxiedServerOnly are the directives allowed directly in the proxied server
// block but not in its location.
var proxiedServerOnly = map[string]argRule{
	"listen":      func(a []token, _ policyScope) bool { return managedListen(a, false) },
	"http2":       onOff,
	"server_name": func(a []token, p policyScope) bool { return plainExact(a, p.Host) },
	"ssl_certificate": func(a []token, p policyScope) bool {
		return p.CertPath != "" && plainExact(a, p.CertPath)
	},
	"ssl_certificate_key": func(a []token, p policyScope) bool {
		return p.KeyPath != "" && plainExact(a, p.KeyPath)
	},
	// Basic auth needs the htpasswd file the helper writes from the route's
	// structured settings, so a raw config cannot carry it. limit_req needs
	// the zone only a rendered config declares.
	"auth_basic": func(a []token, p policyScope) bool { return !p.raw && len(a) == 1 && headerValue(a[0]) },
	"auth_basic_user_file": func(a []token, p policyScope) bool {
		return !p.raw && p.AuthPath != "" && plainExact(a, p.AuthPath)
	},
	"allow": func(a []token, _ policyScope) bool { return plainMatch(a, addressRe) },
	"deny":  func(a []token, _ policyScope) bool { return plainMatch(a, addressRe) },
	"limit_req": func(a []token, p policyScope) bool {
		return p.zone != "" && len(a) == 3 && plainOneOf(a[:1], "zone="+p.zone) && plainMatch(a[1:2], burstRe) && plainOneOf(a[2:], "nodelay")
	},
	"error_log":     errorLogRule,
	"server_tokens": onOff,
}

// locationOnly are the directives allowed in `location / {}` but not directly
// in the server block.
var locationOnly = map[string]argRule{
	"proxy_pass": func(a []token, _ policyScope) bool { return managedProxyPass(a) },
	"rewrite":    func(a []token, _ policyScope) bool { return managedRewrite(a) },
}

// proxiedServerDirectives are the only directives allowed directly in the
// proxied server block; locationDirectives the only ones in `location / {}`.
var (
	proxiedServerDirectives = mergeRules(tuningDirectives, proxiedServerOnly)
	locationDirectives      = mergeRules(tuningDirectives, locationOnly)
)

func mergeRules(sets ...map[string]argRule) map[string]argRule {
	merged := map[string]argRule{}
	for _, set := range sets {
		for name, rule := range set {
			merged[name] = rule
		}
	}
	return merged
}

func onOff(a []token, _ policyScope) bool { return plainOneOf(a, "on", "off") }

// accessLogRule accepts only `access_log off;`: any other form names a file
// or syslog target nginx's root master process would open.
func accessLogRule(a []token, _ policyScope) bool { return plainOneOf(a, "off") }

// errorLogRule accepts only `error_log /var/log/nginx/error.log <level>;`,
// the form nginxgen renders, so nginx opens no file but the host's stock
// error log.
func errorLogRule(a []token, _ policyScope) bool {
	return len(a) == 2 && plainOneOf(a[:1], nginxgen.DefaultErrorLogPath) && plainOneOf(a[1:], proxymodel.ErrorLogLevels...)
}

// redirectServerDirectives are the only directives allowed in the port-80
// force-https companion server, matching what nginxgen renders there:
// `return 301 https://$host$request_uri;` (or the literal host in place of
// $host) and the route's logging overrides. validateRedirectServer also
// requires exactly one server_name and exactly one return.
var redirectServerDirectives = map[string]argRule{
	"access_log":  accessLogRule,
	"error_log":   errorLogRule,
	"listen":      func(a []token, _ policyScope) bool { return managedListen(a, true) },
	"server_name": func(a []token, p policyScope) bool { return plainExact(a, p.Host) },
	"return": func(a []token, p policyScope) bool {
		return len(a) == 2 && plainOneOf(a[:1], "301") && plainOneOf(a[1:], "https://$host$request_uri", "https://"+p.Host+"$request_uri")
	},
}

var (
	directiveNameRe    = regexp.MustCompile(`^[a-z0-9_]+$`)
	headerNameRe       = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	bodySizeRe         = regexp.MustCompile(`^[0-9]{1,9}[kKmMgG]?$`)
	addressRe          = regexp.MustCompile(`^(all|[0-9A-Fa-f:.]+(/[0-9]{1,3})?)$`)
	sizeRe             = regexp.MustCompile(`^([0-9]{1,9})([kKmM]?)$`)
	countRe            = regexp.MustCompile(`^([2-9]|[1-5][0-9]|6[0-4])$`)
	durationRe         = regexp.MustCompile(`^[0-9]{1,6}(ms|s|m|h)?$`)
	compLevelRe        = regexp.MustCompile(`^[1-9]$`)
	mimeTypeRe         = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]*/[a-z0-9*][a-z0-9.+*-]*$`)
	burstRe            = regexp.MustCompile(`^burst=[0-9]+$`)
	zoneDeclRe         = regexp.MustCompile(`^zone=(nurproxy_[a-z0-9_]+):10m$`)
	rateRe             = regexp.MustCompile(`^rate=[0-9]+r/[sm]$`)
	managedProxyPassRe = regexp.MustCompile(`^https?://([A-Za-z0-9._-]+|\[[0-9A-Fa-f:.]+\]):([0-9]{1,5})/?$`)
)

// maxBufferBytes bounds every per-request buffer size (16m).
const maxBufferBytes = 16 << 20

// parseSize reads an nginx size ("512", "16k", "1M") as bytes.
func parseSize(v string) (int64, bool) {
	m := sizeRe.FindStringSubmatch(v)
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, false
	}
	switch m[2] {
	case "k", "K":
		n <<= 10
	case "m", "M":
		n <<= 20
	}
	return n, true
}

// sizeAtMost accepts one plain size of at most limit bytes.
func sizeAtMost(a []token, limit int64) bool {
	if len(a) != 1 || a[0].quote != 0 || !plainArgument(a[0].source) {
		return false
	}
	n, ok := parseSize(a[0].value)
	return ok && n <= limit
}

// managedRewrite accepts the two rewrite forms nginxgen renders:
// `rewrite ^<escaped prefix>/?(.*)$ /$1 break;` for a stripped prefix and
// `rewrite ^.*$ <uri> break;` for a whole-URI rewrite. The prefix must be a
// literal path in which every regex metacharacter is escaped, so no
// operator-written regex reaches nginx's PCRE.
func managedRewrite(a []token) bool {
	if len(a) != 3 || !rewriteArgument(a[0]) || !rewriteArgument(a[1]) || !plainOneOf(a[2:], "break") {
		return false
	}
	pattern, replacement := a[0].value, a[1].value
	if pattern == "^.*$" {
		return true
	}
	prefix, ok := strings.CutPrefix(pattern, "^")
	if !ok || replacement != "/$1" {
		return false
	}
	prefix, ok = strings.CutSuffix(prefix, "/?(.*)$")
	return ok && literalPathRegexp(prefix)
}

// literalPathRegexp reports whether s is a path starting with "/" in which
// every regex metacharacter is backslash-escaped.
func literalPathRegexp(s string) bool {
	if !strings.HasPrefix(s, "/") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if strings.IndexByte(`.+*?()|[]{}^$`, s[i]) >= 0 {
			return false
		}
	}
	return true
}

// gzipProxiedValues are the gzip_proxied flags nginx knows.
var gzipProxiedValues = map[string]bool{
	"off": true, "expired": true, "no-cache": true, "no-store": true, "private": true,
	"no_last_modified": true, "no_etag": true, "auth": true, "any": true,
}

// managedProxyPass accepts `proxy_pass scheme://host:port[/];` with a port in
// 1..65535: no variables, upstream{} names or unix sockets.
func managedProxyPass(a []token) bool {
	if !plainMatch(a, managedProxyPassRe) {
		return false
	}
	port, err := strconv.Atoi(managedProxyPassRe.FindStringSubmatch(a[0].value)[2])
	return err == nil && port > 0 && port <= 65535
}

// allPlain reports whether every argument is a plain word whose value ok
// accepts.
func allPlain(args []token, ok func(string) bool) bool {
	for _, a := range args {
		if a.quote != 0 || !plainArgument(a.source) || !ok(a.value) {
			return false
		}
	}
	return true
}

// rateLimitZone returns the zone name of a `limit_req_zone` in the form
// nginxgen renders, or "" when the arguments differ from that form.
func rateLimitZone(a []token) string {
	if len(a) != 3 || !plainOneOf(a[:1], "$binary_remote_addr") || !plainMatch(a[2:], rateRe) || !plainMatch(a[1:2], zoneDeclRe) {
		return ""
	}
	return zoneDeclRe.FindStringSubmatch(a[1].value)[1]
}

func validateProxiedServer(server block, scope policyScope) error {
	if err := validateDirectives(server.directives, proxiedServerDirectives, scope, "the server block"); err != nil {
		return err
	}
	if n := countDirectives(server.directives, "server_name"); n != 1 {
		return fmt.Errorf("line %d: the proxied server block needs exactly one server_name %s, found %d", scope.line(server.offset), scope.Host, n)
	}
	if len(server.blocks) > 1+2*proxymodel.MaxPathRoutes {
		return fmt.Errorf("line %d: the server block holds more than %d location blocks", scope.line(server.offset), 1+2*proxymodel.MaxPathRoutes)
	}
	serverBuffers := readProxyBuffers(server.directives)
	if err := serverBuffers.check(); err != nil {
		return fmt.Errorf("line %d: the server block's proxy buffer settings %v", scope.line(server.offset), err)
	}
	root := 0
	seen := map[string]bool{}
	for _, location := range server.blocks {
		match, ok := managedLocation(location)
		if !ok {
			return fmt.Errorf("line %d: nginx block %s is not allowed in the server block, only location /, location = <path> and location <path>/", scope.line(location.offset), blockName(location))
		}
		if seen[match] {
			return fmt.Errorf("line %d: the server block holds location %s twice", scope.line(location.offset), match)
		}
		seen[match] = true
		if match == "/" {
			root++
		}
		where := "location " + match
		if len(location.blocks) != 0 {
			return fmt.Errorf("line %d: nginx block %s is not allowed inside %s", scope.line(location.blocks[0].offset), blockName(location.blocks[0]), where)
		}
		if err := validateDirectives(location.directives, locationDirectives, scope, where); err != nil {
			return err
		}
		if n := countDirectives(location.directives, "proxy_pass"); n != 1 {
			return fmt.Errorf("line %d: %s needs exactly one proxy_pass, found %d", scope.line(location.offset), where, n)
		}
		if err := serverBuffers.inherit(readProxyBuffers(location.directives)).check(); err != nil {
			return fmt.Errorf("line %d: the proxy buffer settings of %s %v", scope.line(location.offset), where, err)
		}
	}
	if root != 1 {
		return fmt.Errorf("line %d: the server block needs exactly one location / block, found %d", scope.line(server.offset), root)
	}
	return nil
}

// managedLocation reports whether a block is one of the location headers
// nginxgen renders and returns its match as one string: `location /`,
// `location = <path>` for an exact path route, and `location <path>/` for a
// prefix path route, with a path proxymodel accepts for that match kind.
func managedLocation(b block) (string, bool) {
	if b.comment || len(b.tokens) < 2 || len(b.tokens) > 3 || !header(b, wordsOf(b)...) || b.tokens[0].value != "location" {
		return "", false
	}
	if len(b.tokens) == 3 {
		path := b.tokens[2].value
		if b.tokens[1].value != "=" || proxymodel.ValidateRoutePath(proxymodel.PathMatchExact, path) != nil {
			return "", false
		}
		return "= " + path, true
	}
	path := b.tokens[1].value
	if path == "/" {
		return path, true
	}
	if !strings.HasSuffix(path, "/") || proxymodel.ValidateRoutePath(proxymodel.PathMatchPrefix, strings.TrimSuffix(path, "/")) != nil {
		return "", false
	}
	return path, true
}

// wordsOf returns a block header's token values, for header() to check that
// each word is plain.
func wordsOf(b block) []string {
	words := make([]string, len(b.tokens))
	for i, t := range b.tokens {
		words[i] = t.value
	}
	return words
}

// proxyBuffers are the proxy buffer directives of one block, 0 when unset.
type proxyBuffers struct {
	bufferSize, busySize, count, size int64
}

// readProxyBuffers reads the buffer directives of a block whose arguments
// validateDirectives already accepted.
func readProxyBuffers(directives []directive) proxyBuffers {
	var b proxyBuffers
	for _, d := range directives {
		switch d.tokens[0].value {
		case "proxy_buffer_size":
			b.bufferSize, _ = parseSize(d.tokens[1].value)
		case "proxy_busy_buffers_size":
			b.busySize, _ = parseSize(d.tokens[1].value)
		case "proxy_buffers":
			b.count, _ = strconv.ParseInt(d.tokens[1].value, 10, 64)
			b.size, _ = parseSize(d.tokens[2].value)
		}
	}
	return b
}

// inherit returns the location's settings with unset values taken from the
// server, the way nginx merges them.
func (server proxyBuffers) inherit(location proxyBuffers) proxyBuffers {
	if location.bufferSize == 0 {
		location.bufferSize = server.bufferSize
	}
	if location.busySize == 0 {
		location.busySize = server.busySize
	}
	if location.count == 0 {
		location.count, location.size = server.count, server.size
	}
	return location
}

// check mirrors the proxy buffer checks nginx runs when it merges a location.
// nginx's defaults depend on the host's page size, so the three directives
// are only accepted together, which makes the outcome the same on every host.
func (b proxyBuffers) check() error {
	if b == (proxyBuffers{}) {
		return nil
	}
	if b.bufferSize == 0 || b.busySize == 0 || b.count == 0 {
		return fmt.Errorf("must set proxy_buffer_size, proxy_buffers and proxy_busy_buffers_size together")
	}
	if b.busySize < max(b.bufferSize, b.size) {
		return fmt.Errorf("need proxy_busy_buffers_size of at least proxy_buffer_size and one proxy_buffers buffer")
	}
	if b.busySize > (b.count-1)*b.size {
		return fmt.Errorf("need proxy_busy_buffers_size of at most the size of all proxy_buffers minus one buffer")
	}
	return nil
}

func validateRedirectServer(server block, scope policyScope) error {
	if err := validateDirectives(server.directives, redirectServerDirectives, scope, "the redirect server block"); err != nil {
		return err
	}
	if countDirectives(server.directives, "server_name") != 1 || countDirectives(server.directives, "return") != 1 {
		return fmt.Errorf("line %d: nginx redirect server needs exactly one server_name and one return", scope.line(server.offset))
	}
	return nil
}

// countDirectives counts the directives with the given name. It runs after
// validateDirectives, so every name is plain.
func countDirectives(directives []directive, name string) int {
	n := 0
	for _, d := range directives {
		if d.tokens[0].value == name {
			n++
		}
	}
	return n
}

// repeatableDirectives are the allowlisted directives nginx accepts more than
// once in the same block. nginx fails `nginx -t` with "is duplicate" for a
// repeated one of any other allowlisted directive.
var repeatableDirectives = map[string]bool{
	"listen": true, "server_name": true, "ssl_certificate": true, "ssl_certificate_key": true,
	"add_header": true, "proxy_set_header": true, "proxy_hide_header": true,
	"allow": true, "deny": true, "access_log": true, "error_log": true, "rewrite": true,
	"gzip_types": true, "gzip_proxied": true,
}

func validateDirectives(directives []directive, allowed map[string]argRule, scope policyScope, where string) error {
	seen := map[string]bool{}
	for _, d := range directives {
		if d.comment || !plainName(d.tokens[0]) {
			return fmt.Errorf("line %d: nginx directive is not in plain form (quoted or escaped name, or a comment inside the statement)", scope.line(d.offset))
		}
		name := d.tokens[0].value
		rule, ok := allowed[name]
		if !ok {
			return fmt.Errorf("line %d: nginx directive %s is not allowed in %s", scope.line(d.offset), quoteName(name), where)
		}
		if !rule(d.tokens[1:], scope) {
			return fmt.Errorf("line %d: nginx directive %s has unsupported arguments in %s", scope.line(d.offset), quoteName(name), where)
		}
		if seen[name] && !repeatableDirectives[name] {
			return fmt.Errorf("line %d: nginx directive %s appears more than once in %s", scope.line(d.offset), quoteName(name), where)
		}
		seen[name] = true
	}
	return nil
}

// maxQuotedName bounds a directive or block name quoted in an error.
const maxQuotedName = 64

// quoteName quotes a plain directive name for an error, shortened to
// maxQuotedName bytes.
func quoteName(name string) string {
	if len(name) > maxQuotedName {
		name = name[:maxQuotedName] + "..."
	}
	return fmt.Sprintf("%q", name)
}

// blockName names a block's kind for an error, or describes it when the kind
// is not a plain name. Like directive errors, it never quotes the block's
// arguments.
func blockName(b block) string {
	if len(b.tokens) == 0 || b.comment || !plainName(b.tokens[0]) {
		return "with a non-plain name"
	}
	return quoteName(b.tokens[0].value)
}

// header reports whether a block's header is exactly the given plain words.
func header(b block, words ...string) bool {
	if b.comment || len(b.tokens) != len(words) || !plainName(b.tokens[0]) {
		return false
	}
	for i, w := range words {
		if !plainArgument(b.tokens[i].source) || b.tokens[i].value != w {
			return false
		}
	}
	return true
}

// plainName reports whether a directive or block name is an unquoted word of
// lowercase letters, digits and underscores.
func plainName(t token) bool {
	return t.quote == 0 && t.source == t.value && directiveNameRe.MatchString(t.value)
}

// plainArgument reports whether an unquoted word's source has no character
// that nginx's tokenizer treats specially anywhere in a word: no quotes, no
// backslash, no comment start, no braces, no separator, no control character.
func plainArgument(source string) bool {
	if source == "" {
		return false
	}
	for i := 0; i < len(source); i++ {
		c := source[i]
		if c <= ' ' || c == 0x7f || strings.IndexByte("\"'\\#{};", c) >= 0 {
			return false
		}
	}
	return true
}

func plainExact(args []token, want string) bool {
	return len(args) == 1 && args[0].quote == 0 && plainArgument(args[0].source) && args[0].value == want
}

func plainOneOf(args []token, options ...string) bool {
	if len(args) != 1 || args[0].quote != 0 || !plainArgument(args[0].source) {
		return false
	}
	for _, o := range options {
		if args[0].value == o {
			return true
		}
	}
	return false
}

func plainMatch(args []token, re *regexp.Regexp) bool {
	return len(args) == 1 && args[0].quote == 0 && plainArgument(args[0].source) && re.MatchString(args[0].value)
}

// headerValue accepts a header value either as a plain word or as one
// double-quoted string whose only escapes are \" and \\ (the form nginxgen
// renders for values with spaces, semicolons, quotes or backslashes).
func headerValue(t token) bool {
	switch t.quote {
	case 0:
		return plainArgument(t.source)
	case '"':
		inner := t.source[1 : len(t.source)-1]
		for i := 0; i < len(inner); i++ {
			c := inner[i]
			if (c < ' ' && c != '\t') || c == 0x7f {
				return false
			}
			if c == '\\' {
				if i+1 >= len(inner) || (inner[i+1] != '"' && inner[i+1] != '\\') {
					return false
				}
				i++
			}
		}
		return true
	default:
		return false
	}
}

// rewriteArgument accepts a rewrite regex or replacement as an unquoted word in
// which a backslash only escapes a regex metacharacter, the form nginxgen's
// regexpEscape produces. nginx keeps those escapes verbatim, so the value
// equals the source. An escaped backslash is refused: nginx would reduce it
// to one backslash before the regex sees it (proxymodel refuses backslashes
// in path rules, so nginxgen never renders one).
func rewriteArgument(t token) bool {
	if t.quote != 0 || t.source != t.value || t.source == "" {
		return false
	}
	s := t.source
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' {
			if i+1 >= len(s) || strings.IndexByte(`.+*?()|[]{}^$`, s[i+1]) < 0 {
				return false
			}
			i++
			continue
		}
		if c <= ' ' || c == 0x7f || strings.IndexByte("\"'#{};", c) >= 0 {
			return false
		}
	}
	return true
}

// managedListen accepts exactly the listeners nginxgen renders. nginx merges
// listen options per address and port across all vhosts, so an option on one
// vhost changes every other vhost on that port: port 80 takes no options and
// port 443 takes `ssl`, plus `http2` for nginx older than 1.25.1. The
// redirect server only listens on port 80.
func managedListen(args []token, redirect bool) bool {
	words := make([]string, 0, len(args))
	for _, a := range args {
		if a.quote != 0 || !plainArgument(a.source) {
			return false
		}
		words = append(words, a.value)
	}
	switch strings.Join(words, " ") {
	case "80", "[::]:80":
		return true
	case "443 ssl", "[::]:443 ssl", "443 ssl http2", "[::]:443 ssl http2":
		return !redirect
	}
	return false
}

// HasErrorLog reports whether a config contains an error_log directive in
// any scope. A config nginx's tokenizer cannot read counts as having one, so
// a caller that guards the directive fails closed.
func HasErrorLog(content string) bool {
	blocks, directives, err := parseConfig(content)
	if err != nil {
		return true
	}
	return directivesHaveErrorLog(directives) || blocksHaveErrorLog(blocks)
}

func blocksHaveErrorLog(blocks []block) bool {
	for _, b := range blocks {
		if directivesHaveErrorLog(b.directives) || blocksHaveErrorLog(b.blocks) {
			return true
		}
	}
	return false
}

func directivesHaveErrorLog(directives []directive) bool {
	for _, d := range directives {
		if len(d.tokens) > 0 && d.tokens[0].value == "error_log" {
			return true
		}
	}
	return false
}

package nginxparse

import (
	"fmt"
	"regexp"
	"strings"
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
// explicit allowlist for its scope; anything else is refused. A raw config
// must also be a clean single-route mask (Parse(content).OK).
func ValidateManaged(content string, policy ManagedPolicy) error {
	blocks, directives, err := parsePolicyConfig(content, policy)
	if err != nil {
		return err
	}
	if len(directives) != 0 {
		return fmt.Errorf("raw nginx configuration has unsupported top-level scope")
	}
	parsed := Parse(content)
	if !parsed.OK || parsed.Route.Host != policy.Host || parsed.Route.Upstream.Addr == "" || parsed.Route.Upstream.Port <= 0 || parsed.Route.Upstream.Port > 65535 {
		return fmt.Errorf("raw nginx configuration is not a clean single-route mask")
	}
	return validateServers(blocks, policy, "")
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
			return fmt.Errorf("rendered nginx configuration has unsupported top-level scope")
		}
		if zone = rateLimitZone(d.tokens[1:]); zone == "" {
			return fmt.Errorf("rendered nginx limit_req_zone has unsupported arguments")
		}
	}
	return validateServers(blocks, policy, zone)
}

// parsePolicyConfig tokenizes content for a policy check and enforces the
// checks shared by raw and rendered configs.
func parsePolicyConfig(content string, policy ManagedPolicy) ([]block, []directive, error) {
	if strings.TrimSpace(policy.Host) == "" || strings.ContainsAny(policy.Host, " \t\r\n;/$") || !plainArgument(policy.Host) {
		return nil, nil, fmt.Errorf("managed nginx policy has no exact host")
	}
	lineStart := 0
	for i := 0; i < len(content); i++ {
		c := content[i]
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			return nil, nil, fmt.Errorf("nginx configuration contains control characters")
		}
		if c == '\n' {
			lineStart = i + 1
		} else if i-lineStart >= maxPolicyLine {
			return nil, nil, fmt.Errorf("nginx configuration has a line longer than %d bytes", maxPolicyLine)
		}
	}
	blocks, directives, err := parseConfig(content)
	if err != nil {
		return nil, nil, fmt.Errorf("nginx configuration is not valid nginx syntax")
	}
	if len(blocks) == 0 || len(blocks) > 2 {
		return nil, nil, fmt.Errorf("nginx configuration has unsupported top-level scope")
	}
	return blocks, directives, nil
}

// validateServers checks every top-level server block. zone is the rate-limit
// zone a rendered config declares, or "" when limit_req is not allowed.
func validateServers(blocks []block, policy ManagedPolicy, zone string) error {
	scope := policyScope{ManagedPolicy: policy, zone: zone}
	proxied := 0
	for _, server := range blocks {
		if !header(server, "server") {
			return fmt.Errorf("nginx configuration has an unsupported block")
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
		return fmt.Errorf("nginx configuration must have exactly one proxied server")
	}
	return nil
}

// maxPolicyLine bounds every line, and with it every word and comment, well
// below the 4096-byte buffer nginx's tokenizer reads a word or comment into;
// a longer one fails `nginx -t` with "too long parameter". Quoted values may
// not span lines (headerValue refuses control characters), so no word is
// longer than its line.
const maxPolicyLine = 2048

// policyScope is what argument rules may compare against.
type policyScope struct {
	ManagedPolicy
	// zone is the rate-limit zone declared by a rendered config, or "".
	zone string
}

// argRule checks a directive's arguments (nginx values, name excluded).
type argRule func(args []token, scope policyScope) bool

// proxiedServerDirectives are the only directives allowed directly in the
// proxied server block.
var proxiedServerDirectives = map[string]argRule{
	"listen":      func(a []token, _ policyScope) bool { return managedListen(a, false) },
	"http2":       func(a []token, _ policyScope) bool { return plainOneOf(a, "on", "off") },
	"server_name": func(a []token, p policyScope) bool { return plainExact(a, p.Host) },
	"ssl_certificate": func(a []token, p policyScope) bool {
		return p.CertPath != "" && plainExact(a, p.CertPath)
	},
	"ssl_certificate_key": func(a []token, p policyScope) bool {
		return p.KeyPath != "" && plainExact(a, p.KeyPath)
	},
	// auth_basic and limit_req only pass in rendered configs: for a raw
	// config Parse() reports them as not clean, so ValidateManaged refuses
	// them before these rules run, and limit_req also needs the zone that
	// only ValidateRendered accepts.
	"auth_basic": func(a []token, _ policyScope) bool { return len(a) == 1 && headerValue(a[0]) },
	"auth_basic_user_file": func(a []token, p policyScope) bool {
		return p.AuthPath != "" && plainExact(a, p.AuthPath)
	},
	"client_max_body_size": func(a []token, _ policyScope) bool { return plainMatch(a, bodySizeRe) },
	"allow":                func(a []token, _ policyScope) bool { return plainMatch(a, addressRe) },
	"deny":                 func(a []token, _ policyScope) bool { return plainMatch(a, addressRe) },
	"add_header": func(a []token, _ policyScope) bool {
		if len(a) == 3 && !plainOneOf(a[2:], "always") {
			return false
		}
		return (len(a) == 2 || len(a) == 3) && plainMatch(a[:1], headerNameRe) && headerValue(a[1])
	},
	"limit_req": func(a []token, p policyScope) bool {
		return p.zone != "" && len(a) == 3 && plainOneOf(a[:1], "zone="+p.zone) && plainMatch(a[1:2], burstRe) && plainOneOf(a[2:], "nodelay")
	},
}

// locationDirectives are the only directives allowed in `location / {}`.
var locationDirectives = map[string]argRule{
	"proxy_pass": func(a []token, _ policyScope) bool { return plainMatch(a, managedProxyPassRe) },
	"proxy_set_header": func(a []token, _ policyScope) bool {
		return len(a) == 2 && plainMatch(a[:1], headerNameRe) && headerValue(a[1])
	},
	"proxy_http_version": func(a []token, _ policyScope) bool { return plainOneOf(a, "1.0", "1.1") },
	"rewrite": func(a []token, _ policyScope) bool {
		return len(a) == 3 && rewriteArgument(a[0]) && rewriteArgument(a[1]) && plainOneOf(a[2:], "break")
	},
	"proxy_connect_timeout": func(a []token, _ policyScope) bool { return plainMatch(a, secondsRe) },
	"proxy_send_timeout":    func(a []token, _ policyScope) bool { return plainMatch(a, secondsRe) },
	"proxy_read_timeout":    func(a []token, _ policyScope) bool { return plainMatch(a, secondsRe) },
}

// redirectServerDirectives are the only directives allowed in the port-80
// force-https companion server, matching what nginxgen renders there:
// `return 301 https://$host$request_uri;` (or the literal host in place of
// $host). validateRedirectServer also requires exactly one server_name and
// exactly one return.
var redirectServerDirectives = map[string]argRule{
	"listen":      func(a []token, _ policyScope) bool { return managedListen(a, true) },
	"server_name": func(a []token, p policyScope) bool { return plainExact(a, p.Host) },
	"return": func(a []token, p policyScope) bool {
		return len(a) == 2 && plainOneOf(a[:1], "301") && plainOneOf(a[1:], "https://$host$request_uri", "https://"+p.Host+"$request_uri")
	},
}

var (
	directiveNameRe    = regexp.MustCompile(`^[a-z0-9_]+$`)
	headerNameRe       = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	bodySizeRe         = regexp.MustCompile(`^[0-9]+[kKmMgG]?$`)
	addressRe          = regexp.MustCompile(`^(all|[0-9A-Fa-f:.]+(/[0-9]{1,3})?)$`)
	secondsRe          = regexp.MustCompile(`^[0-9]+s?$`)
	burstRe            = regexp.MustCompile(`^burst=[0-9]+$`)
	zoneDeclRe         = regexp.MustCompile(`^zone=(nurproxy_[a-z0-9_]+):10m$`)
	rateRe             = regexp.MustCompile(`^rate=[0-9]+r/[sm]$`)
	managedProxyPassRe = regexp.MustCompile(`^https?://([A-Za-z0-9._-]+|\[[0-9A-Fa-f:.]+\]):[0-9]+/?$`)
)

// rateLimitZone returns the zone name of a `limit_req_zone` in the form
// nginxgen renders, or "" when the arguments differ from that form.
func rateLimitZone(a []token) string {
	if len(a) != 3 || !plainOneOf(a[:1], "$binary_remote_addr") || !plainMatch(a[2:], rateRe) || !plainMatch(a[1:2], zoneDeclRe) {
		return ""
	}
	return zoneDeclRe.FindStringSubmatch(a[1].value)[1]
}

func validateProxiedServer(server block, scope policyScope) error {
	if err := validateDirectives(server.directives, proxiedServerDirectives, scope); err != nil {
		return err
	}
	if len(server.blocks) != 1 {
		return fmt.Errorf("nginx configuration has an unsupported nested scope")
	}
	location := server.blocks[0]
	if !header(location, "location", "/") || len(location.blocks) != 0 {
		return fmt.Errorf("nginx configuration has an unsupported nested scope")
	}
	return validateDirectives(location.directives, locationDirectives, scope)
}

func validateRedirectServer(server block, scope policyScope) error {
	if err := validateDirectives(server.directives, redirectServerDirectives, scope); err != nil {
		return err
	}
	count := map[string]int{}
	for _, d := range server.directives {
		count[d.tokens[0].value]++
	}
	if count["server_name"] != 1 || count["return"] != 1 {
		return fmt.Errorf("nginx redirect server needs exactly one server_name and one return")
	}
	return nil
}

func validateDirectives(directives []directive, allowed map[string]argRule, scope policyScope) error {
	for _, d := range directives {
		if d.comment || !plainName(d.tokens[0]) {
			return fmt.Errorf("nginx directive is not in plain form")
		}
		name := d.tokens[0].value
		rule, ok := allowed[name]
		if !ok {
			return fmt.Errorf("nginx directive %q is not allowed in this scope", name)
		}
		if !rule(d.tokens[1:], scope) {
			return fmt.Errorf("nginx directive %q has unsupported arguments", name)
		}
	}
	return nil
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

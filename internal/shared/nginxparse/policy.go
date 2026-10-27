package nginxparse

import (
	"fmt"
	"regexp"
	"strings"
)

// ManagedPolicy names the values a raw nginx vhost must use verbatim before
// the privileged helper writes it: the route's host and the helper-owned
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
// explicit allowlist for its scope; anything else is refused.
func ValidateManaged(content string, policy ManagedPolicy) error {
	if strings.TrimSpace(policy.Host) == "" || strings.ContainsAny(policy.Host, " \t\r\n;/") || !plainArgument(policy.Host) {
		return fmt.Errorf("managed nginx policy has no exact host")
	}
	for i := 0; i < len(content); i++ {
		if c := content[i]; (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			return fmt.Errorf("raw nginx configuration contains control characters")
		}
	}
	blocks, leftover, err := parseConfig(content)
	if err != nil {
		return fmt.Errorf("raw nginx configuration is not valid nginx syntax")
	}
	if len(leftover) != 0 || len(blocks) == 0 || len(blocks) > 2 {
		return fmt.Errorf("raw nginx configuration has unsupported top-level scope")
	}
	parsed := Parse(content)
	if !parsed.OK || parsed.Route.Host != policy.Host || parsed.Route.Upstream.Addr == "" || parsed.Route.Upstream.Port <= 0 || parsed.Route.Upstream.Port > 65535 {
		return fmt.Errorf("raw nginx configuration is not a clean single-route mask")
	}
	proxied := 0
	for _, server := range blocks {
		if !header(server, "server") {
			return fmt.Errorf("raw nginx configuration has an unsupported block")
		}
		if len(server.blocks) == 0 {
			if err := validateRedirectServer(server, policy); err != nil {
				return err
			}
			continue
		}
		proxied++
		if err := validateProxiedServer(server, policy); err != nil {
			return err
		}
	}
	if proxied != 1 {
		return fmt.Errorf("raw nginx configuration must have exactly one proxied server")
	}
	return nil
}

// argRule checks a directive's arguments (nginx values, name excluded).
type argRule func(args []token, policy ManagedPolicy) bool

// proxiedServerDirectives are the only directives allowed directly in the
// proxied server block.
var proxiedServerDirectives = map[string]argRule{
	"listen":      func(a []token, _ ManagedPolicy) bool { return managedListen(a, false) },
	"http2":       func(a []token, _ ManagedPolicy) bool { return plainOneOf(a, "on", "off") },
	"server_name": func(a []token, p ManagedPolicy) bool { return plainExact(a, p.Host) },
	"ssl_certificate": func(a []token, p ManagedPolicy) bool {
		return p.CertPath != "" && plainExact(a, p.CertPath)
	},
	"ssl_certificate_key": func(a []token, p ManagedPolicy) bool {
		return p.KeyPath != "" && plainExact(a, p.KeyPath)
	},
	"auth_basic": func(a []token, _ ManagedPolicy) bool { return len(a) == 1 && headerValue(a[0]) },
	"auth_basic_user_file": func(a []token, p ManagedPolicy) bool {
		return p.AuthPath != "" && plainExact(a, p.AuthPath)
	},
	"client_max_body_size": func(a []token, _ ManagedPolicy) bool { return plainMatch(a, bodySizeRe) },
	"allow":                func(a []token, _ ManagedPolicy) bool { return plainMatch(a, addressRe) },
	"deny":                 func(a []token, _ ManagedPolicy) bool { return plainMatch(a, addressRe) },
	"add_header": func(a []token, _ ManagedPolicy) bool {
		if len(a) == 3 && !plainOneOf(a[2:], "always") {
			return false
		}
		return (len(a) == 2 || len(a) == 3) && plainMatch(a[:1], headerNameRe) && headerValue(a[1])
	},
}

// locationDirectives are the only directives allowed in `location / {}`.
var locationDirectives = map[string]argRule{
	"proxy_pass": func(a []token, _ ManagedPolicy) bool { return plainMatch(a, managedProxyPassRe) },
	"proxy_set_header": func(a []token, _ ManagedPolicy) bool {
		return len(a) == 2 && plainMatch(a[:1], headerNameRe) && headerValue(a[1])
	},
	"proxy_http_version": func(a []token, _ ManagedPolicy) bool { return plainOneOf(a, "1.0", "1.1") },
	"rewrite": func(a []token, _ ManagedPolicy) bool {
		return len(a) == 3 && rewriteArgument(a[0]) && rewriteArgument(a[1]) && plainOneOf(a[2:], "break")
	},
	"proxy_connect_timeout": func(a []token, _ ManagedPolicy) bool { return plainMatch(a, secondsRe) },
	"proxy_send_timeout":    func(a []token, _ ManagedPolicy) bool { return plainMatch(a, secondsRe) },
	"proxy_read_timeout":    func(a []token, _ ManagedPolicy) bool { return plainMatch(a, secondsRe) },
}

// redirectServerDirectives are the only directives allowed in the port-80
// force-https companion server, matching what nginxgen renders there.
var redirectServerDirectives = map[string]argRule{
	"listen":      func(a []token, _ ManagedPolicy) bool { return managedListen(a, true) },
	"server_name": func(a []token, p ManagedPolicy) bool { return plainExact(a, p.Host) },
	"return": func(a []token, _ ManagedPolicy) bool {
		return len(a) == 2 && plainOneOf(a[:1], "301") && plainArgument(a[1].source) && strings.HasPrefix(a[1].value, "https://")
	},
}

var (
	directiveNameRe    = regexp.MustCompile(`^[a-z0-9_]+$`)
	headerNameRe       = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	bodySizeRe         = regexp.MustCompile(`^[0-9]+[kKmMgG]?$`)
	addressRe          = regexp.MustCompile(`^(all|[0-9A-Fa-f:.]+(/[0-9]{1,3})?)$`)
	secondsRe          = regexp.MustCompile(`^[0-9]+s?$`)
	managedProxyPassRe = regexp.MustCompile(`^https?://[A-Za-z0-9._-]+:[0-9]+/?$`)
)

func validateProxiedServer(server block, policy ManagedPolicy) error {
	if err := validateDirectives(server.directives, proxiedServerDirectives, policy); err != nil {
		return err
	}
	if len(server.blocks) != 1 {
		return fmt.Errorf("raw nginx configuration has an unsupported nested scope")
	}
	location := server.blocks[0]
	if !header(location, "location", "/") || len(location.blocks) != 0 {
		return fmt.Errorf("raw nginx configuration has an unsupported nested scope")
	}
	return validateDirectives(location.directives, locationDirectives, policy)
}

func validateRedirectServer(server block, policy ManagedPolicy) error {
	if err := validateDirectives(server.directives, redirectServerDirectives, policy); err != nil {
		return err
	}
	for _, d := range server.directives {
		if d.tokens[0].value == "return" {
			return nil
		}
	}
	return fmt.Errorf("raw nginx redirect server has no redirect")
}

func validateDirectives(directives []directive, allowed map[string]argRule, policy ManagedPolicy) error {
	for _, d := range directives {
		if d.comment || !plainName(d.tokens[0]) {
			return fmt.Errorf("raw nginx directive is not in plain form")
		}
		name := d.tokens[0].value
		rule, ok := allowed[name]
		if !ok {
			return fmt.Errorf("raw nginx directive %q is not allowed in this scope", name)
		}
		if !rule(d.tokens[1:], policy) {
			return fmt.Errorf("raw nginx directive %q has unsupported arguments", name)
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
// double-quoted string whose only escape is \" (the form nginxgen renders
// for values with spaces, semicolons or quotes).
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
				if i+1 >= len(inner) || inner[i+1] != '"' {
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
// equals the source.
func rewriteArgument(t token) bool {
	if t.quote != 0 || t.source != t.value || t.source == "" {
		return false
	}
	s := t.source
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' {
			if i+1 >= len(s) || strings.IndexByte(`.+*?()|[]^$`, s[i+1]) < 0 {
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

// managedListen accepts listeners on ports 80 and 443 only. The redirect
// server may only listen on port 80 without options.
func managedListen(args []token, redirect bool) bool {
	if len(args) == 0 {
		return false
	}
	for _, a := range args {
		if a.quote != 0 || !plainArgument(a.source) {
			return false
		}
	}
	if redirect {
		return len(args) == 1 && (args[0].value == "80" || args[0].value == "[::]:80")
	}
	switch args[0].value {
	case "80", "[::]:80", "443", "[::]:443":
	default:
		return false
	}
	for _, option := range args[1:] {
		if option.value != "ssl" && option.value != "http2" {
			return false
		}
	}
	return true
}

package apacheparse

import (
	"regexp"
	"strings"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// ManagedPolicy names the values an Apache vhost must use verbatim before the
// privileged helper writes it: the route's host and the helper-owned
// certificate, key and htpasswd paths. An empty path refuses the directive
// that would name it.
type ManagedPolicy struct {
	Host     string
	CertPath string
	KeyPath  string
	AuthPath string
}

// ValidateManaged reports whether an Apache config is a bounded single-route
// vhost the helper may write, raw or rendered by apachegen. Only
// <VirtualHost *:80> and <VirtualHost *:443> sections are allowed at the top
// level, and every directive and section inside them must match an explicit
// allowlist with argument rules for the forms apachegen renders. Anything
// else is refused, so a config cannot load modules, include files, run
// programs (piped logs, RewriteMap prg:, CGI handlers), write logs outside
// /dev/null, expose the filesystem with <Directory> or set variables.
func ValidateManaged(content string, policy ManagedPolicy) error {
	if strings.TrimSpace(policy.Host) == "" || !plainText(policy.Host) {
		return refuse(0, "", "managed Apache policy has no exact host")
	}
	directives, sections, err := parse(content)
	if err != nil {
		return err
	}
	for _, d := range directives {
		return refuse(d.line, d.name, "%s", notAllowedReason(d.name, "outside <VirtualHost>"))
	}
	if len(sections) == 0 {
		return refuse(0, "", "config has no <VirtualHost>")
	}
	if len(sections) > 2 {
		return refuse(sections[2].line, "<"+sections[2].name+">", "config has more than two <VirtualHost> sections")
	}
	proxied := 0
	for _, vhost := range sections {
		if !asciiEqualFold(vhost.name, "VirtualHost") {
			return refuse(vhost.line, "<"+vhost.name+">", "%s", notAllowedReason("<"+vhost.name+">", "at the top level"))
		}
		redirect, err := validateVirtualHost(vhost, policy)
		if err != nil {
			return err
		}
		if !redirect {
			proxied++
		}
	}
	if proxied != 1 {
		return refuse(0, "", "config must have exactly one proxied <VirtualHost>")
	}
	return nil
}

// argRule checks a directive's arguments (name excluded).
type argRule func(args []word, policy ManagedPolicy) bool

// vhostDirectives are the only directives allowed directly in a
// <VirtualHost>.
var vhostDirectives = map[string]argRule{
	"servername": func(a []word, p ManagedPolicy) bool { return plainExact(a, p.Host) },
	"sslengine":  func(a []word, _ ManagedPolicy) bool { return plainFold(a, "on") },
	"sslcertificatefile": func(a []word, p ManagedPolicy) bool {
		return p.CertPath != "" && plainExact(a, p.CertPath)
	},
	"sslcertificatekeyfile": func(a []word, p ManagedPolicy) bool {
		return p.KeyPath != "" && plainExact(a, p.KeyPath)
	},
	"customlog": func(a []word, _ ManagedPolicy) bool {
		return len(a) == 2 && plainExact(a[:1], "/dev/null") && plainExact(a[1:], "common")
	},
	"loglevel":          func(a []word, _ ManagedPolicy) bool { return plainOneOf(a, proxymodel.ErrorLogLevels...) },
	"limitrequestbody":  func(a []word, _ ManagedPolicy) bool { return plainMatch(a, digitsRe) },
	"header":            headerRule(true),
	"requestheader":     headerRule(false),
	"proxypreservehost": func(a []word, _ ManagedPolicy) bool { return plainFold(a, "on", "off") },
	"rewriteengine":     func(a []word, _ ManagedPolicy) bool { return plainFold(a, "on", "off") },
	"rewritecond":       rewriteCondRule,
	"rewriterule":       rewriteRuleRule,
	"proxypass":         proxyPassRule,
	"proxypassmatch":    proxyPassMatchRule,
	"proxypassreverse":  proxyPassReverseRule,
	// Needed for https:// upstreams; it only enables TLS to the backend.
	"sslproxyengine": func(a []word, _ ManagedPolicy) bool { return plainFold(a, "on") },
	"redirect": func(a []word, p ManagedPolicy) bool {
		return len(a) == 3 && plainFold(a[:1], "permanent", "301") && plainExact(a[1:2], "/") && plainExact(a[2:], "https://"+p.Host+"/")
	},
}

// locationDirectives are the only directives allowed in <Location />.
var locationDirectives = map[string]argRule{
	"authtype": func(a []word, _ ManagedPolicy) bool { return plainFold(a, "basic") },
	// httpd evaluates AuthName as an ap_expr string, so "%{file:...}" or
	// "%{ENV:...}" would send a file or variable to unauthenticated clients
	// in WWW-Authenticate. Only the realm apachegen renders is allowed.
	"authname": func(a []word, p ManagedPolicy) bool {
		want := "Restricted: " + p.Host
		return len(a) == 1 && a[0].quote == '"' && a[0].source == `"`+want+`"`
	},
	"authuserfile": func(a []word, p ManagedPolicy) bool {
		return p.AuthPath != "" && plainExact(a, p.AuthPath)
	},
	"require": requireRule,
}

// requireAllDirectives are the only directives allowed in <RequireAll>.
var requireAllDirectives = map[string]argRule{"require": requireRule}

// dangerReasons explains directives that are refused for a specific reason,
// so the operator sees why rather than only that the name is not listed.
var dangerReasons = map[string]string{
	"loadmodule":       "loads a module into the root-started server",
	"loadfile":         "loads a library into the root-started server",
	"include":          "reads another file into the config",
	"includeoptional":  "reads another file into the config",
	"errorlog":         "opens a log file or starts a program",
	"customlog":        "opens a log file or starts a program",
	"transferlog":      "opens a log file or starts a program",
	"globallog":        "opens a log file or starts a program",
	"scriptalias":      "runs programs as CGI scripts",
	"scriptaliasmatch": "runs programs as CGI scripts",
	"rewritemap":       "can run a program or read a file",
	"define":           "sets a config-time variable",
	"undefine":         "sets a config-time variable",
	"setenv":           "sets an environment variable",
	"setenvif":         "sets an environment variable",
	"setenvifnocase":   "sets an environment variable",
	"passenv":          "passes the server's environment to requests",
	"unsetenv":         "changes the environment",
	"<directory>":      "exposes a filesystem path",
	"<directorymatch>": "exposes a filesystem path",
	"<files>":          "exposes filesystem paths",
	"<filesmatch>":     "exposes filesystem paths",
	"documentroot":     "serves a filesystem path",
	"alias":            "serves a filesystem path",
	"aliasmatch":       "serves a filesystem path",
	"addhandler":       "assigns a handler that can run programs",
	"sethandler":       "assigns a handler that can run programs",
	"action":           "runs a program for requests",
	"user":             "changes the server's account",
	"group":            "changes the server's account",
	"listen":           "opens a listener for every vhost",
	"serveralias":      "claims other host names",
}

func notAllowedReason(name, scope string) string {
	if reason, ok := dangerReasons[strings.ToLower(name)]; ok {
		return "not allowed " + scope + " (" + reason + ")"
	}
	return "not allowed " + scope
}

// validateVirtualHost checks one <VirtualHost> and reports whether it is the
// port-80 redirect companion rather than the proxied vhost.
func validateVirtualHost(vhost section, policy ManagedPolicy) (bool, error) {
	if len(vhost.args) != 1 || !plain(vhost.args[0]) || (vhost.args[0].value != "*:80" && vhost.args[0].value != "*:443") {
		return false, refuse(vhost.line, "<VirtualHost>", "only *:80 and *:443 are allowed as the address")
	}
	if err := validateDirectives(vhost.directives, vhostDirectives, policy, "in <VirtualHost>"); err != nil {
		return false, err
	}
	count := map[string]int{}
	for _, d := range vhost.directives {
		count[strings.ToLower(d.name)]++
	}
	if count["servername"] != 1 {
		return false, refuse(vhost.line, "<VirtualHost>", "needs exactly one ServerName")
	}
	redirect := count["redirect"] > 0
	if redirect {
		if vhost.args[0].value != "*:80" || count["redirect"] != 1 || len(vhost.sections) != 0 {
			return false, refuse(vhost.line, "<VirtualHost>", "a redirect vhost listens on *:80 and has exactly one Redirect")
		}
		for _, d := range vhost.directives {
			switch strings.ToLower(d.name) {
			case "servername", "redirect", "customlog", "loglevel":
			default:
				return false, refuse(d.line, d.name, "not allowed in a redirect vhost")
			}
		}
		return true, nil
	}
	if count["proxypass"] == 0 && count["rewriterule"] == 0 {
		return false, refuse(vhost.line, "<VirtualHost>", "the proxied vhost needs a ProxyPass or RewriteRule [P]")
	}
	if len(vhost.sections) > 1 {
		return false, refuse(vhost.sections[1].line, "<"+vhost.sections[1].name+">", "only one <Location /> is allowed")
	}
	for _, s := range vhost.sections {
		if err := validateLocation(s, policy); err != nil {
			return false, err
		}
	}
	return false, nil
}

func validateLocation(location section, policy ManagedPolicy) error {
	name := "<" + location.name + ">"
	if !asciiEqualFold(location.name, "Location") {
		return refuse(location.line, name, "%s", notAllowedReason(name, "in <VirtualHost>"))
	}
	if len(location.args) != 1 || !plainExact(location.args, "/") {
		return refuse(location.line, name, "only <Location /> is allowed")
	}
	if err := validateDirectives(location.directives, locationDirectives, policy, "in <Location />"); err != nil {
		return err
	}
	if len(location.sections) > 1 {
		return refuse(location.sections[1].line, "<"+location.sections[1].name+">", "only one <RequireAll> is allowed")
	}
	for _, s := range location.sections {
		inner := "<" + s.name + ">"
		if !asciiEqualFold(s.name, "RequireAll") || len(s.args) != 0 {
			return refuse(s.line, inner, "%s", notAllowedReason(inner, "in <Location />"))
		}
		if len(s.sections) != 0 {
			return refuse(s.sections[0].line, "<"+s.sections[0].name+">", "not allowed in <RequireAll>")
		}
		if err := validateDirectives(s.directives, requireAllDirectives, policy, "in <RequireAll>"); err != nil {
			return err
		}
	}
	return nil
}

func validateDirectives(directives []directive, allowed map[string]argRule, policy ManagedPolicy, scope string) error {
	for _, d := range directives {
		rule, ok := allowed[strings.ToLower(d.name)]
		if !ok {
			return refuse(d.line, d.name, "%s", notAllowedReason(d.name, scope))
		}
		if !rule(d.args, policy) {
			return refuse(d.line, d.name, "has unsupported arguments")
		}
	}
	return nil
}

var (
	headerNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	digitsRe     = regexp.MustCompile(`^[0-9]+$`)
	addressRe    = regexp.MustCompile(`^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$`)
	secondsRe    = regexp.MustCompile(`^(connectiontimeout|timeout)=[0-9]+$`)
	condTestRe   = regexp.MustCompile(`^%\{HTTP:(Upgrade|Connection)\}$`)
	condPatRe    = regexp.MustCompile(`^=?[A-Za-z]+$`)
	upstreamRe   = regexp.MustCompile(`^(https?|wss?)://([A-Za-z0-9._-]+|\[[0-9A-Fa-f:.]+\]):[0-9]{1,5}`)
)

// headerRule accepts `[always] set NAME VALUE` and `[always] unset NAME` for
// Header (withAlways) and the same without "always" for RequestHeader. No
// condition (env=, expr=) or extra argument is allowed.
func headerRule(withAlways bool) argRule {
	return func(a []word, _ ManagedPolicy) bool {
		if withAlways && len(a) > 0 && plainFold(a[:1], "always") {
			a = a[1:]
		}
		switch {
		case len(a) == 3 && plainFold(a[:1], "set"):
			return plainMatch(a[1:2], headerNameRe) && headerValue(a[2])
		case len(a) == 2 && plainFold(a[:1], "unset"):
			return plainMatch(a[1:], headerNameRe)
		}
		return false
	}
}

// headerValue accepts a mod_headers value that sets literal text: "%" only
// as "%%" (a lone "%" starts a format specifier such as %{NAME}e) and "\"
// only as "\\" (mod_headers resolves \n and \t), and no leading "expr=",
// which mod_headers evaluates as an expression.
func headerValue(w word) bool {
	if !quotedOrPlain(w) {
		return false
	}
	v := w.value
	for i := 0; i < len(v); i++ {
		if v[i] == '%' || v[i] == '\\' {
			if i+1 >= len(v) || v[i+1] != v[i] {
				return false
			}
			i++
		}
	}
	trimmed := strings.TrimLeft(v, ` "'`)
	return len(trimmed) < 5 || !asciiEqualFold(trimmed[:5], "expr=")
}

// rewriteCondRule accepts only the WebSocket upgrade test apachegen renders,
// its Connection-header variant, and the path route exclusions.
func rewriteCondRule(a []word, _ ManagedPolicy) bool {
	if routeExclusionCond(a) {
		return true
	}
	if len(a) != 2 && len(a) != 3 {
		return false
	}
	if a[0].quote != 0 || !condTestRe.MatchString(a[0].source) || !plainMatch(a[1:2], condPatRe) {
		return false
	}
	return len(a) == 2 || plainFold(a[2:], "[NC]")
}

// rewriteRuleRule accepts `RewriteRule PATTERN UPSTREAM-URL [FLAGS]` that
// proxies to an http(s) or ws(s) upstream. The flags must include P and may
// only add L, NC, QSA or NE: H= and T= set a handler that can run programs,
// E= sets environment variables.
func rewriteRuleRule(a []word, _ ManagedPolicy) bool {
	if len(a) != 3 || !rewritePattern(a[0]) || !upstreamURL(a[1], true) || !plain(a[2]) {
		return false
	}
	flags := a[2].value
	if len(flags) < 3 || flags[0] != '[' || flags[len(flags)-1] != ']' {
		return false
	}
	proxy := false
	for _, f := range strings.Split(flags[1:len(flags)-1], ",") {
		switch strings.ToUpper(f) {
		case "P":
			proxy = true
		case "L", "NC", "QSA", "NE":
		default:
			return false
		}
	}
	return proxy
}

// proxyPassRule accepts `ProxyPass / URL [connectiontimeout=N] [timeout=N]`
// with an http(s) upstream. unix:, fcgi:, ajp: and balancer: targets are
// refused.
func proxyPassRule(a []word, _ ManagedPolicy) bool {
	if len(a) < 2 || len(a) > 4 || !plainExact(a[:1], "/") || !upstreamURL(a[1], false) {
		return false
	}
	return timeoutParams(a[2:])
}

// requireRule accepts the authorization forms apachegen renders: valid-user,
// all granted/denied, and (not) ip with address or CIDR arguments.
func requireRule(a []word, _ ManagedPolicy) bool {
	switch {
	case len(a) == 1:
		return plainFold(a, "valid-user")
	case len(a) == 2 && plainFold(a[:1], "all"):
		return plainFold(a[1:], "granted", "denied")
	}
	if len(a) >= 2 && plainFold(a[:1], "not") {
		a = a[1:]
	}
	if len(a) < 2 || !plainFold(a[:1], "ip") {
		return false
	}
	for _, ip := range a[1:] {
		if !plainMatch([]word{ip}, addressRe) {
			return false
		}
	}
	return true
}

// upstreamURL accepts an http(s) URL (or ws(s) when ws is set) with a host
// and port, followed by an optional path without quotes, backslashes,
// braces or "%{" (a server variable lookup).
func upstreamURL(w word, ws bool) bool {
	if !plain(w) || strings.Contains(w.value, "%{") {
		return false
	}
	m := upstreamRe.FindStringSubmatch(w.value)
	if len(m) < 2 || (!ws && strings.HasPrefix(m[1], "ws")) {
		return false
	}
	rest := w.value[len(m[0]):]
	return rest == "" || rest[0] == '/'
}

// rewritePattern accepts an unquoted regex in which a backslash only escapes
// a regex metacharacter (the form apachegen's regexpEscape produces).
func rewritePattern(w word) bool {
	if w.quote != 0 || w.source == "" {
		return false
	}
	s := w.source
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' {
			if i+1 >= len(s) || strings.IndexByte(`.+*?()|[]{}^$`, s[i+1]) < 0 {
				return false
			}
			i++
			continue
		}
		if c <= ' ' || c == 0x7f || strings.IndexByte("\"'#{}%", c) >= 0 {
			return false
		}
	}
	return true
}

// plainText reports whether s is non-empty and has no character httpd's
// tokenizer treats specially: whitespace, quotes, backslash, '#', '<', '>',
// braces or '%'.
func plainText(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c == 0x7f || strings.IndexByte("\"'\\#<>{}%", c) >= 0 {
			return false
		}
	}
	return true
}

func plain(w word) bool { return w.quote == 0 && plainText(w.source) }

// quotedOrPlain accepts a plain word or a double-quoted word whose only
// escapes are \" and \\ and that has no control characters.
func quotedOrPlain(w word) bool {
	switch w.quote {
	case 0:
		return plain(w)
	case '"':
		inner := w.source[1 : len(w.source)-1]
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
	}
	return false
}

func plainExact(args []word, want string) bool {
	return len(args) == 1 && plain(args[0]) && args[0].value == want
}

func plainOneOf(args []word, options ...string) bool {
	if len(args) != 1 || !plain(args[0]) {
		return false
	}
	for _, o := range options {
		if args[0].value == o {
			return true
		}
	}
	return false
}

// plainFold is plainOneOf with httpd's case-insensitive keyword matching.
func plainFold(args []word, options ...string) bool {
	if len(args) != 1 || !plain(args[0]) {
		return false
	}
	for _, o := range options {
		if asciiEqualFold(args[0].value, o) {
			return true
		}
	}
	return false
}

func plainMatch(args []word, re *regexp.Regexp) bool {
	return len(args) == 1 && plain(args[0]) && re.MatchString(args[0].value)
}

// asciiEqualFold compares like httpd's strcasecmp: ASCII letters only, so a
// Unicode case folding (such as "ſ" for "s") never makes two words equal.
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

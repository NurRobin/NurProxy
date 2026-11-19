package apacheparse

import (
	"strings"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// routeRegexKind names the three path route regexes apachegen renders.
type routeRegexKind int

const (
	routeExact  routeRegexKind = iota // ^P$
	routePrefix                       // ^P(?:/.*)?$
	routeStrip                        // ^P(?:/(.*))?$, capturing the rest
)

const (
	prefixSuffix = "(?:/.*)?"
	stripSuffix  = "(?:/(.*))?"
)

// routeRegex reads a path route regex in exactly the form apachegen renders:
// "^", the route path with "." escaped and nothing else, one of the suffixes
// above, "$". The path must be one proxymodel accepts for the match kind, so
// the regex can only ever match literal paths.
func routeRegex(src string) (routeRegexKind, bool) {
	if len(src) < 3 || src[0] != '^' || src[len(src)-1] != '$' {
		return 0, false
	}
	body := src[1 : len(src)-1]
	kind, match := routeExact, proxymodel.PathMatchExact
	switch {
	case strings.HasSuffix(body, stripSuffix):
		kind, match, body = routeStrip, proxymodel.PathMatchPrefix, strings.TrimSuffix(body, stripSuffix)
	case strings.HasSuffix(body, prefixSuffix):
		kind, match, body = routePrefix, proxymodel.PathMatchPrefix, strings.TrimSuffix(body, prefixSuffix)
	}
	path := strings.ReplaceAll(body, `\.`, ".")
	if strings.ReplaceAll(path, ".", `\.`) != body || proxymodel.ValidateRoutePath(match, path) != nil {
		return 0, false
	}
	return kind, true
}

// proxyPassMatchRule accepts the ProxyPassMatch lines apachegen renders for
// path routes: an exact or prefix regex with a bare http(s)://host:port
// target (mod_proxy appends the request path), or a strip regex with the
// target host:port/$1. Only the connectiontimeout and timeout parameters
// may follow.
func proxyPassMatchRule(a []word, _ ManagedPolicy) bool {
	if len(a) < 2 || len(a) > 4 || a[0].quote != 0 || a[0].source != a[0].value {
		return false
	}
	kind, ok := routeRegex(a[0].value)
	if !ok || !upstreamURL(a[1], false) {
		return false
	}
	rest := a[1].value[len(upstreamRe.FindString(a[1].value)):]
	if (kind == routeStrip) != (rest == "/$1") || (kind != routeStrip && rest != "") {
		return false
	}
	return timeoutParams(a[2:])
}

// timeoutParams accepts at most one connectiontimeout=N and one timeout=N.
func timeoutParams(params []word) bool {
	seen := map[string]bool{}
	for _, p := range params {
		if !plainMatch([]word{p}, secondsRe) {
			return false
		}
		key, _, _ := strings.Cut(p.value, "=")
		if seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

// routeExclusionCond accepts `RewriteCond %{REQUEST_URI} !^P$` and
// `RewriteCond %{REQUEST_URI} !^P(?:/.*)?$`, which apachegen puts before the
// default upstream's catch-all RewriteRules to leave path routes alone.
func routeExclusionCond(a []word) bool {
	if len(a) != 2 || a[0].quote != 0 || a[0].source != "%{REQUEST_URI}" || a[1].quote != 0 || a[1].source != a[1].value {
		return false
	}
	pattern, ok := strings.CutPrefix(a[1].value, "!")
	if !ok {
		return false
	}
	kind, ok := routeRegex(pattern)
	return ok && kind != routeStrip
}

// proxyPassReverseRule accepts `ProxyPassReverse / URL` and, for a
// stripping prefix route, `ProxyPassReverse <path>/ URL`.
func proxyPassReverseRule(a []word, _ ManagedPolicy) bool {
	if len(a) != 2 || !plain(a[0]) || !upstreamURL(a[1], false) {
		return false
	}
	if a[0].value == "/" {
		return true
	}
	path, ok := strings.CutSuffix(a[0].value, "/")
	return ok && proxymodel.ValidateRoutePath(proxymodel.PathMatchPrefix, path) == nil
}

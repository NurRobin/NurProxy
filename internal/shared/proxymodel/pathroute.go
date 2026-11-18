package proxymodel

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// PathMatch selects how a PathRoute's path is compared with the request path.
type PathMatch string

const (
	// PathMatchPrefix matches the path itself and everything below it on a
	// segment boundary: "/api" matches "/api" and "/api/users", never
	// "/apix".
	PathMatchPrefix PathMatch = "prefix"
	// PathMatchExact matches only the path itself (the query string is not
	// part of the comparison).
	PathMatchExact PathMatch = "exact"
)

// MaxPathRoutes bounds the extra routes one host may carry.
const MaxPathRoutes = 32

// maxRoutePathBytes bounds a path route's path.
const maxRoutePathBytes = 256

// routePathRe is the character set a route path may use: unreserved URL
// characters and "/". It leaves out everything nginx, Apache or Caddy would
// read specially in a location, regex or matcher ("*", "?", "%", "~", braces,
// quotes, whitespace), so every backend can match the path literally.
var routePathRe = regexp.MustCompile(`^/[A-Za-z0-9._/-]*$`)

// PathRoute sends requests whose path matches Path to its own upstream.
//
// Matching follows nginx's location rules, which every renderer reproduces:
// an exact match wins over any prefix, and among prefixes the longest one
// wins. The order of Route.PathRoutes therefore does not change which route
// serves a request; renderers emit the routes most specific first. Regular
// expressions are not supported: nginx tries regex locations in file order
// and lets them override prefixes, Caddy uses RE2 and Apache PCRE, so one
// regex would mean different things per backend.
type PathRoute struct {
	// Match is PathMatchPrefix or PathMatchExact.
	Match PathMatch
	// Path is the request path to match, starting with "/". A prefix path has
	// no trailing slash and is never "/" (that is the default upstream).
	Path string
	// Upstream is the backend for matching requests.
	Upstream Upstream
	// WebSocket enables connection-upgrade passthrough for this route.
	WebSocket bool `json:",omitempty"`
	// StripPrefix removes Path from the request path before it is forwarded
	// ("/api/users" reaches the upstream as "/users", "/api" as "/"). Only
	// valid for prefix routes.
	StripPrefix bool `json:",omitempty"`
}

// EffectiveScheme returns the route's upstream scheme, defaulting to
// SchemeHTTP when unset.
func (p PathRoute) EffectiveScheme() Scheme {
	if p.Upstream.Scheme == "" {
		return SchemeHTTP
	}
	return p.Upstream.Scheme
}

// ValidateShape checks the match, path, port and options of a path route,
// but not the upstream address. The orchestrator uses it on stored settings
// before the upstream server's address is resolved.
func (p PathRoute) ValidateShape() error {
	switch p.Match {
	case PathMatchPrefix, PathMatchExact:
	default:
		return fmt.Errorf("path route %q: match must be %q or %q", p.Path, PathMatchPrefix, PathMatchExact)
	}
	if err := ValidateRoutePath(p.Match, p.Path); err != nil {
		return err
	}
	if p.StripPrefix && p.Match != PathMatchPrefix {
		return fmt.Errorf("path route %q: strip prefix is only possible on a prefix match", p.Path)
	}
	switch p.EffectiveScheme() {
	case SchemeHTTP, SchemeHTTPS:
	default:
		return fmt.Errorf("path route %q: invalid upstream scheme %q", p.Path, p.Upstream.Scheme)
	}
	if p.Upstream.Port <= 0 || p.Upstream.Port > 65535 {
		return fmt.Errorf("path route %q: upstream port %d out of range (1-65535)", p.Path, p.Upstream.Port)
	}
	return nil
}

// Validate checks the path route including its upstream address.
func (p PathRoute) Validate() error {
	if err := p.ValidateShape(); err != nil {
		return err
	}
	if p.Upstream.Addr == "" {
		return fmt.Errorf("path route %q: upstream address is required", p.Path)
	}
	if !validUpstreamAddr(p.Upstream.Addr) {
		return fmt.Errorf("path route %q: upstream address %q is not a host name or IP address", p.Path, p.Upstream.Addr)
	}
	return nil
}

// ValidateRoutePath checks a path route's path for the given match kind.
func ValidateRoutePath(match PathMatch, path string) error {
	if path == "" {
		return fmt.Errorf("path route: path is required")
	}
	if len(path) > maxRoutePathBytes {
		return fmt.Errorf("path route %q: path is longer than %d bytes", path, maxRoutePathBytes)
	}
	if !routePathRe.MatchString(path) {
		return fmt.Errorf("path route %q: path must start with '/' and may only contain letters, digits, '-', '.', '_' and '/'", path)
	}
	if strings.Contains(path, "//") {
		return fmt.Errorf("path route %q: path must not contain '//'", path)
	}
	for _, seg := range strings.Split(path[1:], "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("path route %q: path must not contain '.' or '..' segments", path)
		}
	}
	if match == PathMatchPrefix {
		if path == "/" {
			return fmt.Errorf("path route: prefix \"/\" is the default upstream, not an extra route")
		}
		if strings.HasSuffix(path, "/") {
			return fmt.Errorf("path route %q: a prefix path has no trailing slash (%q already matches everything below it)", path, strings.TrimSuffix(path, "/"))
		}
	}
	return nil
}

// ValidatePathRoutes checks a route list: each route, the count, and that no
// match kind and path appear twice. withAddr also checks each upstream
// address.
func ValidatePathRoutes(routes []PathRoute, withAddr bool) error {
	if len(routes) > MaxPathRoutes {
		return fmt.Errorf("at most %d path routes per domain", MaxPathRoutes)
	}
	seen := make(map[string]bool, len(routes))
	for _, p := range routes {
		var err error
		if withAddr {
			err = p.Validate()
		} else {
			err = p.ValidateShape()
		}
		if err != nil {
			return err
		}
		key := string(p.Match) + " " + p.Path
		if seen[key] {
			return fmt.Errorf("path route %q (%s) is defined twice", p.Path, p.Match)
		}
		seen[key] = true
	}
	return nil
}

// SortedPathRoutes returns the routes most specific first: exact matches
// before prefixes, longer paths before shorter ones, then by path. Backends
// where the first matching rule wins (Caddy, Apache) render them in this
// order, which gives them nginx's precedence.
func SortedPathRoutes(routes []PathRoute) []PathRoute {
	out := append([]PathRoute(nil), routes...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.Match == PathMatchExact) != (b.Match == PathMatchExact) {
			return a.Match == PathMatchExact
		}
		if len(a.Path) != len(b.Path) {
			return len(a.Path) > len(b.Path)
		}
		return a.Path < b.Path
	})
	return out
}

// Package nginxdiscover is a lenient, read-only scanner that pulls the backend
// targets out of an existing nginx configuration so the dashboard can suggest
// them as Servers (#52). It is deliberately NOT the strict round-trippable
// parser in internal/shared/nginxparse — that one expects NurProxy's clean
// one-server-one-upstream shape and bails (OK=false) on the hand-written, many-
// server, upstream{}-using configs a real host accumulates. Here we only want to
// answer "which addresses does this nginx proxy to, and from which vhosts", so a
// tolerant brace-aware token scan beats a precise parse.
//
// It resolves both direct `proxy_pass http://host:port` targets and named
// upstreams (`proxy_pass http://backend` + `upstream backend { server ...; }`).
// Variable targets ($foo) and anything it cannot make sense of are skipped, never
// guessed. Pure and table-tested; the agent feeds it file contents, never the
// other way around.
package nginxdiscover

import (
	"sort"
	"strconv"
	"strings"
)

// Upstream is one discovered backend target. Port is 0 when the config did not
// specify one (nginx then defaults by scheme). ServerNames are the server_name
// values of the vhost(s) that proxy to it, for a human-friendly suggestion.
type Upstream struct {
	Scheme      string   `json:"scheme,omitempty"`
	Host        string   `json:"host"`
	Port        int      `json:"port,omitempty"`
	ServerNames []string `json:"server_names,omitempty"`
}

// Addr renders host[:port] for display and dedup.
func (u Upstream) Addr() string {
	if u.Port == 0 {
		return u.Host
	}
	return u.Host + ":" + strconv.Itoa(u.Port)
}

// Discover scans one nginx config file's content and returns the distinct
// backend upstreams it proxies to, each annotated with the enclosing vhost's
// server_name(s). Names are attached at block close so directive order inside a
// server block does not matter. Named upstreams are resolved to their member
// addresses.
func Discover(content string) []Upstream {
	toks := tokenize(stripComments(content))

	type frame struct {
		kind  string   // "server", "upstream", or "" (generic/location/http/...)
		name  string   // upstream name, for the "upstream NAME {" form
		names []string // server_name values (server frames)
		addrs []string // member addresses (upstream frames)
		refs  []ref    // proxy_pass references collected within a server frame
	}
	type pending struct {
		target string
		names  []string
	}

	var stack []*frame
	var cur []string                   // words of the in-progress directive
	upstreams := map[string][]string{} // upstream name -> member addresses
	var pendings []pending             // proxy_pass refs awaiting upstream resolution
	var direct []Upstream              // proxy_pass that named a host:port directly

	nearest := func(kind string) *frame {
		for i := len(stack) - 1; i >= 0; i-- {
			if stack[i].kind == kind {
				return stack[i]
			}
		}
		return nil
	}

	for i := 0; i < len(toks); i++ {
		switch toks[i] {
		case "{":
			f := &frame{}
			if len(cur) > 0 {
				switch cur[0] {
				case "server":
					f.kind = "server"
				case "upstream":
					f.kind = "upstream"
					if len(cur) > 1 {
						f.name = cur[1]
					}
				}
			}
			stack = append(stack, f)
			cur = nil
		case "}":
			if len(stack) > 0 {
				f := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if f.kind == "upstream" && f.name != "" {
					upstreams[f.name] = append(upstreams[f.name], f.addrs...)
				}
				if f.kind == "server" {
					names := dedup(f.names)
					for _, r := range f.refs {
						pendings = append(pendings, pending{target: r.target, names: names})
					}
				}
			}
			cur = nil
		case ";":
			if len(cur) > 0 {
				switch cur[0] {
				case "server_name":
					if f := nearest("server"); f != nil {
						f.names = append(f.names, cleanNames(cur[1:])...)
					}
				case "proxy_pass":
					if len(cur) >= 2 {
						if sf := nearest("server"); sf != nil {
							sf.refs = append(sf.refs, ref{target: cur[1]})
						} else {
							pendings = append(pendings, pending{target: cur[1]})
						}
					}
				case "server":
					// `server addr;` inside an upstream{} block.
					if uf := nearest("upstream"); uf != nil && len(cur) >= 2 {
						uf.addrs = append(uf.addrs, cur[1])
					}
				}
			}
			cur = nil
		default:
			cur = append(cur, toks[i])
		}
	}

	// Resolve every proxy_pass reference to one or more concrete upstreams.
	for _, p := range pendings {
		for _, u := range resolve(p.target, upstreams) {
			u.ServerNames = p.names
			direct = append(direct, u)
		}
	}
	return dedup2(direct)
}

type ref struct{ target string }

// resolve turns a single proxy_pass target into concrete upstreams. A direct
// scheme://host:port yields one; a named upstream expands to its members
// (carrying the named scheme); an unresolvable/variable target yields none.
func resolve(target string, upstreams map[string][]string) []Upstream {
	scheme, rest, ok := splitScheme(target)
	if !ok {
		return nil
	}
	hostport := stripPath(rest)
	if hostport == "" || strings.ContainsAny(hostport, "$ ") {
		return nil // variable or junk
	}
	// Named upstream? (no port, matches a known upstream{} name)
	if members, isnamed := upstreams[hostport]; isnamed {
		var out []Upstream
		for _, m := range members {
			if u, ok := parseHostPort(m); ok {
				u.Scheme = scheme
				out = append(out, u)
			}
		}
		return out
	}
	if u, ok := parseHostPort(hostport); ok {
		u.Scheme = scheme
		return []Upstream{u}
	}
	return nil
}

// splitScheme splits "http://rest" / "https://rest". A proxy_pass without a
// scheme (rare, e.g. to a unix: socket or a fastcgi pass) is not a host target
// we can suggest, so it is rejected.
func splitScheme(t string) (scheme, rest string, ok bool) {
	switch {
	case strings.HasPrefix(t, "https://"):
		return "https", t[len("https://"):], true
	case strings.HasPrefix(t, "http://"):
		return "http", t[len("http://"):], true
	}
	return "", "", false
}

// stripPath drops a trailing "/path" (and any query) from host[:port]/path.
func stripPath(s string) string {
	if i := strings.IndexAny(s, "/?"); i >= 0 {
		return s[:i]
	}
	return s
}

// parseHostPort parses "host" or "host:port" into an Upstream. A port must be a
// valid TCP port (1..65535); anything out of range, negative, or non-numeric is
// rejected (ok=false) rather than surfaced as a malformed suggestion. A bare host
// with no port is kept as host-only. The scanner must never emit a value it could
// not actually parse.
func parseHostPort(s string) (Upstream, bool) {
	if s == "" {
		return Upstream{}, false
	}
	// IPv6 in brackets: [::1]:8080 (the host itself contains colons).
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return Upstream{}, false
		}
		host := s[1:end]
		if host == "" {
			return Upstream{}, false
		}
		rest := s[end+1:]
		if rest == "" {
			return Upstream{Host: host}, true
		}
		if !strings.HasPrefix(rest, ":") {
			return Upstream{}, false // junk after the bracket, e.g. "[::1]x"
		}
		port, ok := parsePort(rest[1:])
		if !ok {
			return Upstream{}, false
		}
		return Upstream{Host: host, Port: port}, true
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		host := s[:i]
		port, ok := parsePort(s[i+1:])
		if !ok {
			// Non-numeric/out-of-range port. Keep the token as a host only if it
			// has no colon left in it; otherwise it is unparseable junk and is
			// dropped rather than glued back together as a host.
			if host == "" || strings.Contains(host, ":") {
				return Upstream{}, false
			}
			return Upstream{Host: host}, false
		}
		if host == "" {
			return Upstream{}, false
		}
		return Upstream{Host: host, Port: port}, true
	}
	return Upstream{Host: s}, true
}

// parsePort parses a TCP port string, accepting only 1..65535. Leading-plus,
// whitespace, or overflow all fail.
func parsePort(s string) (int, bool) {
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, false
	}
	return p, true
}

// cleanNames drops wildcard/regex/underscore server_name tokens that are not a
// useful suggestion label, keeping concrete hostnames.
func cleanNames(in []string) []string {
	var out []string
	for _, n := range in {
		n = strings.Trim(n, "\"'")
		if n == "" || n == "_" || strings.ContainsAny(n, "*~") {
			continue
		}
		out = append(out, n)
	}
	return out
}

// dedup returns the input with duplicates removed, order preserved.
func dedup(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// dedup2 collapses upstreams by addr, merging the server_names that reference
// the same backend, and returns them sorted by addr for stable output.
func dedup2(in []Upstream) []Upstream {
	byAddr := map[string]*Upstream{}
	var order []string
	for i := range in {
		u := in[i]
		key := u.Scheme + "|" + u.Addr()
		if e, ok := byAddr[key]; ok {
			e.ServerNames = dedup(append(e.ServerNames, u.ServerNames...))
			continue
		}
		cp := u
		cp.ServerNames = dedup(cp.ServerNames)
		byAddr[key] = &cp
		order = append(order, key)
	}
	if len(order) == 0 {
		return nil
	}
	sort.Strings(order)
	out := make([]Upstream, 0, len(order))
	for _, k := range order {
		out = append(out, *byAddr[k])
	}
	return out
}

// tokenize splits nginx config text into words plus the structural tokens
// "{", "}" and ";". Quotes are not interpreted beyond being kept inside a word;
// that is enough for the directives we care about (server_name, proxy_pass).
func tokenize(s string) []string {
	var toks []string
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			toks = append(toks, b.String())
			b.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '{', '}', ';':
			flush()
			toks = append(toks, string(c))
		case ' ', '\t', '\n', '\r', '\f', '\v':
			flush()
		default:
			b.WriteByte(c)
		}
	}
	flush()
	return toks
}

// stripComments removes "# ... EOL" comments. nginx has no block comments and
// '#' is not valid mid-token in the directives we read, so a line scan suffices.
func stripComments(s string) string {
	var out strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.String()
}

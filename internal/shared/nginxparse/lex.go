package nginxparse

import "strings"

// This file holds the tiny, dependency-free nginx tokenizer the mask parser
// uses. It is NOT a full nginx grammar — it recognizes the brace/semicolon
// structure (directives and nested blocks) well enough to walk a config while
// preserving the exact source text of anything it does not descend into. The
// parser layered on top (parse.go) decides which constructs map onto a Route;
// the lexer's only job is structure + verbatim preservation.

// directive is one `name args;` statement, with its verbatim source text kept so
// unrecognized directives can be preserved byte-for-byte in Result.Unparsed.
type directive struct {
	// name is the leading token, e.g. "proxy_pass".
	name string
	// args is everything after the name up to the terminating ";", trimmed.
	args string
	// raw is the verbatim source of the directive (sans the trailing ";"),
	// trimmed of surrounding whitespace, for loss-free preservation.
	raw string
}

// block is a `name [args] { ... }` construct (server, location, http, ...). It
// holds its direct child directives and nested blocks, plus the verbatim raw
// source of the whole block for loss-free preservation.
type block struct {
	// kind is the block's leading keyword, e.g. "server" or "location".
	kind string
	// args is the text between the kind and the opening brace, e.g. "/" for
	// `location / {`. Trimmed.
	args string
	// directives are the block's direct child statements (not those inside nested
	// blocks).
	directives []directive
	// blocks are nested child blocks (e.g. location inside server).
	blocks []block
	// raw is the verbatim source of the entire block including braces.
	raw string
}

// splitTopLevel parses the config into its top-level blocks and any leftover
// top-level text (comments, stray directives, blank lines collapsed away). It
// never loses input: every non-block, non-blank top-level statement is returned
// in leftover.
func splitTopLevel(content string) (blocks []block, leftover []string) {
	bs, dirs := parseBody(content)
	for _, d := range dirs {
		leftover = append(leftover, d.raw)
	}
	return bs, leftover
}

// parseBody parses a brace-body (or the whole file) into its direct child blocks
// and directives. Comments are skipped for structure but a comment that stands
// alone as a directive line is dropped from structure only — the enclosing block
// keeps its raw text, so nothing the parser preserves via .raw is lost.
func parseBody(s string) (blocks []block, directives []directive) {
	i := 0
	n := len(s)
	for i < n {
		// Skip whitespace.
		for i < n && isSpace(s[i]) {
			i++
		}
		if i >= n {
			break
		}
		// Skip comments to end of line.
		if s[i] == '#' {
			for i < n && s[i] != '\n' {
				i++
			}
			continue
		}
		// Read a statement up to the next ';' or '{' (respecting quotes).
		start := i
		var (
			brace   = -1
			semi    = -1
			inQuote byte
			escaped bool
		)
		for j := i; j < n; j++ {
			c := s[j]
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if inQuote != 0 {
				if c == inQuote {
					inQuote = 0
				}
				continue
			}
			if c == '"' || c == '\'' {
				inQuote = c
				continue
			}
			if c == '{' {
				brace = j
				break
			}
			if c == ';' {
				semi = j
				break
			}
		}

		if brace == -1 && semi == -1 {
			// Trailing text with no terminator: preserve as a directive-ish leftover.
			raw := strings.TrimSpace(s[start:])
			if raw != "" {
				directives = append(directives, directive{raw: raw})
			}
			break
		}

		if brace != -1 && (semi == -1 || brace < semi) {
			// Block: header is s[start:brace], body runs to the matching close brace.
			header := strings.TrimSpace(s[start:brace])
			bodyStart := brace + 1
			bodyEnd, ok := matchBrace(s, brace)
			if !ok {
				// Unbalanced braces: preserve the rest verbatim and stop.
				raw := strings.TrimSpace(s[start:])
				if raw != "" {
					directives = append(directives, directive{raw: raw})
				}
				break
			}
			body := s[bodyStart:bodyEnd]
			kind, args := splitHeader(header)
			childBlocks, childDirs := parseBody(body)
			blocks = append(blocks, block{
				kind:       kind,
				args:       args,
				directives: childDirs,
				blocks:     childBlocks,
				raw:        strings.TrimSpace(s[start : bodyEnd+1]),
			})
			i = bodyEnd + 1
			continue
		}

		// Directive ending at semi.
		raw := strings.TrimSpace(s[start:semi])
		if raw != "" {
			name, args := splitHeader(raw)
			directives = append(directives, directive{name: name, args: args, raw: raw})
		}
		i = semi + 1
	}
	return blocks, directives
}

// matchBrace returns the index of the '}' matching the '{' at open, honoring
// quotes and escapes, plus whether a match was found.
func matchBrace(s string, open int) (int, bool) {
	depth := 0
	var inQuote byte
	escaped := false
	for i := open; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inQuote = c
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

// splitHeader splits a statement/block header into its leading keyword and the
// remaining arguments (trimmed). For "location / " → ("location", "/").
func splitHeader(h string) (kind, args string) {
	h = strings.TrimSpace(h)
	idx := strings.IndexAny(h, " \t\n")
	if idx < 0 {
		return h, ""
	}
	return h[:idx], strings.TrimSpace(h[idx+1:])
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// findRootLocation returns the `location / {}` block in a server, if present.
func findRootLocation(s block) (block, bool) {
	for _, b := range s.blocks {
		if b.kind == "location" && b.args == "/" {
			return b, true
		}
	}
	return block{}, false
}

// isRedirectServer reports whether a server block is a pure HTTP→HTTPS redirect
// (a `return 301 https://...` with no proxy location), i.e. nginxgen's
// force-https companion.
func isRedirectServer(s block) bool {
	hasReturn := false
	for _, d := range s.directives {
		if d.name == "return" && strings.Contains(d.args, "301") && strings.Contains(d.args, "https://") {
			hasReturn = true
		}
	}
	// A redirect server has no proxy location.
	for _, b := range s.blocks {
		if b.kind == "location" {
			return false
		}
	}
	return hasReturn
}

// redirectMatches reports whether a redirect server is the force-https companion
// for the given host (its server_name matches).
func redirectMatches(s block, host string) bool {
	if host == "" {
		return false
	}
	for _, d := range s.directives {
		if d.name == "server_name" && strings.TrimSpace(d.args) == host {
			return true
		}
	}
	return false
}

package nginxparse

import (
	"errors"
	"strings"
)

// This file holds the dependency-free nginx tokenizer the mask parser and the
// managed-config policy share. It follows nginx's own ngx_conf_read_token rules
// (src/core/ngx_conf_file.c) so the statements it reports are the statements
// nginx itself would see:
//
//   - a quote opens a quoted token only at the start of a token; inside an
//     unquoted token `"` and `'` are ordinary characters;
//   - `#` starts a comment (to end of line) only at the start of a token, also
//     in the middle of a statement; inside a token it is an ordinary character;
//   - a backslash makes the next character literal, in and outside quotes;
//   - an unquoted token ends at whitespace, `;` or `{`, except that `{` right
//     after `$` belongs to a `${name}` variable reference; `}` only has meaning
//     at the start of a token;
//   - a closing quote must be followed by whitespace, `;`, `{` or `)`.
//
// On top of that structure the lexer keeps the exact source text of every
// statement, so text the parser does not understand can be preserved verbatim.

// token is one nginx configuration word.
type token struct {
	// value is the word as nginx stores it: quotes removed and the escapes
	// nginx resolves (\" \' \\ \t \r \n) applied.
	value string
	// source is the word's verbatim source text, including any quotes.
	source string
	// quote is the quote character that delimited the word, or 0 when unquoted.
	quote byte
}

// directive is one `name args;` statement, with its verbatim source text kept so
// unrecognized directives can be preserved byte-for-byte in Result.Unparsed.
type directive struct {
	// name is the verbatim source of the leading token, e.g. "proxy_pass". A
	// quoted name keeps its quotes, so it never matches a recognized directive.
	name string
	// args is everything after the name up to the terminating ";", trimmed.
	args string
	// raw is the verbatim source of the directive (sans the trailing ";"),
	// trimmed of surrounding whitespace, for loss-free preservation.
	raw string
	// tokens are the statement's words as nginx reads them, name first.
	tokens []token
	// comment reports that a comment appeared between the statement's words.
	comment bool
}

// block is a `name [args] { ... }` construct (server, location, http, ...). It
// holds its direct child directives and nested blocks, plus the verbatim raw
// source of the whole block for loss-free preservation.
type block struct {
	// kind is the verbatim source of the block's leading keyword, e.g. "server".
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
	// tokens are the header's words as nginx reads them, kind first.
	tokens []token
	// comment reports that a comment appeared between the header's words.
	comment bool
}

// statementEnd says how nginx's tokenizer finished a statement.
type statementEnd int

const (
	endDirective  statementEnd = iota // terminated by ';'
	endBlockStart                     // terminated by '{'
	endBlockDone                      // a '}' closing the enclosing block
	endFile                           // end of input with no pending words
)

// errSyntax marks input nginx's tokenizer refuses (unbalanced braces, a missing
// terminator, a quote not followed by a separator, ...).
var errSyntax = errors.New("nginx configuration syntax error")

// statement is one tokenizer step: the words read and how they ended.
type statement struct {
	tokens []token
	end    statementEnd
	// start is the source offset of the first word (or of the terminator when
	// there are no words); stop is the offset of the terminating character.
	start, stop int
	// next is the offset right after the terminator.
	next int
	// comment reports a comment between the statement's words.
	comment bool
}

// readStatement reads the next statement starting at offset i, following
// ngx_conf_read_token.
func readStatement(s string, i int) (statement, error) {
	var (
		st        = statement{start: -1}
		lastSpace = true
		needSpace bool
		dQuoted   bool
		sQuoted   bool
		quoted    bool
		sharp     bool
		variable  bool
		wordStart int // first byte of the word's value
		srcStart  int // first byte of the word's source (the quote, if any)
	)
	finish := func(end statementEnd, at int) (statement, error) {
		st.end = end
		st.stop = at
		st.next = at + 1
		if st.start < 0 {
			st.start = at
		}
		return st, nil
	}
	for ; i < len(s); i++ {
		ch := s[i]
		if ch == '\n' {
			sharp = false
		}
		if sharp {
			continue
		}
		if quoted {
			quoted = false
			continue
		}
		if needSpace {
			if isSpace(ch) {
				lastSpace = true
				needSpace = false
				continue
			}
			switch ch {
			case ';':
				return finish(endDirective, i)
			case '{':
				return finish(endBlockStart, i)
			case ')':
				lastSpace = true
				needSpace = false
			default:
				return st, errSyntax
			}
		}
		if lastSpace {
			wordStart, srcStart = i, i
			if isSpace(ch) {
				continue
			}
			switch ch {
			case ';', '{':
				if len(st.tokens) == 0 {
					return st, errSyntax
				}
				if ch == '{' {
					return finish(endBlockStart, i)
				}
				return finish(endDirective, i)
			case '}':
				if len(st.tokens) != 0 {
					return st, errSyntax
				}
				return finish(endBlockDone, i)
			case '#':
				sharp = true
				if len(st.tokens) != 0 {
					st.comment = true
				}
				continue
			case '\\':
				quoted = true
				lastSpace = false
			case '"':
				wordStart++
				dQuoted = true
				lastSpace = false
			case '\'':
				wordStart++
				sQuoted = true
				lastSpace = false
			case '$':
				variable = true
				lastSpace = false
			default:
				lastSpace = false
			}
			if st.start < 0 {
				st.start = srcStart
			}
			continue
		}
		if ch == '{' && variable {
			continue
		}
		variable = false
		if ch == '\\' {
			quoted = true
			continue
		}
		if ch == '$' {
			variable = true
			continue
		}
		found := false
		var quote byte
		switch {
		case dQuoted:
			if ch == '"' {
				dQuoted, needSpace, found, quote = false, true, true, '"'
			}
		case sQuoted:
			if ch == '\'' {
				sQuoted, needSpace, found, quote = false, true, true, '\''
			}
		case isSpace(ch) || ch == ';' || ch == '{':
			lastSpace, found = true, true
		}
		if !found {
			continue
		}
		srcEnd := i
		if quote != 0 {
			srcEnd = i + 1
		}
		st.tokens = append(st.tokens, token{value: unescapeWord(s[wordStart:i]), source: s[srcStart:srcEnd], quote: quote})
		switch ch {
		case ';':
			return finish(endDirective, i)
		case '{':
			return finish(endBlockStart, i)
		}
	}
	if len(st.tokens) != 0 || !lastSpace {
		return st, errSyntax
	}
	return finish(endFile, len(s))
}

// unescapeWord applies the escapes nginx resolves when it stores a word.
func unescapeWord(w string) string {
	if !strings.Contains(w, `\`) {
		return w
	}
	var b strings.Builder
	for i := 0; i < len(w); i++ {
		if w[i] == '\\' && i+1 < len(w) {
			switch w[i+1] {
			case '"', '\'', '\\':
				i++
			case 't':
				b.WriteByte('\t')
				i++
				continue
			case 'r':
				b.WriteByte('\r')
				i++
				continue
			case 'n':
				b.WriteByte('\n')
				i++
				continue
			}
		}
		b.WriteByte(w[i])
	}
	return b.String()
}

// splitTopLevel parses the config into its top-level blocks and any leftover
// top-level text (stray directives, or everything from a statement nginx would
// refuse onward). It never loses input: every non-block top-level statement is
// returned in leftover.
func splitTopLevel(content string) (blocks []block, leftover []string) {
	bs, dirs, _ := parseConfig(content)
	for _, d := range dirs {
		leftover = append(leftover, d.raw)
	}
	return bs, leftover
}

// parseConfig parses a whole config file. On a syntax error it returns what it
// parsed so far plus the rest of the input, from the failing top-level
// statement on, as one raw directive, together with errSyntax.
func parseConfig(s string) ([]block, []directive, error) {
	var (
		blocks     []block
		directives []directive
	)
	i := 0
	for {
		stmtStart := i
		bs, ds, next, done, err := parseStatement(s, i, 0)
		if err != nil {
			if raw := strings.TrimSpace(s[stmtStart:]); raw != "" {
				directives = append(directives, directive{raw: raw})
			}
			return blocks, directives, err
		}
		blocks = append(blocks, bs...)
		directives = append(directives, ds...)
		if done {
			return blocks, directives, nil
		}
		i = next
	}
}

// parseStatement reads one statement at offset i inside a body at the given
// depth. It returns the block or directive it produced (if any), the offset of
// the next statement, and done=true when the body ended (a matching '}' at
// depth > 0, or end of input at depth 0).
func parseStatement(s string, i, depth int) ([]block, []directive, int, bool, error) {
	st, err := readStatement(s, i)
	if err != nil {
		return nil, nil, 0, false, err
	}
	switch st.end {
	case endFile:
		if depth != 0 {
			return nil, nil, 0, false, errSyntax
		}
		return nil, nil, st.next, true, nil
	case endBlockDone:
		if depth == 0 {
			return nil, nil, 0, false, errSyntax
		}
		return nil, nil, st.next, true, nil
	case endDirective:
		name := st.tokens[0].source
		nameEnd := st.start + len(name)
		return nil, []directive{{
			name:    name,
			args:    strings.TrimSpace(s[nameEnd:st.stop]),
			raw:     strings.TrimSpace(s[st.start:st.stop]),
			tokens:  st.tokens,
			comment: st.comment,
		}}, st.next, false, nil
	}
	// Block: parse the body up to the matching '}'.
	kind := st.tokens[0].source
	b := block{
		kind:    kind,
		args:    strings.TrimSpace(s[st.start+len(kind) : st.stop]),
		tokens:  st.tokens,
		comment: st.comment,
	}
	j := st.next
	for {
		bs, ds, next, done, err := parseStatement(s, j, depth+1)
		if err != nil {
			return nil, nil, 0, false, err
		}
		b.blocks = append(b.blocks, bs...)
		b.directives = append(b.directives, ds...)
		j = next
		if done {
			break
		}
	}
	b.raw = strings.TrimSpace(s[st.start:j])
	return []block{b}, nil, j, false, nil
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

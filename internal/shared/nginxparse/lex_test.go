package nginxparse

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

type lexTestStatement struct {
	words   []string
	end     statementEnd
	comment bool
}

// lexTestStatements runs readStatement over the whole input.
func lexTestStatements(s string) ([]lexTestStatement, bool) {
	var out []lexTestStatement
	for i := 0; ; {
		st, err := readStatement(s, i)
		if err != nil {
			return out, false
		}
		var words []string
		for _, tok := range st.tokens {
			words = append(words, tok.value)
		}
		out = append(out, lexTestStatement{words: words, end: st.end, comment: st.comment})
		if st.end == endFile {
			return out, true
		}
		i = st.next
	}
}

func TestReadStatementFollowsNginxTokenizer(t *testing.T) {
	end := func(words ...string) lexTestStatement { return lexTestStatement{words: words, end: endDirective} }
	open := func(words ...string) lexTestStatement { return lexTestStatement{words: words, end: endBlockStart} }
	closeBlock := lexTestStatement{end: endBlockDone}
	eof := lexTestStatement{end: endFile}
	tests := []struct {
		name  string
		input string
		want  []lexTestStatement
		ok    bool
	}{
		{"simple", "a b;", []lexTestStatement{end("a", "b"), eof}, true},
		{"block", "s { a 1; }", []lexTestStatement{open("s"), end("a", "1"), closeBlock, eof}, true},
		{"quoted", `a "b c" 'd;e';`, []lexTestStatement{end("a", "b c", "d;e"), eof}, true},
		{"quote inside word is literal", `a b"c; d;`, []lexTestStatement{end("a", `b"c`), end("d"), eof}, true},
		{"single quote inside word is literal", `a b'c; d;`, []lexTestStatement{end("a", "b'c"), end("d"), eof}, true},
		{"hash inside word is literal", `a b#c; d;`, []lexTestStatement{end("a", "b#c"), end("d"), eof}, true},
		{"comment at word start mid statement", "a b #c;\n d;", []lexTestStatement{{words: []string{"a", "b", "d"}, end: endDirective, comment: true}, eof}, true},
		{"comment line", "# x; y {\na;", []lexTestStatement{end("a"), eof}, true},
		{"quoted name", `"a" b;`, []lexTestStatement{end("a", "b"), eof}, true},
		{"escaped name", `\a b;`, []lexTestStatement{end(`\a`, "b"), eof}, true},
		{"escaped separator", `a b\;c;`, []lexTestStatement{end("a", `b\;c`), eof}, true},
		{"escapes resolved", `a "x\"y\\z\n";`, []lexTestStatement{end("a", "x\"y\\z\n"), eof}, true},
		{"variable braces stay in word", `a ${b}c;`, []lexTestStatement{end("a", "${b}c"), eof}, true},
		{"brace ends word", `a b{`, []lexTestStatement{open("a", "b"), eof}, true},
		{"close brace inside word is literal", `a b}c;`, []lexTestStatement{end("a", "b}c"), eof}, true},
		{"paren after quote", `a "b");`, []lexTestStatement{end("a", "b", ")"), eof}, true},
		{"text after quote", `a "b"c;`, nil, false},
		{"semicolon without words", `;`, nil, false},
		{"close brace after words", `a }`, nil, false},
		{"unterminated", `a b`, nil, false},
		{"unterminated quote", `a "b;`, nil, false},
		{"empty", "  \n# c\n", []lexTestStatement{eof}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := lexTestStatements(tt.input)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v (got %+v)", ok, tt.ok, got)
			}
			if tt.want != nil && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("statements = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// lexTestReference is an independent, word-at-a-time reading of nginx's
// tokenizer rules used to cross-check readStatement.
func lexTestReference(s string) ([]lexTestStatement, bool) {
	var out []lexTestStatement
	i := 0
	for {
		var cur lexTestStatement
		for {
			for i < len(s) && isSpace(s[i]) {
				i++
			}
			if i >= len(s) {
				if len(cur.words) != 0 {
					return out, false
				}
				cur.end = endFile
				return append(out, cur), true
			}
			c := s[i]
			if c == '#' {
				if len(cur.words) != 0 {
					cur.comment = true
				}
				for i < len(s) && s[i] != '\n' {
					i++
				}
				continue
			}
			if c == ';' || c == '{' {
				if len(cur.words) == 0 {
					return out, false
				}
				i++
				cur.end = endDirective
				if c == '{' {
					cur.end = endBlockStart
				}
				break
			}
			if c == '}' {
				if len(cur.words) != 0 {
					return out, false
				}
				i++
				cur.end = endBlockDone
				break
			}
			if c == '"' || c == '\'' {
				j := i + 1
				for j < len(s) && s[j] != c {
					if s[j] == '\\' {
						j++
					}
					j++
				}
				if j >= len(s) {
					return out, false
				}
				cur.words = append(cur.words, lexTestUnescape(s[i+1:j]))
				i = j + 1
				if i >= len(s) {
					return out, false
				}
				switch s[i] {
				case ' ', '\t', '\r', '\n', ')':
					continue
				case ';', '{':
					cur.end = endDirective
					if s[i] == '{' {
						cur.end = endBlockStart
					}
					i++
				default:
					return out, false
				}
				break
			}
			j := i
			dollar := false
			for {
				if j >= len(s) {
					return out, false
				}
				ch := s[j]
				if ch == '\\' {
					dollar = false
					j += 2
					continue
				}
				if ch == '{' && dollar {
					j++
					continue
				}
				if isSpace(ch) || ch == ';' || ch == '{' {
					break
				}
				dollar = ch == '$'
				j++
			}
			cur.words = append(cur.words, lexTestUnescape(s[i:j]))
			i = j
			if s[j] == ';' || s[j] == '{' {
				cur.end = endDirective
				if s[j] == '{' {
					cur.end = endBlockStart
				}
				i++
				break
			}
		}
		out = append(out, cur)
	}
}

func lexTestUnescape(w string) string {
	r := strings.NewReplacer(`\"`, `"`, `\'`, `'`, `\\`, `\`, `\t`, "\t", `\r`, "\r", `\n`, "\n")
	return r.Replace(w)
}

// TestReadStatementMatchesReferenceTokenizer feeds random configs built from
// the characters nginx's tokenizer treats specially and requires readStatement
// to produce exactly the reference statement stream.
func TestReadStatementMatchesReferenceTokenizer(t *testing.T) {
	pieces := []string{"a", "b", "error_log", "$", "{", "}", ";", `"`, "'", `\`, "#", " ", "\n", "\t", ")", "x/y", "${v}"}
	rng := rand.New(rand.NewSource(1))
	for n := 0; n < 50000; n++ {
		var b strings.Builder
		for k := rng.Intn(24); k >= 0; k-- {
			b.WriteString(pieces[rng.Intn(len(pieces))])
		}
		input := b.String()
		got, gotOK := lexTestStatements(input)
		want, wantOK := lexTestReference(input)
		if gotOK != wantOK || !reflect.DeepEqual(got, want) {
			t.Fatalf("input %q:\n got  %v %+v\n want %v %+v", input, gotOK, got, wantOK, want)
		}
	}
}

// TestParseConfigKeepsSourceAndNginxView checks that the block tree carries both
// the verbatim source the mask parser preserves and nginx's reading of it.
func TestParseConfigKeepsSourceAndNginxView(t *testing.T) {
	content := "server {\n    # c\n    add_header X-A a\"b;\n    \"error_log\" x;\n    location / { proxy_pass http://h:1; }\n}\n"
	blocks, leftover, err := parseConfig(content)
	if err != nil || len(leftover) != 0 || len(blocks) != 1 {
		t.Fatalf("parseConfig = %d blocks, %v leftover, %v", len(blocks), leftover, err)
	}
	server := blocks[0]
	if len(server.directives) != 2 || len(server.blocks) != 1 {
		t.Fatalf("server = %+v", server)
	}
	if d := server.directives[0]; d.name != "add_header" || d.args != `X-A a"b` || d.tokens[2].value != `a"b` {
		t.Fatalf("add_header = %+v", d)
	}
	if d := server.directives[1]; d.name != `"error_log"` || d.tokens[0].value != "error_log" || d.tokens[0].quote != '"' {
		t.Fatalf("quoted name = %+v", d)
	}
	if loc := server.blocks[0]; loc.kind != "location" || loc.args != "/" || loc.raw != "location / { proxy_pass http://h:1; }" {
		t.Fatalf("location = %+v", loc)
	}
	if server.raw != strings.TrimSpace(content) {
		t.Fatalf("server raw = %q", server.raw)
	}
}

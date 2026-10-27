package apachegen

import (
	"math/rand"
	"strings"
	"testing"
)

// apacheGetwordConf follows ap_getword_conf and substring_conf in httpd's
// server/util.c: it reads one word from a directive line and returns it with
// the rest of the line.
func apacheGetwordConf(line string) (string, string) {
	line = strings.TrimLeft(line, " \t")
	if line == "" {
		return "", ""
	}
	quote := byte(0)
	if line[0] == '"' || line[0] == '\'' {
		quote = line[0]
	}
	var raw, rest string
	if quote != 0 {
		end := 1
		for end < len(line) && line[end] != quote {
			if line[end] == '\\' && end+1 < len(line) && (line[end+1] == quote || line[end+1] == '\\') {
				end += 2
			} else {
				end++
			}
		}
		raw = line[1:end]
		if end < len(line) {
			end++
		}
		rest = line[end:]
	} else {
		end := strings.IndexAny(line, " \t")
		if end < 0 {
			end = len(line)
		}
		raw, rest = line[:end], line[end:]
	}
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' && i+1 < len(raw) && (raw[i+1] == '\\' || (quote != 0 && raw[i+1] == quote)) {
			i++
		}
		b.WriteByte(raw[i])
	}
	return b.String(), strings.TrimLeft(rest, " \t")
}

// modHeadersLiteral follows mod_headers' parse_misc_string and the "%%"
// case of parse_format_tag for a format string without other specifiers.
// ok is false when the string would be evaluated (expr=) or holds another
// format specifier.
func modHeadersLiteral(s string) (string, bool) {
	if strings.HasPrefix(s, "expr=") {
		return "", false
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '%':
			if i+1 < len(s) && s[i+1] != '%' {
				return "", false
			}
			b.WriteByte('%')
			i++
		case '\\':
			if i+1 < len(s) {
				switch s[i+1] {
				case '\\':
					b.WriteByte('\\')
					i++
					continue
				case 'r', 'n', 't':
					return "", false
				}
			}
			b.WriteByte('\\')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String(), true
}

// TestHeaderValueReachesModHeadersLiterally renders values through
// headerValue and reads them back the way Apache and mod_headers do: the
// directive must get exactly one word, and mod_headers must set exactly the
// stored value.
func TestHeaderValueReachesModHeadersLiterally(t *testing.T) {
	values := []string{
		"", "plain", "a b", `say "hi"`, `'expr=%{file:/etc/passwd}'`, `"expr=1"`, `a\`, `\"`, `a\\b`,
		`\n`, "100%", "%{HOME}e", "x expr=1", `'`, `"`, ` "lead`, `a" early`, `${HOME}`,
	}
	pieces := []string{"a", " ", `"`, "'", `\`, "%", "{", "}", "e", "expr=", "n", "$"}
	rng := rand.New(rand.NewSource(1))
	for n := 0; n < 20000; n++ {
		var b strings.Builder
		for k := rng.Intn(10); k >= 0; k-- {
			b.WriteString(pieces[rng.Intn(len(pieces))])
		}
		values = append(values, b.String())
	}
	for _, v := range values {
		if strings.HasPrefix(v, "expr=") {
			// mod_headers has no escape for a leading "expr="; proxymodel
			// refuses such values before rendering.
			continue
		}
		rendered := headerValue(v)
		word, rest := apacheGetwordConf(rendered + " ")
		if rest != "" {
			t.Fatalf("headerValue(%q) = %s is more than one word (rest %q)", v, rendered, rest)
		}
		got, ok := modHeadersLiteral(word)
		if !ok || got != v {
			t.Fatalf("headerValue(%q) = %s reaches mod_headers as %q (literal=%v)", v, rendered, got, ok)
		}
	}
	if got, _ := apacheGetwordConf(quoteValue(`Restricted: a "b" \c`)); got != `Restricted: a "b" \c` {
		t.Fatalf("quoteValue round trip = %q", got)
	}
}

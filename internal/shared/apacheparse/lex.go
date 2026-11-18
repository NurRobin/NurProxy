// Package apacheparse reads Apache httpd vhost configs the way httpd's config
// reader does and checks them against the policy the privileged helper
// enforces before it writes a vhost as root.
package apacheparse

import (
	"fmt"
	"strings"
)

// MaxLineBytes bounds a config line. httpd reads a line into an 8192-byte
// buffer (MAX_STRING_LEN) and refuses longer ones; the margin keeps admitted
// configs clear of that limit.
const MaxLineBytes = 8000

// word is one argument as httpd's ap_getword_conf returns it.
type word struct {
	// value is the argument with quotes removed and the escapes httpd
	// resolves (\\ and, inside quotes, \" or \') applied.
	value string
	// source is the verbatim text, including quotes.
	source string
	// quote is the quote character that delimited the word, or 0.
	quote byte
}

// directive is one `Name args...` line.
type directive struct {
	line int
	name string
	args []word
}

// section is a `<Name args>` ... `</Name>` container.
type section struct {
	line       int
	name       string
	args       []word
	directives []directive
	sections   []section
}

// PolicyError is a policy refusal. It names the config line and directive
// so the operator can find what to change.
type PolicyError struct {
	Line      int
	Directive string
	Reason    string
}

func (e *PolicyError) Error() string {
	switch {
	case e.Line > 0 && e.Directive != "":
		return fmt.Sprintf("line %d: %s: %s", e.Line, e.Directive, e.Reason)
	case e.Line > 0:
		return fmt.Sprintf("line %d: %s", e.Line, e.Reason)
	default:
		return e.Reason
	}
}

func refuse(line int, name, format string, args ...any) error {
	return &PolicyError{Line: line, Directive: name, Reason: fmt.Sprintf(format, args...)}
}

// parse splits content into top-level directives and sections. It is
// stricter than httpd where httpd's reading is easy to misjudge: it refuses
// control characters, line continuations, "${" (httpd replaces it with an
// environment variable or Define before any module sees the line),
// unterminated quotes and a closing quote that is not followed by a space.
func parse(content string) ([]directive, []section, error) {
	for i := 0; i < len(content); i++ {
		if c := content[i]; (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			return nil, nil, refuse(0, "", "config contains control characters")
		}
	}
	root := &section{}
	stack := []*section{root}
	for index, raw := range strings.Split(content, "\n") {
		lineNo := index + 1
		if len(raw) > MaxLineBytes {
			return nil, nil, refuse(lineNo, "", "line is longer than %d bytes", MaxLineBytes)
		}
		line := strings.Trim(raw, " \t\r")
		// httpd joins a line ending in a backslash with the next one before
		// it looks for comments, so "# note \" would swallow the following
		// directive. Continuations are refused everywhere, comments included.
		if strings.HasSuffix(line, `\`) {
			return nil, nil, refuse(lineNo, "", "line continuations are not allowed (also not in comments)")
		}
		if line == "" || line[0] == '#' {
			continue
		}
		if strings.ContainsRune(line, '\r') {
			return nil, nil, refuse(lineNo, "", "line contains a carriage return")
		}
		if strings.Contains(line, "${") {
			return nil, nil, refuse(lineNo, "", "\"${\" is not allowed: Apache replaces it with an environment variable or Define value")
		}
		current := stack[len(stack)-1]
		switch {
		case strings.HasPrefix(line, "</"):
			if !strings.HasSuffix(line, ">") {
				return nil, nil, refuse(lineNo, "", "section end is not closed with '>'")
			}
			name := strings.TrimSpace(line[2 : len(line)-1])
			if len(stack) == 1 || !strings.EqualFold(name, current.name) {
				return nil, nil, refuse(lineNo, name, "section end does not match an open section")
			}
			stack = stack[:len(stack)-1]
			parent := stack[len(stack)-1]
			parent.sections = append(parent.sections, *current)
		case strings.HasPrefix(line, "<"):
			if !strings.HasSuffix(line, ">") || len(line) < 3 {
				return nil, nil, refuse(lineNo, "", "section start is not closed with '>'")
			}
			words, err := splitWords(line[1 : len(line)-1])
			if err != nil {
				return nil, nil, refuse(lineNo, "", "%v", err)
			}
			if len(words) == 0 || words[0].quote != 0 || words[0].value == "" {
				return nil, nil, refuse(lineNo, "", "section name is not a plain word")
			}
			stack = append(stack, &section{line: lineNo, name: words[0].value, args: words[1:]})
		default:
			words, err := splitWords(line)
			if err != nil {
				return nil, nil, refuse(lineNo, "", "%v", err)
			}
			if len(words) == 0 || words[0].quote != 0 {
				return nil, nil, refuse(lineNo, "", "directive name is not a plain word")
			}
			current.directives = append(current.directives, directive{line: lineNo, name: words[0].value, args: words[1:]})
		}
	}
	if len(stack) != 1 {
		open := stack[len(stack)-1]
		return nil, nil, refuse(open.line, "<"+open.name+">", "section is never closed")
	}
	return root.directives, root.sections, nil
}

// splitWords splits a line into words like httpd's ap_getword_conf.
func splitWords(s string) ([]word, error) {
	var words []word
	i := 0
	for {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			return words, nil
		}
		start := i
		if q := s[i]; q == '"' || q == '\'' {
			var value strings.Builder
			i++
			closed := false
			for i < len(s) {
				c := s[i]
				if c == '\\' && i+1 < len(s) && (s[i+1] == '\\' || s[i+1] == q) {
					value.WriteByte(s[i+1])
					i += 2
					continue
				}
				if c == q {
					closed = true
					i++
					break
				}
				value.WriteByte(c)
				i++
			}
			if !closed {
				return nil, fmt.Errorf("quoted argument is not closed")
			}
			if i < len(s) && s[i] != ' ' && s[i] != '\t' {
				return nil, fmt.Errorf("closing quote is not followed by a space")
			}
			words = append(words, word{value: value.String(), source: s[start:i], quote: q})
			continue
		}
		for i < len(s) && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		src := s[start:i]
		var value strings.Builder
		for j := 0; j < len(src); j++ {
			if src[j] == '\\' && j+1 < len(src) && src[j+1] == '\\' {
				j++
			}
			value.WriteByte(src[j])
		}
		words = append(words, word{value: value.String(), source: src})
	}
}

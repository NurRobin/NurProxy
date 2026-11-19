package nginxdiscover

import (
	"path/filepath"
	"strings"
)

// CertRef is one certificate/key file pair an nginx config serves TLS with,
// as written in its ssl_certificate and ssl_certificate_key directives.
type CertRef struct {
	CertPath string
	KeyPath  string
}

// CertRefs returns the ssl_certificate / ssl_certificate_key pairs in an nginx
// config. A block that sets only one of the two inherits the other from the
// nearest enclosing block, as nginx does. Several certificates in one block
// (an RSA plus an ECDSA bundle) pair with their keys in order. Relative paths
// are resolved against prefix, nginx's configuration prefix; paths containing
// variables are skipped because their value is only known per request.
func CertRefs(content, prefix string) []CertRef {
	type frame struct {
		certs []string
		keys  []string
	}
	stack := []*frame{{}} // the bottom frame is the main (top-level) context
	var cur []string
	var out []CertRef
	seen := map[CertRef]bool{}

	// emit records the pairs a block defines, filling a missing half from the
	// enclosing blocks stack[:depth].
	emit := func(f *frame, depth int) {
		if len(f.certs) == 0 && len(f.keys) == 0 {
			return
		}
		certs, keys := f.certs, f.keys
		parents := stack[:depth]
		if len(certs) == 0 {
			for i := len(parents) - 1; i >= 0 && len(certs) == 0; i-- {
				certs = parents[i].certs
			}
		}
		if len(keys) == 0 {
			for i := len(parents) - 1; i >= 0 && len(keys) == 0; i-- {
				keys = parents[i].keys
			}
		}
		for i := 0; i < len(certs) && i < len(keys); i++ {
			ref := CertRef{CertPath: resolvePath(certs[i], prefix), KeyPath: resolvePath(keys[i], prefix)}
			if ref.CertPath == "" || ref.KeyPath == "" || seen[ref] {
				continue
			}
			seen[ref] = true
			out = append(out, ref)
		}
	}
	for _, tok := range tokenize(stripComments(content)) {
		switch tok {
		case "{":
			stack = append(stack, &frame{})
			cur = nil
		case "}":
			if len(stack) > 1 {
				f := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				emit(f, len(stack))
			}
			cur = nil
		case ";":
			if len(cur) >= 2 {
				f := stack[len(stack)-1]
				switch cur[0] {
				case "ssl_certificate":
					f.certs = append(f.certs, unquote(cur[1]))
				case "ssl_certificate_key":
					f.keys = append(f.keys, unquote(cur[1]))
				}
			}
			cur = nil
		default:
			cur = append(cur, tok)
		}
	}
	emit(stack[0], 0)
	return out
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// resolvePath makes a directive path absolute the way nginx does. Variable
// paths and nginx's "data:" inline form cannot be read from disk and yield "".
func resolvePath(p, prefix string) string {
	if p == "" || strings.Contains(p, "$") || strings.HasPrefix(p, "data:") || strings.HasPrefix(p, "engine:") {
		return ""
	}
	if !filepath.IsAbs(p) {
		if prefix == "" {
			return ""
		}
		p = filepath.Join(prefix, p)
	}
	return filepath.Clean(p)
}

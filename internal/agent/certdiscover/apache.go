package certdiscover

import (
	"path/filepath"
	"strings"
)

// ApacheRefs returns the certificate files an Apache configuration serves TLS
// with. Each <VirtualHost> yields its SSLCertificateFile with the matching
// SSLCertificateKeyFile (or the certificate file itself, which may hold the
// key) and SSLCertificateChainFile. Directives outside a virtual host form one
// more pair, the server-wide default. Relative paths resolve against
// serverRoot; paths with variables are skipped.
func ApacheRefs(content, serverRoot string) []Pair {
	type scope struct{ cert, key, chain string }
	var out []Pair
	seen := map[Pair]bool{}
	emit := func(s scope) {
		cert := apachePath(s.cert, serverRoot)
		if cert == "" {
			return
		}
		key := apachePath(s.key, serverRoot)
		if key == "" {
			key = cert
		}
		p := Pair{CertPath: cert, KeyPath: key, ChainPath: apachePath(s.chain, serverRoot), Source: SourceApache}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}

	var global, vhost scope
	inVhost := false
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "<virtualhost"):
			inVhost, vhost = true, scope{}
			continue
		case strings.HasPrefix(lower, "</virtualhost"):
			if inVhost {
				if vhost.cert == "" {
					vhost.cert = global.cert
				}
				if vhost.key == "" && vhost.cert == global.cert {
					vhost.key = global.key
				}
				if vhost.chain == "" {
					vhost.chain = global.chain
				}
				emit(vhost)
			}
			inVhost = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		target := &global
		if inVhost {
			target = &vhost
		}
		value := unquote(fields[1])
		switch strings.ToLower(fields[0]) {
		case "sslcertificatefile":
			target.cert = value
		case "sslcertificatekeyfile":
			target.key = value
		case "sslcertificatechainfile":
			target.chain = value
		}
	}
	emit(global)
	return out
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

func apachePath(p, serverRoot string) string {
	if p == "" || strings.Contains(p, "${") || strings.Contains(p, "%{") {
		return ""
	}
	if !filepath.IsAbs(p) {
		if serverRoot == "" {
			return ""
		}
		p = filepath.Join(serverRoot, p)
	}
	return filepath.Clean(p)
}

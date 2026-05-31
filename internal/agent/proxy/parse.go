package proxy

import (
	"os"
	"regexp"
	"strconv"
	"strings"
)

// versionRe matches a dotted version number like 1.24.0 or 2.7.6.
var versionRe = regexp.MustCompile(`\d+\.\d+(?:\.\d+)*`)

// ParseVersion extracts a version string from the raw output of the proxy's
// version command. It is a pure function (no host access) so it can be
// table-driven tested against captured sample outputs.
//
//   - nginx -v      -> "nginx version: nginx/1.24.0 (Ubuntu)"
//   - apachectl -v  -> "Server version: Apache/2.4.58 (Ubuntu)"
//   - httpd -v      -> "Server version: Apache/2.4.57 (Red Hat ...)"
//   - caddy version -> "v2.7.6 h1:..."
func ParseVersion(kind Kind, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	switch kind {
	case KindCaddy:
		// caddy prints "v2.7.6 h1:..."; trim the leading v and take the version.
		if m := versionRe.FindString(strings.TrimPrefix(raw, "v")); m != "" {
			return m
		}
	default:
		// nginx/apache print "<name>/<version>"; find the first dotted version.
		if m := versionRe.FindString(raw); m != "" {
			return m
		}
	}
	return ""
}

// Paths holds the resolved §9 OS-default locations for a proxy kind.
type Paths struct {
	ConfigDir string
	LogPaths  []string
}

// ResolvePaths returns the §9 OS-default config dir and log paths for a proxy
// kind, preferring whichever default directory actually exists on disk. This
// lets one binary serve both Debian/Ubuntu and RHEL/Fedora layouts (nginx
// sites-available vs conf.d; apache2 vs httpd). It is a pure-ish function: the
// only host interaction is dir existence, injected via the package-level
// dirExists hook for tests.
func ResolvePaths(kind Kind) Paths {
	switch kind {
	case KindNginx:
		// Debian/Ubuntu: sites-available + sites-enabled. RHEL/Fedora: conf.d.
		cfg := firstExistingDir(
			"/etc/nginx/sites-available",
			"/etc/nginx/conf.d",
			"/etc/nginx",
		)
		return Paths{
			ConfigDir: cfg,
			LogPaths: existingFiles(
				"/var/log/nginx/error.log",
				"/var/log/nginx/access.log",
			),
		}
	case KindApache:
		// Debian: sites-available. RHEL: conf.d. Fall back to the base dir.
		cfg := firstExistingDir(
			"/etc/apache2/sites-available",
			"/etc/httpd/conf.d",
			"/etc/apache2",
			"/etc/httpd",
		)
		logs := existingFiles(
			"/var/log/apache2/error.log",
			"/var/log/apache2/access.log",
			"/var/log/httpd/error_log",
			"/var/log/httpd/access_log",
		)
		return Paths{ConfigDir: cfg, LogPaths: logs}
	case KindCaddy:
		// Caddy uses a single Caddyfile dir plus the admin API on :2019.
		cfg := firstExistingDir("/etc/caddy")
		return Paths{
			ConfigDir: cfg,
			LogPaths:  existingFiles("/var/log/caddy/access.log"),
		}
	}
	return Paths{}
}

// dirExists is the existence check used by path resolution. It is a package
// variable so tests can stub it with a synthetic filesystem layout.
var dirExists = func(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// fileExists mirrors dirExists for log files; also a hook for tests.
var fileExists = func(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// firstExistingDir returns the first candidate directory that exists, or — if
// none exist — the first candidate (the primary §9 default), so detection still
// reports the canonical location even on a host where it hasn't been created.
func firstExistingDir(candidates ...string) string {
	for _, c := range candidates {
		if dirExists(c) {
			return c
		}
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	return ""
}

// existingFiles returns the subset of candidate files that exist on disk.
func existingFiles(candidates ...string) []string {
	var out []string
	for _, c := range candidates {
		if fileExists(c) {
			out = append(out, c)
		}
	}
	return out
}

// listener is one parsed listening socket from `ss -ltnp`.
type listener struct {
	port    int
	process string
	pid     int
}

// ssProcRe extracts the process name and pid from an ss "users:(...)" field,
// e.g. users:(("nginx",pid=1234,fd=6)).
var ssProcRe = regexp.MustCompile(`users:\(\("([^"]+)",pid=(\d+)`)

// ParseSSOutput parses the output of `ss -ltnp` into the listening sockets it
// describes. It is a pure function so the §2.1 conflict logic can be tested
// against captured ss output without a real host.
//
// Example line (header skipped):
//
//	LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=1234,fd=6),...)
func ParseSSOutput(raw string) []listener {
	var out []listener
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Skip the header row (starts with "State").
		if strings.HasPrefix(line, "State") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// The Local Address:Port column is field index 3 for `ss -ltn`.
		local := fields[3]
		port, ok := portFromAddr(local)
		if !ok {
			continue
		}
		l := listener{port: port}
		if m := ssProcRe.FindStringSubmatch(line); m != nil {
			l.process = m[1]
			if pid, err := strconv.Atoi(m[2]); err == nil {
				l.pid = pid
			}
		}
		out = append(out, l)
	}
	return out
}

// portFromAddr extracts the port from an ss local-address token such as
// "0.0.0.0:443", "*:80", "[::]:443", or "127.0.0.1:8080".
func portFromAddr(addr string) (int, bool) {
	idx := strings.LastIndex(addr, ":")
	if idx < 0 || idx == len(addr)-1 {
		return 0, false
	}
	port, err := strconv.Atoi(addr[idx+1:])
	if err != nil {
		return 0, false
	}
	return port, true
}

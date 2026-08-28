package nginx

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// nginxErrRe matches the "in <file>:<line>" location nginx -t prints on a config
// error, e.g.
//
//	nginx: [emerg] unknown directive "proxy_pas" in /etc/nginx/sites-enabled/site:5
//	nginx: configuration file /etc/nginx/nginx.conf test failed
//
// The location is the trailing "in <path>:<line>" clause; we capture the path
// and line so error attribution can decide whether the fault is in a file we
// manage or in the operator's pre-existing config (§10).
var nginxErrRe = regexp.MustCompile(`in (\S+):(\d+)`)

// permDeniedRe detects a permission failure in nginx -t output — the agent (run
// unprivileged) cannot read files nginx -t touches, e.g. other vhosts' TLS
// private keys or the error log. That is NOT a config error in any file; it means
// the agent needs privilege to run nginx -t / reload (§12).
var permDeniedRe = regexp.MustCompile(`(?im)^(?:(?:nginx: \[(?:emerg|alert)\]|[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9:]+ \[(?:emerg|alert)\] [0-9]+#[0-9]+:).*(?:permission denied|operation not permitted)|sudo: .*(?:a password is required|no tty present and no askpass program specified| is not allowed to execute .*))$`)

// ErrAttribution classifies an nginx -t failure as either ours (the file this
// apply wrote) or the operator's pre-existing config elsewhere in the managed
// dir (§10). nginx -t validates the WHOLE config, so a long-standing operator
// error can trip our apply through no fault of ours; this lets the agent surface
// "your existing config at X:N" distinctly from "we broke it", with an inline
// jump-to-file signal (we manage the dir, so the file is reachable).
type ErrAttribution struct {
	// File is the config file nginx blamed, empty if none could be parsed.
	File string
	// Line is the 1-based line number nginx blamed, 0 if none could be parsed.
	Line int
	// Ours reports whether File is the file this apply wrote (managed by us). When
	// false and File is non-empty, the fault is in the operator's existing config.
	Ours bool
	// Located reports whether a file:line was parsed at all. A test failure with no
	// parseable location (e.g. a permission error) yields Located=false, and the
	// caller surfaces the raw nginx output unattributed.
	Located bool
	// Permission reports that nginx -t failed because the agent lacks permission to
	// read files nginx touches (e.g. other vhosts' TLS keys), not because any
	// config is broken. The caller surfaces a "grant the agent privilege" message
	// rather than blaming a line of config.
	Permission bool
	// Raw is the verbatim nginx -t output, always carried so the caller can show
	// the operator the exact message.
	Raw string
}

// AttributeNginxTestError parses nginx -t output and attributes the failure
// relative to the files this apply wrote. It is a pure function — no host, no
// filesystem — so it is table-driven testable against captured nginx output
// (§14). Exact clean paths match directly; a sites-enabled path may match its
// sites-available sibling only under the same parent with the same basename.
//
// When several "in file:line" clauses appear (nginx can chain context lines),
// the LAST one is the innermost frame nginx blames, so we attribute to it.
func AttributeNginxTestError(out string, ourFiles ...string) ErrAttribution {
	a := ErrAttribution{Raw: out}
	a.Permission = permDeniedRe.MatchString(out)

	// nginx prints benign [warn]/[alert] lines that can carry an "in file:line"
	// clause (e.g. the "user" directive "ignored in /etc/nginx/nginx.conf:1") but
	// are NOT the failure. Skip those lines so the location we attribute comes from
	// the fatal frame (an [emerg] line, or the final "configuration file ... failed
	// in <file>:<line>"), not a warning that happens to mention line 1.
	var loc []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "[warn]") || strings.Contains(line, "[alert]") {
			continue
		}
		if m := nginxErrRe.FindStringSubmatch(line); m != nil {
			loc = m // keep the last (innermost) frame
		}
	}
	if loc == nil {
		// No fatal location parsed (e.g. a permission error, or a cert-key load
		// failure that names no line). The caller surfaces the raw output.
		return a
	}
	a.File = loc[1]
	if n, err := strconv.Atoi(loc[2]); err == nil {
		a.Line = n
	}
	a.Located = true
	for _, ourFile := range ourFiles {
		if sameManagedFile(a.File, ourFile) {
			a.Ours = true
			break
		}
	}
	return a
}

// sameManagedFile reports whether the file nginx blamed is the file we wrote.
// nginx may name the sites-available source or its sites-enabled symlink. A
// basename alone is insufficient because an operator file in another root may
// share it. An empty path is never ours.
func sameManagedFile(blamed, ourFile string) bool {
	if ourFile == "" || blamed == "" || !filepath.IsAbs(blamed) || !filepath.IsAbs(ourFile) {
		return false
	}
	blamedClean := filepath.Clean(blamed)
	ourClean := filepath.Clean(ourFile)
	if blamedClean != blamed || ourClean != ourFile {
		return false
	}
	if blamedClean == ourClean {
		return true
	}
	if filepath.Base(blamedClean) != filepath.Base(ourClean) {
		return false
	}
	blamedDir := filepath.Dir(blamedClean)
	ourDir := filepath.Dir(ourClean)
	if filepath.Dir(blamedDir) != filepath.Dir(ourDir) {
		return false
	}
	blamedRole := filepath.Base(blamedDir)
	ourRole := filepath.Base(ourDir)
	return (blamedRole == "sites-enabled" && ourRole == "sites-available") ||
		(blamedRole == "sites-available" && ourRole == "sites-enabled")
}

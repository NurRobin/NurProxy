package apache

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// apacheErrRe matches the "<file>:<line>" location apachectl configtest prints
// on a config error, e.g.
//
//	AH00526: Syntax error on line 5 of /etc/apache2/sites-enabled/site.conf:
//	Invalid command 'Bogus', perhaps misspelled ...
//
// and the alternate compact form some builds emit:
//
//	Syntax error on line 5 of /etc/httpd/conf.d/site.conf:
//
// We capture the file and line so error attribution can decide whether the fault
// is in a file we manage or in the operator's pre-existing config (§10).
var apacheErrRe = regexp.MustCompile(`on line (\d+) of (\S+?):?$`)

var permDeniedRe = regexp.MustCompile(`(?im)^(?:(?:httpd|apache2|apachectl):.*(?:permission denied|operation not permitted)|\([0-9]+\)(?:permission denied|operation not permitted): ah00091: (?:apache2|httpd): .+|sudo: .*(?:a password is required|no tty present and no askpass program specified| is not allowed to execute .*))$`)

// ErrAttribution classifies an apachectl configtest failure as either ours (the
// file this apply wrote) or the operator's pre-existing config elsewhere in the
// managed dir (§10). configtest validates the WHOLE config, so a long-standing
// operator error can trip our apply through no fault of ours; this lets the
// agent surface "your existing config at X:N" distinctly from "we broke it",
// with an inline jump-to-file signal (we manage the dir, so the file is
// reachable).
type ErrAttribution struct {
	// File is the config file Apache blamed, empty if none could be parsed.
	File string
	// Line is the 1-based line number Apache blamed, 0 if none could be parsed.
	Line int
	// Ours reports whether File is the file this apply wrote (managed by us). When
	// false and File is non-empty, the fault is in the operator's existing config.
	Ours bool
	// Located reports whether a file:line was parsed at all. A test failure with no
	// parseable location (e.g. a permission error) yields Located=false, and the
	// caller surfaces the raw output unattributed.
	Located bool
	// Permission reports that configtest could not read a required file rather
	// than finding invalid configuration syntax.
	Permission bool
	// Raw is the verbatim configtest output, always carried so the caller can show
	// the operator the exact message.
	Raw string
}

// AttributeConfigtestError parses apachectl configtest output and attributes the
// failure relative to the files this apply wrote. It is a pure function — no
// host, no filesystem — so it is table-driven testable against captured output
// (§14). Exact clean paths match directly; a sites-enabled path may match its
// sites-available sibling only under the same parent with the same basename.
//
// When several "on line N of file" clauses appear, the LAST one is the innermost
// frame Apache blames, so we attribute to it.
func AttributeConfigtestError(out string, ourFiles ...string) ErrAttribution {
	a := ErrAttribution{Raw: out}
	a.Permission = permDeniedRe.MatchString(out)

	var last []string
	for _, line := range strings.Split(out, "\n") {
		if m := apacheErrRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			last = m
		}
	}
	if last == nil {
		return a
	}
	if n, err := strconv.Atoi(last[1]); err == nil {
		a.Line = n
	}
	a.File = last[2]
	a.Located = true
	for _, ourFile := range ourFiles {
		if sameManagedFile(a.File, ourFile) {
			a.Ours = true
			break
		}
	}
	return a
}

// sameManagedFile reports whether the file Apache blamed is the file we wrote.
// Apache may name the sites-available source or its sites-enabled symlink. A
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

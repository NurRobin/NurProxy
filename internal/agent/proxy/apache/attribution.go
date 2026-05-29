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
	// Raw is the verbatim configtest output, always carried so the caller can show
	// the operator the exact message.
	Raw string
}

// AttributeConfigtestError parses apachectl configtest output and attributes the
// failure relative to ourFile (the file this apply wrote, e.g.
// sites-available/nurproxy-app.example.com.conf). It is a pure function — no
// host, no filesystem — so it is table-driven testable against captured output
// (§14). Apache may reference a file via its sites-available path, its
// sites-enabled symlink, or an absolute include; we compare by base name so the
// symlink and its target attribute to the same managed file.
//
// When several "on line N of file" clauses appear, the LAST one is the innermost
// frame Apache blames, so we attribute to it.
func AttributeConfigtestError(out, ourFile string) ErrAttribution {
	a := ErrAttribution{Raw: out}

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
	a.Ours = sameManagedFile(a.File, ourFile)
	return a
}

// sameManagedFile reports whether the file Apache blamed is the file we wrote.
// Apache may name the sites-available source or the sites-enabled symlink; both
// share the base name nurproxy-<domain>.conf, so a base-name comparison treats
// the symlink and its target as the same managed artifact. An empty ourFile
// (we wrote nothing identifiable) is never "ours".
func sameManagedFile(blamed, ourFile string) bool {
	if ourFile == "" || blamed == "" {
		return false
	}
	if blamed == ourFile {
		return true
	}
	return strings.EqualFold(filepath.Base(blamed), filepath.Base(ourFile))
}

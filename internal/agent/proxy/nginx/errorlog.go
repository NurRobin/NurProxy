package nginx

import (
	"os"
	"os/exec"
	"strings"

	"github.com/NurRobin/NurProxy/internal/shared/nginxgen"
)

// defaultConfPath is the main nginx.conf used when `nginx -V` names none.
const defaultConfPath = "/etc/nginx/nginx.conf"

// errorLogPathMatches reports whether the error log that applies to server
// blocks on this host is exactly nginxgen.DefaultErrorLogPath, and that file
// exists. Only then can a per-domain `error_log <path> <level>;` change the
// level without moving the domain's errors to another file or failing
// `nginx -t` because the directory is missing (source builds, OpenResty).
//
// The applicable log is the http-level error_log in the main config if there
// is one, else the main-level one, else the compiled --error-log-path. Files
// pulled in by include are not followed; an error_log set only there is not
// seen.
func errorLogPathMatches(binary string) bool {
	if binary == "" {
		return false
	}
	out, err := exec.Command(binary, "-V").CombinedOutput()
	if err != nil {
		return false
	}
	return errorLogTargetIsDefault(string(out), os.ReadFile, os.Stat)
}

// errorLogTargetIsDefault is errorLogPathMatches with the `nginx -V` output
// and file access injected, for tests.
func errorLogTargetIsDefault(versionOutput string, readFile func(string) ([]byte, error), stat func(string) (os.FileInfo, error)) bool {
	compiled, confPath := configureArgs(versionOutput)
	if confPath == "" {
		confPath = defaultConfPath
	}
	conf, err := readFile(confPath)
	if err != nil {
		return false
	}
	mainLogs, httpLogs := topLevelErrorLogs(string(conf))
	effective := httpLogs
	if len(effective) == 0 {
		effective = mainLogs
	}
	if len(effective) == 0 {
		if compiled == "" {
			return false
		}
		effective = []string{compiled}
	}
	for _, path := range effective {
		if path != nginxgen.DefaultErrorLogPath {
			return false
		}
	}
	info, err := stat(nginxgen.DefaultErrorLogPath)
	return err == nil && info.Mode().IsRegular()
}

// configureArgs extracts --error-log-path and --conf-path from `nginx -V`.
func configureArgs(versionOutput string) (errorLogPath, confPath string) {
	for _, field := range strings.Fields(versionOutput) {
		if v, ok := strings.CutPrefix(field, "--error-log-path="); ok {
			errorLogPath = v
		}
		if v, ok := strings.CutPrefix(field, "--conf-path="); ok {
			confPath = v
		}
	}
	return errorLogPath, confPath
}

// topLevelErrorLogs returns the first argument of every error_log directive
// in the main context and directly inside the http block of an nginx.conf.
// It is a small scanner for that one question: comments are stripped, quoted
// strings are not interpreted (a quoted path never equals the default path,
// so it only ever makes the answer "no").
func topLevelErrorLogs(conf string) (mainLogs, httpLogs []string) {
	var (
		stack []string // block names from the outside in
		stmt  strings.Builder
	)
	flush := func() []string {
		fields := strings.Fields(stmt.String())
		stmt.Reset()
		return fields
	}
	for _, line := range strings.Split(conf, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		for _, r := range line + "\n" {
			switch r {
			case '{':
				fields := flush()
				name := ""
				if len(fields) > 0 {
					name = fields[0]
				}
				stack = append(stack, name)
			case '}':
				flush()
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
			case ';':
				fields := flush()
				if len(fields) < 2 || fields[0] != "error_log" {
					continue
				}
				switch {
				case len(stack) == 0:
					mainLogs = append(mainLogs, fields[1])
				case len(stack) == 1 && stack[0] == "http":
					httpLogs = append(httpLogs, fields[1])
				}
			default:
				stmt.WriteRune(r)
			}
		}
	}
	return mainLogs, httpLogs
}

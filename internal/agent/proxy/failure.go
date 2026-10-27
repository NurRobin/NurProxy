package proxy

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

const (
	MaxFailureCaptureBytes = recoverymodel.MaxEvidenceBytes
	MaxFailurePathBytes    = 1024
	maxFailureSummaryBytes = 512
	FailureOutputTruncated = "[output truncated]"
)

const failureTruncationSuffix = "\n" + FailureOutputTruncated

type FailurePhase string

const (
	FailurePhaseValidate    FailurePhase = "validate"
	FailurePhaseReload      FailurePhase = "reload"
	FailurePhaseCertInstall FailurePhase = "cert_install"
)

// Failure is a sanitized, backend-neutral description of a proxy command
// failure. ManagedHint is attribution evidence only; recovery code must still
// prove ownership before choosing a repair.
type Failure struct {
	Backend            Kind
	Phase              FailurePhase
	Output             string
	File               string
	Line               int
	Located            bool
	ManagedHint        bool
	Permission         bool
	MissingCert        bool
	MissingRuntimeKey  bool
	RuntimeKeyMismatch bool
	BinaryMissing      bool
	ReferencedPaths    []string
	Err                error
}

type ExecutionError struct {
	Executable       string
	Role             ExecutionRole
	TargetExecutable string
	TargetRole       ExecutionRole
	output           string
	Err              error
}

type ExecutionRole string

const (
	ExecutionRoleBackend  ExecutionRole = "backend"
	ExecutionRoleOverride ExecutionRole = "override"
	ExecutionRoleSystem   ExecutionRole = "system"
)

func (e *ExecutionError) Error() string {
	return "starting proxy executable failed"
}

func (e *ExecutionError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func NewFailure(backend Kind, phase FailurePhase, output string, err error) *Failure {
	canonicalOutput := output
	var executionErr *ExecutionError
	if errors.As(err, &executionErr) && executionErr.output != "" {
		canonicalOutput = executionErr.output
	}
	f := &Failure{
		Backend: backend,
		Phase:   phase,
		Output:  boundedFailureOutput(canonicalOutput, len(canonicalOutput) > MaxFailureCaptureBytes),
		Err:     err,
	}
	f.BinaryMissing = isBinaryMissing(backend, f.Output, err)
	f.Permission = errors.Is(err, os.ErrPermission) || permissionOutput(f.Output)
	f.classifyKnownOutput(f.Output)
	return f
}

func (f *Failure) SetLocation(file string, line int, managedHint bool) {
	f.File = ""
	f.Line = 0
	f.Located = false
	f.ManagedHint = false
	if !validFailureLocation(file, line) {
		return
	}
	f.File = file
	f.Line = line
	f.Located = true
	f.ManagedHint = managedHint
}

func (f *Failure) SetReferencedPaths(paths ...string) bool {
	f.ReferencedPaths = nil
	if len(paths) == 0 || len(paths) > 2 {
		return false
	}
	validated := make([]string, len(paths))
	for i, path := range paths {
		if !ValidFailurePath(path) {
			return false
		}
		validated[i] = path
	}
	f.ReferencedPaths = validated
	return true
}

func (f *Failure) Error() string {
	if f == nil {
		return "proxy operation failed"
	}
	command := f.commandLabel()
	if f.BinaryMissing {
		return command + " failed: proxy binary missing"
	}
	if f.Permission {
		return command + " could not complete: permission denied"
	}
	if validFailureLocation(f.File, f.Line) && f.Located {
		if f.ManagedHint {
			return fmt.Sprintf("%s failed in the generated config at %s:%d", command, f.File, f.Line)
		}
		return fmt.Sprintf("%s failed: error in your existing config at %s:%d", command, f.File, f.Line)
	}
	if summary := failureSummary(f.Output); summary != "" {
		return command + " failed: " + summary
	}
	return command + " failed"
}

func (f *Failure) Unwrap() error {
	if f == nil {
		return nil
	}
	return f.Err
}

func (f *Failure) commandLabel() string {
	switch f.Backend {
	case KindNginx:
		switch f.Phase {
		case FailurePhaseValidate:
			return "nginx -t"
		case FailurePhaseReload:
			return "nginx reload"
		case FailurePhaseCertInstall:
			return "nginx certificate installation"
		}
	case KindApache:
		switch f.Phase {
		case FailurePhaseValidate:
			return "apachectl configtest"
		case FailurePhaseReload:
			return "apache reload"
		case FailurePhaseCertInstall:
			return "apache certificate installation"
		}
	}
	return "proxy operation"
}

var nginxEmergLine = regexp.MustCompile(`(?i)^(?:nginx: \[emerg\]|[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9:]+ \[emerg\] [0-9]+#[0-9]+:) `)
var nginxPermissionLine = regexp.MustCompile(`(?i)^(?:nginx: \[(?:emerg|alert)\]|[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9:]+ \[(?:emerg|alert)\] [0-9]+#[0-9]+:) `)
var apachePermissionLine = regexp.MustCompile(`(?i)^\([0-9]+\)(?:permission denied|operation not permitted): ah00091: (?:apache2|httpd): .+$`)
var wrappedCommandOutputLine = regexp.MustCompile(`(?i)^exit status [0-9]+: (.+)$`)
var nginxMissingCertBody = regexp.MustCompile(`(?i)^cannot load certificate "([^"]+)": .+no such file or directory.*$`)
var nginxMissingRuntimeKeyBody = regexp.MustCompile(`(?i)^cannot load certificate key "([^"]+)": .+no such file or directory.*$`)
var nginxRuntimeKeyMismatchBody = regexp.MustCompile(`(?i)^ssl_ctx_use_privatekey\("([^"]+)"\) failed \(ssl: .+key values mismatch\)$`)
var apacheRuntimeKeyMismatchLine = regexp.MustCompile(`(?i)^ah02565: certificate and private key \S+ from (\S+) and (\S+) do not match$`)

func (f *Failure) classifyKnownOutput(output string) {
	apacheSyntaxHeader := false
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		lower := strings.ToLower(line)
		switch f.Backend {
		case KindNginx:
			if !nginxEmergLine.MatchString(line) {
				continue
			}
			body := nginxEmergLine.ReplaceAllString(line, "")
			switch {
			case nginxRuntimeKeyMismatchBody.MatchString(body):
				match := nginxRuntimeKeyMismatchBody.FindStringSubmatch(body)
				if f.SetReferencedPaths(match[1]) {
					f.RuntimeKeyMismatch = true
				}
			case nginxMissingRuntimeKeyBody.MatchString(body):
				match := nginxMissingRuntimeKeyBody.FindStringSubmatch(body)
				if f.SetReferencedPaths(match[1]) {
					f.MissingRuntimeKey = true
				}
			case nginxMissingCertBody.MatchString(body):
				match := nginxMissingCertBody.FindStringSubmatch(body)
				if f.SetReferencedPaths(match[1]) {
					f.MissingCert = true
				}
			}
		case KindApache:
			switch {
			case apacheRuntimeKeyMismatchLine.MatchString(line):
				match := apacheRuntimeKeyMismatchLine.FindStringSubmatch(line)
				if f.SetReferencedPaths(match[1], match[2]) {
					f.RuntimeKeyMismatch = true
				}
			case apacheSyntaxHeader:
				if path, ok := apacheMissingDirectivePath(line, "SSLCertificateKeyFile: file '"); ok && f.SetReferencedPaths(path) {
					f.MissingRuntimeKey = true
				} else if path, ok := apacheMissingDirectivePath(line, "SSLCertificateFile: file '"); ok && f.SetReferencedPaths(path) {
					f.MissingCert = true
				}
			}
			apacheSyntaxHeader = strings.HasPrefix(lower, "ah00526: syntax error on line ") && strings.HasSuffix(lower, ":")
		}
	}
}

func apacheMissingDirectivePath(line, directive string) (string, bool) {
	const suffix = "' does not exist or is empty"
	if len(line) <= len(directive)+len(suffix) || !strings.EqualFold(line[:len(directive)], directive) || !strings.HasSuffix(strings.ToLower(line), suffix) {
		return "", false
	}
	return line[len(directive) : len(line)-len(suffix)], true
}

func isBinaryMissing(backend Kind, output string, err error) bool {
	var executionErr *ExecutionError
	if !errors.As(err, &executionErr) {
		return false
	}
	target, targetRole := executionErr.TargetExecutable, executionErr.TargetRole
	if target == "" {
		target, targetRole = executionErr.Executable, executionErr.Role
	}
	if targetRole != ExecutionRoleBackend || !backendExecutable(backend, target) {
		return false
	}
	if executionErr.Executable == target && executionErr.Role == ExecutionRoleBackend {
		return missingExecutionCause(executionErr.Err)
	}
	var exitErr *exec.ExitError
	if executionErr.Role != ExecutionRoleSystem || filepath.Base(executionErr.Executable) != "sudo" || !errors.As(executionErr.Err, &exitErr) {
		return false
	}
	return sudoMissingTarget(output, target)
}

func sudoMissingTarget(output, target string) bool {
	const prefix = "sudo: unable to execute "
	const suffix = ": No such file or directory"
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSuffix(rawLine, "\r")
		if strings.HasPrefix(line, prefix) && strings.HasSuffix(line, suffix) && strings.TrimSuffix(strings.TrimPrefix(line, prefix), suffix) == target {
			return true
		}
	}
	return false
}

func backendExecutable(backend Kind, executable string) bool {
	name := filepath.Base(filepath.Clean(executable))
	switch backend {
	case KindNginx:
		return name == "nginx"
	case KindApache:
		switch name {
		case "apachectl", "apache2ctl", "httpd", "apache2":
			return true
		}
	}
	return false
}

func missingExecutionCause(err error) bool {
	if err == exec.ErrNotFound {
		return true
	}
	var execErr *exec.Error
	if errors.As(err, &execErr) {
		return errors.Is(execErr.Err, exec.ErrNotFound) || errors.Is(execErr.Err, os.ErrNotExist)
	}
	var pathErr *os.PathError
	return errors.As(err, &pathErr) && pathErr.Op == "fork/exec" && errors.Is(pathErr.Err, os.ErrNotExist)
}

func permissionOutput(output string) bool {
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.ToLower(strings.TrimSpace(rawLine))
		if match := wrappedCommandOutputLine.FindStringSubmatch(line); match != nil {
			line = match[1]
			rawLine = match[1]
		}
		switch {
		case strings.HasPrefix(line, "sudo: ") && strings.HasSuffix(line, "a password is required"):
			return true
		case strings.HasPrefix(line, "sudo: ") && strings.Contains(line, "no tty present and no askpass program specified"):
			return true
		case strings.HasPrefix(line, "sudo: ") && strings.Contains(line, " is not allowed to execute "):
			return true
		case (nginxPermissionLine.MatchString(rawLine) || strings.HasPrefix(line, "httpd:") || strings.HasPrefix(line, "apache2:") || apachePermissionLine.MatchString(line)) &&
			(strings.Contains(line, "permission denied") || strings.Contains(line, "operation not permitted")):
			return true
		}
	}
	return false
}

func validFailureLocation(file string, line int) bool {
	return line > 0 && ValidFailurePath(file)
}

func ValidFailurePath(file string) bool {
	if file == "" || len(file) > MaxFailurePathBytes || !utf8.ValidString(file) || !filepath.IsAbs(file) || filepath.Clean(file) != file {
		return false
	}
	for _, r := range file {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return recoverymodel.SanitizeEvidence(file) == file
}

func failureSummary(output string) string {
	safe := boundedFailureOutput(output, len(output) > MaxFailureCaptureBytes)
	for _, line := range strings.Split(safe, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == FailureOutputTruncated {
			continue
		}
		if len(line) > maxFailureSummaryBytes {
			line = trimUTF8(line, maxFailureSummaryBytes)
		}
		return line
	}
	return ""
}

func failureOutputPayloadBytes() int {
	return MaxFailureCaptureBytes - len(failureTruncationSuffix)
}

func boundedFailureOutput(output string, truncated bool) string {
	if !truncated && len(output) <= MaxFailureCaptureBytes {
		return recoverymodel.SanitizeEvidence(strings.ToValidUTF8(output, "?"))
	}
	limit := failureOutputPayloadBytes()
	if len(output) > limit {
		output = output[:limit]
		truncated = true
	}
	output = strings.ToValidUTF8(output, "?")
	output = recoverymodel.SanitizeEvidence(output)
	if len(output) > limit {
		output = trimUTF8(output, limit)
	}
	if truncated {
		return output + failureTruncationSuffix
	}
	return output
}

func trimUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	end := limit
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end]
}

type boundedOutputWriter struct {
	mu        sync.Mutex
	buf       []byte
	truncated bool
}

func newBoundedOutputWriter() *boundedOutputWriter {
	return &boundedOutputWriter{buf: make([]byte, 0, failureOutputPayloadBytes())}
}

func (w *boundedOutputWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	written := len(p)
	remaining := failureOutputPayloadBytes() - len(w.buf)
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		w.buf = append(w.buf, p...)
	}
	if written > remaining {
		w.truncated = true
	}
	return written, nil
}

func (w *boundedOutputWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return boundedFailureOutput(string(w.buf), w.truncated)
}

func RunCombinedOutput(cmd *exec.Cmd) (string, error) {
	return RunTargetCombinedOutput(cmd, cmd.Path, ExecutionRoleSystem)
}

func RunBackendCombinedOutput(cmd *exec.Cmd) (string, error) {
	return RunTargetCombinedOutput(cmd, cmd.Path, ExecutionRoleBackend)
}

func RunOverrideCombinedOutput(cmd *exec.Cmd) (string, error) {
	return RunTargetCombinedOutput(cmd, cmd.Path, ExecutionRoleOverride)
}

func RunTargetCombinedOutput(cmd *exec.Cmd, target string, targetRole ExecutionRole) (string, error) {
	w := newBoundedOutputWriter()
	cmd.Stdout = w
	cmd.Stderr = w
	err := cmd.Run()
	if err != nil {
		role := ExecutionRoleSystem
		if cmd.Path == target {
			role = targetRole
		}
		output := w.String()
		err = &ExecutionError{
			Executable:       cmd.Path,
			Role:             role,
			TargetExecutable: target,
			TargetRole:       targetRole,
			output:           output,
			Err:              err,
		}
		return output, err
	}
	return w.String(), err
}

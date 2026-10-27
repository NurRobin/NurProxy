package helper

import (
	"errors"
	"strings"
	"unicode"
)

// maxNativeDiagnosticBytes bounds how much native validator output travels in
// an error, a receipt or a log line.
const maxNativeDiagnosticBytes = 1024

// nativeValidationError carries the bounded, sanitized output of a native
// proxy validator (`nginx -t`, `apachectl configtest`, `caddy validate`) next
// to the process error, so the cause of a failed apply is visible in the
// receipt instead of only "exit status 1".
type nativeValidationError struct {
	err    error
	output string
}

func newNativeValidationError(err error, output string) error {
	return &nativeValidationError{err: err, output: sanitizeNativeDiagnostic(output)}
}

func (e *nativeValidationError) Error() string {
	if e.output == "" {
		return e.err.Error()
	}
	return e.err.Error() + ": " + e.output
}

func (e *nativeValidationError) Unwrap() error { return e.err }

// sanitizeNativeDiagnostic folds the output onto one line, drops control and
// non-printable characters and truncates it on a UTF-8 boundary.
func sanitizeNativeDiagnostic(output string) string {
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		cleaned := strings.Map(func(r rune) rune {
			if r == '\t' {
				return ' '
			}
			if !unicode.IsPrint(r) {
				return -1
			}
			return r
		}, line)
		if cleaned = strings.TrimSpace(cleaned); cleaned != "" {
			lines = append(lines, cleaned)
		}
	}
	return truncateUTF8(strings.Join(lines, " | "), maxNativeDiagnosticBytes)
}

// nativeDiagnostic returns the sanitized validator output carried anywhere in
// err's chain, or "" when the failure did not come from a native validator.
func nativeDiagnostic(err error) string {
	var validation *nativeValidationError
	if errors.As(err, &validation) {
		return validation.output
	}
	return ""
}

// withNativeDiagnostic appends the validator output of err to a fixed receipt
// message.
func withNativeDiagnostic(message string, err error) string {
	if detail := nativeDiagnostic(err); detail != "" {
		return message + "; native validation: " + detail
	}
	return message
}

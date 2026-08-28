package proxy

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

func TestNewFailureRecognizesOnlyKnownBackendMessages(t *testing.T) {
	tests := []struct {
		name                   string
		backend                Kind
		output                 string
		err                    error
		wantMissingCert        bool
		wantMissingRuntimeKey  bool
		wantRuntimeKeyMismatch bool
		wantBinaryMissing      bool
	}{
		{
			name:            "nginx missing certificate",
			backend:         KindNginx,
			output:          `nginx: [emerg] cannot load certificate "/var/lib/nurproxy/certs/app.crt": BIO_new_file() failed (SSL: error:80000002:system library::No such file or directory)`,
			wantMissingCert: true,
		},
		{
			name:                  "nginx missing runtime key",
			backend:               KindNginx,
			output:                `nginx: [emerg] cannot load certificate key "/var/lib/nurproxy/certs/app.key.plain": BIO_new_file() failed (SSL: error:80000002:system library::No such file or directory)`,
			wantMissingRuntimeKey: true,
		},
		{
			name:                   "nginx runtime key mismatch",
			backend:                KindNginx,
			output:                 `nginx: [emerg] SSL_CTX_use_PrivateKey("/var/lib/nurproxy/certs/app.key.plain") failed (SSL: error:05800074:x509 certificate routines::key values mismatch)`,
			wantRuntimeKeyMismatch: true,
		},
		{
			name:            "apache missing certificate",
			backend:         KindApache,
			output:          "AH00526: Syntax error on line 12 of /etc/apache2/sites-enabled/app.conf:\nSSLCertificateFile: file '/var/lib/nurproxy/certs/app.crt' does not exist or is empty",
			wantMissingCert: true,
		},
		{
			name:                  "apache missing runtime key",
			backend:               KindApache,
			output:                "AH00526: Syntax error on line 13 of /etc/apache2/sites-enabled/app.conf:\nSSLCertificateKeyFile: file '/var/lib/nurproxy/certs/app.key.plain' does not exist or is empty",
			wantMissingRuntimeKey: true,
		},
		{
			name:                   "apache runtime key mismatch",
			backend:                KindApache,
			output:                 `AH02565: Certificate and private key app.example.com:443:0 from /var/lib/nurproxy/certs/app.crt and /var/lib/nurproxy/certs/app.key.plain do not match`,
			wantRuntimeKeyMismatch: true,
		},
		{
			name:    "untyped binary error has no identity",
			backend: KindNginx,
			err:     exec.ErrNotFound,
		},
		{
			name:    "unknown output has no repair hint",
			backend: KindNginx,
			output:  `nginx: [emerg] something entirely new happened`,
		},
		{
			name:    "near miss without nginx error prefix",
			backend: KindNginx,
			output:  `operator note: cannot load certificate "/tmp/app.crt": No such file or directory`,
		},
		{
			name:    "near miss without apache error code",
			backend: KindApache,
			output:  `operator note: Certificate and private key app.crt and app.key do not match`,
		},
		{
			name:    "orphan apache directive line is not enough",
			backend: KindApache,
			output:  `SSLCertificateFile: file '/tmp/app.crt' does not exist or is empty`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewFailure(tt.backend, FailurePhaseValidate, tt.output, tt.err)
			if got.MissingCert != tt.wantMissingCert {
				t.Errorf("MissingCert = %v, want %v", got.MissingCert, tt.wantMissingCert)
			}
			if got.MissingRuntimeKey != tt.wantMissingRuntimeKey {
				t.Errorf("MissingRuntimeKey = %v, want %v", got.MissingRuntimeKey, tt.wantMissingRuntimeKey)
			}
			if got.RuntimeKeyMismatch != tt.wantRuntimeKeyMismatch {
				t.Errorf("RuntimeKeyMismatch = %v, want %v", got.RuntimeKeyMismatch, tt.wantRuntimeKeyMismatch)
			}
			if got.BinaryMissing != tt.wantBinaryMissing {
				t.Errorf("BinaryMissing = %v, want %v", got.BinaryMissing, tt.wantBinaryMissing)
			}
			if !tt.wantMissingCert && !tt.wantMissingRuntimeKey && !tt.wantRuntimeKeyMismatch && !tt.wantBinaryMissing &&
				(got.Permission || got.ManagedHint) {
				t.Errorf("unknown/near-miss output gained a repair hint: %#v", got)
			}
		})
	}
}

func TestNewFailureSanitizesAndBoundsOutput(t *testing.T) {
	secret := "top-secret-value"
	out := "token=" + secret + "\n" + strings.Repeat("x", recoverymodel.MaxEvidenceBytes*2)
	failure := NewFailure(KindNginx, FailurePhaseValidate, out, errors.New("exit status 1"))

	if strings.Contains(failure.Output, secret) {
		t.Fatalf("Output leaked secret: %q", failure.Output)
	}
	if len(failure.Output) > recoverymodel.MaxEvidenceBytes {
		t.Fatalf("Output bytes = %d, want <= %d", len(failure.Output), recoverymodel.MaxEvidenceBytes)
	}
}

func TestFailureErrorIsConciseAndUnwraps(t *testing.T) {
	cause := errors.New("exit status 1 with token=do-not-render")
	failure := NewFailure(KindApache, FailurePhaseReload, "reload output", cause)
	failure.SetLocation("/etc/apache2/sites-enabled/app.conf", 7, false)

	if got, want := failure.Error(), "apache reload failed: error in your existing config at /etc/apache2/sites-enabled/app.conf:7"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if strings.Contains(failure.Error(), "token") {
		t.Fatalf("Error() leaked wrapped details: %q", failure.Error())
	}
	if !errors.Is(failure, cause) {
		t.Fatal("Failure does not unwrap to its cause")
	}
}

func TestNewFailureDoesNotCallMissingCertFileABinaryFailure(t *testing.T) {
	failure := NewFailure(KindNginx, FailurePhaseCertInstall, "writing cert", os.ErrNotExist)
	if failure.BinaryMissing {
		t.Fatal("BinaryMissing = true for a cert-install filesystem error")
	}
}

func TestFailureSetLocationRejectsUnsafePathsAndClearsAttribution(t *testing.T) {
	tooLong := "/" + strings.Repeat("x", MaxFailurePathBytes)
	tests := []struct {
		name string
		path string
		line int
	}{
		{name: "invalid UTF-8", path: string([]byte{'/', 'x', 0xff}), line: 1},
		{name: "newline control", path: "/etc/nginx/a\n.conf", line: 1},
		{name: "carriage return", path: "/etc/nginx/a\r.conf", line: 1},
		{name: "bidi formatting", path: "/etc/nginx/a\u202e.conf", line: 1},
		{name: "secret assignment", path: "/etc/nginx/token=super-secret", line: 1},
		{name: "relative", path: "etc/nginx/app.conf", line: 1},
		{name: "unclean", path: "/etc/nginx/../nginx/app.conf", line: 1},
		{name: "over byte limit", path: tooLong, line: 1},
		{name: "invalid line", path: "/etc/nginx/app.conf", line: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			failure := NewFailure(KindNginx, FailurePhaseValidate, "failure", errors.New("exit 1"))
			failure.SetLocation("/etc/nginx/sites-enabled/nurproxy-good.conf", 2, true)
			failure.SetLocation(tt.path, tt.line, true)
			if failure.Located || failure.File != "" || failure.Line != 0 || failure.ManagedHint {
				t.Fatalf("unsafe location was retained: %#v", failure)
			}
			if strings.Contains(failure.Error(), "super-secret") {
				t.Fatalf("Error leaked rejected path: %q", failure.Error())
			}
		})
	}
}

func TestFailureSetLocationAcceptsCleanAbsolutePath(t *testing.T) {
	failure := NewFailure(KindNginx, FailurePhaseValidate, "failure", errors.New("exit 1"))
	failure.SetLocation("/etc/nginx/sites-enabled/nurproxy-app.conf", 12, true)
	if !failure.Located || failure.File != "/etc/nginx/sites-enabled/nurproxy-app.conf" || failure.Line != 12 || !failure.ManagedHint {
		t.Fatalf("location = %#v", failure)
	}
}

func TestFailureErrorRevalidatesExportedLocationFields(t *testing.T) {
	failure := NewFailure(KindNginx, FailurePhaseValidate, "safe fallback", errors.New("exit 1"))
	failure.File = "/etc/nginx/token=super-secret"
	failure.Line = 1
	failure.Located = true
	failure.ManagedHint = true
	if got := failure.Error(); strings.Contains(got, "super-secret") || strings.Contains(got, "generated config") {
		t.Fatalf("Error trusted unsafe exported location: %q", got)
	}
}

func TestFailureErrorKeepsVisibleDiagnosticCategories(t *testing.T) {
	tests := []struct {
		name string
		make func() *Failure
		want string
	}{
		{
			name: "generated config",
			make: func() *Failure {
				f := NewFailure(KindNginx, FailurePhaseValidate, "raw", errors.New("exit 1"))
				f.SetLocation("/etc/nginx/sites-enabled/nurproxy-app.conf", 4, true)
				return f
			},
			want: "nginx -t failed in the generated config at /etc/nginx/sites-enabled/nurproxy-app.conf:4",
		},
		{
			name: "existing config",
			make: func() *Failure {
				f := NewFailure(KindApache, FailurePhaseValidate, "raw", errors.New("exit 1"))
				f.SetLocation("/etc/apache2/sites-enabled/operator.conf", 9, false)
				return f
			},
			want: "apachectl configtest failed: error in your existing config at /etc/apache2/sites-enabled/operator.conf:9",
		},
		{
			name: "permission",
			make: func() *Failure {
				return NewFailure(KindNginx, FailurePhaseValidate, "sudo: a password is required", errors.New("exit 1"))
			},
			want: "nginx -t could not complete: permission denied",
		},
		{
			name: "binary missing",
			make: func() *Failure {
				return NewFailure(KindApache, FailurePhaseValidate, "", &ExecutionError{
					Executable: "/usr/sbin/apachectl",
					Role:       ExecutionRoleBackend,
					Err:        &exec.Error{Name: "apachectl", Err: exec.ErrNotFound},
				})
			},
			want: "apachectl configtest failed: proxy binary missing",
		},
		{
			name: "safe useful fallback",
			make: func() *Failure {
				return NewFailure(KindNginx, FailurePhaseValidate, "unexpected failure\nsecond line token=secret", errors.New("exit 1"))
			},
			want: "nginx -t failed: unexpected failure",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.make().Error(); got != tt.want {
				t.Fatalf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewFailureBinaryMissingRequiresExecutionEvidence(t *testing.T) {
	tests := []struct {
		name    string
		backend Kind
		err     error
		want    bool
	}{
		{name: "typed nginx executable", backend: KindNginx, err: &ExecutionError{Executable: "/usr/sbin/nginx", Role: ExecutionRoleBackend, Err: &os.PathError{Op: "fork/exec", Path: "/usr/sbin/nginx", Err: os.ErrNotExist}}, want: true},
		{name: "typed apachectl executable", backend: KindApache, err: &ExecutionError{Executable: "/usr/sbin/apachectl", Role: ExecutionRoleBackend, Err: &exec.Error{Name: "apachectl", Err: exec.ErrNotFound}}, want: true},
		{name: "typed apache2 alias", backend: KindApache, err: &ExecutionError{Executable: "/usr/sbin/apache2", Role: ExecutionRoleBackend, Err: exec.ErrNotFound}, want: true},
		{name: "nested typed identity", backend: KindNginx, err: fmt.Errorf("validate: %w", &ExecutionError{Executable: "nginx", Role: ExecutionRoleBackend, Err: exec.ErrNotFound}), want: true},
		{name: "same-name override", backend: KindNginx, err: &ExecutionError{Executable: "/tmp/nginx", Role: ExecutionRoleOverride, Err: exec.ErrNotFound}},
		{name: "same-name system wrapper", backend: KindApache, err: &ExecutionError{Executable: "/tmp/httpd", Role: ExecutionRoleSystem, Err: exec.ErrNotFound}},
		{name: "missing sudo is not backend", backend: KindNginx, err: &ExecutionError{Executable: "/usr/bin/sudo", Role: ExecutionRoleSystem, Err: exec.ErrNotFound}},
		{name: "missing custom wrapper is not backend", backend: KindNginx, err: &ExecutionError{Executable: "/opt/bin/nginx-wrapper", Role: ExecutionRoleOverride, Err: exec.ErrNotFound}},
		{name: "other backend executable", backend: KindNginx, err: &ExecutionError{Executable: "/usr/sbin/apachectl", Role: ExecutionRoleBackend, Err: exec.ErrNotFound}},
		{name: "typed ordinary file miss", backend: KindNginx, err: &ExecutionError{Executable: "nginx", Role: ExecutionRoleBackend, Err: os.ErrNotExist}},
		{name: "untyped exec sentinel", backend: KindNginx, err: exec.ErrNotFound},
		{name: "untyped exec error", backend: KindNginx, err: &exec.Error{Name: "nginx", Err: exec.ErrNotFound}},
		{name: "untyped fork exec path error", backend: KindNginx, err: &os.PathError{Op: "fork/exec", Path: "/missing/nginx", Err: os.ErrNotExist}},
		{name: "plain not exist", backend: KindNginx, err: os.ErrNotExist},
		{name: "wrapped plain not exist", backend: KindNginx, err: fmt.Errorf("config vanished: %w", os.ErrNotExist)},
		{name: "open path error", backend: KindNginx, err: &os.PathError{Op: "open", Path: "/etc/nginx/nginx.conf", Err: os.ErrNotExist}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewFailure(tt.backend, FailurePhaseValidate, "", tt.err)
			if got.BinaryMissing != tt.want {
				t.Fatalf("BinaryMissing = %v, want %v for %T", got.BinaryMissing, tt.want, tt.err)
			}
		})
	}
}

func TestNewFailurePermissionDetectionAcrossPhases(t *testing.T) {
	tests := []struct {
		name   string
		phase  FailurePhase
		output string
		err    error
		want   bool
	}{
		{name: "wrapped permission on reload", phase: FailurePhaseReload, err: fmt.Errorf("reload: %w", os.ErrPermission), want: true},
		{name: "sudo password", phase: FailurePhaseValidate, output: "sudo: a password is required", want: true},
		{name: "sudo no tty", phase: FailurePhaseReload, output: "sudo: no tty present and no askpass program specified", want: true},
		{name: "sudo denied", phase: FailurePhaseValidate, output: "sudo: main is not allowed to execute '/usr/sbin/nginx -t' as root on host", want: true},
		{name: "command permission denied", phase: FailurePhaseValidate, output: "nginx: [emerg] open() failed (13: Permission denied)", want: true},
		{name: "nginx alert operation denied", phase: FailurePhaseValidate, output: `nginx: [alert] open() "/var/log/nginx/error.log" failed (1: Operation not permitted)`, want: true},
		{name: "timestamped nginx alert operation denied", phase: FailurePhaseReload, output: `2026/08/29 01:20:31 [alert] 4242#4242: open() "/run/nginx.pid" failed (1: Operation not permitted)`, want: true},
		{name: "apache numeric permission prefix", phase: FailurePhaseValidate, output: `(13)Permission denied: AH00091: apache2: could not open error log file /var/log/apache2/error.log.`, want: true},
		{name: "httpd numeric operation prefix", phase: FailurePhaseReload, output: `(1)Operation not permitted: AH00091: httpd: could not open error log file /var/log/httpd/error_log.`, want: true},
		{name: "near miss prose", phase: FailurePhaseValidate, output: "documentation mentions permission denied handling", want: false},
		{name: "near miss nginx alert prose", phase: FailurePhaseValidate, output: "guide: nginx: [alert] means Operation not permitted", want: false},
		{name: "near miss apache numeric prose", phase: FailurePhaseValidate, output: "guide: (13)Permission denied: AH00091: apache2", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewFailure(KindNginx, tt.phase, tt.output, tt.err)
			if got.Permission != tt.want {
				t.Fatalf("Permission = %v, want %v", got.Permission, tt.want)
			}
		})
	}
}

func TestNewFailureRecognizesPermissionFromReloadExitError(t *testing.T) {
	sh, lookupErr := exec.LookPath("sh")
	if lookupErr != nil {
		t.Skip("sh unavailable")
	}
	exitErr := exec.Command(sh, "-c", "exit 1").Run()
	var typedExit *exec.ExitError
	if !errors.As(exitErr, &typedExit) {
		t.Fatalf("setup error = %T, want *exec.ExitError", exitErr)
	}
	out := `exit status 1: 2026/08/29 01:20:31 [alert] 4242#4242: open() "/run/nginx.pid" failed (1: Operation not permitted)`
	failure := NewFailure(KindNginx, FailurePhaseReload, out, exitErr)
	if !failure.Permission || failure.BinaryMissing {
		t.Fatalf("failure = %#v, want permission-only reload failure", failure)
	}
	if !errors.Is(failure, exitErr) {
		t.Fatal("Failure did not preserve the original ExitError")
	}
}

func TestRunCombinedOutputWrapsOnlyStartErrorsWithExecutableIdentity(t *testing.T) {
	missingNginx := filepath.Join(t.TempDir(), "nginx")
	_, err := RunCombinedOutput(exec.Command(missingNginx, "-t"))
	var executionErr *ExecutionError
	if !errors.As(err, &executionErr) {
		t.Fatalf("start error = %T, want *ExecutionError", err)
	}
	if executionErr.Executable != missingNginx {
		t.Fatalf("Executable = %q, want %q", executionErr.Executable, missingNginx)
	}
	if executionErr.Role != ExecutionRoleSystem {
		t.Fatalf("generic execution role = %q, want system", executionErr.Role)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal("ExecutionError does not unwrap to the original missing-file cause")
	}
	failure := NewFailure(KindNginx, FailurePhaseValidate, "", fmt.Errorf("nested: %w", err))
	if failure.BinaryMissing || !errors.Is(failure, os.ErrNotExist) {
		t.Fatalf("failure = %#v, want generic execution to remain unknown", failure)
	}
	var nestedExecution *ExecutionError
	if !errors.As(failure, &nestedExecution) || nestedExecution.Executable != missingNginx || nestedExecution.Role != ExecutionRoleSystem {
		t.Fatalf("Failure did not preserve typed execution identity: %#v", nestedExecution)
	}

	_, backendErr := RunBackendCombinedOutput(exec.Command(missingNginx, "-t"))
	backendFailure := NewFailure(KindNginx, FailurePhaseValidate, "", fmt.Errorf("nested: %w", backendErr))
	if !backendFailure.BinaryMissing || !errors.Is(backendFailure, os.ErrNotExist) {
		t.Fatalf("failure = %#v, want verified backend execution", backendFailure)
	}
	if !errors.As(backendFailure, &nestedExecution) || nestedExecution.Role != ExecutionRoleBackend {
		t.Fatalf("backend execution role not preserved: %#v", nestedExecution)
	}
	for _, name := range []string{"sudo", "nginx-wrapper"} {
		missingWrapper := filepath.Join(t.TempDir(), name)
		_, wrapperErr := RunCombinedOutput(exec.Command(missingWrapper))
		wrapperFailure := NewFailure(KindNginx, FailurePhaseValidate, "", wrapperErr)
		if wrapperFailure.BinaryMissing {
			t.Fatalf("missing %s was mistaken for missing nginx: %#v", name, wrapperFailure)
		}
	}

	sh, lookupErr := exec.LookPath("sh")
	if lookupErr != nil {
		t.Skip("sh unavailable")
	}
	_, exitErr := RunCombinedOutput(exec.Command(sh, "-c", "exit 7"))
	if errors.As(exitErr, &executionErr) {
		t.Fatalf("started command exit was wrapped as start error: %#v", executionErr)
	}
}

func TestFailureCommandLabelRejectsUnknownEnums(t *testing.T) {
	tests := []struct {
		name    string
		backend Kind
		phase   FailurePhase
	}{
		{name: "unknown backend", backend: Kind("token=backend-secret"), phase: FailurePhaseReload},
		{name: "control backend", backend: Kind("nginx\nsecret"), phase: FailurePhaseValidate},
		{name: "overlong backend", backend: Kind(strings.Repeat("x", MaxFailureCaptureBytes)), phase: FailurePhaseCertInstall},
		{name: "unknown phase", backend: KindNginx, phase: FailurePhase("token=phase-secret")},
		{name: "control phase", backend: KindApache, phase: FailurePhase("reload\nsecret")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			failure := &Failure{Backend: tt.backend, Phase: tt.phase}
			if got := failure.Error(); got != "proxy operation failed" {
				t.Fatalf("Error() = %q, want fail-closed label", got)
			}
		})
	}
}

func TestNewFailureBoundsBeforeClassificationAndKeepsTruncationMarker(t *testing.T) {
	secret := "cutoff-secret"
	prefix := strings.Repeat("x", MaxFailureCaptureBytes-40)
	raw := prefix + "\ntoken=" + secret + strings.Repeat("z", 2<<20)
	failure := NewFailure(KindNginx, FailurePhaseValidate, raw, errors.New("exit 1"))
	if len(failure.Output) > recoverymodel.MaxEvidenceBytes || !utf8.ValidString(failure.Output) {
		t.Fatalf("unsafe bounded output: bytes=%d valid=%v", len(failure.Output), utf8.ValidString(failure.Output))
	}
	if strings.Contains(failure.Output, secret) {
		t.Fatalf("Output leaked cutoff secret: %q", failure.Output)
	}
	if !strings.Contains(failure.Output, FailureOutputTruncated) {
		t.Fatalf("Output lacks truncation marker: %q", failure.Output[len(failure.Output)-80:])
	}
}

func TestNewFailureKeepsOutputThatFitsHardLimit(t *testing.T) {
	raw := strings.Repeat("x", MaxFailureCaptureBytes-1)
	failure := NewFailure(KindNginx, FailurePhaseValidate, raw, errors.New("exit 1"))
	if failure.Output != raw || strings.Contains(failure.Output, FailureOutputTruncated) {
		t.Fatalf("in-limit output was truncated: bytes=%d marker=%v", len(failure.Output), strings.Contains(failure.Output, FailureOutputTruncated))
	}
}

func TestBoundedOutputWriterKeepsMemoryAndUTF8Bounded(t *testing.T) {
	w := newBoundedOutputWriter()
	chunk := []byte(strings.Repeat("€", 400_000))
	for i := 0; i < 4; i++ {
		if _, err := w.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if cap(w.buf) > MaxFailureCaptureBytes {
		t.Fatalf("capture capacity = %d, want <= %d", cap(w.buf), MaxFailureCaptureBytes)
	}
	got := w.String()
	if len(got) > MaxFailureCaptureBytes || !utf8.ValidString(got) || !strings.Contains(got, FailureOutputTruncated) {
		t.Fatalf("bounded output bytes=%d valid=%v marker=%v", len(got), utf8.ValidString(got), strings.Contains(got, FailureOutputTruncated))
	}
}

func TestRunCombinedOutputBoundsMultiMegabyteCommand(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh unavailable")
	}
	cmd := exec.Command(sh, "-c", "printf 'stdout-line\\n'; printf 'stderr-line\\n' >&2; head -c 4194304 /dev/zero | tr '\\000' x")
	out, err := RunCombinedOutput(cmd)
	if err != nil {
		t.Fatalf("RunCombinedOutput: %v", err)
	}
	if len(out) > MaxFailureCaptureBytes || !utf8.ValidString(out) || !strings.Contains(out, FailureOutputTruncated) {
		t.Fatalf("combined output bytes=%d valid=%v marker=%v", len(out), utf8.ValidString(out), strings.Contains(out, FailureOutputTruncated))
	}
	if !strings.Contains(out, "stdout-line") || !strings.Contains(out, "stderr-line") {
		t.Fatalf("combined output did not capture both streams: %q", out[:80])
	}
	if filepath.Base(cmd.Path) != "sh" {
		t.Fatalf("unexpected command path %q", cmd.Path)
	}
}

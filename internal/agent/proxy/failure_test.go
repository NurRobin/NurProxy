package proxy

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
		wantReferencedPaths    []string
	}{
		{
			name:                "nginx missing certificate",
			backend:             KindNginx,
			output:              `nginx: [emerg] cannot load certificate "/var/lib/nurproxy/certs/app.crt": BIO_new_file() failed (SSL: error:80000002:system library::No such file or directory)`,
			wantMissingCert:     true,
			wantReferencedPaths: []string{"/var/lib/nurproxy/certs/app.crt"},
		},
		{
			name:                  "nginx missing runtime key",
			backend:               KindNginx,
			output:                `nginx: [emerg] cannot load certificate key "/var/lib/nurproxy/certs/app.key.plain": BIO_new_file() failed (SSL: error:80000002:system library::No such file or directory)`,
			wantMissingRuntimeKey: true,
			wantReferencedPaths:   []string{"/var/lib/nurproxy/certs/app.key.plain"},
		},
		{
			name:                   "nginx runtime key mismatch",
			backend:                KindNginx,
			output:                 `nginx: [emerg] SSL_CTX_use_PrivateKey("/var/lib/nurproxy/certs/app.key.plain") failed (SSL: error:05800074:x509 certificate routines::key values mismatch)`,
			wantRuntimeKeyMismatch: true,
			wantReferencedPaths:    []string{"/var/lib/nurproxy/certs/app.key.plain"},
		},
		{
			name:                "apache missing certificate",
			backend:             KindApache,
			output:              "AH00526: Syntax error on line 12 of /etc/apache2/sites-enabled/app.conf:\nSSLCertificateFile: file '/var/lib/nurproxy/certs/app.crt' does not exist or is empty",
			wantMissingCert:     true,
			wantReferencedPaths: []string{"/var/lib/nurproxy/certs/app.crt"},
		},
		{
			name:                  "apache missing runtime key",
			backend:               KindApache,
			output:                "AH00526: Syntax error on line 13 of /etc/apache2/sites-enabled/app.conf:\nSSLCertificateKeyFile: file '/var/lib/nurproxy/certs/app.key.plain' does not exist or is empty",
			wantMissingRuntimeKey: true,
			wantReferencedPaths:   []string{"/var/lib/nurproxy/certs/app.key.plain"},
		},
		{
			name:                   "apache runtime key mismatch",
			backend:                KindApache,
			output:                 `AH02565: Certificate and private key app.example.com:443:0 from /var/lib/nurproxy/certs/app.crt and /var/lib/nurproxy/certs/app.key.plain do not match`,
			wantRuntimeKeyMismatch: true,
			wantReferencedPaths:    []string{"/var/lib/nurproxy/certs/app.crt", "/var/lib/nurproxy/certs/app.key.plain"},
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
			if !slices.Equal(got.ReferencedPaths, tt.wantReferencedPaths) {
				t.Errorf("ReferencedPaths = %q, want %q", got.ReferencedPaths, tt.wantReferencedPaths)
			}
			if !tt.wantMissingCert && !tt.wantMissingRuntimeKey && !tt.wantRuntimeKeyMismatch && !tt.wantBinaryMissing &&
				(got.Permission || got.ManagedHint) {
				t.Errorf("unknown/near-miss output gained a repair hint: %#v", got)
			}
		})
	}
}

func TestNewFailureRejectsUnsafeReferencedPathsFromOtherwiseRecognizedLines(t *testing.T) {
	tests := []struct {
		name    string
		backend Kind
		output  string
	}{
		{"nginx traversal", KindNginx, `nginx: [emerg] cannot load certificate "/var/lib/nurproxy/certs/../secret.crt": BIO_new_file() failed (SSL: error:80000002:system library::No such file or directory)`},
		{"nginx secret assignment", KindNginx, `nginx: [emerg] cannot load certificate key "/var/lib/nurproxy/token=secret": BIO_new_file() failed (SSL: error:80000002:system library::No such file or directory)`},
		{"apache relative", KindApache, "AH00526: Syntax error on line 1 of /etc/apache2/a.conf:\nSSLCertificateFile: file 'relative.crt' does not exist or is empty"},
		{"apache mismatch outside syntax", KindApache, `AH02565: Certificate and private key app:443:0 from /safe/app.crt and ../app.key do not match`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewFailure(tt.backend, FailurePhaseValidate, tt.output, errors.New("exit 1"))
			if got.MissingCert || got.MissingRuntimeKey || got.RuntimeKeyMismatch || len(got.ReferencedPaths) != 0 {
				t.Fatalf("unsafe referenced path retained a repair hint: %#v", got)
			}
		})
	}
}

func TestFailureSetReferencedPathsIsBoundedAndAtomic(t *testing.T) {
	failure := NewFailure(KindNginx, FailurePhaseValidate, "unknown", errors.New("exit 1"))
	if !failure.SetReferencedPaths("/var/lib/nurproxy/certs/app.crt", "/var/lib/nurproxy/certs/app.key.plain") {
		t.Fatal("safe referenced paths rejected")
	}
	if failure.SetReferencedPaths("/safe.crt", "/safe.key", "/extra") || len(failure.ReferencedPaths) != 0 {
		t.Fatalf("too many referenced paths were retained: %q", failure.ReferencedPaths)
	}
	if failure.SetReferencedPaths("/safe.crt", "/unsafe/../key") || len(failure.ReferencedPaths) != 0 {
		t.Fatalf("unsafe referenced path was retained: %q", failure.ReferencedPaths)
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

func TestNewFailureBinaryMissingThroughSudoRequiresExactBackendTarget(t *testing.T) {
	sh, lookupErr := exec.LookPath("sh")
	if lookupErr != nil {
		t.Skip("sh unavailable")
	}
	exitErr := exec.Command(sh, "-c", "exit 1").Run()
	var typedExit *exec.ExitError
	if !errors.As(exitErr, &typedExit) {
		t.Fatalf("setup error = %T, want *exec.ExitError", exitErr)
	}
	target := "/opt/nurproxy/bin/nginx"
	tests := []struct {
		name       string
		backend    Kind
		launcher   string
		target     string
		targetRole ExecutionRole
		output     string
		cause      error
		want       bool
	}{
		{name: "exact nginx backend target", backend: KindNginx, launcher: "/usr/bin/sudo", target: target, targetRole: ExecutionRoleBackend, output: "sudo: unable to execute /opt/nurproxy/bin/nginx: No such file or directory\n", cause: exitErr, want: true},
		{name: "exact apache backend target", backend: KindApache, launcher: "/usr/bin/sudo", target: "/opt/nurproxy/bin/apachectl", targetRole: ExecutionRoleBackend, output: "sudo: unable to execute /opt/nurproxy/bin/apachectl: No such file or directory\n", cause: exitErr, want: true},
		{name: "same-name override", backend: KindNginx, launcher: "/usr/bin/sudo", target: target, targetRole: ExecutionRoleOverride, output: "sudo: unable to execute /opt/nurproxy/bin/nginx: No such file or directory\n", cause: exitErr},
		{name: "different target", backend: KindNginx, launcher: "/usr/bin/sudo", target: target, targetRole: ExecutionRoleBackend, output: "sudo: unable to execute /tmp/nginx: No such file or directory\n", cause: exitErr},
		{name: "prose near miss", backend: KindNginx, launcher: "/usr/bin/sudo", target: target, targetRole: ExecutionRoleBackend, output: "notice: sudo: unable to execute /opt/nurproxy/bin/nginx: No such file or directory\n", cause: exitErr},
		{name: "indented near miss", backend: KindNginx, launcher: "/usr/bin/sudo", target: target, targetRole: ExecutionRoleBackend, output: "  sudo: unable to execute /opt/nurproxy/bin/nginx: No such file or directory\n", cause: exitErr},
		{name: "wrong backend", backend: KindNginx, launcher: "/usr/bin/sudo", target: "/opt/nurproxy/bin/apachectl", targetRole: ExecutionRoleBackend, output: "sudo: unable to execute /opt/nurproxy/bin/apachectl: No such file or directory\n", cause: exitErr},
		{name: "missing sudo launcher", backend: KindNginx, launcher: "/missing/sudo", target: target, targetRole: ExecutionRoleBackend, cause: &os.PathError{Op: "fork/exec", Path: "/missing/sudo", Err: os.ErrNotExist}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &ExecutionError{
				Executable:       tt.launcher,
				Role:             ExecutionRoleSystem,
				TargetExecutable: tt.target,
				TargetRole:       tt.targetRole,
				output:           tt.output,
				Err:              tt.cause,
			}
			failure := NewFailure(tt.backend, FailurePhaseValidate, tt.output, err)
			if failure.BinaryMissing != tt.want {
				t.Fatalf("BinaryMissing = %v, want %v", failure.BinaryMissing, tt.want)
			}
			if tt.cause == exitErr && (!errors.As(failure, &typedExit) || !errors.Is(failure, exitErr)) {
				t.Fatal("wrapped sudo ExitError chain was not preserved")
			}
		})
	}
}

func TestRunTargetCombinedOutputPreservesSudoBackendIdentity(t *testing.T) {
	fakeSudo := filepath.Join(t.TempDir(), "sudo")
	script := "#!/bin/sh\nprintf 'sudo: unable to execute %s: No such file or directory\\n' \"$1\" >&2\nexit 1\n"
	if err := os.WriteFile(fakeSudo, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		backend Kind
		phase   FailurePhase
		target  string
	}{
		{name: "nginx validate", backend: KindNginx, phase: FailurePhaseValidate, target: "/opt/nurproxy/bin/nginx"},
		{name: "nginx reload", backend: KindNginx, phase: FailurePhaseReload, target: "/opt/nurproxy/bin/nginx"},
		{name: "apache validate", backend: KindApache, phase: FailurePhaseValidate, target: "/opt/nurproxy/bin/apachectl"},
		{name: "apache reload", backend: KindApache, phase: FailurePhaseReload, target: "/opt/nurproxy/bin/httpd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := RunTargetCombinedOutput(exec.Command(fakeSudo, tt.target), tt.target, ExecutionRoleBackend)
			var executionErr *ExecutionError
			if !errors.As(err, &executionErr) {
				t.Fatalf("error = %T, want *ExecutionError", err)
			}
			if executionErr.Executable != fakeSudo || executionErr.Role != ExecutionRoleSystem || executionErr.TargetExecutable != tt.target || executionErr.TargetRole != ExecutionRoleBackend || executionErr.output != out {
				t.Fatalf("execution metadata = %#v, output %q", executionErr, out)
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatal("wrapped process exit did not preserve *exec.ExitError")
			}
			failure := NewFailure(tt.backend, tt.phase, out, err)
			if !failure.BinaryMissing || !errors.As(failure, &exitErr) {
				t.Fatalf("failure = %#v, want verified missing sudo target", failure)
			}
		})
	}

	missingSudo := filepath.Join(t.TempDir(), "sudo")
	target := "/opt/nurproxy/bin/nginx"
	out, err := RunTargetCombinedOutput(exec.Command(missingSudo, target), target, ExecutionRoleBackend)
	if failure := NewFailure(KindNginx, FailurePhaseValidate, out, err); failure.BinaryMissing {
		t.Fatalf("missing sudo launcher was mistaken for missing target: %#v", failure)
	}
}

func TestNewFailureUsesCanonicalCapturedExecutionOutput(t *testing.T) {
	sh, lookupErr := exec.LookPath("sh")
	if lookupErr != nil {
		t.Skip("sh unavailable")
	}
	script := "printf 'nginx: [alert] open() failed (1: Operation not permitted)\\n' >&2; " +
		"printf 'token=canonical-secret\\n' >&2; head -c 4194304 /dev/zero | tr '\\000' x >&2; exit 1"
	out, err := RunTargetCombinedOutput(exec.Command(sh, "-c", script), "/usr/sbin/nginx", ExecutionRoleBackend)
	if err == nil {
		t.Fatal("command unexpectedly succeeded")
	}
	failure := NewFailure(KindNginx, FailurePhaseReload, "starting proxy executable failed: unrelated prose token=argument-secret", fmt.Errorf("reload wrapper: %w", err))
	if failure.Output != out {
		t.Fatalf("Failure.Output did not use canonical capture\n got: %q\nwant: %q", failure.Output, out)
	}
	if !failure.Permission {
		t.Fatalf("failure = %#v, want canonical nginx permission classification", failure)
	}
	if len(failure.Output) > MaxFailureCaptureBytes || !strings.Contains(failure.Output, FailureOutputTruncated) {
		t.Fatalf("canonical output bytes=%d, truncated=%v", len(failure.Output), strings.Contains(failure.Output, FailureOutputTruncated))
	}
	for _, leaked := range []string{"canonical-secret", "argument-secret", "starting proxy executable failed"} {
		if strings.Contains(failure.Output, leaked) || strings.Contains(failure.Error(), leaked) {
			t.Fatalf("failure leaked %q: output=%q error=%q", leaked, failure.Output, failure.Error())
		}
	}
	var exitErr *exec.ExitError
	if !errors.As(failure, &exitErr) || !errors.Is(failure, exitErr) {
		t.Fatal("canonical output selection changed the execution error chain")
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

func TestRunCombinedOutputPreservesExecutionIdentityAndCauses(t *testing.T) {
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
	if executionErr.TargetExecutable != missingNginx || executionErr.TargetRole != ExecutionRoleSystem {
		t.Fatalf("generic target metadata = %#v, want system target %q", executionErr, missingNginx)
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
	if nestedExecution.TargetExecutable != missingNginx || nestedExecution.TargetRole != ExecutionRoleBackend {
		t.Fatalf("backend target metadata not preserved: %#v", nestedExecution)
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
	if !errors.As(exitErr, &executionErr) {
		t.Fatalf("started command exit = %T, want metadata-preserving ExecutionError", exitErr)
	}
	var typedExit *exec.ExitError
	if !errors.As(exitErr, &typedExit) || !errors.Is(exitErr, typedExit) {
		t.Fatalf("ExecutionError did not preserve ExitError chain: %#v", executionErr)
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

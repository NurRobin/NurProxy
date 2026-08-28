package proxy

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

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
			output:          `AH00526: Syntax error on line 12 of /etc/apache2/sites-enabled/app.conf: SSLCertificateFile: file '/var/lib/nurproxy/certs/app.crt' does not exist or is empty`,
			wantMissingCert: true,
		},
		{
			name:                  "apache missing runtime key",
			backend:               KindApache,
			output:                `AH00526: Syntax error on line 13 of /etc/apache2/sites-enabled/app.conf: SSLCertificateKeyFile: file '/var/lib/nurproxy/certs/app.key.plain' does not exist or is empty`,
			wantMissingRuntimeKey: true,
		},
		{
			name:                   "apache runtime key mismatch",
			backend:                KindApache,
			output:                 `AH02565: Certificate and private key app.example.com:443:0 from /var/lib/nurproxy/certs/app.crt and /var/lib/nurproxy/certs/app.key.plain do not match`,
			wantRuntimeKeyMismatch: true,
		},
		{
			name:              "binary missing",
			backend:           KindNginx,
			err:               exec.ErrNotFound,
			wantBinaryMissing: true,
		},
		{
			name:    "unknown output has no repair hint",
			backend: KindNginx,
			output:  `nginx: [emerg] something entirely new happened`,
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
	failure.File = "/etc/apache2/sites-enabled/app.conf"
	failure.Line = 7
	failure.Located = true

	if got, want := failure.Error(), "apache reload failed at /etc/apache2/sites-enabled/app.conf:7"; got != want {
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

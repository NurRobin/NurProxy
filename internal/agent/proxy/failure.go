package proxy

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

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
	Err                error
}

func NewFailure(backend Kind, phase FailurePhase, output string, err error) *Failure {
	f := &Failure{
		Backend: backend,
		Phase:   phase,
		Output:  recoverymodel.SanitizeEvidence(output),
		Err:     err,
	}
	if phase == FailurePhaseValidate || phase == FailurePhaseReload {
		f.BinaryMissing = errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist)
	}
	f.classifyKnownOutput(output)
	return f
}

func (f *Failure) Error() string {
	backend := strings.TrimSpace(string(f.Backend))
	if backend == "" {
		backend = "proxy"
	}
	phase := strings.TrimSpace(string(f.Phase))
	if phase == "" {
		phase = "operation"
	}
	if f.Located && f.File != "" && f.Line > 0 {
		return fmt.Sprintf("%s %s failed at %s:%d", backend, phase, f.File, f.Line)
	}
	return fmt.Sprintf("%s %s failed", backend, phase)
}

func (f *Failure) Unwrap() error {
	if f == nil {
		return nil
	}
	return f.Err
}

func (f *Failure) classifyKnownOutput(output string) {
	lower := strings.ToLower(output)
	switch f.Backend {
	case KindNginx:
		switch {
		case strings.Contains(lower, "ssl_ctx_use_privatekey(") && strings.Contains(lower, "key values mismatch"):
			f.RuntimeKeyMismatch = true
		case strings.Contains(lower, "cannot load certificate key ") && strings.Contains(lower, "no such file or directory"):
			f.MissingRuntimeKey = true
		case strings.Contains(lower, "cannot load certificate ") && strings.Contains(lower, "no such file or directory"):
			f.MissingCert = true
		}
	case KindApache:
		switch {
		case strings.Contains(lower, "ah02565:") && strings.Contains(lower, "certificate and private key") && strings.Contains(lower, "do not match"):
			f.RuntimeKeyMismatch = true
		case strings.Contains(lower, "sslcertificatekeyfile:") && strings.Contains(lower, "does not exist or is empty"):
			f.MissingRuntimeKey = true
		case strings.Contains(lower, "sslcertificatefile:") && strings.Contains(lower, "does not exist or is empty"):
			f.MissingCert = true
		}
	}
}

package recoverymodel

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const MaxEvidenceBytes = 8 << 10

type Code string

const (
	CodeManagedOrphanConfig       Code = "managed_orphan_config"
	CodeManagedStaleTemp          Code = "managed_stale_temp"
	CodeManagedCertFileMissing    Code = "managed_cert_file_missing"
	CodeManagedRuntimeKeyMissing  Code = "managed_runtime_key_missing"
	CodeManagedRuntimeKeyMismatch Code = "managed_runtime_key_mismatch"
	CodeGeneratedConfigInvalid    Code = "generated_config_invalid"
	CodeOperatorConfigInvalid     Code = "operator_config_invalid"
	CodePermissionDenied          Code = "permission_denied"
	CodeSystemdSandboxDenied      Code = "systemd_sandbox_denied"
	CodeProxyReloadFailed         Code = "proxy_reload_failed"
	CodeProxyNotRunning           Code = "proxy_not_running"
	CodePortConflict              Code = "port_conflict"
	CodeProxyBinaryMissing        Code = "proxy_binary_missing"
	CodeUnknownProxyError         Code = "unknown_proxy_error"
)

func (v Code) Valid() bool {
	switch v {
	case CodeManagedOrphanConfig, CodeManagedStaleTemp,
		CodeManagedCertFileMissing, CodeManagedRuntimeKeyMissing,
		CodeManagedRuntimeKeyMismatch, CodeGeneratedConfigInvalid,
		CodeOperatorConfigInvalid, CodePermissionDenied,
		CodeSystemdSandboxDenied, CodeProxyReloadFailed,
		CodeProxyNotRunning, CodePortConflict, CodeProxyBinaryMissing,
		CodeUnknownProxyError:
		return true
	default:
		return false
	}
}

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
)

func (v Severity) Valid() bool {
	switch v {
	case SeverityInfo, SeverityWarning, SeverityError, SeverityCritical:
		return true
	default:
		return false
	}
}

type Ownership string

const (
	OwnershipNurProxy Ownership = "nurproxy"
	OwnershipOperator Ownership = "operator"
	OwnershipSystem   Ownership = "system"
	OwnershipUnknown  Ownership = "unknown"
)

func (v Ownership) Valid() bool {
	switch v {
	case OwnershipNurProxy, OwnershipOperator, OwnershipSystem, OwnershipUnknown:
		return true
	default:
		return false
	}
}

type Action string

const (
	ActionPruneManagedOrphan      Action = "prune_managed_orphan"
	ActionRemoveManagedTemp       Action = "remove_managed_temp"
	ActionRematerializeCertBundle Action = "rematerialize_cert_bundle"
	ActionRematerializeRuntimeKey Action = "rematerialize_runtime_key"
	ActionRestoreLastLiveArtifact Action = "restore_last_live_artifact"
)

func (v Action) Valid() bool {
	switch v {
	case ActionPruneManagedOrphan, ActionRemoveManagedTemp,
		ActionRematerializeCertBundle, ActionRematerializeRuntimeKey,
		ActionRestoreLastLiveArtifact:
		return true
	default:
		return false
	}
}

func (v *Action) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	action := Action(raw)
	if action != "" && !action.Valid() {
		return fmt.Errorf("unknown recovery action %q", raw)
	}
	*v = action
	return nil
}

type OperationState string

const (
	OperationStateDetected       OperationState = "detected"
	OperationStateDiagnosisOnly  OperationState = "diagnosis_only"
	OperationStatePlanned        OperationState = "planned"
	OperationStateSnapshotted    OperationState = "snapshotted"
	OperationStateApplying       OperationState = "applying"
	OperationStateValidating     OperationState = "validating"
	OperationStateSucceeded      OperationState = "succeeded"
	OperationStateRollingBack    OperationState = "rolling_back"
	OperationStateRolledBack     OperationState = "rolled_back"
	OperationStateRollbackFailed OperationState = "rollback_failed"
	OperationStateSuppressed     OperationState = "suppressed"
)

func (v OperationState) Valid() bool {
	switch v {
	case OperationStateDetected, OperationStateDiagnosisOnly,
		OperationStatePlanned, OperationStateSnapshotted,
		OperationStateApplying, OperationStateValidating,
		OperationStateSucceeded, OperationStateRollingBack,
		OperationStateRolledBack, OperationStateRollbackFailed,
		OperationStateSuppressed:
		return true
	default:
		return false
	}
}

func (v *OperationState) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	state := OperationState(raw)
	if !state.Valid() {
		return fmt.Errorf("unknown recovery operation state %q", raw)
	}
	*v = state
	return nil
}

type RequestSource string

const (
	RequestSourceAutomatic RequestSource = "automatic"
	RequestSourceUser      RequestSource = "user"
)

func (v RequestSource) Valid() bool {
	return v == RequestSourceAutomatic || v == RequestSourceUser
}

type Diagnostic struct {
	ID                  string    `json:"id"`
	Code                Code      `json:"code"`
	Subsystem           string    `json:"subsystem"`
	Severity            Severity  `json:"severity"`
	Ownership           Ownership `json:"ownership"`
	Summary             string    `json:"summary"`
	Evidence            string    `json:"evidence"`
	AffectedPaths       []string  `json:"affected_paths"`
	ResourceFingerprint string    `json:"resource_fingerprint"`
	ProposedAction      Action    `json:"proposed_action"`
	AutoRepairEligible  bool      `json:"auto_repair_eligible"`
	HardChange          bool      `json:"hard_change"`
	FirstSeenAt         time.Time `json:"first_seen_at"`
	LastSeenAt          time.Time `json:"last_seen_at"`
	Occurrences         int       `json:"occurrences"`
}

type Capability struct {
	Stage   int      `json:"stage"`
	Actions []Action `json:"actions"`
}

type RepairRequest struct {
	OperationID  string `json:"operation_id"`
	DiagnosticID string `json:"diagnostic_id"`
	Action       Action `json:"action"`
}

type Step struct {
	Name    string         `json:"name"`
	Summary string         `json:"summary"`
	State   OperationState `json:"state"`
	At      time.Time      `json:"at"`
}

type OperationReport struct {
	OperationID       string         `json:"operation_id"`
	DiagnosticID      string         `json:"diagnostic_id"`
	Action            Action         `json:"action"`
	Source            RequestSource  `json:"source"`
	State             OperationState `json:"state"`
	Steps             []Step         `json:"steps"`
	SnapshotReference string         `json:"snapshot_reference"`
	ValidationOutcome string         `json:"validation_outcome"`
	RollbackOutcome   string         `json:"rollback_outcome"`
	Error             string         `json:"error"`
	StartedAt         time.Time      `json:"started_at"`
	FinishedAt        *time.Time     `json:"finished_at"`
}

func StableDiagnosticID(agentID string, code Code, resourceFingerprint string) string {
	h := sha256.New()
	for _, value := range []string{agentID, string(code), resourceFingerprint} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(value))
	}
	return "diag_" + hex.EncodeToString(h.Sum(nil))
}

var (
	privateKeyPattern = regexp.MustCompile(`(?is)-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----`)
	bearerPattern     = regexp.MustCompile(`(?i)(authorization\s*:\s*bearer\s+)[^\s]+`)
	secretPattern     = regexp.MustCompile(`(?i)(\b(?:api[_-]?key|token|password|secret|private[_-]?key)\b\s*[:=]\s*)[^\s,;]+`)
)

func SanitizeEvidence(evidence string) string {
	evidence = strings.ToValidUTF8(evidence, "�")
	evidence = privateKeyPattern.ReplaceAllString(evidence, "[REDACTED]")
	evidence = bearerPattern.ReplaceAllString(evidence, "${1}[REDACTED]")
	evidence = secretPattern.ReplaceAllString(evidence, "${1}[REDACTED]")
	evidence = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return -1
		}
		return r
	}, evidence)
	if len(evidence) <= MaxEvidenceBytes {
		return evidence
	}
	end := MaxEvidenceBytes
	for end > 0 && !utf8.RuneStart(evidence[end]) {
		end--
	}
	return evidence[:end]
}

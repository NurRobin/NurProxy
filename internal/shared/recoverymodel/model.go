package recoverymodel

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

func (v *Code) UnmarshalJSON(data []byte) error {
	raw, err := unmarshalClosedString(data, "diagnostic code", false, func(value string) bool { return Code(value).Valid() })
	if err != nil {
		return err
	}
	*v = Code(raw)
	return nil
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

func (v *Severity) UnmarshalJSON(data []byte) error {
	raw, err := unmarshalClosedString(data, "diagnostic severity", false, func(value string) bool { return Severity(value).Valid() })
	if err != nil {
		return err
	}
	*v = Severity(raw)
	return nil
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

func (v *Ownership) UnmarshalJSON(data []byte) error {
	raw, err := unmarshalClosedString(data, "diagnostic ownership", false, func(value string) bool { return Ownership(value).Valid() })
	if err != nil {
		return err
	}
	*v = Ownership(raw)
	return nil
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
	raw, err := unmarshalClosedString(data, "recovery action", true, func(value string) bool { return Action(value).Valid() })
	if err != nil {
		return err
	}
	*v = Action(raw)
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
	raw, err := unmarshalClosedString(data, "recovery operation state", false, func(value string) bool { return OperationState(value).Valid() })
	if err != nil {
		return err
	}
	*v = OperationState(raw)
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

func (v *RequestSource) UnmarshalJSON(data []byte) error {
	raw, err := unmarshalClosedString(data, "recovery request source", false, func(value string) bool { return RequestSource(value).Valid() })
	if err != nil {
		return err
	}
	*v = RequestSource(raw)
	return nil
}

func unmarshalClosedString(data []byte, name string, allowEmpty bool, valid func(string) bool) (string, error) {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return "", err
	}
	if raw == "" && allowEmpty {
		return "", nil
	}
	if !valid(raw) {
		return "", fmt.Errorf("unknown %s %q", name, raw)
	}
	return raw, nil
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

func (d Diagnostic) Validate() error {
	if strings.TrimSpace(d.ID) == "" {
		return fmt.Errorf("diagnostic ID is required")
	}
	if !d.Code.Valid() {
		return fmt.Errorf("invalid diagnostic code %q", d.Code)
	}
	if strings.TrimSpace(d.Subsystem) == "" {
		return fmt.Errorf("diagnostic subsystem is required")
	}
	if !d.Severity.Valid() {
		return fmt.Errorf("invalid diagnostic severity %q", d.Severity)
	}
	if !d.Ownership.Valid() {
		return fmt.Errorf("invalid diagnostic ownership %q", d.Ownership)
	}
	if strings.TrimSpace(d.ResourceFingerprint) == "" {
		return fmt.Errorf("diagnostic resource fingerprint is required")
	}
	if d.Occurrences < 1 {
		return fmt.Errorf("diagnostic occurrences must be positive")
	}
	if d.ProposedAction != "" && !d.ProposedAction.Valid() {
		return fmt.Errorf("invalid proposed recovery action %q", d.ProposedAction)
	}
	if d.AutoRepairEligible && d.ProposedAction == "" {
		return fmt.Errorf("auto-repair eligible diagnostic requires an action")
	}
	return nil
}

func (c Capability) Validate() error {
	if c.Stage < 1 {
		return fmt.Errorf("recovery capability stage must be positive")
	}
	seen := make(map[Action]struct{}, len(c.Actions))
	for _, action := range c.Actions {
		if !action.Valid() {
			return fmt.Errorf("invalid recovery capability action %q", action)
		}
		if _, exists := seen[action]; exists {
			return fmt.Errorf("duplicate recovery capability action %q", action)
		}
		seen[action] = struct{}{}
	}
	return nil
}

func (r RepairRequest) Validate() error {
	if strings.TrimSpace(r.OperationID) == "" {
		return fmt.Errorf("repair operation ID is required")
	}
	if strings.TrimSpace(r.DiagnosticID) == "" {
		return fmt.Errorf("repair diagnostic ID is required")
	}
	if !r.Action.Valid() {
		return fmt.Errorf("invalid repair action %q", r.Action)
	}
	return nil
}

func (r *RepairRequest) UnmarshalJSON(data []byte) error {
	type plain RepairRequest
	var decoded plain
	if err := DecodeStrict(data, &decoded); err != nil {
		return err
	}
	*r = RepairRequest(decoded)
	return r.Validate()
}

func (r OperationReport) Validate() error {
	if strings.TrimSpace(r.OperationID) == "" {
		return fmt.Errorf("repair operation ID is required")
	}
	if strings.TrimSpace(r.DiagnosticID) == "" {
		return fmt.Errorf("repair diagnostic ID is required")
	}
	if !r.Action.Valid() {
		return fmt.Errorf("invalid repair action %q", r.Action)
	}
	if !r.Source.Valid() {
		return fmt.Errorf("invalid repair request source %q", r.Source)
	}
	if !r.State.Valid() {
		return fmt.Errorf("invalid repair operation state %q", r.State)
	}
	if r.StartedAt.IsZero() {
		return fmt.Errorf("repair operation start time is required")
	}
	if r.FinishedAt != nil && r.FinishedAt.Before(r.StartedAt) {
		return fmt.Errorf("repair operation finish time precedes start time")
	}
	for i, step := range r.Steps {
		if strings.TrimSpace(step.Name) == "" {
			return fmt.Errorf("repair step %d name is required", i)
		}
		if !step.State.Valid() {
			return fmt.Errorf("repair step %d has invalid state %q", i, step.State)
		}
	}
	return nil
}

func DecodeStrict(data []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	if validator, ok := dst.(interface{ Validate() error }); ok {
		return validator.Validate()
	}
	return nil
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
	privateKeyPattern    = regexp.MustCompile(`(?is)-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|\z)`)
	nginxAuthPattern     = regexp.MustCompile(`(?i)(\bproxy_set_header\s+authorization\s+)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^;\r\n]+)`)
	authorizationPattern = regexp.MustCompile(`(?i)(\bauthorization\b\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\r\n,;]+)`)
	secretPattern        = regexp.MustCompile(`(?i)((?:"(?:[a-z][a-z0-9]*_)*(?:api_?key|token|password|secret|private_?key)"|(?:[a-z][a-z0-9]*_)*(?:api_?key|token|password|secret|private_?key))\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;}]+)`)
)

func SanitizeEvidence(evidence string) string {
	evidence = strings.ToValidUTF8(evidence, "�")
	evidence = strings.ReplaceAll(evidence, "\r\n", "\n")
	evidence = strings.Map(func(r rune) rune {
		if r == '\r' || unicode.Is(unicode.Cf, r) || (unicode.IsControl(r) && r != '\n' && r != '\t') {
			return -1
		}
		return r
	}, evidence)
	evidence = privateKeyPattern.ReplaceAllString(evidence, "[REDACTED]")
	evidence = nginxAuthPattern.ReplaceAllString(evidence, "${1}[REDACTED]")
	evidence = authorizationPattern.ReplaceAllString(evidence, "${1}[REDACTED]")
	evidence = secretPattern.ReplaceAllString(evidence, "${1}[REDACTED]")
	if len(evidence) <= MaxEvidenceBytes {
		return evidence
	}
	end := MaxEvidenceBytes
	for end > 0 && !utf8.RuneStart(evidence[end]) {
		end--
	}
	return evidence[:end]
}

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

var allCodes = []Code{
	CodeManagedOrphanConfig, CodeManagedStaleTemp,
	CodeManagedCertFileMissing, CodeManagedRuntimeKeyMissing,
	CodeManagedRuntimeKeyMismatch, CodeGeneratedConfigInvalid,
	CodeOperatorConfigInvalid, CodePermissionDenied,
	CodeSystemdSandboxDenied, CodeProxyReloadFailed,
	CodeProxyNotRunning, CodePortConflict, CodeProxyBinaryMissing,
	CodeUnknownProxyError,
}

func AllCodes() []Code {
	return append([]Code(nil), allCodes...)
}

func (v Code) Valid() bool {
	for _, code := range allCodes {
		if v == code {
			return true
		}
	}
	return false
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

type OwnershipConfidence string

const (
	OwnershipConfidenceCertain  OwnershipConfidence = "certain"
	OwnershipConfidenceInferred OwnershipConfidence = "inferred"
	OwnershipConfidenceUnknown  OwnershipConfidence = "unknown"
)

func (v OwnershipConfidence) Valid() bool {
	return v == OwnershipConfidenceCertain || v == OwnershipConfidenceInferred || v == OwnershipConfidenceUnknown
}

func (v *OwnershipConfidence) UnmarshalJSON(data []byte) error {
	raw, err := unmarshalClosedString(data, "ownership confidence", false, func(value string) bool { return OwnershipConfidence(value).Valid() })
	if err != nil {
		return err
	}
	*v = OwnershipConfidence(raw)
	return nil
}

type RepairScope string

const (
	RepairScopeExactProvenancedFile      RepairScope = "exact_provenanced_file"
	RepairScopeExclusiveManagedDirectory RepairScope = "exclusive_managed_directory"
	RepairScopeSharedBackendNamespace    RepairScope = "shared_backend_namespace"
	RepairScopeAgentSandbox              RepairScope = "agent_sandbox"
	RepairScopeDetectedProxyService      RepairScope = "detected_proxy_service"
	RepairScopeSupportedPackage          RepairScope = "supported_package"
	RepairScopeLocalFirewall             RepairScope = "local_firewall"
	RepairScopeOutsideManagedRoots       RepairScope = "outside_managed_roots"
	RepairScopeAmbiguous                 RepairScope = "ambiguous"
	RepairScopeUnsupportedEnvironment    RepairScope = "unsupported_environment"
)

func (v RepairScope) Valid() bool {
	switch v {
	case RepairScopeExactProvenancedFile, RepairScopeExclusiveManagedDirectory,
		RepairScopeSharedBackendNamespace, RepairScopeAgentSandbox,
		RepairScopeDetectedProxyService, RepairScopeSupportedPackage,
		RepairScopeLocalFirewall, RepairScopeOutsideManagedRoots,
		RepairScopeAmbiguous, RepairScopeUnsupportedEnvironment:
		return true
	default:
		return false
	}
}

func (v *RepairScope) UnmarshalJSON(data []byte) error {
	raw, err := unmarshalClosedString(data, "repair scope", false, func(value string) bool { return RepairScope(value).Valid() })
	if err != nil {
		return err
	}
	*v = RepairScope(raw)
	return nil
}

type ResolutionReason string

const (
	ResolutionReasonRepaired                  ResolutionReason = "repaired"
	ResolutionReasonResourceDisappeared       ResolutionReason = "resource_disappeared"
	ResolutionReasonDesiredStateChanged       ResolutionReason = "desired_state_changed"
	ResolutionReasonOperatorResolved          ResolutionReason = "operator_resolved"
	ResolutionReasonSuperseded                ResolutionReason = "superseded"
	ResolutionReasonConditionNoLongerObserved ResolutionReason = "condition_no_longer_observed"
)

func (v ResolutionReason) Valid() bool {
	switch v {
	case ResolutionReasonRepaired, ResolutionReasonResourceDisappeared,
		ResolutionReasonDesiredStateChanged, ResolutionReasonOperatorResolved,
		ResolutionReasonSuperseded, ResolutionReasonConditionNoLongerObserved:
		return true
	default:
		return false
	}
}

func (v *ResolutionReason) UnmarshalJSON(data []byte) error {
	raw, err := unmarshalClosedString(data, "resolution reason", false, func(value string) bool { return ResolutionReason(value).Valid() })
	if err != nil {
		return err
	}
	*v = ResolutionReason(raw)
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
	ID                    string              `json:"id"`
	Code                  Code                `json:"code"`
	Subsystem             string              `json:"subsystem"`
	Severity              Severity            `json:"severity"`
	Ownership             Ownership           `json:"ownership"`
	OwnershipConfidence   OwnershipConfidence `json:"ownership_confidence,omitempty"`
	Summary               string              `json:"summary"`
	Evidence              string              `json:"evidence"`
	AffectedPaths         []string            `json:"affected_paths"`
	ResourceFingerprint   string              `json:"resource_fingerprint"`
	ProposedAction        Action              `json:"proposed_action"`
	RepairScope           RepairScope         `json:"repair_scope,omitempty"`
	RepairEligible        bool                `json:"repair_eligible"`
	RepairRefusalCode     string              `json:"repair_refusal_code,omitempty"`
	AutoRepairEligible    bool                `json:"auto_repair_eligible"`
	HardChange            bool                `json:"hard_change"`
	FirstSeenAt           time.Time           `json:"first_seen_at"`
	LastSeenAt            time.Time           `json:"last_seen_at"`
	Occurrences           int                 `json:"occurrences"`
	ResolvedAt            *time.Time          `json:"resolved_at,omitempty"`
	ResolutionReason      ResolutionReason    `json:"resolution_reason,omitempty"`
	ResolutionOperationID string              `json:"resolution_operation_id,omitempty"`
}

type Capability struct {
	Stage   int      `json:"stage"`
	Actions []Action `json:"actions"`
}

type RepairRequest struct {
	OperationID  string    `json:"operation_id"`
	DiagnosticID string    `json:"diagnostic_id"`
	Action       Action    `json:"action"`
	StartedAt    time.Time `json:"started_at"`
	InitialStep  Step      `json:"initial_step"`
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
	if d.OwnershipConfidence != "" && !d.OwnershipConfidence.Valid() {
		return fmt.Errorf("invalid ownership confidence %q", d.OwnershipConfidence)
	}
	if d.RepairScope != "" && !d.RepairScope.Valid() {
		return fmt.Errorf("invalid repair scope %q", d.RepairScope)
	}
	if d.ResolutionReason != "" && !d.ResolutionReason.Valid() {
		return fmt.Errorf("invalid resolution reason %q", d.ResolutionReason)
	}
	if d.ResolvedAt == nil && (d.ResolutionReason != "" || d.ResolutionOperationID != "") {
		return fmt.Errorf("active diagnostic cannot contain resolution state")
	}
	if d.ResolvedAt != nil && d.ResolutionReason == "" {
		return fmt.Errorf("resolved diagnostic requires a resolution reason")
	}
	if d.ResolutionReason == ResolutionReasonRepaired && strings.TrimSpace(d.ResolutionOperationID) == "" {
		return fmt.Errorf("repaired diagnostic requires its operation identity")
	}
	if d.RepairEligible && d.RepairRefusalCode != "" {
		return fmt.Errorf("repair-eligible diagnostic cannot contain a refusal code")
	}
	if d.RepairRefusalCode != "" && !validSemanticID(d.RepairRefusalCode) {
		return fmt.Errorf("invalid repair refusal code")
	}
	if d.ResolutionOperationID != "" && !validSemanticID(d.ResolutionOperationID) {
		return fmt.Errorf("invalid resolution operation identity")
	}
	if d.ResolvedAt != nil && d.ResolvedAt.Before(d.LastSeenAt) {
		return fmt.Errorf("diagnostic resolution precedes last observation")
	}
	if strings.TrimSpace(d.ResourceFingerprint) == "" {
		return fmt.Errorf("diagnostic resource fingerprint is required")
	}
	if d.Occurrences < 1 {
		return fmt.Errorf("diagnostic occurrences must be positive")
	}
	if d.FirstSeenAt.IsZero() || d.LastSeenAt.IsZero() {
		return fmt.Errorf("diagnostic timestamps are required")
	}
	if d.LastSeenAt.Before(d.FirstSeenAt) {
		return fmt.Errorf("diagnostic last-seen time precedes first-seen time")
	}
	if err := validateBoundedSanitized("diagnostic evidence", d.Evidence); err != nil {
		return err
	}
	if d.ProposedAction != "" && !d.ProposedAction.Valid() {
		return fmt.Errorf("invalid proposed recovery action %q", d.ProposedAction)
	}
	if d.AutoRepairEligible {
		if d.Ownership != OwnershipNurProxy {
			return fmt.Errorf("auto-repair eligible diagnostic must be NurProxy-owned")
		}
		if d.HardChange {
			return fmt.Errorf("hard-change diagnostic cannot be auto-repair eligible")
		}
		if !d.ProposedAction.Valid() {
			return fmt.Errorf("auto-repair eligible diagnostic requires a valid action")
		}
	}
	return nil
}

func validSemanticID(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && !strings.ContainsRune("._:-", r) {
			return false
		}
	}
	return true
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
	if r.StartedAt.IsZero() || r.InitialStep.State != OperationStatePlanned || r.InitialStep.At.IsZero() || !r.InitialStep.At.Equal(r.StartedAt) || strings.TrimSpace(r.InitialStep.Name) == "" {
		return fmt.Errorf("repair request requires the persisted planned start identity")
	}
	if err := validateBoundedSanitized("repair request initial step name", r.InitialStep.Name); err != nil {
		return err
	}
	if err := validateBoundedSanitized("repair request initial step summary", r.InitialStep.Summary); err != nil {
		return err
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
	for _, field := range []struct {
		name  string
		value string
	}{
		{"repair operation error", r.Error},
		{"repair operation validation outcome", r.ValidationOutcome},
		{"repair operation rollback outcome", r.RollbackOutcome},
		{"repair operation snapshot reference", r.SnapshotReference},
	} {
		if err := validateBoundedSanitized(field.name, field.value); err != nil {
			return err
		}
	}
	var previousStepAt time.Time
	for i, step := range r.Steps {
		if strings.TrimSpace(step.Name) == "" {
			return fmt.Errorf("repair step %d name is required", i)
		}
		if err := validateBoundedSanitized(fmt.Sprintf("repair step %d name", i), step.Name); err != nil {
			return err
		}
		if !step.State.Valid() {
			return fmt.Errorf("repair step %d has invalid state %q", i, step.State)
		}
		if step.At.IsZero() {
			return fmt.Errorf("repair step %d time is required", i)
		}
		if step.At.Before(r.StartedAt) {
			return fmt.Errorf("repair step %d precedes operation start", i)
		}
		if r.FinishedAt != nil && step.At.After(*r.FinishedAt) {
			return fmt.Errorf("repair step %d follows operation finish", i)
		}
		if !previousStepAt.IsZero() && step.At.Before(previousStepAt) {
			return fmt.Errorf("repair step %d precedes the previous step", i)
		}
		if err := validateBoundedSanitized(fmt.Sprintf("repair step %d summary", i), step.Summary); err != nil {
			return err
		}
		previousStepAt = step.At
	}
	return nil
}

func validateBoundedSanitized(name, value string) error {
	if len(value) > MaxEvidenceBytes {
		return fmt.Errorf("%s exceeds %d bytes", name, MaxEvidenceBytes)
	}
	if SanitizeEvidence(value) != value {
		return fmt.Errorf("%s is not sanitized", name)
	}
	return nil
}

// DecodeStrict must be used at JSON trust boundaries. Unlike encoding/json's
// default decoder, it rejects unknown fields, trailing values, and invalid
// recovery shapes instead of silently broadening the accepted control plane.
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
	privateKeyPattern      = regexp.MustCompile(`(?is)-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|\z)`)
	headerDirectivePattern = regexp.MustCompile(`(?i)\b(?:proxy_set_header[ \t]+|requestheader[ \t]+(?:set|add|append)[ \t]+)([a-z][a-z0-9_-]*)[ \t]+`)
	assignmentPattern      = regexp.MustCompile(`(?i)(?:\\?")?([a-z][a-z0-9_-]*)(?:\\?")?\s*[:=]\s*`)
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
	evidence = redactSensitiveHeaderDirectives(evidence)
	evidence = redactSensitiveAssignments(evidence)
	if len(evidence) <= MaxEvidenceBytes {
		return evidence
	}
	end := MaxEvidenceBytes
	for end > 0 && !utf8.RuneStart(evidence[end]) {
		end--
	}
	return evidence[:end]
}

func redactSensitiveHeaderDirectives(value string) string {
	lines := strings.SplitAfter(value, "\n")
	for i, line := range lines {
		location := headerDirectivePattern.FindStringSubmatchIndex(line)
		if location == nil {
			continue
		}
		header := normalizeSensitiveKey(line[location[2]:location[3]])
		if !isSensitiveKey(header) {
			continue
		}
		newline := ""
		if strings.HasSuffix(line, "\n") {
			newline = "\n"
		}
		lines[i] = line[:location[1]] + "[REDACTED]" + newline
	}
	return strings.Join(lines, "")
}

func redactSensitiveAssignments(value string) string {
	var out strings.Builder
	for cursor := 0; cursor < len(value); {
		location := assignmentPattern.FindStringSubmatchIndex(value[cursor:])
		if location == nil {
			out.WriteString(value[cursor:])
			break
		}
		matchEnd := cursor + location[1]
		keyStart := cursor + location[2]
		keyEnd := cursor + location[3]
		key := normalizeSensitiveKey(value[keyStart:keyEnd])
		if !isSensitiveKey(key) {
			out.WriteString(value[cursor:matchEnd])
			cursor = matchEnd
			continue
		}
		out.WriteString(value[cursor:matchEnd])
		end := sensitiveValueEnd(value, matchEnd, strings.HasSuffix(key, "authorization"))
		out.WriteString("[REDACTED]")
		cursor = end
	}
	return out.String()
}

func normalizeSensitiveKey(key string) string {
	return strings.Map(func(r rune) rune {
		if r == '_' || r == '-' {
			return -1
		}
		return unicode.ToLower(r)
	}, key)
}

func isSensitiveKey(key string) bool {
	for _, suffix := range []string{"authorization", "apikey", "privatekey", "clientsecret", "secretkey", "password", "token"} {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	return key == "secret"
}

func sensitiveValueEnd(value string, start int, throughLine bool) int {
	if throughLine {
		if newline := strings.IndexByte(value[start:], '\n'); newline >= 0 {
			return start + newline
		}
		return len(value)
	}
	if strings.HasPrefix(value[start:], `\"`) {
		for i := start + 2; i < len(value); i++ {
			if value[i] != '"' {
				continue
			}
			backslashes := 0
			for j := i - 1; j >= start && value[j] == '\\'; j-- {
				backslashes++
			}
			if backslashes == 1 {
				return i + 1
			}
		}
		return len(value)
	}
	if start < len(value) && (value[start] == '"' || value[start] == '\'') {
		quote := value[start]
		for i := start + 1; i < len(value); i++ {
			if value[i] == '\\' {
				i++
				continue
			}
			if value[i] == quote {
				return i + 1
			}
		}
		return len(value)
	}
	for i := start; i < len(value); i++ {
		switch value[i] {
		case ' ', '\t', '\n', ',', ';', '}':
			return i
		}
	}
	return len(value)
}

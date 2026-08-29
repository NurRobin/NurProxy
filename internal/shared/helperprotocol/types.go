package helperprotocol

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

const (
	ProtocolVersion  uint16 = 1
	ProtocolDomain          = "nurproxy.helper.v1"
	MaxGrantLifetime        = 10 * time.Minute
)

type MessageType string

const (
	MessagePlanActionRequest          MessageType = "plan_action_request"
	MessageExecuteActionRequest       MessageType = "execute_action_request"
	MessagePlanManagedApplyRequest    MessageType = "plan_managed_apply_request"
	MessageExecuteManagedApplyRequest MessageType = "execute_managed_apply_request"
	MessageGetReceiptRequest          MessageType = "get_receipt_request"
	MessageCancelOperationRequest     MessageType = "cancel_operation_request"
	MessageExecutionGrant             MessageType = "execution_grant"
	MessageApplyIntent                MessageType = "apply_intent"
	MessageApplyGrant                 MessageType = "apply_grant"
	MessageCancellationGrant          MessageType = "cancellation_grant"
	MessageHelperPlan                 MessageType = "helper_plan"
	MessageHelperReceipt              MessageType = "helper_receipt"
)

func (m MessageType) Valid() bool {
	switch m {
	case MessagePlanActionRequest, MessageExecuteActionRequest,
		MessagePlanManagedApplyRequest, MessageExecuteManagedApplyRequest,
		MessageGetReceiptRequest, MessageCancelOperationRequest,
		MessageExecutionGrant, MessageApplyIntent, MessageApplyGrant,
		MessageCancellationGrant, MessageHelperPlan, MessageHelperReceipt:
		return true
	default:
		return false
	}
}

type Action string

const (
	ActionRepairAgentSandboxPaths Action = "repair_agent_sandbox_paths"
	ActionRepairManagedPathAccess Action = "repair_managed_path_access"
	ActionValidateReloadProxy     Action = "validate_reload_proxy"
	ActionStartProxy              Action = "start_proxy"
	ActionRestartProxy            Action = "restart_proxy"
	ActionInstallSupportedPackage Action = "install_supported_proxy_package"
	ActionOpenProxyFirewallPorts  Action = "open_proxy_firewall_ports"
	ActionApplyManagedProxyState  Action = "apply_managed_proxy_state"
)

func (a Action) Valid() bool {
	switch a {
	case ActionRepairAgentSandboxPaths, ActionRepairManagedPathAccess,
		ActionValidateReloadProxy, ActionStartProxy, ActionRestartProxy,
		ActionInstallSupportedPackage, ActionOpenProxyFirewallPorts,
		ActionApplyManagedProxyState:
		return true
	default:
		return false
	}
}

type LogicalTarget string

const (
	LogicalTargetAgentUnit     LogicalTarget = "installed_agent_unit"
	LogicalTargetDetectedProxy LogicalTarget = "detected_proxy"
	LogicalTargetManagedPath   LogicalTarget = "managed_path"
	LogicalTargetProxyPackage  LogicalTarget = "supported_proxy_package"
	LogicalTargetLocalFirewall LogicalTarget = "local_proxy_firewall"
	LogicalTargetManagedState  LogicalTarget = "managed_proxy_state"
)

func (t LogicalTarget) Valid() bool {
	switch t {
	case LogicalTargetAgentUnit, LogicalTargetDetectedProxy,
		LogicalTargetManagedPath, LogicalTargetProxyPackage,
		LogicalTargetLocalFirewall, LogicalTargetManagedState:
		return true
	default:
		return false
	}
}

type AuthorizationKind string

const (
	AuthorizationAuthenticatedDesiredState AuthorizationKind = "authenticated_desired_state"
	AuthorizationStoredConvergence         AuthorizationKind = "stored_convergence"
	AuthorizationStage1AutomaticPolicy     AuthorizationKind = "stage1_automatic_policy"
)

func (k AuthorizationKind) Valid() bool {
	switch k {
	case AuthorizationAuthenticatedDesiredState, AuthorizationStoredConvergence,
		AuthorizationStage1AutomaticPolicy:
		return true
	default:
		return false
	}
}

type JournalState string

const (
	JournalPlanned              JournalState = "planned"
	JournalAuthorized           JournalState = "authorized"
	JournalRunning              JournalState = "running"
	JournalMutated              JournalState = "mutated"
	JournalValidated            JournalState = "validated"
	JournalSucceeded            JournalState = "succeeded"
	JournalFailedBeforeMutation JournalState = "failed_before_mutation"
	JournalRollbackRunning      JournalState = "rollback_running"
	JournalRolledBack           JournalState = "rolled_back"
	JournalRollbackFailed       JournalState = "rollback_failed"
	JournalOutcomeIndeterminate JournalState = "outcome_indeterminate"
)

func (s JournalState) Valid() bool {
	switch s {
	case JournalPlanned, JournalAuthorized, JournalRunning, JournalMutated,
		JournalValidated, JournalSucceeded, JournalFailedBeforeMutation,
		JournalRollbackRunning, JournalRolledBack, JournalRollbackFailed,
		JournalOutcomeIndeterminate:
		return true
	default:
		return false
	}
}

func CanTransition(from, to JournalState) bool {
	switch from {
	case JournalPlanned:
		return to == JournalAuthorized
	case JournalAuthorized:
		return to == JournalRunning || to == JournalFailedBeforeMutation
	case JournalRunning:
		return to == JournalMutated || to == JournalFailedBeforeMutation || to == JournalOutcomeIndeterminate
	case JournalMutated:
		return to == JournalValidated || to == JournalRollbackRunning || to == JournalOutcomeIndeterminate
	case JournalValidated:
		return to == JournalSucceeded || to == JournalRollbackRunning || to == JournalOutcomeIndeterminate
	case JournalRollbackRunning:
		return to == JournalRolledBack || to == JournalRollbackFailed
	default:
		return false
	}
}

type RollbackCoverage string

const (
	RollbackCoverageFull    RollbackCoverage = "full"
	RollbackCoveragePartial RollbackCoverage = "partial"
	RollbackCoverageNone    RollbackCoverage = "none"
)

func (c RollbackCoverage) Valid() bool {
	return c == RollbackCoverageFull || c == RollbackCoveragePartial || c == RollbackCoverageNone
}

type Envelope[T any] struct {
	ProtocolVersion uint16      `json:"protocol_version"`
	MessageType     MessageType `json:"message_type"`
	Domain          string      `json:"domain"`
	Payload         T           `json:"payload"`
}

func NewEnvelope[T any](messageType MessageType, payload T) Envelope[T] {
	return Envelope[T]{ProtocolVersion: ProtocolVersion, MessageType: messageType, Domain: ProtocolDomain, Payload: payload}
}

func (e Envelope[T]) Validate() error {
	if e.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("unsupported protocol version")
	}
	if !e.MessageType.Valid() || e.Domain != ProtocolDomain {
		return fmt.Errorf("invalid protocol envelope")
	}
	return validateValue(e.Payload)
}

type Signed[T any] struct {
	KeyID     string      `json:"key_id"`
	Envelope  Envelope[T] `json:"envelope"`
	Signature string      `json:"signature"`
}

func (s Signed[T]) Validate() error {
	if !validID(s.KeyID) || s.Envelope.Validate() != nil {
		return fmt.Errorf("invalid signed envelope")
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(s.Signature)
	if err != nil || len(signature) != 64 {
		return fmt.Errorf("invalid signature encoding")
	}
	return nil
}

type PlanActionRequest struct {
	RequestID           string        `json:"request_id"`
	Action              Action        `json:"action"`
	LogicalTarget       LogicalTarget `json:"logical_target"`
	DiagnosticReference string        `json:"diagnostic_reference"`
}

func (r PlanActionRequest) Validate() error {
	if !validID(r.RequestID) || !r.Action.Valid() || !r.LogicalTarget.Valid() || !validID(r.DiagnosticReference) {
		return fmt.Errorf("invalid plan action request")
	}
	return nil
}

type ExecuteActionRequest struct {
	OperationID  string                 `json:"operation_id"`
	HelperPlanID string                 `json:"helper_plan_id"`
	Grant        Signed[ExecutionGrant] `json:"signed_execution_grant"`
}

func (r ExecuteActionRequest) Validate() error {
	if !validID(r.OperationID) || !validID(r.HelperPlanID) || r.Grant.Validate() != nil ||
		r.Grant.Envelope.MessageType != MessageExecutionGrant ||
		r.OperationID != r.Grant.Envelope.Payload.OperationID || r.HelperPlanID != r.Grant.Envelope.Payload.HelperPlanID {
		return fmt.Errorf("invalid execute action request")
	}
	return nil
}

type PlanManagedApplyRequest struct {
	RequestID string              `json:"request_id"`
	Intent    Signed[ApplyIntent] `json:"signed_apply_intent"`
}

func (r PlanManagedApplyRequest) Validate() error {
	if !validID(r.RequestID) || r.Intent.Validate() != nil || r.Intent.Envelope.MessageType != MessageApplyIntent {
		return fmt.Errorf("invalid managed apply plan request")
	}
	return nil
}

type ExecuteManagedApplyRequest struct {
	OperationID  string             `json:"operation_id"`
	HelperPlanID string             `json:"helper_plan_id"`
	Grant        Signed[ApplyGrant] `json:"signed_apply_grant"`
}

func (r ExecuteManagedApplyRequest) Validate() error {
	if !validID(r.OperationID) || !validID(r.HelperPlanID) || r.Grant.Validate() != nil ||
		r.Grant.Envelope.MessageType != MessageApplyGrant ||
		r.OperationID != r.Grant.Envelope.Payload.OperationID || r.HelperPlanID != r.Grant.Envelope.Payload.HelperPlanID {
		return fmt.Errorf("invalid managed apply request")
	}
	return nil
}

type GetReceiptRequest struct {
	OperationID            string `json:"operation_id"`
	CanonicalRequestDigest string `json:"canonical_request_digest"`
}

func (r GetReceiptRequest) Validate() error {
	if !validID(r.OperationID) || !validDigest(r.CanonicalRequestDigest) {
		return fmt.Errorf("invalid receipt request")
	}
	return nil
}

type CancelOperationRequest struct {
	OperationID string                    `json:"operation_id"`
	Grant       Signed[CancellationGrant] `json:"signed_cancellation_grant"`
}

func (r CancelOperationRequest) Validate() error {
	if !validID(r.OperationID) || r.Grant.Validate() != nil ||
		r.Grant.Envelope.MessageType != MessageCancellationGrant || r.OperationID != r.Grant.Envelope.Payload.OperationID {
		return fmt.Errorf("invalid cancellation request")
	}
	return nil
}

type ExecutionGrant struct {
	GrantID              string   `json:"grant_id"`
	AgentID              string   `json:"agent_id"`
	HelperInstanceID     string   `json:"helper_instance_id"`
	DiagnosticID         string   `json:"diagnostic_id"`
	OperationID          string   `json:"operation_id"`
	Action               Action   `json:"action"`
	HelperPlanID         string   `json:"helper_plan_id"`
	DisplayPlanHash      string   `json:"display_plan_hash"`
	ExecutionPlanHash    string   `json:"execution_plan_hash"`
	ResourceFingerprint  string   `json:"resource_fingerprint"`
	ConfirmationEventIDs []string `json:"confirmation_event_ids"`
	IssuedAt             string   `json:"issued_at"`
	ExpiresAt            string   `json:"expires_at"`
}

func (g ExecutionGrant) Validate() error {
	if !validID(g.GrantID) || !validID(g.AgentID) || !validID(g.HelperInstanceID) ||
		!validID(g.DiagnosticID) || !validID(g.OperationID) || !g.Action.Valid() ||
		g.Action == ActionApplyManagedProxyState || !validID(g.HelperPlanID) ||
		!validDigest(g.DisplayPlanHash) || !validDigest(g.ExecutionPlanHash) ||
		!validDigest(g.ResourceFingerprint) || len(g.ConfirmationEventIDs) != 2 ||
		!validID(g.ConfirmationEventIDs[0]) || !validID(g.ConfirmationEventIDs[1]) ||
		g.ConfirmationEventIDs[0] == g.ConfirmationEventIDs[1] {
		return fmt.Errorf("invalid execution grant binding")
	}
	return validateGrantTimes(g.IssuedAt, g.ExpiresAt)
}

type LogicalArtifact struct {
	ResourceID string `json:"resource_id"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
}

func (a LogicalArtifact) Validate() error {
	if !validID(a.ResourceID) || !validLogicalName(a.Name) || !validDigest(a.SHA256) || a.Size < 0 || a.Size > MaxArtifactBytes {
		return fmt.Errorf("invalid logical artifact")
	}
	switch a.Kind {
	case "vhost", "certificate", "source_key", "runtime_key", "auth_sidecar":
		return nil
	default:
		return fmt.Errorf("invalid logical artifact kind")
	}
}

const MaxArtifactBytes int64 = 8 << 20

type ApplyIntent struct {
	AgentID              string            `json:"agent_id"`
	HelperInstanceID     string            `json:"helper_instance_id"`
	OperationID          string            `json:"operation_id"`
	DesiredStateRevision string            `json:"desired_state_revision"`
	Resources            []string          `json:"resource_ids"`
	Artifacts            []LogicalArtifact `json:"artifact_manifest"`
	DeletionSet          []string          `json:"deletion_set"`
	AuthorizationKind    AuthorizationKind `json:"authorization_kind"`
	AuthorizationEventID string            `json:"authorization_event_id"`
	IssuedAt             string            `json:"issued_at"`
	ExpiresAt            string            `json:"expires_at"`
}

func (i ApplyIntent) Validate() error {
	if !validID(i.AgentID) || !validID(i.HelperInstanceID) || !validID(i.OperationID) ||
		!validID(i.DesiredStateRevision) || len(i.Resources) > MaxManifestEntries || len(i.Artifacts) > MaxManifestEntries ||
		len(i.DeletionSet) > MaxManifestEntries || !i.AuthorizationKind.Valid() || !validID(i.AuthorizationEventID) ||
		validateGrantTimes(i.IssuedAt, i.ExpiresAt) != nil {
		return fmt.Errorf("invalid apply intent")
	}
	for _, id := range append(append([]string(nil), i.Resources...), i.DeletionSet...) {
		if !validID(id) {
			return fmt.Errorf("invalid apply intent resource")
		}
	}
	for _, artifact := range i.Artifacts {
		if err := artifact.Validate(); err != nil {
			return err
		}
	}
	return nil
}

const MaxManifestEntries = 1024

type ApplyGrant struct {
	GrantID                   string            `json:"grant_id"`
	AuthorizationKind         AuthorizationKind `json:"authorization_kind"`
	AuthorizationEventID      string            `json:"authorization_event_id"`
	AgentID                   string            `json:"agent_id"`
	HelperInstanceID          string            `json:"helper_instance_id"`
	OperationID               string            `json:"operation_id"`
	HelperPlanID              string            `json:"helper_plan_id"`
	DesiredStateRevision      string            `json:"desired_state_revision"`
	LogicalManifestDigest     string            `json:"logical_manifest_digest"`
	ArtifactManifestDigest    string            `json:"staged_artifact_manifest_digest"`
	DeletionSetDigest         string            `json:"deletion_set_digest"`
	CertificateIdentityDigest string            `json:"certificate_identity_digest"`
	CustomPolicyVersion       string            `json:"custom_policy_version"`
	ExecutionPlanHash         string            `json:"execution_plan_hash"`
	ResourceFingerprint       string            `json:"resource_fingerprint"`
	IssuedAt                  string            `json:"issued_at"`
	ExpiresAt                 string            `json:"expires_at"`
}

func (g ApplyGrant) Validate() error {
	if !validID(g.GrantID) || !g.AuthorizationKind.Valid() || !validID(g.AuthorizationEventID) ||
		!validID(g.AgentID) || !validID(g.HelperInstanceID) || !validID(g.OperationID) ||
		!validID(g.HelperPlanID) || !validID(g.DesiredStateRevision) ||
		!validDigest(g.LogicalManifestDigest) || !validDigest(g.ArtifactManifestDigest) ||
		!validDigest(g.DeletionSetDigest) || !validDigest(g.CertificateIdentityDigest) ||
		!validID(g.CustomPolicyVersion) || !validDigest(g.ExecutionPlanHash) ||
		!validDigest(g.ResourceFingerprint) {
		return fmt.Errorf("invalid apply grant binding")
	}
	return validateGrantTimes(g.IssuedAt, g.ExpiresAt)
}

type CancellationGrant struct {
	GrantID                string `json:"grant_id"`
	AgentID                string `json:"agent_id"`
	HelperInstanceID       string `json:"helper_instance_id"`
	OperationID            string `json:"operation_id"`
	CanonicalRequestDigest string `json:"canonical_request_digest"`
	IssuedAt               string `json:"issued_at"`
	ExpiresAt              string `json:"expires_at"`
}

func (g CancellationGrant) Validate() error {
	if !validID(g.GrantID) || !validID(g.AgentID) || !validID(g.HelperInstanceID) || !validID(g.OperationID) || !validDigest(g.CanonicalRequestDigest) {
		return fmt.Errorf("invalid cancellation grant")
	}
	return validateGrantTimes(g.IssuedAt, g.ExpiresAt)
}

type PlanStep struct {
	Kind    string `json:"kind"`
	Summary string `json:"summary"`
}

type HelperPlan struct {
	HelperPlanID        string           `json:"helper_plan_id"`
	HelperInstanceID    string           `json:"helper_instance_id"`
	Action              Action           `json:"action"`
	LogicalTarget       LogicalTarget    `json:"logical_target"`
	DisplayPlanHash     string           `json:"display_plan_hash"`
	ExecutionPlanHash   string           `json:"execution_plan_hash"`
	ResourceFingerprint string           `json:"resource_fingerprint"`
	RollbackCoverage    RollbackCoverage `json:"rollback_coverage"`
	Steps               []PlanStep       `json:"steps"`
	ExpiresAt           string           `json:"expires_at"`
}

func (p HelperPlan) Validate() error {
	if !validID(p.HelperPlanID) || !validID(p.HelperInstanceID) || !p.Action.Valid() || !p.LogicalTarget.Valid() ||
		!validDigest(p.DisplayPlanHash) || !validDigest(p.ExecutionPlanHash) || !validDigest(p.ResourceFingerprint) ||
		!p.RollbackCoverage.Valid() || len(p.Steps) == 0 || len(p.Steps) > 64 || parseCanonicalTime(p.ExpiresAt) == nil {
		return fmt.Errorf("invalid helper plan")
	}
	for _, step := range p.Steps {
		if !validID(step.Kind) || strings.TrimSpace(step.Summary) == "" || len(step.Summary) > 512 {
			return fmt.Errorf("invalid helper plan step")
		}
	}
	return nil
}

type HelperReceipt struct {
	OperationID            string           `json:"operation_id"`
	CanonicalRequestDigest string           `json:"canonical_request_digest"`
	HelperInstanceID       string           `json:"helper_instance_id"`
	Action                 Action           `json:"action"`
	State                  JournalState     `json:"state"`
	RollbackCoverage       RollbackCoverage `json:"rollback_coverage"`
	SnapshotDigest         string           `json:"snapshot_digest,omitempty"`
	SanitizedResult        string           `json:"sanitized_result"`
	UpdatedAt              string           `json:"updated_at"`
}

func (r HelperReceipt) Validate() error {
	if !validID(r.OperationID) || !validDigest(r.CanonicalRequestDigest) || !validID(r.HelperInstanceID) ||
		!r.Action.Valid() || !r.State.Valid() || !r.RollbackCoverage.Valid() ||
		(r.SnapshotDigest != "" && !validDigest(r.SnapshotDigest)) || len(r.SanitizedResult) > 4096 || parseCanonicalTime(r.UpdatedAt) == nil {
		return fmt.Errorf("invalid helper receipt")
	}
	return nil
}

func validateGrantTimes(issuedText, expiresText string) error {
	issued := parseCanonicalTime(issuedText)
	expires := parseCanonicalTime(expiresText)
	if issued == nil || expires == nil || !expires.After(*issued) || expires.Sub(*issued) > MaxGrantLifetime {
		return fmt.Errorf("invalid grant lifetime")
	}
	return nil
}

func parseCanonicalTime(value string) *time.Time {
	if !strings.HasSuffix(value, "Z") || len(value) > len("2006-01-02T15:04:05.999999999Z") {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return nil
	}
	return &parsed
}

func validID(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r)) {
			return false
		}
	}
	return true
}

func validLogicalName(value string) bool {
	return validID(value) && !strings.Contains(value, "..")
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func validateValue(value any) error {
	if validatable, ok := value.(interface{ Validate() error }); ok {
		return validatable.Validate()
	}
	return nil
}

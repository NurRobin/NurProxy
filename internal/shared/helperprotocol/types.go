package helperprotocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
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
	MessageManagedApplyPlan           MessageType = "managed_apply_plan"
	MessageHelperReceipt              MessageType = "helper_receipt"
	MessageHelperHelloRequest         MessageType = "helper_hello_request"
	MessageHelperHello                MessageType = "helper_hello"
	MessageErrorResponse              MessageType = "error_response"
)

func (m MessageType) Valid() bool {
	switch m {
	case MessagePlanActionRequest, MessageExecuteActionRequest,
		MessagePlanManagedApplyRequest, MessageExecuteManagedApplyRequest,
		MessageGetReceiptRequest, MessageCancelOperationRequest,
		MessageExecutionGrant, MessageApplyIntent, MessageApplyGrant,
		MessageCancellationGrant, MessageHelperPlan, MessageManagedApplyPlan, MessageHelperReceipt:
		return true
	case MessageHelperHelloRequest, MessageHelperHello, MessageErrorResponse:
		return true
	default:
		return false
	}
}

type ErrorCode string

const (
	ErrorExecutionGrantInvalid    ErrorCode = "EXECUTION_GRANT_INVALID"
	ErrorExecutionGrantExpired    ErrorCode = "EXECUTION_GRANT_EXPIRED"
	ErrorHelperPlanNotFound       ErrorCode = "HELPER_PLAN_NOT_FOUND"
	ErrorDisplayPlanMismatch      ErrorCode = "DISPLAY_PLAN_MISMATCH"
	ErrorHelperInstanceMismatch   ErrorCode = "HELPER_INSTANCE_MISMATCH"
	ErrorRootConfigUntrusted      ErrorCode = "ROOT_CONFIG_UNTRUSTED"
	ErrorAmbiguousLocalTarget     ErrorCode = "AMBIGUOUS_LOCAL_TARGET"
	ErrorOutcomeIndeterminate     ErrorCode = "OUTCOME_INDETERMINATE"
	ErrorHelperJournalCorrupt     ErrorCode = "HELPER_JOURNAL_CORRUPT"
	ErrorUnsafePackageTransaction ErrorCode = "UNSAFE_PACKAGE_TRANSACTION"
	ErrorFirewallScopeAmbiguous   ErrorCode = "FIREWALL_SCOPE_AMBIGUOUS"
	ErrorBuildIDMismatch          ErrorCode = "BUILD_ID_MISMATCH"
	ErrorPeerCredentialsInvalid   ErrorCode = "PEER_CREDENTIALS_INVALID"
	ErrorRequestConflict          ErrorCode = "REQUEST_CONFLICT"
	ErrorStalePlan                ErrorCode = "STALE_PLAN"
)

func (c ErrorCode) Valid() bool {
	switch c {
	case ErrorExecutionGrantInvalid, ErrorExecutionGrantExpired,
		ErrorHelperPlanNotFound, ErrorDisplayPlanMismatch,
		ErrorHelperInstanceMismatch, ErrorRootConfigUntrusted,
		ErrorAmbiguousLocalTarget, ErrorOutcomeIndeterminate,
		ErrorHelperJournalCorrupt, ErrorUnsafePackageTransaction,
		ErrorFirewallScopeAmbiguous, ErrorBuildIDMismatch,
		ErrorPeerCredentialsInvalid, ErrorRequestConflict, ErrorStalePlan:
		return true
	default:
		return false
	}
}

type HelperHelloRequest struct {
	RequestID    string `json:"request_id"`
	AgentID      string `json:"agent_id"`
	AgentBuildID string `json:"agent_build_id"`
}

func (r HelperHelloRequest) Validate() error {
	if !validID(r.RequestID) || !validID(r.AgentID) || !validID(r.AgentBuildID) {
		return fmt.Errorf("invalid helper hello request")
	}
	return nil
}

type HelperHello struct {
	RequestID            string `json:"request_id"`
	HelperInstanceID     string `json:"helper_instance_id"`
	HelperBuildID        string `json:"helper_build_id"`
	AttestationKeyID     string `json:"attestation_key_id"`
	AttestationPublicKey string `json:"attestation_public_key"`
}

func (r HelperHello) Validate() error {
	if !validID(r.RequestID) || !validID(r.HelperInstanceID) || !validID(r.HelperBuildID) || !validID(r.AttestationKeyID) {
		return fmt.Errorf("invalid helper hello")
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(r.AttestationPublicKey)
	if err != nil || len(key) != 32 {
		return fmt.Errorf("invalid helper attestation public key")
	}
	return nil
}

type ErrorResponse struct {
	RequestID string    `json:"request_id"`
	Code      ErrorCode `json:"code"`
	Message   string    `json:"message"`
	Retryable bool      `json:"retryable"`
}

func (r ErrorResponse) Validate() error {
	if !validID(r.RequestID) || !r.Code.Valid() || strings.TrimSpace(r.Message) == "" || len(r.Message) > 512 {
		return fmt.Errorf("invalid protocol error response")
	}
	return nil
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
		return to == JournalMutated || to == JournalSucceeded || to == JournalFailedBeforeMutation || to == JournalOutcomeIndeterminate
	case JournalMutated:
		return to == JournalValidated || to == JournalRollbackRunning || to == JournalOutcomeIndeterminate
	case JournalValidated:
		return to == JournalSucceeded || to == JournalRollbackRunning || to == JournalOutcomeIndeterminate
	case JournalRollbackRunning:
		return to == JournalRolledBack || to == JournalRollbackFailed || to == JournalOutcomeIndeterminate
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

type ManagedIntentSetEnvelope struct {
	IntentSet proxymodel.IntentSet `json:"intent_set"`
	Intent    Signed[ApplyIntent]  `json:"signed_apply_intent"`
}

func NormalizeManagedIntentSet(set proxymodel.IntentSet) proxymodel.IntentSet {
	set.Intents = append([]proxymodel.RouteIntent{}, set.Intents...)
	set.Certs = append([]proxymodel.CertBundle{}, set.Certs...)
	set.Keep = append([]string{}, set.Keep...)
	set.CertKeep = append([]string{}, set.CertKeep...)
	for index := range set.Intents {
		route := &set.Intents[index].Route
		if route.RequestHeaders == nil {
			route.RequestHeaders = map[string]string{}
		}
		if route.ResponseHeaders == nil {
			route.ResponseHeaders = map[string]string{}
		}
		route.IPAllowlist = append([]string{}, route.IPAllowlist...)
		route.IPBlocklist = append([]string{}, route.IPBlocklist...)
	}
	return set
}

func (e ManagedIntentSetEnvelope) Validate() error {
	if e.IntentSet.Validate() != nil || e.Intent.Validate() != nil || e.Intent.Envelope.MessageType != MessageApplyIntent {
		return fmt.Errorf("invalid managed intent set envelope")
	}
	intent := e.Intent.Envelope.Payload
	revision, revisionErr := Digest(e.IntentSet)
	if revisionErr != nil || revision != intent.DesiredStateRevision {
		return fmt.Errorf("managed intent desired-state revision mismatch")
	}
	if len(intent.Routes) != len(e.IntentSet.Intents) {
		return fmt.Errorf("managed intent route count mismatch")
	}
	left, leftErr := Digest(intent.Routes)
	right, rightErr := Digest(e.IntentSet.Intents)
	if leftErr != nil || rightErr != nil || left != right {
		return fmt.Errorf("managed intent routes do not match stream intent set")
	}
	expectedArtifacts, artifactErr := CertificateArtifacts(e.IntentSet.Certs)
	left, leftErr = Digest(intent.Artifacts)
	right, rightErr = Digest(expectedArtifacts)
	if artifactErr != nil || leftErr != nil || rightErr != nil || left != right {
		return fmt.Errorf("managed intent certificate manifest does not match stream intent set")
	}
	expectedKeep := append([]string(nil), e.IntentSet.CertKeep...)
	sort.Strings(expectedKeep)
	actualKeep := append([]string(nil), intent.CertificateKeep...)
	sort.Strings(actualKeep)
	left, leftErr = Digest(actualKeep)
	right, rightErr = Digest(expectedKeep)
	if leftErr != nil || rightErr != nil || left != right || intent.PruneCertificates != e.IntentSet.PruneCerts {
		return fmt.Errorf("managed intent certificate retention does not match stream intent set")
	}
	return nil
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

func CertificateArtifacts(certificates []proxymodel.CertBundle) ([]LogicalArtifact, error) {
	artifacts := make([]LogicalArtifact, 0, len(certificates)*2)
	seen := make(map[string]struct{}, len(certificates))
	for _, certificate := range certificates {
		if !validCertificateName(certificate.Host) {
			return nil, fmt.Errorf("invalid certificate artifact host")
		}
		if _, exists := seen[certificate.Host]; exists {
			return nil, fmt.Errorf("duplicate certificate artifact host")
		}
		seen[certificate.Host] = struct{}{}
		certDigest := sha256.Sum256([]byte(certificate.CertPEM))
		keyDigest := sha256.Sum256([]byte(certificate.KeyPEM))
		resourceID := CertificateResourceID(certificate.Host)
		artifacts = append(artifacts,
			LogicalArtifact{ResourceID: resourceID, Kind: "certificate", Name: certificate.Host, SHA256: hex.EncodeToString(certDigest[:]), Size: int64(len(certificate.CertPEM))},
			LogicalArtifact{ResourceID: resourceID, Kind: "source_key", Name: certificate.Host, SHA256: hex.EncodeToString(keyDigest[:]), Size: int64(len(certificate.KeyPEM))},
		)
	}
	return artifacts, nil
}

func CertificateResourceID(host string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(host)))
	return "cert-" + hex.EncodeToString(digest[:16])
}

func StagedArtifactFileName(artifact LogicalArtifact) (string, error) {
	if err := artifact.Validate(); err != nil {
		return "", err
	}
	return artifact.ResourceID + "." + artifact.Kind, nil
}

func (a LogicalArtifact) Validate() error {
	if !validID(a.ResourceID) || !validDigest(a.SHA256) || a.Size < 0 || a.Size > MaxArtifactBytes {
		return fmt.Errorf("invalid logical artifact")
	}
	switch a.Kind {
	case "certificate", "source_key", "runtime_key":
		if !validCertificateName(a.Name) {
			return fmt.Errorf("invalid certificate artifact name")
		}
		return nil
	case "vhost", "auth_sidecar":
		if !validLogicalName(a.Name) {
			return fmt.Errorf("invalid logical artifact name")
		}
		return nil
	default:
		return fmt.Errorf("invalid logical artifact kind")
	}
}

const MaxArtifactBytes int64 = 8 << 20

type ApplyIntent struct {
	AgentID              string                   `json:"agent_id"`
	HelperInstanceID     string                   `json:"helper_instance_id"`
	OperationID          string                   `json:"operation_id"`
	DesiredStateRevision string                   `json:"desired_state_revision"`
	Resources            []string                 `json:"resource_ids"`
	Artifacts            []LogicalArtifact        `json:"artifact_manifest"`
	DeletionSet          []ManagedDeletion        `json:"deletion_set"`
	Routes               []proxymodel.RouteIntent `json:"routes"`
	PruneCertificates    bool                     `json:"prune_certificates"`
	CertificateKeep      []string                 `json:"certificate_keep"`
	AuthorizationKind    AuthorizationKind        `json:"authorization_kind"`
	AuthorizationEventID string                   `json:"authorization_event_id"`
	IssuedAt             string                   `json:"issued_at"`
	ExpiresAt            string                   `json:"expires_at"`
}

type ManagedDeletion struct {
	ResourceID string `json:"resource_id"`
	Host       string `json:"host"`
	Backend    string `json:"backend"`
}

func (d ManagedDeletion) Validate() error {
	if !validID(d.ResourceID) || !validCertificateName(d.Host) || (d.Backend != "nginx" && d.Backend != "apache") {
		return fmt.Errorf("invalid managed deletion")
	}
	return nil
}

func (i ApplyIntent) Validate() error {
	if !validID(i.AgentID) || !validID(i.HelperInstanceID) || !validID(i.OperationID) ||
		i.Resources == nil || i.Artifacts == nil || i.DeletionSet == nil || i.Routes == nil || i.CertificateKeep == nil ||
		!validID(i.DesiredStateRevision) || len(i.Resources) > MaxManifestEntries || len(i.Artifacts) > MaxManifestEntries ||
		len(i.DeletionSet) > MaxManifestEntries || len(i.Routes) > MaxManifestEntries || len(i.CertificateKeep) > MaxManifestEntries ||
		!i.AuthorizationKind.Valid() || !validID(i.AuthorizationEventID) ||
		validateGrantTimes(i.IssuedAt, i.ExpiresAt) != nil {
		return fmt.Errorf("invalid apply intent")
	}
	for _, id := range i.Resources {
		if !validID(id) {
			return fmt.Errorf("invalid apply intent resource")
		}
	}
	certificateKeep := make(map[string]struct{}, len(i.CertificateKeep))
	for _, host := range i.CertificateKeep {
		if !validCertificateName(host) {
			return fmt.Errorf("invalid certificate retention host")
		}
		if _, exists := certificateKeep[host]; exists {
			return fmt.Errorf("duplicate certificate retention host")
		}
		certificateKeep[host] = struct{}{}
	}
	resources := make(map[string]struct{}, len(i.Resources))
	for _, id := range i.Resources {
		if _, exists := resources[id]; exists {
			return fmt.Errorf("duplicate apply intent resource")
		}
		resources[id] = struct{}{}
	}
	artifacts := make(map[string]struct{}, len(i.Artifacts))
	for _, artifact := range i.Artifacts {
		if err := artifact.Validate(); err != nil {
			return err
		}
		if _, exists := resources[artifact.ResourceID]; !exists {
			return fmt.Errorf("apply artifact is not in logical resources")
		}
		key := artifact.ResourceID + "\x00" + artifact.Kind + "\x00" + artifact.Name
		if _, exists := artifacts[key]; exists {
			return fmt.Errorf("duplicate apply artifact")
		}
		if artifact.Kind == "certificate" || artifact.Kind == "source_key" || artifact.Kind == "runtime_key" {
			if _, retained := certificateKeep[artifact.Name]; !retained {
				return fmt.Errorf("certificate artifact is absent from retention set")
			}
		}
		artifacts[key] = struct{}{}
	}
	deletions := make(map[string]struct{}, len(i.DeletionSet))
	for _, deletion := range i.DeletionSet {
		if deletion.Validate() != nil {
			return fmt.Errorf("invalid apply deletion")
		}
		if _, exists := resources[deletion.ResourceID]; exists {
			return fmt.Errorf("apply resource cannot be retained and deleted")
		}
		if _, exists := deletions[deletion.ResourceID]; exists {
			return fmt.Errorf("duplicate apply deletion")
		}
		deletions[deletion.ResourceID] = struct{}{}
	}
	routes := make(map[string]struct{}, len(i.Routes))
	for _, route := range i.Routes {
		if !validID(route.ArtifactID) || (route.Backend != "nginx" && route.Backend != "apache" && route.Backend != "caddy") || route.Route.Validate() != nil {
			return fmt.Errorf("invalid apply intent route")
		}
		if route.Route.RequestHeaders == nil || route.Route.ResponseHeaders == nil || route.Route.IPAllowlist == nil || route.Route.IPBlocklist == nil {
			return fmt.Errorf("apply route containers must be canonical arrays and objects")
		}
		if route.Route.IsRaw() && route.Route.Raw.Backend != route.Backend {
			return fmt.Errorf("raw apply route backend mismatch")
		}
		if _, exists := resources[route.ArtifactID]; !exists {
			return fmt.Errorf("apply route is not in logical resources")
		}
		if _, exists := routes[route.ArtifactID]; exists {
			return fmt.Errorf("duplicate apply route")
		}
		routes[route.ArtifactID] = struct{}{}
	}
	return nil
}

func ManagedApplyDigests(intent ApplyIntent) (logical, artifacts, deletions, certificates string, err error) {
	if err = intent.Validate(); err != nil {
		return "", "", "", "", err
	}
	logical, err = Digest(struct {
		Resources         []string                 `json:"resource_ids"`
		Routes            []proxymodel.RouteIntent `json:"routes"`
		PruneCertificates bool                     `json:"prune_certificates"`
		CertificateKeep   []string                 `json:"certificate_keep"`
	}{
		Resources: intent.Resources, Routes: intent.Routes,
		PruneCertificates: intent.PruneCertificates, CertificateKeep: intent.CertificateKeep,
	})
	if err != nil {
		return "", "", "", "", err
	}
	artifacts, err = Digest(intent.Artifacts)
	if err != nil {
		return "", "", "", "", err
	}
	deletions, err = Digest(intent.DeletionSet)
	if err != nil {
		return "", "", "", "", err
	}
	certificateArtifacts := make([]LogicalArtifact, 0, len(intent.Artifacts))
	for _, artifact := range intent.Artifacts {
		switch artifact.Kind {
		case "certificate", "source_key", "runtime_key":
			certificateArtifacts = append(certificateArtifacts, artifact)
		}
	}
	certificates, err = Digest(struct {
		Artifacts []LogicalArtifact `json:"certificate_artifacts"`
		Keep      []string          `json:"certificate_keep"`
		Prune     bool              `json:"prune_certificates"`
	}{Artifacts: certificateArtifacts, Keep: intent.CertificateKeep, Prune: intent.PruneCertificates})
	return logical, artifacts, deletions, certificates, err
}

func ApplyGrantMatchesPlan(grant ApplyGrant, plan ManagedApplyPlan, intent ApplyIntent) bool {
	return grant.AgentID == intent.AgentID && grant.HelperInstanceID == plan.HelperInstanceID &&
		grant.OperationID == plan.OperationID && grant.HelperPlanID == plan.HelperPlanID &&
		grant.AuthorizationKind == intent.AuthorizationKind && grant.AuthorizationEventID == intent.AuthorizationEventID &&
		grant.DesiredStateRevision == plan.DesiredStateRevision && grant.LogicalManifestDigest == plan.LogicalManifestDigest &&
		grant.ArtifactManifestDigest == plan.ArtifactManifestDigest && grant.DeletionSetDigest == plan.DeletionSetDigest &&
		grant.CertificateIdentityDigest == plan.CertificateIdentityDigest && grant.CustomPolicyVersion == plan.CustomPolicyVersion &&
		grant.ExecutionPlanHash == plan.ExecutionPlanHash && grant.ResourceFingerprint == plan.ResourceFingerprint &&
		grant.RollbackCoverage == plan.RollbackCoverage
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
	RollbackCoverage          RollbackCoverage  `json:"rollback_coverage"`
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
		!validDigest(g.ResourceFingerprint) || !g.RollbackCoverage.Valid() {
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
	DiagnosticID        string           `json:"diagnostic_id"`
	Action              Action           `json:"action"`
	LogicalTarget       LogicalTarget    `json:"logical_target"`
	DisplayPlanHash     string           `json:"display_plan_hash"`
	ExecutionPlanHash   string           `json:"execution_plan_hash"`
	ResourceFingerprint string           `json:"resource_fingerprint"`
	RollbackCoverage    RollbackCoverage `json:"rollback_coverage"`
	Steps               []PlanStep       `json:"steps"`
	ExpiresAt           string           `json:"expires_at"`
}

type ManagedApplyPlan struct {
	HelperPlanID              string           `json:"helper_plan_id"`
	HelperInstanceID          string           `json:"helper_instance_id"`
	OperationID               string           `json:"operation_id"`
	DesiredStateRevision      string           `json:"desired_state_revision"`
	LogicalManifestDigest     string           `json:"logical_manifest_digest"`
	ArtifactManifestDigest    string           `json:"staged_artifact_manifest_digest"`
	DeletionSetDigest         string           `json:"deletion_set_digest"`
	CertificateIdentityDigest string           `json:"certificate_identity_digest"`
	CustomPolicyVersion       string           `json:"custom_policy_version"`
	ExecutionPlanHash         string           `json:"execution_plan_hash"`
	ResourceFingerprint       string           `json:"resource_fingerprint"`
	RollbackCoverage          RollbackCoverage `json:"rollback_coverage"`
	ExpiresAt                 string           `json:"expires_at"`
}

func (p ManagedApplyPlan) Validate() error {
	if !validID(p.HelperPlanID) || !validID(p.HelperInstanceID) || !validID(p.OperationID) || !validID(p.DesiredStateRevision) ||
		!validDigest(p.LogicalManifestDigest) || !validDigest(p.ArtifactManifestDigest) || !validDigest(p.DeletionSetDigest) ||
		!validDigest(p.CertificateIdentityDigest) || !validID(p.CustomPolicyVersion) || !validDigest(p.ExecutionPlanHash) ||
		!validDigest(p.ResourceFingerprint) || !p.RollbackCoverage.Valid() || parseCanonicalTime(p.ExpiresAt) == nil {
		return fmt.Errorf("invalid managed apply plan")
	}
	return nil
}

func (p HelperPlan) Validate() error {
	if !validID(p.HelperPlanID) || !validID(p.HelperInstanceID) || !validID(p.DiagnosticID) || !p.Action.Valid() ||
		p.Action == ActionApplyManagedProxyState || !p.LogicalTarget.Valid() ||
		!validDigest(p.DisplayPlanHash) || !validDigest(p.ExecutionPlanHash) || !validDigest(p.ResourceFingerprint) ||
		!p.RollbackCoverage.Valid() || len(p.Steps) == 0 || len(p.Steps) > 64 || parseCanonicalTime(p.ExpiresAt) == nil {
		return fmt.Errorf("invalid helper plan")
	}
	for _, step := range p.Steps {
		if !validID(step.Kind) || strings.TrimSpace(step.Summary) == "" || len(step.Summary) > 512 {
			return fmt.Errorf("invalid helper plan step")
		}
	}
	displayHash, err := DisplayPlanDigest(p)
	if err != nil || displayHash != p.DisplayPlanHash {
		return fmt.Errorf("helper display plan hash mismatch")
	}
	return nil
}

type DisplayedPlan struct {
	HelperPlanID     string           `json:"helper_plan_id"`
	HelperInstanceID string           `json:"helper_instance_id"`
	DiagnosticID     string           `json:"diagnostic_id"`
	Action           Action           `json:"action"`
	LogicalTarget    LogicalTarget    `json:"logical_target"`
	RollbackCoverage RollbackCoverage `json:"rollback_coverage"`
	Steps            []PlanStep       `json:"steps"`
	ExpiresAt        string           `json:"expires_at"`
}

func (p DisplayedPlan) Validate() error {
	if !validID(p.HelperPlanID) || !validID(p.HelperInstanceID) || !validID(p.DiagnosticID) ||
		!p.Action.Valid() || p.Action == ActionApplyManagedProxyState || !p.LogicalTarget.Valid() ||
		!p.RollbackCoverage.Valid() || len(p.Steps) == 0 || len(p.Steps) > 64 || parseCanonicalTime(p.ExpiresAt) == nil {
		return fmt.Errorf("invalid displayed helper plan")
	}
	for _, step := range p.Steps {
		if !validID(step.Kind) || strings.TrimSpace(step.Summary) == "" || len(step.Summary) > 512 {
			return fmt.Errorf("invalid displayed helper plan step")
		}
	}
	return nil
}

func (p HelperPlan) Displayed() DisplayedPlan {
	return DisplayedPlan{
		HelperPlanID:     p.HelperPlanID,
		HelperInstanceID: p.HelperInstanceID,
		DiagnosticID:     p.DiagnosticID,
		Action:           p.Action,
		LogicalTarget:    p.LogicalTarget,
		RollbackCoverage: p.RollbackCoverage,
		Steps:            append([]PlanStep(nil), p.Steps...),
		ExpiresAt:        p.ExpiresAt,
	}
}

func DisplayPlanDigest(plan HelperPlan) (string, error) {
	return Digest(plan.Displayed())
}

type HelperReceipt struct {
	OperationID            string                   `json:"operation_id"`
	CanonicalRequestDigest string                   `json:"canonical_request_digest"`
	HelperInstanceID       string                   `json:"helper_instance_id"`
	Action                 Action                   `json:"action"`
	State                  JournalState             `json:"state"`
	RollbackCoverage       RollbackCoverage         `json:"rollback_coverage"`
	SnapshotDigest         string                   `json:"snapshot_digest,omitempty"`
	SanitizedResult        string                   `json:"sanitized_result"`
	ManagedArtifacts       []ManagedArtifactReceipt `json:"managed_artifacts,omitempty"`
	UpdatedAt              string                   `json:"updated_at"`
}

const MaxManagedReceiptContentBytes = MaxFrameBytes / 8

type ManagedArtifactReceipt struct {
	ArtifactID string   `json:"artifact_id"`
	Backend    string   `json:"backend"`
	TargetKind string   `json:"target_kind"`
	TargetPath string   `json:"target_path"`
	Content    string   `json:"content"`
	Checksum   string   `json:"checksum"`
	Enabled    bool     `json:"enabled"`
	Warnings   []string `json:"warnings"`
}

func (a ManagedArtifactReceipt) Validate() error {
	if !validID(a.ArtifactID) || (a.Backend != "nginx" && a.Backend != "apache") || a.TargetKind != "file" ||
		!strings.HasPrefix(a.TargetPath, "/") || path.Clean(a.TargetPath) != a.TargetPath || len(a.TargetPath) > 4096 ||
		len(a.Content) > MaxManagedReceiptContentBytes || !validDigest(a.Checksum) || len(a.Warnings) > 64 {
		return fmt.Errorf("invalid managed artifact receipt")
	}
	digest := sha256.Sum256([]byte(a.Content))
	if hex.EncodeToString(digest[:]) != a.Checksum {
		return fmt.Errorf("managed artifact receipt checksum mismatch")
	}
	for _, warning := range a.Warnings {
		if strings.TrimSpace(warning) == "" || len(warning) > 512 {
			return fmt.Errorf("invalid managed artifact receipt warning")
		}
	}
	return nil
}

func (r HelperReceipt) Validate() error {
	if !validID(r.OperationID) || !validDigest(r.CanonicalRequestDigest) || !validID(r.HelperInstanceID) ||
		!r.Action.Valid() || !r.State.Valid() || !r.RollbackCoverage.Valid() ||
		(r.SnapshotDigest != "" && !validDigest(r.SnapshotDigest)) || len(r.SanitizedResult) > 4096 || parseCanonicalTime(r.UpdatedAt) == nil {
		return fmt.Errorf("invalid helper receipt")
	}
	if r.ManagedArtifacts != nil && (r.Action != ActionApplyManagedProxyState || r.State != JournalSucceeded || len(r.ManagedArtifacts) > MaxManifestEntries) {
		return fmt.Errorf("invalid helper receipt managed artifacts")
	}
	seenIDs := make(map[string]struct{}, len(r.ManagedArtifacts))
	seenPaths := make(map[string]struct{}, len(r.ManagedArtifacts))
	totalContent := 0
	for _, artifact := range r.ManagedArtifacts {
		if artifact.Validate() != nil {
			return fmt.Errorf("invalid helper receipt managed artifact")
		}
		if _, exists := seenIDs[artifact.ArtifactID]; exists {
			return fmt.Errorf("duplicate helper receipt artifact")
		}
		if _, exists := seenPaths[artifact.TargetPath]; exists {
			return fmt.Errorf("duplicate helper receipt artifact target")
		}
		seenIDs[artifact.ArtifactID] = struct{}{}
		seenPaths[artifact.TargetPath] = struct{}{}
		totalContent += len(artifact.Content)
		if totalContent > MaxManagedReceiptContentBytes {
			return fmt.Errorf("helper receipt managed artifacts exceed content limit")
		}
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

func validCertificateName(value string) bool {
	if strings.HasPrefix(value, "*.") {
		value = strings.TrimPrefix(value, "*.")
	}
	if value == "" || len(value) > 253 || strings.TrimSpace(value) != value || strings.Contains(value, "..") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
	}
	return true
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

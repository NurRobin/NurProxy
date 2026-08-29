package helper

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/google/uuid"
)

const planLifetime = 5 * time.Minute

type ProtocolError struct {
	Code      helperprotocol.ErrorCode
	Message   string
	Retryable bool
}

func (e *ProtocolError) Error() string { return e.Message }

type PlanMaterial struct {
	Steps               []helperprotocol.PlanStep
	ExecutionPlanHash   string
	ResourceFingerprint string
	RollbackCoverage    helperprotocol.RollbackCoverage
}

type PreparedAction struct {
	SnapshotDigest   string
	RollbackCoverage helperprotocol.RollbackCoverage
}

type ActionResult struct {
	Mutated          bool
	Validated        bool
	SanitizedResult  string
	ManagedArtifacts []helperprotocol.ManagedArtifactReceipt
}

type ActionHandler interface {
	Plan(context.Context, helperprotocol.PlanActionRequest) (PlanMaterial, error)
	Rediscover(context.Context, helperprotocol.HelperPlan) (executionPlanHash string, resourceFingerprint string, err error)
	Prepare(context.Context, string, helperprotocol.HelperPlan) (PreparedAction, error)
	Execute(context.Context, string, helperprotocol.HelperPlan, PreparedAction) (ActionResult, error)
	Rollback(context.Context, string, helperprotocol.HelperPlan, PreparedAction) error
}

type ManagedApplyMaterial struct {
	CustomPolicyVersion string
	ExecutionPlanHash   string
	ResourceFingerprint string
	RollbackCoverage    helperprotocol.RollbackCoverage
}

type ManagedApplyHandler interface {
	Plan(context.Context, helperprotocol.ApplyIntent) (ManagedApplyMaterial, error)
	Rediscover(context.Context, helperprotocol.ManagedApplyPlan, helperprotocol.ApplyIntent) (executionPlanHash string, resourceFingerprint string, err error)
	Prepare(context.Context, string, helperprotocol.ManagedApplyPlan, helperprotocol.ApplyIntent) (PreparedAction, error)
	Execute(context.Context, string, helperprotocol.ManagedApplyPlan, helperprotocol.ApplyIntent, PreparedAction) (ActionResult, error)
	Rollback(context.Context, string, helperprotocol.ManagedApplyPlan, helperprotocol.ApplyIntent, PreparedAction) error
}

type Engine struct {
	config         RootConfig
	buildID        string
	journal        *Journal
	attestationKey ed25519.PrivateKey
	actions        map[helperprotocol.Action]ActionHandler
	managedApply   ManagedApplyHandler
	now            func() time.Time
	executeMu      sync.Mutex
}

func (e *Engine) SetManagedApplyHandler(handler ManagedApplyHandler) error {
	if e == nil || handler == nil {
		return fmt.Errorf("managed apply handler is invalid")
	}
	e.managedApply = handler
	return nil
}

func NewEngine(config RootConfig, buildID string, journal *Journal, attestationKey ed25519.PrivateKey, actions map[helperprotocol.Action]ActionHandler) (*Engine, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if !validConfigID(buildID) || config.ExpectedBuildID != buildID {
		return nil, fmt.Errorf("helper build id does not match root configuration")
	}
	if journal == nil || len(attestationKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("helper journal or attestation key is invalid")
	}
	compiled := make(map[helperprotocol.Action]ActionHandler, len(actions))
	for action, handler := range actions {
		if !action.Valid() || action == helperprotocol.ActionApplyManagedProxyState || handler == nil {
			return nil, fmt.Errorf("invalid compiled helper action")
		}
		compiled[action] = handler
	}
	return &Engine{config: config, buildID: buildID, journal: journal, attestationKey: attestationKey, actions: compiled, now: time.Now}, nil
}

func (e *Engine) Hello(request helperprotocol.HelperHelloRequest) (helperprotocol.Signed[helperprotocol.HelperHello], error) {
	if err := request.Validate(); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperHello]{}, protocolFailure(helperprotocol.ErrorRequestConflict, "invalid helper hello request", false)
	}
	if request.AgentID != e.config.AgentID {
		return helperprotocol.Signed[helperprotocol.HelperHello]{}, protocolFailure(helperprotocol.ErrorPeerCredentialsInvalid, "main agent identity does not match root configuration", false)
	}
	if request.AgentBuildID != e.buildID {
		return helperprotocol.Signed[helperprotocol.HelperHello]{}, protocolFailure(helperprotocol.ErrorBuildIDMismatch, "main agent and helper build ids differ", false)
	}
	publicKey := e.attestationKey.Public().(ed25519.PublicKey)
	response := helperprotocol.HelperHello{
		RequestID:            request.RequestID,
		HelperInstanceID:     e.config.HelperInstanceID,
		HelperBuildID:        e.buildID,
		AttestationKeyID:     e.config.AttestationKeyID,
		AttestationPublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
	}
	return helperprotocol.Sign(e.config.AttestationKeyID, e.attestationKey, helperprotocol.NewEnvelope(helperprotocol.MessageHelperHello, response))
}

func (e *Engine) Plan(ctx context.Context, request helperprotocol.PlanActionRequest) (helperprotocol.Signed[helperprotocol.HelperPlan], error) {
	if err := request.Validate(); err != nil || !targetMatchesAction(request.Action, request.LogicalTarget) {
		return helperprotocol.Signed[helperprotocol.HelperPlan]{}, protocolFailure(helperprotocol.ErrorAmbiguousLocalTarget, "action and logical target are not an allowed pair", false)
	}
	handler, ok := e.actions[request.Action]
	if !ok {
		return helperprotocol.Signed[helperprotocol.HelperPlan]{}, protocolFailure(helperprotocol.ErrorAmbiguousLocalTarget, "no compiled action can prove a unique local target", false)
	}
	material, err := handler.Plan(ctx, request)
	if err != nil {
		return helperprotocol.Signed[helperprotocol.HelperPlan]{}, protocolFailure(helperprotocol.ErrorAmbiguousLocalTarget, "local target discovery refused the action", false)
	}
	if err := validatePlanMaterial(material); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperPlan]{}, protocolFailure(helperprotocol.ErrorAmbiguousLocalTarget, "compiled action produced an invalid local plan", false)
	}
	now := e.now().UTC()
	plan := helperprotocol.HelperPlan{
		HelperPlanID:        uuid.NewString(),
		HelperInstanceID:    e.config.HelperInstanceID,
		DiagnosticID:        request.DiagnosticReference,
		Action:              request.Action,
		LogicalTarget:       request.LogicalTarget,
		ExecutionPlanHash:   material.ExecutionPlanHash,
		ResourceFingerprint: material.ResourceFingerprint,
		RollbackCoverage:    material.RollbackCoverage,
		Steps:               append([]helperprotocol.PlanStep(nil), material.Steps...),
		ExpiresAt:           now.Add(planLifetime).Format(time.RFC3339Nano),
	}
	plan.DisplayPlanHash, err = helperprotocol.DisplayPlanDigest(plan)
	if err != nil {
		return helperprotocol.Signed[helperprotocol.HelperPlan]{}, err
	}
	if err := plan.Validate(); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperPlan]{}, err
	}
	if err := e.journal.StorePlan(plan); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperPlan]{}, err
	}
	return helperprotocol.Sign(e.config.AttestationKeyID, e.attestationKey, helperprotocol.NewEnvelope(helperprotocol.MessageHelperPlan, plan))
}

func (e *Engine) PlanManagedApply(ctx context.Context, request helperprotocol.PlanManagedApplyRequest) (helperprotocol.Signed[helperprotocol.ManagedApplyPlan], error) {
	if err := request.Validate(); err != nil || e.managedApply == nil {
		return helperprotocol.Signed[helperprotocol.ManagedApplyPlan]{}, protocolFailure(helperprotocol.ErrorExecutionGrantInvalid, "managed apply planning request is invalid", false)
	}
	signedIntent := request.Intent
	if signedIntent.KeyID != e.config.OrchestratorKeyID || helperprotocol.Verify(e.config.OrchestratorPublicKey(), signedIntent, helperprotocol.MessageApplyIntent) != nil {
		return helperprotocol.Signed[helperprotocol.ManagedApplyPlan]{}, protocolFailure(helperprotocol.ErrorExecutionGrantInvalid, "orchestrator apply intent signature is invalid", false)
	}
	intent := signedIntent.Envelope.Payload
	if intent.AgentID != e.config.AgentID {
		return helperprotocol.Signed[helperprotocol.ManagedApplyPlan]{}, protocolFailure(helperprotocol.ErrorExecutionGrantInvalid, "apply intent targets another agent", false)
	}
	if intent.HelperInstanceID != e.config.HelperInstanceID {
		return helperprotocol.Signed[helperprotocol.ManagedApplyPlan]{}, protocolFailure(helperprotocol.ErrorHelperInstanceMismatch, "apply intent targets another helper instance", false)
	}
	if err := e.validateGrantTime(intent.IssuedAt, intent.ExpiresAt); err != nil {
		return helperprotocol.Signed[helperprotocol.ManagedApplyPlan]{}, err
	}
	material, err := e.managedApply.Plan(ctx, intent)
	if err != nil {
		slog.Error("managed apply planning refused by local host policy", "operation_id", intent.OperationID, "error", err)
		return helperprotocol.Signed[helperprotocol.ManagedApplyPlan]{}, protocolFailure(helperprotocol.ErrorAmbiguousLocalTarget, "local managed apply planning refused the desired state", false)
	}
	if err := validateManagedApplyMaterial(material); err != nil {
		slog.Error("managed apply planning produced invalid local material", "operation_id", intent.OperationID, "error", err)
		return helperprotocol.Signed[helperprotocol.ManagedApplyPlan]{}, protocolFailure(helperprotocol.ErrorAmbiguousLocalTarget, "local managed apply planning refused the desired state", false)
	}
	logicalDigest, artifactDigest, deletionDigest, certificateDigest, err := helperprotocol.ManagedApplyDigests(intent)
	if err != nil {
		return helperprotocol.Signed[helperprotocol.ManagedApplyPlan]{}, err
	}
	intentIssued, issuedErr := time.Parse(time.RFC3339Nano, intent.IssuedAt)
	intentExpires, parseErr := time.Parse(time.RFC3339Nano, intent.ExpiresAt)
	if issuedErr != nil || parseErr != nil {
		return helperprotocol.Signed[helperprotocol.ManagedApplyPlan]{}, protocolFailure(helperprotocol.ErrorExecutionGrantExpired, "apply intent lifetime is invalid", false)
	}
	expires := intentIssued.Add(planLifetime)
	if intentExpires.Before(expires) {
		expires = intentExpires
	}
	intentDigest, err := helperprotocol.Digest(signedIntent)
	if err != nil {
		return helperprotocol.Signed[helperprotocol.ManagedApplyPlan]{}, err
	}
	planIdentity, err := helperprotocol.Digest(struct {
		IntentDigest        string                          `json:"intent_digest"`
		ExecutionPlanHash   string                          `json:"execution_plan_hash"`
		ResourceFingerprint string                          `json:"resource_fingerprint"`
		CustomPolicyVersion string                          `json:"custom_policy_version"`
		RollbackCoverage    helperprotocol.RollbackCoverage `json:"rollback_coverage"`
		ExpiresAt           string                          `json:"expires_at"`
	}{
		IntentDigest: intentDigest, ExecutionPlanHash: material.ExecutionPlanHash,
		ResourceFingerprint: material.ResourceFingerprint, CustomPolicyVersion: material.CustomPolicyVersion,
		RollbackCoverage: material.RollbackCoverage, ExpiresAt: expires.Format(time.RFC3339Nano),
	})
	if err != nil {
		return helperprotocol.Signed[helperprotocol.ManagedApplyPlan]{}, err
	}
	plan := helperprotocol.ManagedApplyPlan{
		HelperPlanID: "managed-plan-" + planIdentity, HelperInstanceID: e.config.HelperInstanceID,
		OperationID: intent.OperationID, DesiredStateRevision: intent.DesiredStateRevision,
		LogicalManifestDigest: logicalDigest, ArtifactManifestDigest: artifactDigest, DeletionSetDigest: deletionDigest,
		CertificateIdentityDigest: certificateDigest, CustomPolicyVersion: material.CustomPolicyVersion,
		ExecutionPlanHash: material.ExecutionPlanHash, ResourceFingerprint: material.ResourceFingerprint,
		RollbackCoverage: material.RollbackCoverage, ExpiresAt: expires.Format(time.RFC3339Nano),
	}
	if err := plan.Validate(); err != nil {
		return helperprotocol.Signed[helperprotocol.ManagedApplyPlan]{}, err
	}
	if existing, found, err := e.journal.FindCompatibleManagedPlan(signedIntent, plan, e.now().UTC()); err != nil {
		return helperprotocol.Signed[helperprotocol.ManagedApplyPlan]{}, err
	} else if found {
		return helperprotocol.Sign(e.config.AttestationKeyID, e.attestationKey, helperprotocol.NewEnvelope(helperprotocol.MessageManagedApplyPlan, existing))
	}
	if err := e.journal.StoreManagedPlan(plan, signedIntent); err != nil {
		return helperprotocol.Signed[helperprotocol.ManagedApplyPlan]{}, err
	}
	return helperprotocol.Sign(e.config.AttestationKeyID, e.attestationKey, helperprotocol.NewEnvelope(helperprotocol.MessageManagedApplyPlan, plan))
}

func (e *Engine) Execute(ctx context.Context, request helperprotocol.Envelope[helperprotocol.ExecuteActionRequest]) (helperprotocol.Signed[helperprotocol.HelperReceipt], error) {
	e.executeMu.Lock()
	defer e.executeMu.Unlock()
	if request.MessageType != helperprotocol.MessageExecuteActionRequest || request.Domain != helperprotocol.ProtocolDomain || request.ProtocolVersion != helperprotocol.ProtocolVersion {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorExecutionGrantInvalid, "invalid execute request envelope", false)
	}
	if err := request.Payload.Validate(); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorExecutionGrantInvalid, "invalid execute request", false)
	}
	grantSigned := request.Payload.Grant
	if grantSigned.KeyID != e.config.OrchestratorKeyID || helperprotocol.Verify(e.config.OrchestratorPublicKey(), grantSigned, helperprotocol.MessageExecutionGrant) != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorExecutionGrantInvalid, "orchestrator execution grant signature is invalid", false)
	}
	grant := grantSigned.Envelope.Payload
	if grant.AgentID != e.config.AgentID {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorExecutionGrantInvalid, "execution grant targets another agent", false)
	}
	if grant.HelperInstanceID != e.config.HelperInstanceID {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorHelperInstanceMismatch, "execution grant targets another helper instance", false)
	}
	requestDigest, err := helperprotocol.Digest(request)
	if err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	if existing, receiptErr := e.journal.GetReceipt(grant.OperationID, requestDigest); receiptErr == nil {
		return e.signReceipt(existing)
	} else if errors.Is(receiptErr, ErrRequestConflict) {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorRequestConflict, "operation id is already bound to another request", false)
	} else if receiptErr != nil && !errors.Is(receiptErr, fs.ErrNotExist) && !errors.Is(receiptErr, ErrReceiptNotFound) {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, receiptErr
	}
	if err := e.validateGrantTime(grant.IssuedAt, grant.ExpiresAt); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	plan, err := e.journal.LoadPlan(grant.HelperPlanID)
	if err != nil {
		if errors.Is(err, ErrPlanNotFound) {
			return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorHelperPlanNotFound, "helper-local plan was not found", false)
		}
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	if !timeAfter(e.now().UTC(), plan.ExpiresAt) {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorStalePlan, "helper-local plan has expired", false)
	}
	if grant.DiagnosticID != plan.DiagnosticID || grant.Action != plan.Action || grant.DisplayPlanHash != plan.DisplayPlanHash ||
		grant.ExecutionPlanHash != plan.ExecutionPlanHash || grant.ResourceFingerprint != plan.ResourceFingerprint {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorDisplayPlanMismatch, "execution grant does not match the helper-local displayed plan", false)
	}
	handler, ok := e.actions[plan.Action]
	if !ok {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorAmbiguousLocalTarget, "compiled action is unavailable", false)
	}
	executionHash, fingerprint, err := handler.Rediscover(ctx, plan)
	if err != nil || executionHash != plan.ExecutionPlanHash || fingerprint != plan.ResourceFingerprint {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorStalePlan, "local host facts changed after planning", false)
	}
	if e.journal.BreakerOpen() {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorOutcomeIndeterminate, "persistent helper breaker is open", false)
	}
	record, existing, err := e.journal.BeginOperation(grant.OperationID, grant.GrantID, requestDigest, plan.Action)
	if err != nil {
		switch {
		case errors.Is(err, ErrGrantReplay):
			return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorExecutionGrantInvalid, "execution grant was already consumed by another operation", false)
		case errors.Is(err, ErrRequestConflict):
			return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorRequestConflict, "operation id conflicts with an existing request", false)
		default:
			return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
		}
	}
	if existing && record.State != helperprotocol.JournalAuthorized {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorOutcomeIndeterminate, "existing operation cannot be safely resumed", false)
	}
	prepared, prepareErr := handler.Prepare(ctx, grant.OperationID, plan)
	if prepareErr != nil || !prepared.ValidFor(plan.RollbackCoverage) {
		prepared = PreparedAction{RollbackCoverage: plan.RollbackCoverage}
		receipt := e.newReceipt(grant.OperationID, requestDigest, plan, helperprotocol.JournalFailedBeforeMutation, prepared, "privileged pre-state snapshot failed")
		if _, transitionErr := e.journal.Transition(grant.OperationID, helperprotocol.JournalFailedBeforeMutation, receipt); transitionErr != nil {
			return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, transitionErr
		}
		return e.signReceipt(receipt)
	}
	running := e.newReceipt(grant.OperationID, requestDigest, plan, helperprotocol.JournalRunning, prepared, "privileged execution started")
	if _, err := e.journal.Transition(grant.OperationID, helperprotocol.JournalRunning, running); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	result, executeErr := handler.Execute(ctx, grant.OperationID, plan, prepared)
	if !result.Mutated {
		failed := e.newReceipt(grant.OperationID, requestDigest, plan, helperprotocol.JournalFailedBeforeMutation, prepared, "action failed before mutation")
		if _, err := e.journal.Transition(grant.OperationID, helperprotocol.JournalFailedBeforeMutation, failed); err != nil {
			return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
		}
		return e.signReceipt(failed)
	}
	mutated := e.newReceipt(grant.OperationID, requestDigest, plan, helperprotocol.JournalMutated, prepared, "privileged mutation completed")
	if _, err := e.journal.Transition(grant.OperationID, helperprotocol.JournalMutated, mutated); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	if executeErr != nil || !result.Validated {
		return e.rollback(ctx, grant.OperationID, requestDigest, plan, prepared)
	}
	validated := e.newReceipt(grant.OperationID, requestDigest, plan, helperprotocol.JournalValidated, prepared, "post-mutation validation succeeded")
	if _, err := e.journal.Transition(grant.OperationID, helperprotocol.JournalValidated, validated); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	message := truncateUTF8(result.SanitizedResult, 4096)
	if strings.TrimSpace(message) == "" {
		message = "privileged action succeeded"
	}
	succeeded := e.newReceipt(grant.OperationID, requestDigest, plan, helperprotocol.JournalSucceeded, prepared, message)
	if _, err := e.journal.Transition(grant.OperationID, helperprotocol.JournalSucceeded, succeeded); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	return e.signReceipt(succeeded)
}

func (e *Engine) ExecuteManagedApply(ctx context.Context, request helperprotocol.Envelope[helperprotocol.ExecuteManagedApplyRequest]) (helperprotocol.Signed[helperprotocol.HelperReceipt], error) {
	e.executeMu.Lock()
	defer e.executeMu.Unlock()
	if request.MessageType != helperprotocol.MessageExecuteManagedApplyRequest || request.Domain != helperprotocol.ProtocolDomain || request.ProtocolVersion != helperprotocol.ProtocolVersion || e.managedApply == nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorExecutionGrantInvalid, "invalid managed apply execute request envelope", false)
	}
	if err := request.Payload.Validate(); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorExecutionGrantInvalid, "invalid managed apply execute request", false)
	}
	grantSigned := request.Payload.Grant
	if grantSigned.KeyID != e.config.OrchestratorKeyID || helperprotocol.Verify(e.config.OrchestratorPublicKey(), grantSigned, helperprotocol.MessageApplyGrant) != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorExecutionGrantInvalid, "orchestrator apply grant signature is invalid", false)
	}
	grant := grantSigned.Envelope.Payload
	if grant.AgentID != e.config.AgentID {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorExecutionGrantInvalid, "apply grant targets another agent", false)
	}
	if grant.HelperInstanceID != e.config.HelperInstanceID {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorHelperInstanceMismatch, "apply grant targets another helper instance", false)
	}
	requestDigest, err := helperprotocol.Digest(request)
	if err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	if existing, receiptErr := e.journal.GetReceipt(grant.OperationID, requestDigest); receiptErr == nil {
		return e.signReceipt(existing)
	} else if errors.Is(receiptErr, ErrRequestConflict) {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorRequestConflict, "operation id is already bound to another request", false)
	} else if receiptErr != nil && !errors.Is(receiptErr, fs.ErrNotExist) && !errors.Is(receiptErr, ErrReceiptNotFound) {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, receiptErr
	}
	if err := e.validateGrantTime(grant.IssuedAt, grant.ExpiresAt); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	plan, intentSigned, err := e.journal.LoadManagedPlan(grant.HelperPlanID)
	if err != nil {
		if errors.Is(err, ErrPlanNotFound) {
			return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorHelperPlanNotFound, "helper-local managed plan was not found", false)
		}
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	if intentSigned.KeyID != e.config.OrchestratorKeyID || helperprotocol.Verify(e.config.OrchestratorPublicKey(), intentSigned, helperprotocol.MessageApplyIntent) != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorHelperJournalCorrupt, "stored managed apply intent attestation is invalid", false)
	}
	intent := intentSigned.Envelope.Payload
	if !timeAfter(e.now().UTC(), plan.ExpiresAt) {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorStalePlan, "helper-local managed plan has expired", false)
	}
	if !helperprotocol.ApplyGrantMatchesPlan(grant, plan, intent) {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorDisplayPlanMismatch, "apply grant does not match the helper-local managed plan", false)
	}
	executionHash, fingerprint, err := e.managedApply.Rediscover(ctx, plan, intent)
	if err != nil || executionHash != plan.ExecutionPlanHash || fingerprint != plan.ResourceFingerprint {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorStalePlan, "local managed proxy facts changed after planning", false)
	}
	if e.journal.BreakerOpen() {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorOutcomeIndeterminate, "persistent helper breaker is open", false)
	}
	record, existing, err := e.journal.BeginOperation(grant.OperationID, grant.GrantID, requestDigest, helperprotocol.ActionApplyManagedProxyState)
	if err != nil {
		switch {
		case errors.Is(err, ErrGrantReplay):
			return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorExecutionGrantInvalid, "apply grant was already consumed by another operation", false)
		case errors.Is(err, ErrRequestConflict):
			return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorRequestConflict, "managed operation conflicts with an existing request", false)
		default:
			return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
		}
	}
	if existing && record.State != helperprotocol.JournalAuthorized {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorOutcomeIndeterminate, "existing managed operation cannot be safely resumed", false)
	}
	prepared, prepareErr := e.managedApply.Prepare(ctx, grant.OperationID, plan, intent)
	if prepareErr != nil || !prepared.ValidFor(plan.RollbackCoverage) {
		prepared = PreparedAction{RollbackCoverage: plan.RollbackCoverage}
		receipt := e.newManagedReceipt(grant.OperationID, requestDigest, plan, helperprotocol.JournalFailedBeforeMutation, prepared, "privileged managed pre-state snapshot failed")
		if _, transitionErr := e.journal.Transition(grant.OperationID, helperprotocol.JournalFailedBeforeMutation, receipt); transitionErr != nil {
			return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, transitionErr
		}
		return e.signReceipt(receipt)
	}
	running := e.newManagedReceipt(grant.OperationID, requestDigest, plan, helperprotocol.JournalRunning, prepared, "privileged managed execution started")
	if _, err := e.journal.Transition(grant.OperationID, helperprotocol.JournalRunning, running); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	result, executeErr := e.managedApply.Execute(ctx, grant.OperationID, plan, intent, prepared)
	if executeErr != nil {
		slog.Error("managed apply execution failed on local host", "operation_id", grant.OperationID, "mutated", result.Mutated, "error", executeErr)
	}
	if !result.Mutated && executeErr == nil && result.Validated {
		message := truncateUTF8(result.SanitizedResult, 4096)
		if strings.TrimSpace(message) == "" {
			message = "managed proxy state already converged"
		}
		succeeded := e.newManagedReceipt(grant.OperationID, requestDigest, plan, helperprotocol.JournalSucceeded, prepared, message)
		succeeded.ManagedArtifacts = append([]helperprotocol.ManagedArtifactReceipt(nil), result.ManagedArtifacts...)
		if _, err := e.journal.Transition(grant.OperationID, helperprotocol.JournalSucceeded, succeeded); err != nil {
			return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
		}
		return e.signReceipt(succeeded)
	}
	if !result.Mutated {
		failed := e.newManagedReceipt(grant.OperationID, requestDigest, plan, helperprotocol.JournalFailedBeforeMutation, prepared, "managed apply failed before mutation")
		if _, err := e.journal.Transition(grant.OperationID, helperprotocol.JournalFailedBeforeMutation, failed); err != nil {
			return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
		}
		return e.signReceipt(failed)
	}
	mutated := e.newManagedReceipt(grant.OperationID, requestDigest, plan, helperprotocol.JournalMutated, prepared, "managed proxy mutation completed")
	if _, err := e.journal.Transition(grant.OperationID, helperprotocol.JournalMutated, mutated); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	if executeErr != nil || !result.Validated {
		return e.rollbackManagedApply(ctx, grant.OperationID, requestDigest, plan, intent, prepared)
	}
	validated := e.newManagedReceipt(grant.OperationID, requestDigest, plan, helperprotocol.JournalValidated, prepared, "managed proxy post-validation succeeded")
	if _, err := e.journal.Transition(grant.OperationID, helperprotocol.JournalValidated, validated); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	message := truncateUTF8(result.SanitizedResult, 4096)
	if strings.TrimSpace(message) == "" {
		message = "managed proxy state applied"
	}
	succeeded := e.newManagedReceipt(grant.OperationID, requestDigest, plan, helperprotocol.JournalSucceeded, prepared, message)
	succeeded.ManagedArtifacts = append([]helperprotocol.ManagedArtifactReceipt(nil), result.ManagedArtifacts...)
	if _, err := e.journal.Transition(grant.OperationID, helperprotocol.JournalSucceeded, succeeded); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	return e.signReceipt(succeeded)
}

func (e *Engine) rollbackManagedApply(ctx context.Context, operationID, requestDigest string, plan helperprotocol.ManagedApplyPlan, intent helperprotocol.ApplyIntent, prepared PreparedAction) (helperprotocol.Signed[helperprotocol.HelperReceipt], error) {
	running := e.newManagedReceipt(operationID, requestDigest, plan, helperprotocol.JournalRollbackRunning, prepared, "managed proxy rollback started")
	if _, err := e.journal.Transition(operationID, helperprotocol.JournalRollbackRunning, running); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	rollbackErr := e.managedApply.Rollback(ctx, operationID, plan, intent, prepared)
	if rollbackErr != nil {
		slog.Error("managed apply rollback failed on local host", "operation_id", operationID, "error", rollbackErr)
	} else if prepared.RollbackCoverage != helperprotocol.RollbackCoverageFull {
		slog.Warn("managed apply rollback restored its bounded snapshot but coverage remains incomplete", "operation_id", operationID, "coverage", prepared.RollbackCoverage)
	}
	state := helperprotocol.JournalRolledBack
	message := "managed apply failed and privileged pre-state was fully restored"
	if rollbackErr != nil || prepared.RollbackCoverage != helperprotocol.RollbackCoverageFull {
		state = helperprotocol.JournalRollbackFailed
		message = "managed apply failed and full restoration could not be proven"
		if err := e.journal.OpenBreaker(message); err != nil {
			return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
		}
	}
	receipt := e.newManagedReceipt(operationID, requestDigest, plan, state, prepared, message)
	if _, err := e.journal.Transition(operationID, state, receipt); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	return e.signReceipt(receipt)
}

func (e *Engine) rollback(ctx context.Context, operationID, requestDigest string, plan helperprotocol.HelperPlan, prepared PreparedAction) (helperprotocol.Signed[helperprotocol.HelperReceipt], error) {
	running := e.newReceipt(operationID, requestDigest, plan, helperprotocol.JournalRollbackRunning, prepared, "local rollback started")
	if _, err := e.journal.Transition(operationID, helperprotocol.JournalRollbackRunning, running); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	handler := e.actions[plan.Action]
	rollbackErr := handler.Rollback(ctx, operationID, plan, prepared)
	state := helperprotocol.JournalRolledBack
	message := "privileged action failed and pre-state was fully restored"
	if rollbackErr != nil || prepared.RollbackCoverage != helperprotocol.RollbackCoverageFull {
		state = helperprotocol.JournalRollbackFailed
		message = "privileged action failed and full restoration could not be proven"
		if err := e.journal.OpenBreaker(message); err != nil {
			return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
		}
	}
	receipt := e.newReceipt(operationID, requestDigest, plan, state, prepared, message)
	if _, err := e.journal.Transition(operationID, state, receipt); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	return e.signReceipt(receipt)
}

func (e *Engine) GetReceipt(request helperprotocol.GetReceiptRequest) (helperprotocol.Signed[helperprotocol.HelperReceipt], error) {
	if err := request.Validate(); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, protocolFailure(helperprotocol.ErrorRequestConflict, "invalid receipt request", false)
	}
	receipt, err := e.journal.GetReceipt(request.OperationID, request.CanonicalRequestDigest)
	if err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	return e.signReceipt(receipt)
}

func (e *Engine) signReceipt(receipt helperprotocol.HelperReceipt) (helperprotocol.Signed[helperprotocol.HelperReceipt], error) {
	return helperprotocol.Sign(e.config.AttestationKeyID, e.attestationKey, helperprotocol.NewEnvelope(helperprotocol.MessageHelperReceipt, receipt))
}

func (e *Engine) newReceipt(operationID, requestDigest string, plan helperprotocol.HelperPlan, state helperprotocol.JournalState, prepared PreparedAction, message string) helperprotocol.HelperReceipt {
	return helperprotocol.HelperReceipt{
		OperationID:            operationID,
		CanonicalRequestDigest: requestDigest,
		HelperInstanceID:       e.config.HelperInstanceID,
		Action:                 plan.Action,
		State:                  state,
		RollbackCoverage:       prepared.RollbackCoverage,
		SnapshotDigest:         prepared.SnapshotDigest,
		SanitizedResult:        truncateUTF8(message, 4096),
		UpdatedAt:              e.now().UTC().Format(time.RFC3339Nano),
	}
}

func (e *Engine) newManagedReceipt(operationID, requestDigest string, plan helperprotocol.ManagedApplyPlan, state helperprotocol.JournalState, prepared PreparedAction, message string) helperprotocol.HelperReceipt {
	return helperprotocol.HelperReceipt{
		OperationID: operationID, CanonicalRequestDigest: requestDigest,
		HelperInstanceID: e.config.HelperInstanceID, Action: helperprotocol.ActionApplyManagedProxyState, State: state,
		RollbackCoverage: prepared.RollbackCoverage, SnapshotDigest: prepared.SnapshotDigest,
		SanitizedResult: truncateUTF8(message, 4096), UpdatedAt: e.now().UTC().Format(time.RFC3339Nano),
	}
}

func validateManagedApplyMaterial(material ManagedApplyMaterial) error {
	if !validConfigID(material.CustomPolicyVersion) || !validDigest(material.ExecutionPlanHash) ||
		!validDigest(material.ResourceFingerprint) || !material.RollbackCoverage.Valid() {
		return fmt.Errorf("invalid managed apply material")
	}
	return nil
}

func (e *Engine) validateGrantTime(issuedText, expiresText string) error {
	issued, issuedErr := time.Parse(time.RFC3339Nano, issuedText)
	expires, expiresErr := time.Parse(time.RFC3339Nano, expiresText)
	now := e.now().UTC()
	if issuedErr != nil || expiresErr != nil || now.Before(issued.Add(-30*time.Second)) || !now.Before(expires) {
		return protocolFailure(helperprotocol.ErrorExecutionGrantExpired, "execution grant is expired or not yet valid", false)
	}
	return nil
}

func (p PreparedAction) ValidFor(coverage helperprotocol.RollbackCoverage) bool {
	if p.RollbackCoverage != coverage || !coverage.Valid() {
		return false
	}
	if coverage == helperprotocol.RollbackCoverageNone {
		return p.SnapshotDigest == ""
	}
	return validDigest(p.SnapshotDigest)
}

func validatePlanMaterial(material PlanMaterial) error {
	if !validDigest(material.ExecutionPlanHash) || !validDigest(material.ResourceFingerprint) ||
		!material.RollbackCoverage.Valid() || len(material.Steps) == 0 || len(material.Steps) > 64 {
		return fmt.Errorf("invalid compiled plan material")
	}
	for _, step := range material.Steps {
		if !validConfigID(step.Kind) || strings.TrimSpace(step.Summary) == "" || len(step.Summary) > 512 {
			return fmt.Errorf("invalid compiled plan step")
		}
	}
	return nil
}

func targetMatchesAction(action helperprotocol.Action, target helperprotocol.LogicalTarget) bool {
	switch action {
	case helperprotocol.ActionRepairAgentSandboxPaths:
		return target == helperprotocol.LogicalTargetAgentUnit
	case helperprotocol.ActionRepairManagedPathAccess:
		return target == helperprotocol.LogicalTargetManagedPath
	case helperprotocol.ActionValidateReloadProxy, helperprotocol.ActionStartProxy, helperprotocol.ActionRestartProxy:
		return target == helperprotocol.LogicalTargetDetectedProxy
	case helperprotocol.ActionInstallSupportedPackage:
		return target == helperprotocol.LogicalTargetProxyPackage
	case helperprotocol.ActionOpenProxyFirewallPorts:
		return target == helperprotocol.LogicalTargetLocalFirewall
	default:
		return false
	}
}

func timeAfter(now time.Time, expiryText string) bool {
	expires, err := time.Parse(time.RFC3339Nano, expiryText)
	return err == nil && now.Before(expires)
}

func truncateUTF8(value string, maxBytes int) string {
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= maxBytes {
		return value
	}
	value = value[:maxBytes]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func protocolFailure(code helperprotocol.ErrorCode, message string, retryable bool) error {
	return &ProtocolError{Code: code, Message: message, Retryable: retryable}
}

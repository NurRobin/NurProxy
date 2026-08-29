package helperprotocol

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

func validExecutionGrant() ExecutionGrant {
	issued := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	return ExecutionGrant{
		GrantID:              "grant-1",
		AgentID:              "agent-1",
		HelperInstanceID:     "helper-1",
		DiagnosticID:         "diag-1",
		OperationID:          "op-1",
		Action:               ActionValidateReloadProxy,
		HelperPlanID:         "plan-1",
		DisplayPlanHash:      strings.Repeat("a", 64),
		ExecutionPlanHash:    strings.Repeat("b", 64),
		ResourceFingerprint:  strings.Repeat("c", 64),
		ConfirmationEventIDs: []string{"confirmation-1", "confirmation-2"},
		IssuedAt:             issued.Format(time.RFC3339Nano),
		ExpiresAt:            issued.Add(2 * time.Minute).Format(time.RFC3339Nano),
	}
}

func TestApplyIntentBindsValidatedRoutesToLogicalResources(t *testing.T) {
	now := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
	intent := ApplyIntent{
		AgentID: "agent-1", HelperInstanceID: "helper-1", OperationID: "apply-1", DesiredStateRevision: "revision-1",
		Resources: []string{"dom-1"}, Artifacts: []LogicalArtifact{}, DeletionSet: []ManagedDeletion{},
		Routes:            NormalizeManagedIntentSet(proxymodel.IntentSet{Intents: []proxymodel.RouteIntent{{ArtifactID: "dom-1", Backend: "nginx", Route: proxymodel.Route{Host: "app.example", Upstream: proxymodel.Upstream{Addr: "10.0.0.2", Port: 8080}}}}}).Intents,
		CertificateKeep:   []string{},
		AuthorizationKind: AuthorizationAuthenticatedDesiredState, AuthorizationEventID: "event-1",
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
	}
	if err := intent.Validate(); err != nil {
		t.Fatalf("valid intent rejected: %v", err)
	}
	intent.Routes[0].ArtifactID = "dom-2"
	if err := intent.Validate(); err == nil {
		t.Fatal("route outside logical resources accepted")
	}
}

func TestCertificateArtifactsSupportWildcardWithoutUsingHostAsResourceID(t *testing.T) {
	artifacts, err := CertificateArtifacts([]proxymodel.CertBundle{{Host: "*.example.com", CertPEM: "cert", KeyPEM: "key"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 2 || artifacts[0].ResourceID != CertificateResourceID("*.example.com") || artifacts[0].Name != "*.example.com" {
		t.Fatalf("unexpected wildcard certificate artifacts: %+v", artifacts)
	}
	for _, artifact := range artifacts {
		if err := artifact.Validate(); err != nil {
			t.Fatalf("wildcard artifact rejected: %v", err)
		}
	}
}

func TestHelloResponseCarriesBuildAndAttestationIdentity(t *testing.T) {
	response := HelperHello{
		RequestID:            "request-1",
		HelperInstanceID:     "helper-1",
		HelperBuildID:        "v0.4.0-dev-010e5a7",
		AttestationKeyID:     "helper-attestation-1",
		AttestationPublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	if err := response.Validate(); err != nil {
		t.Fatalf("valid helper hello rejected: %v", err)
	}
	response.AttestationPublicKey += "="
	if err := response.Validate(); err == nil {
		t.Fatal("noncanonical attestation key encoding accepted")
	}
}

func TestProtocolErrorCodesAreClosed(t *testing.T) {
	for _, code := range []ErrorCode{
		ErrorExecutionGrantInvalid,
		ErrorExecutionGrantExpired,
		ErrorHelperPlanNotFound,
		ErrorDisplayPlanMismatch,
		ErrorHelperInstanceMismatch,
		ErrorRootConfigUntrusted,
		ErrorAmbiguousLocalTarget,
		ErrorOutcomeIndeterminate,
		ErrorHelperJournalCorrupt,
		ErrorUnsafePackageTransaction,
		ErrorFirewallScopeAmbiguous,
		ErrorBuildIDMismatch,
		ErrorPeerCredentialsInvalid,
		ErrorRequestConflict,
		ErrorStalePlan,
	} {
		if !code.Valid() {
			t.Fatalf("required error code is invalid: %s", code)
		}
	}
	if ErrorCode("ROOT_SHELL_FAILED").Valid() {
		t.Fatal("unknown error code accepted")
	}
}

func TestExecutionGrantValidationRequiresEverySecurityBinding(t *testing.T) {
	if err := validExecutionGrant().Validate(); err != nil {
		t.Fatalf("valid grant rejected: %v", err)
	}
	tests := map[string]func(*ExecutionGrant){
		"grant id":            func(g *ExecutionGrant) { g.GrantID = "" },
		"agent":               func(g *ExecutionGrant) { g.AgentID = "" },
		"helper instance":     func(g *ExecutionGrant) { g.HelperInstanceID = "" },
		"diagnostic":          func(g *ExecutionGrant) { g.DiagnosticID = "" },
		"operation":           func(g *ExecutionGrant) { g.OperationID = "" },
		"action":              func(g *ExecutionGrant) { g.Action = Action("run_shell") },
		"plan":                func(g *ExecutionGrant) { g.HelperPlanID = "" },
		"display hash":        func(g *ExecutionGrant) { g.DisplayPlanHash = "bad" },
		"execution hash":      func(g *ExecutionGrant) { g.ExecutionPlanHash = "bad" },
		"fingerprint":         func(g *ExecutionGrant) { g.ResourceFingerprint = "bad" },
		"confirmations":       func(g *ExecutionGrant) { g.ConfirmationEventIDs = nil },
		"expiry before issue": func(g *ExecutionGrant) { g.ExpiresAt = g.IssuedAt },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			grant := validExecutionGrant()
			mutate(&grant)
			if err := grant.Validate(); err == nil {
				t.Fatal("invalid grant accepted")
			}
		})
	}
}

func TestRequestTypesRejectRawEffectSelectors(t *testing.T) {
	input := `{"protocol_version":1,"message_type":"plan_action_request","domain":"nurproxy.helper.v1","payload":{"request_id":"req-1","action":"validate_reload_proxy","logical_target":"detected_proxy","diagnostic_reference":"diag-1","path":"/etc/passwd"}}`
	if _, err := Decode[Envelope[PlanActionRequest]]([]byte(input)); err == nil {
		t.Fatal("raw privileged path accepted")
	}
}

func TestEnvelopeDecodeBindsMessageTypeToPayloadSchema(t *testing.T) {
	input := `{"protocol_version":1,"message_type":"execute_action_request","domain":"nurproxy.helper.v1","payload":{"operation_id":"op-1","canonical_request_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`
	if _, err := DecodeEnvelope[GetReceiptRequest]([]byte(input), MessageGetReceiptRequest); err == nil {
		t.Fatal("payload schema accepted under another request message type")
	}
}

func TestCanonicalTimeRejectsAlternativeRepresentations(t *testing.T) {
	grant := validExecutionGrant()
	grant.IssuedAt = "2026-08-29T10:00:00.000Z"
	if err := grant.Validate(); err == nil {
		t.Fatal("noncanonical timestamp accepted")
	}
}

func TestJournalTransitionsAreClosedAndFailClosed(t *testing.T) {
	allowed := [][2]JournalState{
		{JournalPlanned, JournalAuthorized},
		{JournalAuthorized, JournalRunning},
		{JournalRunning, JournalMutated},
		{JournalRunning, JournalSucceeded},
		{JournalRunning, JournalFailedBeforeMutation},
		{JournalMutated, JournalValidated},
		{JournalMutated, JournalRollbackRunning},
		{JournalValidated, JournalSucceeded},
		{JournalValidated, JournalRollbackRunning},
		{JournalRollbackRunning, JournalRolledBack},
		{JournalRollbackRunning, JournalRollbackFailed},
		{JournalRollbackRunning, JournalOutcomeIndeterminate},
		{JournalRunning, JournalOutcomeIndeterminate},
		{JournalMutated, JournalOutcomeIndeterminate},
		{JournalValidated, JournalOutcomeIndeterminate},
	}
	for _, transition := range allowed {
		if !CanTransition(transition[0], transition[1]) {
			t.Fatalf("required transition rejected: %s -> %s", transition[0], transition[1])
		}
	}
	for _, transition := range [][2]JournalState{
		{JournalPlanned, JournalSucceeded},
		{JournalSucceeded, JournalRunning},
		{JournalRolledBack, JournalRunning},
		{JournalOutcomeIndeterminate, JournalRunning},
		{JournalState("unknown"), JournalRunning},
	} {
		if CanTransition(transition[0], transition[1]) {
			t.Fatalf("unsafe transition accepted: %s -> %s", transition[0], transition[1])
		}
	}
}

func TestExecuteRequestsMustMatchTheirSignedBindings(t *testing.T) {
	request := ExecuteActionRequest{
		OperationID:  "other-operation",
		HelperPlanID: "plan-1",
		Grant: Signed[ExecutionGrant]{
			KeyID:     "key-1",
			Envelope:  NewEnvelope(MessageExecutionGrant, validExecutionGrant()),
			Signature: strings.Repeat("A", 86),
		},
	}
	if err := request.Validate(); err == nil {
		t.Fatal("execute request accepted with operation not bound by grant")
	}

	request.OperationID = "op-1"
	request.Grant.Envelope.MessageType = MessageApplyGrant
	if err := request.Validate(); err == nil {
		t.Fatal("execute request accepted wrong signed payload type")
	}
}

func TestApplyIntentBindsHostOperationAndCanonicalLifetime(t *testing.T) {
	issued := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	intent := ApplyIntent{
		AgentID:              "agent-1",
		HelperInstanceID:     "helper-1",
		OperationID:          "op-1",
		DesiredStateRevision: "revision-1",
		Resources:            []string{"resource-1"},
		Artifacts:            []LogicalArtifact{},
		DeletionSet:          []ManagedDeletion{},
		Routes:               []proxymodel.RouteIntent{},
		CertificateKeep:      []string{},
		AuthorizationKind:    AuthorizationAuthenticatedDesiredState,
		AuthorizationEventID: "event-1",
		IssuedAt:             issued.Format(time.RFC3339Nano),
		ExpiresAt:            issued.Add(time.Minute).Format(time.RFC3339Nano),
	}
	if err := intent.Validate(); err != nil {
		t.Fatalf("valid apply intent rejected: %v", err)
	}
	intent.HelperInstanceID = ""
	if err := intent.Validate(); err == nil {
		t.Fatal("apply intent without helper binding accepted")
	}
}

func TestDisplayedPlanHashCoversEveryVisibleField(t *testing.T) {
	plan := HelperPlan{
		HelperPlanID:        "plan-1",
		HelperInstanceID:    "helper-1",
		DiagnosticID:        "diagnostic-1",
		Action:              ActionRestartProxy,
		LogicalTarget:       LogicalTargetDetectedProxy,
		ExecutionPlanHash:   strings.Repeat("b", 64),
		ResourceFingerprint: strings.Repeat("c", 64),
		RollbackCoverage:    RollbackCoveragePartial,
		Steps:               []PlanStep{{Kind: "restart", Summary: "Restart nginx"}},
		ExpiresAt:           time.Date(2026, 8, 29, 10, 5, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}
	digest, err := DisplayPlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	plan.DisplayPlanHash = digest
	if err := plan.Validate(); err != nil {
		t.Fatalf("valid displayed plan rejected: %v", err)
	}
	plan.Steps[0].Summary = "Restart a different service"
	if err := plan.Validate(); err == nil {
		t.Fatal("displayed plan mutation did not invalidate display hash")
	}
}

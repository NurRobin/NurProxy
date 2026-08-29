package helperprotocol

import (
	"strings"
	"testing"
	"time"
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
		{JournalRunning, JournalFailedBeforeMutation},
		{JournalMutated, JournalValidated},
		{JournalMutated, JournalRollbackRunning},
		{JournalValidated, JournalSucceeded},
		{JournalValidated, JournalRollbackRunning},
		{JournalRollbackRunning, JournalRolledBack},
		{JournalRollbackRunning, JournalRollbackFailed},
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

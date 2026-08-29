package db

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

func signedRecoveryPlan(t *testing.T) helperprotocol.Signed[helperprotocol.HelperPlan] {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plan := helperprotocol.HelperPlan{
		HelperPlanID: "helper-plan-1", HelperInstanceID: "helper-1", DiagnosticID: "diagnostic-1",
		Action: helperprotocol.ActionValidateReloadProxy, LogicalTarget: helperprotocol.LogicalTargetDetectedProxy,
		ExecutionPlanHash: strings.Repeat("a", 64), ResourceFingerprint: strings.Repeat("b", 64),
		RollbackCoverage: helperprotocol.RollbackCoverageFull,
		Steps:            []helperprotocol.PlanStep{{Kind: "validate", Summary: "Validate and reload nginx"}},
		ExpiresAt:        time.Date(2026, 8, 29, 16, 10, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}
	plan.DisplayPlanHash, err = helperprotocol.DisplayPlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := helperprotocol.Sign("attestation-1", privateKey, helperprotocol.NewEnvelope(helperprotocol.MessageHelperPlan, plan))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func enrollRecoveryPlanHelper(t *testing.T, d *DB, agentID string) {
	t.Helper()
	hello := helperHello()
	if err := d.EnrollRecoveryHelper(agentID, hello, strings.Repeat("e", 64), time.Date(2026, 8, 29, 15, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryExecutionPlanConfirmationOrderingAndIdempotency(t *testing.T) {
	d := testDB(t)
	agent := createTestAgent(t, d)
	enrollRecoveryPlanHelper(t, d, agent.ID)
	signed := signedRecoveryPlan(t)
	receivedAt := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
	if err := d.StoreRecoveryExecutionPlan(agent.ID, "operation-1", signed, receivedAt); err != nil {
		t.Fatal(err)
	}
	if err := d.StoreRecoveryExecutionPlan(agent.ID, "operation-1", signed, receivedAt); err != nil {
		t.Fatalf("idempotent plan store: %v", err)
	}
	plan, err := d.GetRecoveryExecutionPlan(agent.ID, "helper-plan-1")
	if err != nil || plan.OperationID != "operation-1" || plan.DisplayPlanHash != signed.Envelope.Payload.DisplayPlanHash {
		t.Fatalf("stored plan = %#v, err=%v", plan, err)
	}
	if _, err := d.ConfirmRecoveryExecutionPlan(agent.ID, "helper-plan-1", signed.Envelope.Payload.DisplayPlanHash, 2, "confirmation-2", receivedAt.Add(time.Minute)); !errors.Is(err, ErrRecoveryConfirmationOrder) {
		t.Fatalf("phase 2 before phase 1 error = %v", err)
	}
	confirmed, err := d.ConfirmRecoveryExecutionPlan(agent.ID, "helper-plan-1", signed.Envelope.Payload.DisplayPlanHash, 1, "confirmation-1", receivedAt.Add(time.Minute))
	if err != nil || confirmed.ConfirmationEventIDs[0] != "confirmation-1" {
		t.Fatalf("phase 1 = %#v, err=%v", confirmed, err)
	}
	if _, err := d.ConfirmRecoveryExecutionPlan(agent.ID, "helper-plan-1", signed.Envelope.Payload.DisplayPlanHash, 1, "confirmation-other", receivedAt.Add(time.Minute)); !errors.Is(err, ErrRecoveryConfirmationConflict) {
		t.Fatalf("changed phase 1 error = %v", err)
	}
	if _, err := d.ConfirmRecoveryExecutionPlan(agent.ID, "helper-plan-1", signed.Envelope.Payload.DisplayPlanHash, 2, "confirmation-1", receivedAt.Add(2*time.Minute)); !errors.Is(err, ErrRecoveryConfirmationConflict) {
		t.Fatalf("reused confirmation event error = %v", err)
	}
	confirmed, err = d.ConfirmRecoveryExecutionPlan(agent.ID, "helper-plan-1", signed.Envelope.Payload.DisplayPlanHash, 2, "confirmation-2", receivedAt.Add(2*time.Minute))
	if err != nil || len(confirmed.ConfirmationEventIDs) != 2 || confirmed.ConfirmationEventIDs[1] != "confirmation-2" {
		t.Fatalf("phase 2 = %#v, err=%v", confirmed, err)
	}
}

func TestRecoveryExecutionPlanRejectsDisplayHashSubstitution(t *testing.T) {
	d := testDB(t)
	agent := createTestAgent(t, d)
	enrollRecoveryPlanHelper(t, d, agent.ID)
	signed := signedRecoveryPlan(t)
	at := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
	if err := d.StoreRecoveryExecutionPlan(agent.ID, "operation-1", signed, at); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ConfirmRecoveryExecutionPlan(agent.ID, "helper-plan-1", strings.Repeat("c", 64), 1, "confirmation-1", at.Add(time.Minute)); !errors.Is(err, ErrRecoveryPlanMismatch) {
		t.Fatalf("display hash substitution error = %v", err)
	}
}

func TestRecoveryExecutionGrantMustMatchConfirmedPlan(t *testing.T) {
	d := testDB(t)
	agent := createTestAgent(t, d)
	enrollRecoveryPlanHelper(t, d, agent.ID)
	signedPlan := signedRecoveryPlan(t)
	at := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
	if err := d.StoreRecoveryExecutionPlan(agent.ID, "operation-1", signedPlan, at); err != nil {
		t.Fatal(err)
	}
	for phase, eventID := range []string{"confirmation-1", "confirmation-2"} {
		if _, err := d.ConfirmRecoveryExecutionPlan(agent.ID, "helper-plan-1", signedPlan.Envelope.Payload.DisplayPlanHash, phase+1, eventID, at.Add(time.Duration(phase+1)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plan := signedPlan.Envelope.Payload
	grant := helperprotocol.ExecutionGrant{
		GrantID: "grant-1", AgentID: agent.ID, HelperInstanceID: plan.HelperInstanceID,
		DiagnosticID: plan.DiagnosticID, OperationID: "operation-1", Action: plan.Action,
		HelperPlanID: plan.HelperPlanID, DisplayPlanHash: plan.DisplayPlanHash,
		ExecutionPlanHash: plan.ExecutionPlanHash, ResourceFingerprint: plan.ResourceFingerprint,
		ConfirmationEventIDs: []string{"confirmation-1", "confirmation-2"},
		IssuedAt:             at.Add(2 * time.Minute).Format(time.RFC3339Nano), ExpiresAt: at.Add(5 * time.Minute).Format(time.RFC3339Nano),
	}
	signedGrant, err := helperprotocol.Sign("orchestrator-1", privateKey, helperprotocol.NewEnvelope(helperprotocol.MessageExecutionGrant, grant))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.StoreRecoveryExecutionGrant(agent.ID, "helper-plan-1", signedGrant); err != nil {
		t.Fatal(err)
	}
	if err := d.StoreRecoveryExecutionGrant(agent.ID, "helper-plan-1", signedGrant); err != nil {
		t.Fatalf("idempotent grant store: %v", err)
	}
	stored, err := d.GetRecoveryExecutionPlan(agent.ID, "helper-plan-1")
	if err != nil || stored.SignedGrant == nil || stored.SignedGrant.Envelope.Payload.GrantID != "grant-1" {
		t.Fatalf("stored grant = %#v, err=%v", stored, err)
	}
	wrong := grant
	wrong.ResourceFingerprint = strings.Repeat("f", 64)
	wrongSigned, err := helperprotocol.Sign("orchestrator-1", privateKey, helperprotocol.NewEnvelope(helperprotocol.MessageExecutionGrant, wrong))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.StoreRecoveryExecutionGrant(agent.ID, "helper-plan-1", wrongSigned); !errors.Is(err, ErrRecoveryPlanMismatch) {
		t.Fatalf("mismatched grant error = %v", err)
	}
}

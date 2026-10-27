package db

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

// receiptManagedApply drives the fixture's operation through plan, grant and a
// helper receipt in the given terminal state.
func receiptManagedApply(t *testing.T, d *DB, agentID string, state helperprotocol.JournalState, now time.Time) string {
	t.Helper()
	signedIntent, signedPlan, helperKey := managedApplyFixture(t, agentID)
	if err := d.StoreManagedApplyIntent(agentID, signedIntent, now); err != nil {
		t.Fatal(err)
	}
	if err := d.StoreManagedApplyPlan(agentID, signedPlan, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	plan, intent := signedPlan.Envelope.Payload, signedIntent.Envelope.Payload
	grant := helperprotocol.ApplyGrant{
		GrantID: "managed-grant-1", AuthorizationKind: intent.AuthorizationKind,
		AuthorizationEventID: intent.AuthorizationEventID, AgentID: agentID,
		HelperInstanceID: plan.HelperInstanceID, OperationID: plan.OperationID, HelperPlanID: plan.HelperPlanID,
		DesiredStateRevision: plan.DesiredStateRevision, LogicalManifestDigest: plan.LogicalManifestDigest,
		ArtifactManifestDigest: plan.ArtifactManifestDigest, DeletionSetDigest: plan.DeletionSetDigest,
		CertificateIdentityDigest: plan.CertificateIdentityDigest, CustomPolicyVersion: plan.CustomPolicyVersion,
		ExecutionPlanHash: plan.ExecutionPlanHash, ResourceFingerprint: plan.ResourceFingerprint,
		RollbackCoverage: plan.RollbackCoverage, IssuedAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(4 * time.Minute).Format(time.RFC3339Nano),
	}
	_, authorityKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signedGrant, err := helperprotocol.Sign("authority-1", authorityKey, helperprotocol.NewEnvelope(helperprotocol.MessageApplyGrant, grant))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.StoreManagedApplyGrant(agentID, grant.OperationID, signedGrant); err != nil {
		t.Fatal(err)
	}
	requestDigest, err := helperprotocol.Digest(helperprotocol.NewEnvelope(helperprotocol.MessageExecuteManagedApplyRequest, helperprotocol.ExecuteManagedApplyRequest{
		OperationID: grant.OperationID, HelperPlanID: grant.HelperPlanID, Grant: signedGrant,
	}))
	if err != nil {
		t.Fatal(err)
	}
	receipt := helperprotocol.HelperReceipt{
		OperationID: grant.OperationID, CanonicalRequestDigest: requestDigest, HelperInstanceID: grant.HelperInstanceID,
		Action: helperprotocol.ActionApplyManagedProxyState, State: state,
		RollbackCoverage: helperprotocol.RollbackCoveragePartial, SnapshotDigest: strings.Repeat("c", 64),
		SanitizedResult: "managed apply failed and full restoration could not be proven", UpdatedAt: now.Add(2 * time.Minute).Format(time.RFC3339Nano),
	}
	signedReceipt, err := helperprotocol.Sign("attestation-1", helperKey, helperprotocol.NewEnvelope(helperprotocol.MessageHelperReceipt, receipt))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.StoreManagedApplyReceipt(agentID, grant.OperationID, signedReceipt, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	return grant.OperationID
}

// A rollback_failed receipt is how the orchestrator learns the helper latched
// its permanent breaker (#148). Later intents keep arriving while the breaker
// refuses to execute them, so execution pruning must not evict that receipt.
func TestLatestReceiptedManagedApplySurvivesExecutionPruning(t *testing.T) {
	d := testDB(t)
	agent := createTestAgent(t, d)
	enrollRecoveryPlanHelper(t, d, agent.ID)
	if _, err := d.GetLatestReceiptedManagedApply(agent.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("latest receipt without executions: err=%v, want sql.ErrNoRows", err)
	}
	now := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
	operationID := receiptManagedApply(t, d, agent.ID, helperprotocol.JournalRollbackFailed, now)

	template, _, _ := managedApplyFixture(t, agent.ID)
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxManagedApplyExecutionsPerAgent+10; i++ {
		intent := template.Envelope.Payload
		intent.OperationID = fmt.Sprintf("apply-operation-later-%d", i)
		intent.DesiredStateRevision = fmt.Sprintf("%064d", i+2)
		signed, err := helperprotocol.Sign("authority-1", signer, helperprotocol.NewEnvelope(helperprotocol.MessageApplyIntent, intent))
		if err != nil {
			t.Fatal(err)
		}
		if err := d.StoreManagedApplyIntent(agent.ID, signed, now.Add(3*time.Minute+time.Duration(i)*time.Second)); err != nil {
			t.Fatalf("store later intent %d: %v", i, err)
		}
	}
	latest, err := d.GetLatestReceiptedManagedApply(agent.ID)
	if err != nil || latest.OperationID != operationID || latest.SignedReceipt == nil ||
		latest.SignedReceipt.Envelope.Payload.State != helperprotocol.JournalRollbackFailed {
		t.Fatalf("latest receipted apply = %#v, err=%v", latest, err)
	}
}

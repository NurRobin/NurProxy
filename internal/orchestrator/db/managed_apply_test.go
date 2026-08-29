package db

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

func managedApplyFixture(t *testing.T, agentID string) (
	helperprotocol.Signed[helperprotocol.ApplyIntent],
	helperprotocol.Signed[helperprotocol.ManagedApplyPlan],
	ed25519.PrivateKey,
) {
	t.Helper()
	_, authorityKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, helperKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
	intent := helperprotocol.ApplyIntent{
		AgentID: agentID, HelperInstanceID: "helper-1", OperationID: "apply-operation-1",
		DesiredStateRevision: strings.Repeat("1", 64), Resources: []string{"artifact-1"},
		Artifacts: []helperprotocol.LogicalArtifact{}, DeletionSet: []helperprotocol.ManagedDeletion{},
		Routes: []proxymodel.RouteIntent{{ArtifactID: "artifact-1", Backend: "nginx", Route: proxymodel.Route{
			Host: "app.example.test", Upstream: proxymodel.Upstream{Addr: "127.0.0.1", Port: 3000}, RequestHeaders: map[string]string{},
			ResponseHeaders: map[string]string{}, IPAllowlist: []string{}, IPBlocklist: []string{},
		}}},
		PruneCertificates: true, CertificateKeep: []string{},
		AuthorizationKind: helperprotocol.AuthorizationStoredConvergence, AuthorizationEventID: "desired-event-1",
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
	}
	signedIntent, err := helperprotocol.Sign("authority-1", authorityKey, helperprotocol.NewEnvelope(helperprotocol.MessageApplyIntent, intent))
	if err != nil {
		t.Fatal(err)
	}
	logical, artifacts, deletions, certificates, err := helperprotocol.ManagedApplyDigests(intent)
	if err != nil {
		t.Fatal(err)
	}
	plan := helperprotocol.ManagedApplyPlan{
		HelperPlanID: "managed-plan-1", HelperInstanceID: intent.HelperInstanceID,
		OperationID: intent.OperationID, DesiredStateRevision: intent.DesiredStateRevision,
		LogicalManifestDigest: logical, ArtifactManifestDigest: artifacts, DeletionSetDigest: deletions,
		CertificateIdentityDigest: certificates, CustomPolicyVersion: "proxy-policy-v1",
		ExecutionPlanHash: strings.Repeat("a", 64), ResourceFingerprint: strings.Repeat("b", 64),
		RollbackCoverage: helperprotocol.RollbackCoveragePartial,
		ExpiresAt:        now.Add(5 * time.Minute).Format(time.RFC3339Nano),
	}
	signedPlan, err := helperprotocol.Sign("attestation-1", helperKey, helperprotocol.NewEnvelope(helperprotocol.MessageManagedApplyPlan, plan))
	if err != nil {
		t.Fatal(err)
	}
	return signedIntent, signedPlan, helperKey
}

func TestManagedApplyPersistenceBindsLatestIntentPlanGrantAndReceipt(t *testing.T) {
	d := testDB(t)
	agent := createTestAgent(t, d)
	enrollRecoveryPlanHelper(t, d, agent.ID)
	signedIntent, signedPlan, helperKey := managedApplyFixture(t, agent.ID)
	now := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)

	if err := d.StoreManagedApplyIntent(agent.ID, signedIntent, now); err != nil {
		t.Fatal(err)
	}
	if err := d.StoreManagedApplyIntent(agent.ID, signedIntent, now); err != nil {
		t.Fatalf("idempotent intent store: %v", err)
	}
	if err := d.StoreManagedApplyPlan(agent.ID, signedPlan, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	stored, err := d.GetCurrentManagedApply(agent.ID)
	if err != nil || stored.SignedPlan == nil || stored.OperationID != signedIntent.Envelope.Payload.OperationID {
		t.Fatalf("stored apply = %#v, err=%v", stored, err)
	}

	plan := signedPlan.Envelope.Payload
	intent := signedIntent.Envelope.Payload
	grant := helperprotocol.ApplyGrant{
		GrantID: "managed-grant-1", AuthorizationKind: intent.AuthorizationKind,
		AuthorizationEventID: intent.AuthorizationEventID, AgentID: agent.ID,
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
	if err := d.StoreManagedApplyGrant(agent.ID, grant.OperationID, signedGrant); err != nil {
		t.Fatal(err)
	}
	executeRequest := helperprotocol.NewEnvelope(helperprotocol.MessageExecuteManagedApplyRequest, helperprotocol.ExecuteManagedApplyRequest{
		OperationID: grant.OperationID, HelperPlanID: grant.HelperPlanID, Grant: signedGrant,
	})
	requestDigest, err := helperprotocol.Digest(executeRequest)
	if err != nil {
		t.Fatal(err)
	}
	receipt := helperprotocol.HelperReceipt{
		OperationID: grant.OperationID, CanonicalRequestDigest: requestDigest, HelperInstanceID: grant.HelperInstanceID,
		Action: helperprotocol.ActionApplyManagedProxyState, State: helperprotocol.JournalSucceeded,
		RollbackCoverage: helperprotocol.RollbackCoveragePartial, SnapshotDigest: strings.Repeat("c", 64),
		SanitizedResult: "managed state applied", UpdatedAt: now.Add(2 * time.Minute).Format(time.RFC3339Nano),
	}
	signedReceipt, err := helperprotocol.Sign("attestation-1", helperKey, helperprotocol.NewEnvelope(helperprotocol.MessageHelperReceipt, receipt))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.StoreManagedApplyReceipt(agent.ID, grant.OperationID, signedReceipt, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	stored, err = d.GetManagedApply(agent.ID, grant.OperationID)
	if err != nil || stored.SignedGrant == nil || stored.SignedReceipt == nil || stored.ReceiptDigest == "" {
		t.Fatalf("completed apply = %#v, err=%v", stored, err)
	}
}

func TestManagedApplyRejectsSupersededIntentAndBindingSubstitution(t *testing.T) {
	d := testDB(t)
	agent := createTestAgent(t, d)
	enrollRecoveryPlanHelper(t, d, agent.ID)
	firstIntent, firstPlan, _ := managedApplyFixture(t, agent.ID)
	now := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
	if err := d.StoreManagedApplyIntent(agent.ID, firstIntent, now); err != nil {
		t.Fatal(err)
	}

	secondIntent := firstIntent
	secondIntent.Envelope.Payload.OperationID = "apply-operation-2"
	secondIntent.Envelope.Payload.DesiredStateRevision = strings.Repeat("2", 64)
	secondIntent.Envelope.Payload.AuthorizationEventID = "desired-event-2"
	_, replacementKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secondIntent, err = helperprotocol.Sign("authority-1", replacementKey, helperprotocol.NewEnvelope(helperprotocol.MessageApplyIntent, secondIntent.Envelope.Payload))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.StoreManagedApplyIntent(agent.ID, secondIntent, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := d.StoreManagedApplyPlan(agent.ID, firstPlan, now.Add(2*time.Minute)); !errors.Is(err, ErrManagedApplySuperseded) {
		t.Fatalf("superseded plan error = %v", err)
	}

	tampered := firstPlan
	tampered.Envelope.Payload.OperationID = secondIntent.Envelope.Payload.OperationID
	tampered.Envelope.Payload.DesiredStateRevision = secondIntent.Envelope.Payload.DesiredStateRevision
	tampered.Envelope.Payload.LogicalManifestDigest = strings.Repeat("f", 64)
	if err := d.StoreManagedApplyPlan(agent.ID, tampered, now.Add(2*time.Minute)); !errors.Is(err, ErrManagedApplyMismatch) {
		t.Fatalf("substituted plan error = %v", err)
	}
}

func TestManagedRouteTombstonesPersistUntilExactReceiptCleanup(t *testing.T) {
	d := testDB(t)
	agent := createTestAgent(t, d)
	deletion := helperprotocol.ManagedDeletion{ResourceID: "domain-7", Host: "old.example.test", Backend: "nginx"}
	if err := d.UpsertManagedRouteTombstone(agent.ID, deletion, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	stored, err := d.ListManagedRouteTombstones(agent.ID)
	if err != nil || len(stored) != 1 || stored[0] != deletion {
		t.Fatalf("stored tombstones = %#v, err=%v", stored, err)
	}
	wrong := deletion
	wrong.Host = "other.example.test"
	if err := d.DeleteManagedRouteTombstones(agent.ID, []helperprotocol.ManagedDeletion{wrong}); err != nil {
		t.Fatal(err)
	}
	if stored, _ := d.ListManagedRouteTombstones(agent.ID); len(stored) != 1 {
		t.Fatal("non-exact cleanup removed tombstone")
	}
	if err := d.DeleteManagedRouteTombstones(agent.ID, []helperprotocol.ManagedDeletion{deletion}); err != nil {
		t.Fatal(err)
	}
	if stored, _ := d.ListManagedRouteTombstones(agent.ID); len(stored) != 0 {
		t.Fatalf("tombstones remained: %#v", stored)
	}
}

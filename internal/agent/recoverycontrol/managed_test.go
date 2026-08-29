package recoverycontrol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

type managedHelperMock struct {
	planCalls    int
	executeCalls int
	plan         helperprotocol.Signed[helperprotocol.ManagedApplyPlan]
	receipt      helperprotocol.Signed[helperprotocol.HelperReceipt]
}

func (m *managedHelperMock) PlanManagedApply(_ context.Context, _ helperprotocol.Signed[helperprotocol.ApplyIntent]) (helperprotocol.Signed[helperprotocol.ManagedApplyPlan], error) {
	m.planCalls++
	return m.plan, nil
}

func (m *managedHelperMock) ExecuteManagedApply(_ context.Context, _ helperprotocol.Signed[helperprotocol.ApplyGrant]) (helperprotocol.Signed[helperprotocol.HelperReceipt], string, error) {
	m.executeCalls++
	return m.receipt, strings.Repeat("d", 64), nil
}

func (m *managedHelperMock) GetReceipt(context.Context, string, string) (helperprotocol.Signed[helperprotocol.HelperReceipt], error) {
	return m.receipt, nil
}

type managedRemoteMock struct {
	authorizeCalls int
	receiptCalls   int
	record         ManagedExecutionRecord
}

func (m *managedRemoteMock) AuthorizeManagedApply(_ context.Context, _ string, _ helperprotocol.Signed[helperprotocol.ManagedApplyPlan]) (ManagedExecutionRecord, error) {
	m.authorizeCalls++
	return m.record, nil
}

func (m *managedRemoteMock) SubmitManagedReceipt(_ context.Context, _ string, _ helperprotocol.Signed[helperprotocol.HelperReceipt]) error {
	m.receiptCalls++
	return nil
}

func managedControllerFixture(t *testing.T) (helperprotocol.ManagedIntentSetEnvelope, helperprotocol.Signed[helperprotocol.ManagedApplyPlan], helperprotocol.Signed[helperprotocol.ApplyGrant], helperprotocol.Signed[helperprotocol.HelperReceipt]) {
	t.Helper()
	_, authorityKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, helperKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	set := helperprotocol.NormalizeManagedIntentSet(proxymodel.IntentSet{Intents: []proxymodel.RouteIntent{{
		ArtifactID: "artifact-1", Backend: "nginx", Route: proxymodel.Route{Host: "app.example.test",
			Upstream: proxymodel.Upstream{Addr: "127.0.0.1", Port: 3000}},
	}}})
	revision, err := helperprotocol.Digest(set)
	if err != nil {
		t.Fatal(err)
	}
	intent := helperprotocol.ApplyIntent{
		AgentID: "agent-1", HelperInstanceID: "helper-1", OperationID: "apply-operation-1",
		DesiredStateRevision: revision, Resources: []string{"artifact-1"}, Artifacts: []helperprotocol.LogicalArtifact{},
		DeletionSet: []helperprotocol.ManagedDeletion{}, Routes: set.Intents, PruneCertificates: false, CertificateKeep: []string{},
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
		HelperPlanID: "managed-plan-1", HelperInstanceID: "helper-1", OperationID: intent.OperationID,
		DesiredStateRevision: revision, LogicalManifestDigest: logical, ArtifactManifestDigest: artifacts,
		DeletionSetDigest: deletions, CertificateIdentityDigest: certificates, CustomPolicyVersion: "proxy-policy-v1",
		ExecutionPlanHash: strings.Repeat("a", 64), ResourceFingerprint: strings.Repeat("b", 64),
		RollbackCoverage: helperprotocol.RollbackCoveragePartial, ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339Nano),
	}
	signedPlan, err := helperprotocol.Sign("attestation-1", helperKey, helperprotocol.NewEnvelope(helperprotocol.MessageManagedApplyPlan, plan))
	if err != nil {
		t.Fatal(err)
	}
	grant := helperprotocol.ApplyGrant{
		GrantID: "managed-grant-1", AuthorizationKind: intent.AuthorizationKind, AuthorizationEventID: intent.AuthorizationEventID,
		AgentID: intent.AgentID, HelperInstanceID: plan.HelperInstanceID, OperationID: plan.OperationID, HelperPlanID: plan.HelperPlanID,
		DesiredStateRevision: plan.DesiredStateRevision, LogicalManifestDigest: plan.LogicalManifestDigest,
		ArtifactManifestDigest: plan.ArtifactManifestDigest, DeletionSetDigest: plan.DeletionSetDigest,
		CertificateIdentityDigest: plan.CertificateIdentityDigest, CustomPolicyVersion: plan.CustomPolicyVersion,
		ExecutionPlanHash: plan.ExecutionPlanHash, ResourceFingerprint: plan.ResourceFingerprint,
		RollbackCoverage: plan.RollbackCoverage, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(4 * time.Minute).Format(time.RFC3339Nano),
	}
	signedGrant, err := helperprotocol.Sign("authority-1", authorityKey, helperprotocol.NewEnvelope(helperprotocol.MessageApplyGrant, grant))
	if err != nil {
		t.Fatal(err)
	}
	receipt := helperprotocol.HelperReceipt{
		OperationID: intent.OperationID, CanonicalRequestDigest: strings.Repeat("d", 64), HelperInstanceID: "helper-1",
		Action: helperprotocol.ActionApplyManagedProxyState, State: helperprotocol.JournalSucceeded,
		RollbackCoverage: helperprotocol.RollbackCoveragePartial, SnapshotDigest: strings.Repeat("c", 64),
		SanitizedResult: "managed state applied", UpdatedAt: now.Add(time.Minute).Format(time.RFC3339Nano),
	}
	signedReceipt, err := helperprotocol.Sign("attestation-1", helperKey, helperprotocol.NewEnvelope(helperprotocol.MessageHelperReceipt, receipt))
	if err != nil {
		t.Fatal(err)
	}
	return helperprotocol.ManagedIntentSetEnvelope{IntentSet: set, Intent: signedIntent}, signedPlan, signedGrant, signedReceipt
}

func TestManagedControllerStagesPlansAuthorizesExecutesAndReports(t *testing.T) {
	envelope, plan, grant, receipt := managedControllerFixture(t)
	helper := &managedHelperMock{plan: plan, receipt: receipt}
	remote := &managedRemoteMock{record: ManagedExecutionRecord{OperationID: "apply-operation-1", SignedGrant: &grant}}
	staging := t.TempDir()
	if err := os.Chmod(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	controller, err := NewManaged(helper, remote, staging)
	if err != nil {
		t.Fatal(err)
	}
	got, err := controller.Apply(context.Background(), envelope)
	if err != nil || got.Envelope.Payload.State != helperprotocol.JournalSucceeded {
		t.Fatalf("apply receipt = %#v, err=%v", got, err)
	}
	if helper.planCalls != 1 || helper.executeCalls != 1 || remote.authorizeCalls != 1 || remote.receiptCalls != 1 {
		t.Fatalf("calls helper plan=%d execute=%d remote authorize=%d receipt=%d", helper.planCalls, helper.executeCalls, remote.authorizeCalls, remote.receiptCalls)
	}
}

func TestManagedControllerUsesDurableReceiptWithoutReexecution(t *testing.T) {
	envelope, plan, _, receipt := managedControllerFixture(t)
	helper := &managedHelperMock{plan: plan, receipt: receipt}
	remote := &managedRemoteMock{record: ManagedExecutionRecord{OperationID: "apply-operation-1", SignedReceipt: &receipt}}
	staging := t.TempDir()
	if err := os.Chmod(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	controller, err := NewManaged(helper, remote, staging)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Apply(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if helper.executeCalls != 0 || remote.receiptCalls != 0 {
		t.Fatalf("durable receipt path executed again: execute=%d submit=%d", helper.executeCalls, remote.receiptCalls)
	}
}

func TestManagedControllerClassifiesExclusiveStagingPermissionDrift(t *testing.T) {
	envelope, plan, grant, receipt := managedControllerFixture(t)
	staging := t.TempDir()
	if err := os.Chmod(staging, 0o707); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(staging, 0o700)
	controller, err := NewManaged(
		&managedHelperMock{plan: plan, receipt: receipt},
		&managedRemoteMock{record: ManagedExecutionRecord{OperationID: "apply-operation-1", SignedGrant: &grant}},
		staging,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Apply(context.Background(), envelope); !errors.Is(err, ErrManagedStagingAccess) {
		t.Fatalf("staging permission drift = %v, want ErrManagedStagingAccess", err)
	}
}

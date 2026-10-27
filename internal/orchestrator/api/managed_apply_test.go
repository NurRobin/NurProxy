package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/orchestrator/recoveryauth"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

func managedApplyAPIFixture(t *testing.T, database *db.DB, authority *recoveryauth.Authority) (
	helperprotocol.Signed[helperprotocol.ApplyIntent],
	helperprotocol.Signed[helperprotocol.ManagedApplyPlan],
	ed25519.PrivateKey,
) {
	t.Helper()
	helperPublic, helperPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hello := helperprotocol.HelperHello{
		RequestID: "managed-enrollment-1", HelperInstanceID: "helper-1", HelperBuildID: "dev-build-1",
		AttestationKeyID: "attestation-1", AttestationPublicKey: base64.RawURLEncoding.EncodeToString(helperPublic),
	}
	if err := database.EnrollRecoveryHelper("agent-1", hello, strings.Repeat("e", 64), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	route := proxymodel.Route{Host: "app.example.test", Upstream: proxymodel.Upstream{Addr: "127.0.0.1", Port: 3000},
		RequestHeaders: map[string]string{}, ResponseHeaders: map[string]string{}, IPAllowlist: []string{}, IPBlocklist: []string{}}
	intent := helperprotocol.ApplyIntent{
		AgentID: "agent-1", HelperInstanceID: "helper-1", OperationID: "apply-operation-1",
		DesiredStateRevision: strings.Repeat("1", 64), Resources: []string{"artifact-1"},
		Artifacts: []helperprotocol.LogicalArtifact{}, DeletionSet: []helperprotocol.ManagedDeletion{},
		Routes:            []proxymodel.RouteIntent{{ArtifactID: "artifact-1", Backend: "nginx", Route: route}},
		PruneCertificates: true, CertificateKeep: []string{},
		AuthorizationKind: helperprotocol.AuthorizationStoredConvergence, AuthorizationEventID: "desired-event-1",
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
	}
	signedIntent, err := authority.SignApplyIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.StoreManagedApplyIntent("agent-1", signedIntent, now); err != nil {
		t.Fatal(err)
	}
	logical, artifacts, deletions, certificates, err := helperprotocol.ManagedApplyDigests(intent)
	if err != nil {
		t.Fatal(err)
	}
	plan := helperprotocol.ManagedApplyPlan{
		HelperPlanID: "managed-plan-1", HelperInstanceID: "helper-1", OperationID: intent.OperationID,
		DesiredStateRevision: intent.DesiredStateRevision, LogicalManifestDigest: logical,
		ArtifactManifestDigest: artifacts, DeletionSetDigest: deletions, CertificateIdentityDigest: certificates,
		CustomPolicyVersion: "proxy-policy-v1", ExecutionPlanHash: strings.Repeat("a", 64),
		ResourceFingerprint: strings.Repeat("b", 64), RollbackCoverage: helperprotocol.RollbackCoveragePartial,
		ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339Nano),
	}
	signedPlan, err := helperprotocol.Sign("attestation-1", helperPrivate, helperprotocol.NewEnvelope(helperprotocol.MessageManagedApplyPlan, plan))
	if err != nil {
		t.Fatal(err)
	}
	return signedIntent, signedPlan, helperPrivate
}

func TestManagedApplyPlanGetsImmediateBoundGrantAndAttestedReceipt(t *testing.T) {
	srv, database, handler, _ := recoveryFixture(t)
	authority, err := recoveryauth.New(make([]byte, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	srv.SetRecoveryAuthority(authority)
	_, signedPlan, helperPrivate := managedApplyAPIFixture(t, database, authority)
	basePath := "/api/v1/agents/agent-1/recovery/applies/apply-operation-1"

	w := doRequestWithAuth(t, handler, http.MethodPost, basePath+"/plan", signedPlan, recoveryAgentToken)
	if w.Code != http.StatusCreated {
		t.Fatalf("managed plan = %d: %s", w.Code, w.Body.String())
	}
	var execution db.ManagedApplyExecution
	if err := json.Unmarshal(w.Body.Bytes(), &execution); err != nil {
		t.Fatal(err)
	}
	if execution.SignedGrant == nil {
		t.Fatal("managed apply plan did not receive an immediate grant")
	}
	if err := helperprotocol.Verify(authority.PublicKey(), *execution.SignedGrant, helperprotocol.MessageApplyGrant); err != nil {
		t.Fatalf("managed grant signature: %v", err)
	}
	grant := execution.SignedGrant.Envelope.Payload
	if grant.OperationID != "apply-operation-1" || grant.HelperPlanID != "managed-plan-1" ||
		grant.AuthorizationKind != helperprotocol.AuthorizationStoredConvergence {
		t.Fatalf("managed grant = %#v", grant)
	}

	executeRequest := helperprotocol.NewEnvelope(helperprotocol.MessageExecuteManagedApplyRequest, helperprotocol.ExecuteManagedApplyRequest{
		OperationID: grant.OperationID, HelperPlanID: grant.HelperPlanID, Grant: *execution.SignedGrant,
	})
	requestDigest, err := helperprotocol.Digest(executeRequest)
	if err != nil {
		t.Fatal(err)
	}
	receipt := helperprotocol.HelperReceipt{
		OperationID: grant.OperationID, CanonicalRequestDigest: requestDigest, HelperInstanceID: grant.HelperInstanceID,
		Action: helperprotocol.ActionApplyManagedProxyState, State: helperprotocol.JournalSucceeded,
		RollbackCoverage: helperprotocol.RollbackCoveragePartial, SnapshotDigest: strings.Repeat("c", 64),
		SanitizedResult: "managed state applied", UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	signedReceipt, err := helperprotocol.Sign("attestation-1", helperPrivate, helperprotocol.NewEnvelope(helperprotocol.MessageHelperReceipt, receipt))
	if err != nil {
		t.Fatal(err)
	}
	w = doRequestWithAuth(t, handler, http.MethodPost, basePath+"/receipt", signedReceipt, recoveryAgentToken)
	if w.Code != http.StatusNoContent {
		t.Fatalf("managed receipt = %d: %s", w.Code, w.Body.String())
	}
	w = doRequestWithAuth(t, handler, http.MethodGet, basePath, nil, recoveryAgentToken)
	if w.Code != http.StatusOK {
		t.Fatalf("managed execution fetch = %d: %s", w.Code, w.Body.String())
	}

	retryPlan := signedPlan.Envelope.Payload
	retryPlan.HelperPlanID = "managed-plan-retry"
	signedRetryPlan, err := helperprotocol.Sign("attestation-1", helperPrivate, helperprotocol.NewEnvelope(helperprotocol.MessageManagedApplyPlan, retryPlan))
	if err != nil {
		t.Fatal(err)
	}
	w = doRequestWithAuth(t, handler, http.MethodPost, basePath+"/plan", signedRetryPlan, recoveryAgentToken)
	if w.Code != http.StatusOK {
		t.Fatalf("completed managed retry = %d: %s", w.Code, w.Body.String())
	}
	var retried db.ManagedApplyExecution
	if err := json.Unmarshal(w.Body.Bytes(), &retried); err != nil {
		t.Fatal(err)
	}
	if retried.SignedReceipt == nil || retried.HelperPlanID != "managed-plan-1" {
		t.Fatalf("completed retry did not return the original receipt and plan: %+v", retried)
	}
}

func TestManagedApplyPlanRejectsWrongAgentTamperingAndSupersededIntent(t *testing.T) {
	srv, database, handler, _ := recoveryFixture(t)
	authority, err := recoveryauth.New(make([]byte, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	srv.SetRecoveryAuthority(authority)
	_, signedPlan, _ := managedApplyAPIFixture(t, database, authority)
	basePath := "/api/v1/agents/agent-1/recovery/applies/apply-operation-1/plan"

	if w := doRequestWithAuth(t, handler, http.MethodPost, "/api/v1/agents/other/recovery/applies/apply-operation-1/plan", signedPlan, recoveryAgentToken); w.Code != http.StatusForbidden {
		t.Fatalf("cross-agent managed plan = %d, want 403", w.Code)
	}
	tampered := signedPlan
	tampered.Envelope.Payload.ResourceFingerprint = strings.Repeat("d", 64)
	if w := doRequestWithAuth(t, handler, http.MethodPost, basePath, tampered, recoveryAgentToken); w.Code != http.StatusBadRequest {
		t.Fatalf("tampered managed plan = %d, want 400: %s", w.Code, w.Body.String())
	}

	current, err := database.GetCurrentManagedApply("agent-1")
	if err != nil {
		t.Fatal(err)
	}
	replacement := current.SignedIntent.Envelope.Payload
	replacement.OperationID = "apply-operation-2"
	replacement.DesiredStateRevision = strings.Repeat("2", 64)
	replacement.AuthorizationEventID = "desired-event-2"
	signedReplacement, err := authority.SignApplyIntent(replacement)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.StoreManagedApplyIntent("agent-1", signedReplacement, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if w := doRequestWithAuth(t, handler, http.MethodPost, basePath, signedPlan, recoveryAgentToken); w.Code != http.StatusConflict {
		t.Fatalf("superseded managed plan = %d, want 409: %s", w.Code, w.Body.String())
	}
}

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
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
	"github.com/NurRobin/NurProxy/internal/shared/recoverypolicy"
)

func hardRecoveryDiagnostic(agentID string) recoverymodel.Diagnostic {
	now := time.Now().UTC().Truncate(time.Microsecond)
	fingerprint := strings.Repeat("b", 64)
	diagnostic := recoverymodel.Diagnostic{
		Code: recoverymodel.CodeProxyReloadFailed, Subsystem: "nginx", Severity: recoverymodel.SeverityCritical,
		Ownership: recoverymodel.OwnershipNurProxy, OwnershipConfidence: recoverymodel.OwnershipConfidenceCertain,
		Summary: "nginx reload failed", Evidence: "native reload returned a bounded failure",
		ResourceFingerprint: fingerprint, RepairScope: recoverymodel.RepairScopeDetectedProxyService,
		RepairEligible: true, HardChange: true, FirstSeenAt: now, LastSeenAt: now, Occurrences: 1,
	}
	diagnostic.ID = recoverymodel.StableDiagnosticID(agentID, diagnostic.Code, diagnostic.ResourceFingerprint)
	return diagnostic
}

func enrollAndSignRecoveryPlan(t *testing.T, database *db.DB, diagnostic recoverymodel.Diagnostic) (helperprotocol.Signed[helperprotocol.HelperPlan], ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hello := helperprotocol.HelperHello{
		RequestID: "enrollment-1", HelperInstanceID: "helper-1", HelperBuildID: "dev-build-1",
		AttestationKeyID: "attestation-1", AttestationPublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
	}
	if err := database.EnrollRecoveryHelper("agent-1", hello, strings.Repeat("e", 64), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	action, target, ok := recoverypolicy.HardActionForDiagnostic(diagnostic.Code, diagnostic.RepairScope)
	if !ok {
		t.Fatalf("diagnostic has no hard action: %#v", diagnostic)
	}
	plan := helperprotocol.HelperPlan{
		HelperPlanID: "helper-plan-1", HelperInstanceID: hello.HelperInstanceID, DiagnosticID: diagnostic.ID,
		Action: action, LogicalTarget: target,
		ExecutionPlanHash: strings.Repeat("a", 64), ResourceFingerprint: diagnostic.ResourceFingerprint,
		RollbackCoverage: helperprotocol.RollbackCoverageFull,
		Steps:            []helperprotocol.PlanStep{{Kind: "validate", Summary: "Validate and reload nginx"}},
		ExpiresAt:        time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano),
	}
	plan.DisplayPlanHash, err = helperprotocol.DisplayPlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := helperprotocol.Sign(hello.AttestationKeyID, privateKey, helperprotocol.NewEnvelope(helperprotocol.MessageHelperPlan, plan))
	if err != nil {
		t.Fatal(err)
	}
	return signed, privateKey
}

func TestSensitiveHardRecoveryRequiresFreshPasswordForDashboardGrant(t *testing.T) {
	srv, database, handler, cookie := recoveryFixture(t)
	authority, err := recoveryauth.New(make([]byte, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	srv.SetRecoveryAuthority(authority)
	diagnostic := hardRecoveryDiagnostic("agent-1")
	diagnostic.Code = recoverymodel.CodeProxyBinaryMissing
	diagnostic.RepairScope = recoverymodel.RepairScopeSupportedPackage
	diagnostic.ID = recoverymodel.StableDiagnosticID("agent-1", diagnostic.Code, diagnostic.ResourceFingerprint)
	if err := database.UpsertDiagnostic("agent-1", diagnostic); err != nil {
		t.Fatal(err)
	}
	signedPlan, _ := enrollAndSignRecoveryPlan(t, database, diagnostic)
	basePath := "/api/v1/agents/agent-1/recovery/plans"
	if w := doRequestWithAuth(t, handler, http.MethodPost, basePath, signedPlan, recoveryAgentToken); w.Code != http.StatusCreated {
		t.Fatalf("attested plan = %d: %s", w.Code, w.Body.String())
	}
	confirmPath := basePath + "/helper-plan-1/confirm"
	first := map[string]any{"phase": 1, "confirmation_event_id": "sensitive-1", "display_plan_hash": signedPlan.Envelope.Payload.DisplayPlanHash}
	if w := doRequest(t, handler, http.MethodPost, confirmPath, first, cookie); w.Code != http.StatusOK {
		t.Fatalf("first confirmation = %d: %s", w.Code, w.Body.String())
	}
	second := map[string]any{"phase": 2, "confirmation_event_id": "sensitive-2", "display_plan_hash": signedPlan.Envelope.Payload.DisplayPlanHash}
	if w := doRequest(t, handler, http.MethodPost, confirmPath, second, cookie); w.Code != http.StatusForbidden {
		t.Fatalf("second confirmation without fresh password = %d, want 403: %s", w.Code, w.Body.String())
	}
	second["fresh_password"] = "wrong-password"
	if w := doRequest(t, handler, http.MethodPost, confirmPath, second, cookie); w.Code != http.StatusForbidden {
		t.Fatalf("second confirmation with wrong password = %d, want 403: %s", w.Code, w.Body.String())
	}
	second["fresh_password"] = "testpassword123"
	w := doRequest(t, handler, http.MethodPost, confirmPath, second, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("second confirmation with fresh password = %d: %s", w.Code, w.Body.String())
	}
	var stored db.RecoveryExecutionPlan
	if err := json.Unmarshal(w.Body.Bytes(), &stored); err != nil || stored.SignedGrant == nil {
		t.Fatalf("fresh-authenticated confirmation did not mint grant: %#v err=%v", stored, err)
	}
}

func TestHardRecoveryPlanRequiresAttestedDiagnosticAndTwoAdminConfirmations(t *testing.T) {
	srv, database, handler, cookie := recoveryFixture(t)
	authority, err := recoveryauth.New(make([]byte, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	srv.SetRecoveryAuthority(authority)
	diagnostic := hardRecoveryDiagnostic("agent-1")
	if err := database.UpsertDiagnostic("agent-1", diagnostic); err != nil {
		t.Fatal(err)
	}
	signedPlan, helperPrivateKey := enrollAndSignRecoveryPlan(t, database, diagnostic)
	basePath := "/api/v1/agents/agent-1/recovery/plans"
	w := doRequestWithAuth(t, handler, http.MethodPost, basePath, signedPlan, recoveryAgentToken)
	if w.Code != http.StatusCreated {
		t.Fatalf("attested plan = %d: %s", w.Code, w.Body.String())
	}
	var stored db.RecoveryExecutionPlan
	if err := json.Unmarshal(w.Body.Bytes(), &stored); err != nil {
		t.Fatal(err)
	}
	if stored.OperationID == "" || stored.HelperPlanID != "helper-plan-1" {
		t.Fatalf("stored plan = %#v", stored)
	}
	adminListPath := "/api/v1/agents/agent-1/recovery/hard-plans"
	if w := doRequestWithAuth(t, handler, http.MethodGet, adminListPath, nil, recoveryAgentToken); w.Code != http.StatusUnauthorized {
		t.Fatalf("agent accessed admin plan list: %d", w.Code)
	}
	w = doRequest(t, handler, http.MethodGet, adminListPath, nil, cookie)
	var adminPlans []db.RecoveryExecutionPlan
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &adminPlans) != nil || len(adminPlans) != 1 || adminPlans[0].DisplayPlanHash != stored.DisplayPlanHash {
		t.Fatalf("admin plan list = %d %#v: %s", w.Code, adminPlans, w.Body.String())
	}
	confirmPath := basePath + "/helper-plan-1/confirm"
	confirmation1 := map[string]any{"phase": 1, "confirmation_event_id": "confirmation-1", "display_plan_hash": signedPlan.Envelope.Payload.DisplayPlanHash}
	if w := doRequestWithAuth(t, handler, http.MethodPost, confirmPath, confirmation1, recoveryAgentToken); w.Code != http.StatusUnauthorized {
		t.Fatalf("agent confirmation = %d, want 401", w.Code)
	}
	w = doRequest(t, handler, http.MethodPost, confirmPath, confirmation1, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("first confirmation = %d: %s", w.Code, w.Body.String())
	}
	confirmation2 := map[string]any{"phase": 2, "confirmation_event_id": "confirmation-2", "display_plan_hash": signedPlan.Envelope.Payload.DisplayPlanHash}
	w = doRequest(t, handler, http.MethodPost, confirmPath, confirmation2, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("second confirmation = %d: %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &stored); err != nil {
		t.Fatal(err)
	}
	if stored.SignedGrant == nil {
		t.Fatal("second confirmation did not produce an execution grant")
	}
	if err := helperprotocol.Verify(authority.PublicKey(), *stored.SignedGrant, helperprotocol.MessageExecutionGrant); err != nil {
		t.Fatalf("execution grant signature: %v", err)
	}
	grant := stored.SignedGrant.Envelope.Payload
	if grant.AgentID != "agent-1" || grant.HelperInstanceID != "helper-1" || grant.OperationID != stored.OperationID ||
		grant.DisplayPlanHash != signedPlan.Envelope.Payload.DisplayPlanHash || len(grant.ConfirmationEventIDs) != 2 {
		t.Fatalf("execution grant = %#v", grant)
	}
	w = doRequestWithAuth(t, handler, http.MethodGet, basePath+"/helper-plan-1/grant", nil, recoveryAgentToken)
	if w.Code != http.StatusOK {
		t.Fatalf("agent grant fetch = %d: %s", w.Code, w.Body.String())
	}
	executeRequest := helperprotocol.NewEnvelope(helperprotocol.MessageExecuteActionRequest, helperprotocol.ExecuteActionRequest{
		OperationID: grant.OperationID, HelperPlanID: grant.HelperPlanID, Grant: *stored.SignedGrant,
	})
	requestDigest, err := helperprotocol.Digest(executeRequest)
	if err != nil {
		t.Fatal(err)
	}
	receipt := helperprotocol.HelperReceipt{
		OperationID: grant.OperationID, CanonicalRequestDigest: requestDigest, HelperInstanceID: grant.HelperInstanceID,
		Action: grant.Action, State: helperprotocol.JournalSucceeded, RollbackCoverage: helperprotocol.RollbackCoverageFull,
		SnapshotDigest: strings.Repeat("f", 64), SanitizedResult: "proxy reloaded",
		UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	signedReceipt, err := helperprotocol.Sign("attestation-1", helperPrivateKey, helperprotocol.NewEnvelope(helperprotocol.MessageHelperReceipt, receipt))
	if err != nil {
		t.Fatal(err)
	}
	w = doRequestWithAuth(t, handler, http.MethodPost, basePath+"/helper-plan-1/receipt", signedReceipt, recoveryAgentToken)
	if w.Code != http.StatusNoContent {
		t.Fatalf("helper receipt = %d: %s", w.Code, w.Body.String())
	}
	w = doRequestWithAuth(t, handler, http.MethodGet, basePath, nil, recoveryAgentToken)
	if w.Code != http.StatusOK {
		t.Fatalf("agent plan list = %d: %s", w.Code, w.Body.String())
	}
	var plans []db.RecoveryExecutionPlan
	if err := json.Unmarshal(w.Body.Bytes(), &plans); err != nil || len(plans) != 1 || plans[0].SignedReceipt == nil {
		t.Fatalf("agent plan list = %#v, err=%v", plans, err)
	}
}

func TestHardRecoveryPlanRejectsTamperedAttestationAndDisplayHash(t *testing.T) {
	_, database, handler, cookie := recoveryFixture(t)
	diagnostic := hardRecoveryDiagnostic("agent-1")
	if err := database.UpsertDiagnostic("agent-1", diagnostic); err != nil {
		t.Fatal(err)
	}
	signedPlan, _ := enrollAndSignRecoveryPlan(t, database, diagnostic)
	tampered := signedPlan
	tampered.Envelope.Payload.ResourceFingerprint = strings.Repeat("c", 64)
	basePath := "/api/v1/agents/agent-1/recovery/plans"
	if w := doRequestWithAuth(t, handler, http.MethodPost, basePath, tampered, recoveryAgentToken); w.Code != http.StatusBadRequest {
		t.Fatalf("tampered plan = %d, want 400: %s", w.Code, w.Body.String())
	}
	if w := doRequestWithAuth(t, handler, http.MethodPost, basePath, signedPlan, recoveryAgentToken); w.Code != http.StatusCreated {
		t.Fatalf("valid plan = %d: %s", w.Code, w.Body.String())
	}
	badConfirmation := map[string]any{"phase": 1, "confirmation_event_id": "confirmation-1", "display_plan_hash": strings.Repeat("d", 64)}
	w := doRequest(t, handler, http.MethodPost, basePath+"/helper-plan-1/confirm", badConfirmation, cookie)
	if w.Code != http.StatusConflict {
		t.Fatalf("display hash substitution = %d, want 409: %s", w.Code, w.Body.String())
	}
	_, attackerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forgedReceipt := helperprotocol.HelperReceipt{
		OperationID: "operation-forged", CanonicalRequestDigest: strings.Repeat("a", 64), HelperInstanceID: "helper-1",
		Action: helperprotocol.ActionValidateReloadProxy, State: helperprotocol.JournalSucceeded,
		RollbackCoverage: helperprotocol.RollbackCoverageFull, SnapshotDigest: strings.Repeat("b", 64),
		SanitizedResult: "forged", UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	forgedSigned, err := helperprotocol.Sign("attestation-1", attackerKey, helperprotocol.NewEnvelope(helperprotocol.MessageHelperReceipt, forgedReceipt))
	if err != nil {
		t.Fatal(err)
	}
	w = doRequestWithAuth(t, handler, http.MethodPost, basePath+"/helper-plan-1/receipt", forgedSigned, recoveryAgentToken)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("forged helper receipt = %d, want 400: %s", w.Code, w.Body.String())
	}
}

package helper

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

type fakeActionHandler struct {
	material      PlanMaterial
	prepareCount  int
	executeCount  int
	rollbackCount int
	revalidate    string
	executeErr    error
}

func (h *fakeActionHandler) Plan(context.Context, helperprotocol.PlanActionRequest) (PlanMaterial, error) {
	return h.material, nil
}

func (h *fakeActionHandler) Rediscover(context.Context, helperprotocol.HelperPlan) (string, string, error) {
	fingerprint := h.material.ResourceFingerprint
	if h.revalidate != "" {
		fingerprint = h.revalidate
	}
	return h.material.ExecutionPlanHash, fingerprint, nil
}

func (h *fakeActionHandler) Prepare(context.Context, string, helperprotocol.HelperPlan) (PreparedAction, error) {
	h.prepareCount++
	return PreparedAction{SnapshotDigest: strings.Repeat("d", 64), RollbackCoverage: h.material.RollbackCoverage}, nil
}

func (h *fakeActionHandler) Execute(context.Context, string, helperprotocol.HelperPlan, PreparedAction) (ActionResult, error) {
	h.executeCount++
	return ActionResult{Mutated: true, Validated: h.executeErr == nil, SanitizedResult: "proxy reloaded and validated"}, h.executeErr
}

func (h *fakeActionHandler) Rollback(context.Context, string, helperprotocol.HelperPlan, PreparedAction) error {
	h.rollbackCount++
	return nil
}

type engineFixture struct {
	engine          *Engine
	journal         *Journal
	handler         *fakeActionHandler
	config          RootConfig
	orchestratorKey ed25519.PrivateKey
	attestationPub  ed25519.PublicKey
	now             time.Time
}

func newEngineFixture(t *testing.T) engineFixture {
	t.Helper()
	orchestratorPub, orchestratorKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attestationPub, attestationKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := NewJournal(filepath.Join(parent, "journal"), uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	cfg := RootConfig{
		AgentID:                   "agent-1",
		HelperInstanceID:          "helper-1",
		ExpectedBuildID:           "dev-010e5a7",
		AgentUser:                 "nurproxy",
		AgentUID:                  1000,
		OrchestratorKeyID:         "orchestrator-1",
		OrchestratorPublicKeyText: base64.RawURLEncoding.EncodeToString(orchestratorPub),
		AttestationKeyID:          "attestation-1",
		AttestationPrivateKeyFile: filepath.Join(parent, "attestation.key"),
		StoreDir:                  filepath.Join(parent, "journal"),
		ProxyTarget:               ProxyTargetConfig{Kind: "nginx", Binary: "/usr/sbin/nginx", Unit: "nginx.service", SystemctlBinary: "/usr/bin/systemctl", ConfigRoots: []string{"/etc/nginx"}},
	}
	handler := &fakeActionHandler{material: PlanMaterial{
		Steps:               []helperprotocol.PlanStep{{Kind: "validate", Summary: "Validate and reload nginx"}},
		ExecutionPlanHash:   strings.Repeat("a", 64),
		ResourceFingerprint: strings.Repeat("b", 64),
		RollbackCoverage:    helperprotocol.RollbackCoverageFull,
	}}
	now := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	engine, err := NewEngine(cfg, "dev-010e5a7", journal, attestationKey, map[helperprotocol.Action]ActionHandler{
		helperprotocol.ActionValidateReloadProxy: handler,
	})
	if err != nil {
		t.Fatal(err)
	}
	engine.now = func() time.Time { return now }
	return engineFixture{engine: engine, journal: journal, handler: handler, config: cfg, orchestratorKey: orchestratorKey, attestationPub: attestationPub, now: now}
}

func (f engineFixture) plan(t *testing.T) helperprotocol.HelperPlan {
	t.Helper()
	request := helperprotocol.PlanActionRequest{
		RequestID:           "request-1",
		Action:              helperprotocol.ActionValidateReloadProxy,
		LogicalTarget:       helperprotocol.LogicalTargetDetectedProxy,
		DiagnosticReference: "diagnostic-1",
	}
	signed, err := f.engine.Plan(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := helperprotocol.Verify(f.attestationPub, signed, helperprotocol.MessageHelperPlan); err != nil {
		t.Fatalf("helper plan attestation failed: %v", err)
	}
	return signed.Envelope.Payload
}

func (f engineFixture) executeRequest(t *testing.T, plan helperprotocol.HelperPlan, mutate func(*helperprotocol.ExecutionGrant)) helperprotocol.Envelope[helperprotocol.ExecuteActionRequest] {
	t.Helper()
	grant := helperprotocol.ExecutionGrant{
		GrantID:              "grant-1",
		AgentID:              "agent-1",
		HelperInstanceID:     f.config.HelperInstanceID,
		DiagnosticID:         plan.DiagnosticID,
		OperationID:          "operation-1",
		Action:               plan.Action,
		HelperPlanID:         plan.HelperPlanID,
		DisplayPlanHash:      plan.DisplayPlanHash,
		ExecutionPlanHash:    plan.ExecutionPlanHash,
		ResourceFingerprint:  plan.ResourceFingerprint,
		ConfirmationEventIDs: []string{"confirmation-1", "confirmation-2"},
		IssuedAt:             f.now.Format(time.RFC3339Nano),
		ExpiresAt:            f.now.Add(2 * time.Minute).Format(time.RFC3339Nano),
	}
	if mutate != nil {
		mutate(&grant)
	}
	signed, err := helperprotocol.Sign(f.config.OrchestratorKeyID, f.orchestratorKey, helperprotocol.NewEnvelope(helperprotocol.MessageExecutionGrant, grant))
	if err != nil {
		t.Fatal(err)
	}
	return helperprotocol.NewEnvelope(helperprotocol.MessageExecuteActionRequest, helperprotocol.ExecuteActionRequest{
		OperationID:  grant.OperationID,
		HelperPlanID: grant.HelperPlanID,
		Grant:        signed,
	})
}

func TestEngineAttestsPlanAndExecutesSignedGrantExactlyOnce(t *testing.T) {
	fixture := newEngineFixture(t)
	plan := fixture.plan(t)
	request := fixture.executeRequest(t, plan, nil)
	receipt, err := fixture.engine.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := helperprotocol.Verify(fixture.attestationPub, receipt, helperprotocol.MessageHelperReceipt); err != nil {
		t.Fatalf("receipt attestation failed: %v", err)
	}
	if receipt.Envelope.Payload.State != helperprotocol.JournalSucceeded {
		t.Fatalf("receipt state = %s", receipt.Envelope.Payload.State)
	}

	retry, err := fixture.engine.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Signature != receipt.Signature || fixture.handler.executeCount != 1 || fixture.handler.prepareCount != 1 {
		t.Fatalf("retry repeated execution or changed receipt: execute=%d prepare=%d", fixture.handler.executeCount, fixture.handler.prepareCount)
	}
	fixture.handler.revalidate = strings.Repeat("e", 64)
	fixture.engine.now = func() time.Time { return fixture.now.Add(30 * time.Minute) }
	lateRetry, err := fixture.engine.Execute(context.Background(), request)
	if err != nil || lateRetry.Signature != receipt.Signature || fixture.handler.executeCount != 1 {
		t.Fatalf("durable receipt retry after expiry/fact change failed: receipt=%+v err=%v count=%d", lateRetry, err, fixture.handler.executeCount)
	}
}

func TestEngineRejectsMissingSignaturePlanTamperingCrossHostAndExpiry(t *testing.T) {
	for name, mutate := range map[string]func(*helperprotocol.ExecutionGrant){
		"display tampering": func(g *helperprotocol.ExecutionGrant) { g.DisplayPlanHash = strings.Repeat("c", 64) },
		"cross host":        func(g *helperprotocol.ExecutionGrant) { g.HelperInstanceID = "helper-other" },
		"cross agent":       func(g *helperprotocol.ExecutionGrant) { g.AgentID = "agent-other" },
		"expired": func(g *helperprotocol.ExecutionGrant) {
			g.IssuedAt = time.Date(2026, 8, 29, 9, 55, 0, 0, time.UTC).Format(time.RFC3339Nano)
			g.ExpiresAt = time.Date(2026, 8, 29, 9, 56, 0, 0, time.UTC).Format(time.RFC3339Nano)
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newEngineFixture(t)
			plan := fixture.plan(t)
			_, err := fixture.engine.Execute(context.Background(), fixture.executeRequest(t, plan, mutate))
			if err == nil || fixture.handler.executeCount != 0 {
				t.Fatalf("invalid grant executed: err=%v count=%d", err, fixture.handler.executeCount)
			}
		})
	}

	fixture := newEngineFixture(t)
	plan := fixture.plan(t)
	request := fixture.executeRequest(t, plan, nil)
	request.Payload.Grant.Signature = strings.Repeat("A", 86)
	if _, err := fixture.engine.Execute(context.Background(), request); err == nil || fixture.handler.executeCount != 0 {
		t.Fatal("forged signature executed")
	}
}

func TestEngineHelloRejectsAnotherAgentIdentity(t *testing.T) {
	fixture := newEngineFixture(t)
	_, err := fixture.engine.Hello(helperprotocol.HelperHelloRequest{
		RequestID: "request-other-agent", AgentID: "agent-other", AgentBuildID: fixture.engine.buildID,
	})
	if err == nil {
		t.Fatal("helper hello accepted another agent identity")
	}
}

func TestEngineRediscoversFactsAndFailsStalePlanBeforeMutation(t *testing.T) {
	fixture := newEngineFixture(t)
	plan := fixture.plan(t)
	fixture.handler.revalidate = strings.Repeat("e", 64)
	_, err := fixture.engine.Execute(context.Background(), fixture.executeRequest(t, plan, nil))
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Code != helperprotocol.ErrorStalePlan {
		t.Fatalf("execute error = %v, want stale plan", err)
	}
	if fixture.handler.prepareCount != 0 || fixture.handler.executeCount != 0 {
		t.Fatal("stale plan reached privileged preparation or mutation")
	}
}

func TestEngineFailsClosedWhenPersistentBreakerIsOpen(t *testing.T) {
	fixture := newEngineFixture(t)
	plan := fixture.plan(t)
	if err := fixture.journal.OpenBreaker("test breaker"); err != nil {
		t.Fatal(err)
	}
	_, err := fixture.engine.Execute(context.Background(), fixture.executeRequest(t, plan, nil))
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Code != helperprotocol.ErrorOutcomeIndeterminate {
		t.Fatalf("execute error = %v, want open breaker refusal", err)
	}
	if fixture.handler.executeCount != 0 {
		t.Fatal("open breaker allowed mutation")
	}
}

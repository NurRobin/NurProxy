//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/agenthub"
	orchestratorapi "github.com/NurRobin/NurProxy/internal/orchestrator/api"
	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/auth"
	"github.com/NurRobin/NurProxy/internal/shared/crypto"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

const (
	recoveryE2EAgentID = "recovery-e2e-agent"
	recoveryE2EToken   = "recovery-e2e-agent-token"
)

func TestE2ERecoveryControlPlane(t *testing.T) {
	base, database, cleanup := setupRecoveryOrchestrator(t)
	defer cleanup()
	cookie := setupRecoveryAdmin(t, base)
	createRecoveryAgent(t, database)

	stream := openRecoveryStream(t, base)
	defer func() { stream.Close() }()
	waitRecoveryStreamConnected(t, database)

	putRecoveryJSON(t, base+"/api/v1/settings/safe_auto_repair", map[string]string{"value": "false"}, cookie, http.StatusOK, nil)
	assertRecoveryPolicy(t, nextRecoveryEvent(t, stream, agenthub.EventRecoveryPolicy), false)
	putRecoveryJSON(t, base+"/api/v1/agents/"+recoveryE2EAgentID+"/safe-auto-repair", map[string]string{"mode": "enabled"}, cookie, http.StatusOK, nil)
	assertRecoveryPolicy(t, nextRecoveryEvent(t, stream, agenthub.EventRecoveryPolicy), true)

	now := time.Now().UTC().Truncate(time.Microsecond)
	diagnostic := recoverymodel.Diagnostic{
		Code: recoverymodel.CodeManagedStaleTemp, Subsystem: "proxy", Severity: recoverymodel.SeverityError,
		Ownership: recoverymodel.OwnershipNurProxy, Summary: "managed temporary file is stale",
		Evidence: "nginx: stale generated temporary file", AffectedPaths: []string{"/managed/nurproxy-app.conf.tmp"},
		ResourceFingerprint: "e2e-stale-temp", ProposedAction: recoverymodel.ActionRemoveManagedTemp,
		AutoRepairEligible: true, FirstSeenAt: now, LastSeenAt: now, Occurrences: 1,
	}
	diagnostic.ID = recoverymodel.StableDiagnosticID(recoveryE2EAgentID, diagnostic.Code, diagnostic.ResourceFingerprint)
	capability := &recoverymodel.Capability{Stage: 1, Actions: []recoverymodel.Action{diagnostic.ProposedAction}}

	postRecoveryAgentJSON(t, base+"/api/v1/agents/"+recoveryE2EAgentID+"/heartbeat", map[string]any{
		"last_error": "legacy apply failure remains visible", "recovery_capability": capability,
	}, http.StatusOK, nil)
	postRecoveryAgentJSON(t, base+"/api/v1/agents/"+recoveryE2EAgentID+"/recovery/report",
		proxymodel.RecoveryReportEnvelope{Report: proxymodel.RecoveryReport{Capability: capability, Diagnostics: []recoverymodel.Diagnostic{diagnostic}}},
		http.StatusNoContent, nil)

	var diagnostics []recoverymodel.Diagnostic
	getRecoveryJSON(t, base+"/api/v1/agents/"+recoveryE2EAgentID+"/diagnostics", cookie, http.StatusOK, &diagnostics)
	if len(diagnostics) != 1 || diagnostics[0].ID != diagnostic.ID {
		t.Fatalf("diagnostics = %#v, want reported diagnostic", diagnostics)
	}
	var agents []struct {
		ID        string `json:"id"`
		LastError string `json:"last_error"`
	}
	getRecoveryJSON(t, base+"/api/v1/agents", cookie, http.StatusOK, &agents)
	if len(agents) != 1 || agents[0].LastError != "legacy apply failure remains visible" {
		t.Fatalf("agent last_error compatibility = %#v", agents)
	}

	var operation recoverymodel.OperationReport
	postRecoveryJSON(t, base+"/api/v1/agents/"+recoveryE2EAgentID+"/repairs", map[string]any{
		"diagnostic_id": diagnostic.ID, "action": diagnostic.ProposedAction,
	}, cookie, http.StatusAccepted, &operation)
	live := nextRecoveryEvent(t, stream, agenthub.EventRepairRequest)
	assertRepairRequestIdentity(t, live, operation)

	stream.Close()
	stream = openRecoveryStream(t, base)
	replayed := nextRecoveryEvent(t, stream, agenthub.EventRepairRequest)
	assertRepairRequestIdentity(t, replayed, operation)

	operation = ackRecoveryOperation(t, base, operation, recoverymodel.OperationStateSnapshotted, "snapshot captured", func(op *recoverymodel.OperationReport) {
		op.SnapshotReference = "recovery/" + op.OperationID
	})
	operation = ackRecoveryOperation(t, base, operation, recoverymodel.OperationStateApplying, "repair applied", nil)
	operation = ackRecoveryOperation(t, base, operation, recoverymodel.OperationStateRollingBack, "validation failed; restoring snapshot", func(op *recoverymodel.OperationReport) {
		op.ValidationOutcome = "nginx -t rejected generated config"
	})
	operation = ackRecoveryOperation(t, base, operation, recoverymodel.OperationStateRolledBack, "snapshot restored", func(op *recoverymodel.OperationReport) {
		op.RollbackOutcome = "managed bytes restored"
		finished := op.Steps[len(op.Steps)-1].At
		op.FinishedAt = &finished
	})

	postRecoveryAgentJSON(t, base+"/api/v1/agents/"+recoveryE2EAgentID+"/repairs/"+operation.OperationID+"/ack", operation, http.StatusNoContent, nil)

	var history []recoverymodel.OperationReport
	getRecoveryJSON(t, base+"/api/v1/agents/"+recoveryE2EAgentID+"/repairs", cookie, http.StatusOK, &history)
	if len(history) != 1 || !reflect.DeepEqual(history[0], operation) {
		t.Fatalf("repair history after duplicate terminal ACK = %#v, want exact %#v", history, operation)
	}

	stored, err := database.GetAgent(recoveryE2EAgentID)
	if err != nil || stored.LastError != "legacy apply failure remains visible" {
		t.Fatalf("recovery reporting changed last_error: agent=%#v err=%v", stored, err)
	}
}

func setupRecoveryOrchestrator(t *testing.T) (string, *db.DB, func()) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(":memory:", key)
	if err != nil {
		t.Fatal(err)
	}
	srv := orchestratorapi.NewServer(database, "recovery-e2e")
	srv.SetAgentHub(agenthub.New(), nil)
	ts := httptest.NewServer(srv.Handler())
	return ts.URL, database, func() { ts.Close(); database.Close() }
}

func setupRecoveryAdmin(t *testing.T, base string) *http.Cookie {
	t.Helper()
	resp := httpDo(t, http.MethodPost, base+"/api/v1/auth/setup", map[string]string{"password": "recovery-e2e-password"}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("setup = %d: %s", resp.StatusCode, readBody(t, resp))
	}
	resp.Body.Close()
	resp = httpDo(t, http.MethodPost, base+"/api/v1/auth/login", map[string]string{"password": "recovery-e2e-password"}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login = %d: %s", resp.StatusCode, readBody(t, resp))
	}
	cookie := extractSessionCookie(t, resp)
	resp.Body.Close()
	return cookie
}

func createRecoveryAgent(t *testing.T, database *db.DB) {
	t.Helper()
	if err := database.CreateAgent(&models.Agent{
		ID: recoveryE2EAgentID, Name: "Recovery E2E", FQDN: "recovery.example.test",
		TokenHash: auth.HashToken(recoveryE2EToken), Status: models.AgentStatusOffline,
	}); err != nil {
		t.Fatal(err)
	}
}

type recoveryEventStream struct {
	response *http.Response
	scanner  *bufio.Scanner
	cancel   context.CancelFunc
}

func openRecoveryStream(t *testing.T, base string) *recoveryEventStream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/agents/"+recoveryE2EAgentID+"/stream", nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+recoveryE2EToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("stream = %d: %s", resp.StatusCode, readBody(t, resp))
	}
	return &recoveryEventStream{response: resp, scanner: bufio.NewScanner(resp.Body), cancel: cancel}
}

func waitRecoveryStreamConnected(t *testing.T, database *db.DB) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		agent, err := database.GetAgent(recoveryE2EAgentID)
		if err == nil && agent.Status == models.AgentStatusAdopted {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("recovery SSE stream did not mark the agent online")
}

func (stream *recoveryEventStream) Close() {
	stream.cancel()
	_ = stream.response.Body.Close()
}

func nextRecoveryEvent(t *testing.T, stream *recoveryEventStream, eventType string) json.RawMessage {
	t.Helper()
	matched := false
	for stream.scanner.Scan() {
		line := stream.scanner.Text()
		if strings.HasPrefix(line, "event:") {
			matched = strings.TrimSpace(strings.TrimPrefix(line, "event:")) == eventType
			continue
		}
		if matched && strings.HasPrefix(line, "data:") {
			return json.RawMessage(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	t.Fatalf("stream ended before %s event: %v", eventType, stream.scanner.Err())
	return nil
}

func assertRecoveryPolicy(t *testing.T, raw json.RawMessage, want bool) {
	t.Helper()
	var envelope proxymodel.RecoveryPolicyEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.Policy.SafeAutoRepair != want {
		t.Fatalf("recovery policy = %#v, err=%v, want %t", envelope, err, want)
	}
}

func assertRepairRequestIdentity(t *testing.T, raw json.RawMessage, operation recoverymodel.OperationReport) {
	t.Helper()
	var envelope proxymodel.RepairRequestEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	expected := recoverymodel.RepairRequest{
		OperationID: operation.OperationID, DiagnosticID: operation.DiagnosticID,
		Action: operation.Action, StartedAt: operation.StartedAt, InitialStep: operation.Steps[0],
	}
	if !reflect.DeepEqual(envelope.Request, expected) {
		t.Fatalf("repair request = %#v, want exact %#v", envelope.Request, expected)
	}
}

func ackRecoveryOperation(t *testing.T, base string, operation recoverymodel.OperationReport, state recoverymodel.OperationState, summary string, mutate func(*recoverymodel.OperationReport)) recoverymodel.OperationReport {
	t.Helper()
	operation.State = state
	operation.Steps = append(operation.Steps, recoverymodel.Step{Name: string(state), Summary: summary, State: state, At: operation.StartedAt.Add(time.Duration(len(operation.Steps)) * time.Second)})
	if mutate != nil {
		mutate(&operation)
	}
	postRecoveryAgentJSON(t, base+"/api/v1/agents/"+recoveryE2EAgentID+"/repairs/"+operation.OperationID+"/ack", operation, http.StatusNoContent, nil)
	return operation
}

func getRecoveryJSON(t *testing.T, url string, cookie *http.Cookie, status int, out any) {
	t.Helper()
	resp := httpDo(t, http.MethodGet, url, nil, cookie)
	assertRecoveryResponse(t, resp, status, out)
}

func postRecoveryJSON(t *testing.T, url string, body any, cookie *http.Cookie, status int, out any) {
	t.Helper()
	resp := httpDo(t, http.MethodPost, url, body, cookie)
	assertRecoveryResponse(t, resp, status, out)
}

func putRecoveryJSON(t *testing.T, url string, body any, cookie *http.Cookie, status int, out any) {
	t.Helper()
	resp := httpDo(t, http.MethodPut, url, body, cookie)
	assertRecoveryResponse(t, resp, status, out)
}

func postRecoveryAgentJSON(t *testing.T, url string, body any, status int, out any) {
	t.Helper()
	resp := httpDoWithBearer(t, http.MethodPost, url, body, recoveryE2EToken)
	assertRecoveryResponse(t, resp, status, out)
}

func assertRecoveryResponse(t *testing.T, resp *http.Response, status int, out any) {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("%s %s = %d, want %d: %s", resp.Request.Method, resp.Request.URL, resp.StatusCode, status, readBody(t, resp))
	}
	if out == nil {
		resp.Body.Close()
		return
	}
	decodeJSON(t, resp, out)
}

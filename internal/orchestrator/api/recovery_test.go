package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/agenthub"
	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/auth"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

const recoveryAgentToken = "agent-recovery-token"

func recoveryFixture(t *testing.T) (*Server, *db.DB, http.Handler, *http.Cookie) {
	t.Helper()
	srv, database := testServer(t)
	if err := database.CreateAgent(&models.Agent{
		ID: "agent-1", Name: "Agent 1", FQDN: "agent-1.example.test",
		TokenHash: auth.HashToken(recoveryAgentToken), Status: models.AgentStatusAdopted,
	}); err != nil {
		t.Fatal(err)
	}
	hub := agenthub.New()
	srv.SetAgentHub(hub, nil)
	h := srv.Handler()
	return srv, database, h, setupAdmin(t, h)
}

func recoveryDiagnostic(agentID string) recoverymodel.Diagnostic {
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := recoverymodel.Diagnostic{
		Code: recoverymodel.CodeManagedStaleTemp, Subsystem: "proxy", Severity: recoverymodel.SeverityError,
		Ownership: recoverymodel.OwnershipNurProxy, Summary: "managed temporary file is stale",
		Evidence: "nginx: stale generated temporary file", AffectedPaths: []string{"/etc/nginx/sites-available/nurproxy-app.conf.nurproxy-tmp"},
		ResourceFingerprint: "fp-stale-temp", ProposedAction: recoverymodel.ActionRemoveManagedTemp,
		AutoRepairEligible: true, FirstSeenAt: now, LastSeenAt: now, Occurrences: 1,
	}
	d.ID = recoverymodel.StableDiagnosticID(agentID, d.Code, d.ResourceFingerprint)
	return d
}

func TestRecoveryRoutesRequireCorrectPrincipal(t *testing.T) {
	_, _, h, _ := recoveryFixture(t)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/agents/agent-1/diagnostics"},
		{http.MethodGet, "/api/v1/agents/agent-1/repairs"},
		{http.MethodPut, "/api/v1/agents/agent-1/safe-auto-repair"},
	} {
		w := doRequest(t, h, tc.method, tc.path, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s without user auth = %d, want 401", tc.path, w.Code)
		}
	}

	w := doRequestWithAuth(t, h, http.MethodPost, "/api/v1/agents/other/recovery/report",
		proxymodel.RecoveryReportEnvelope{Report: proxymodel.RecoveryReport{}}, recoveryAgentToken)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-agent report = %d, want 403", w.Code)
	}
	w = doRequestWithAuth(t, h, http.MethodPost, "/api/v1/agents/other/repairs/op/ack",
		map[string]any{}, recoveryAgentToken)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-agent ack = %d, want 403", w.Code)
	}
}

func TestRecoveryReportCoalescesDiagnosticsResolvesOmissionsAndAuditsTransitions(t *testing.T) {
	srv, database, h, cookie := recoveryFixture(t)
	d := recoveryDiagnostic("agent-1")
	capability := &recoverymodel.Capability{Stage: 1, Actions: []recoverymodel.Action{d.ProposedAction}}

	w := doRequestWithAuth(t, h, http.MethodPost, "/api/v1/agents/agent-1/recovery/report",
		proxymodel.RecoveryReportEnvelope{Report: proxymodel.RecoveryReport{Capability: capability, Diagnostics: []recoverymodel.Diagnostic{d}}}, recoveryAgentToken)
	if w.Code != http.StatusNoContent {
		t.Fatalf("first report = %d: %s", w.Code, w.Body.String())
	}
	d.LastSeenAt = d.LastSeenAt.Add(time.Microsecond)
	d.Occurrences = 2
	w = doRequestWithAuth(t, h, http.MethodPost, "/api/v1/agents/agent-1/recovery/report",
		proxymodel.RecoveryReportEnvelope{Report: proxymodel.RecoveryReport{Diagnostics: []recoverymodel.Diagnostic{d}}}, recoveryAgentToken)
	if w.Code != http.StatusNoContent {
		t.Fatalf("repeat report = %d: %s", w.Code, w.Body.String())
	}

	active, err := database.ListDiagnostics("agent-1", false)
	if err != nil || len(active) != 1 || active[0].Occurrences != 2 {
		t.Fatalf("coalesced diagnostics = %#v, err=%v", active, err)
	}
	agent, err := database.GetAgent("agent-1")
	if err != nil || agent.RecoveryCapability == nil || agent.RecoveryCapability.Stage != 1 {
		t.Fatalf("capability was not persisted: %#v, err=%v", agent, err)
	}
	entries, _, err := database.ListAuditLog(50, 0)
	if err != nil {
		t.Fatal(err)
	}
	detections := 0
	for _, entry := range entries {
		if entry.EntityType == "recovery_diagnostic" && entry.Action == "detected" {
			detections++
		}
	}
	if detections != 1 {
		t.Fatalf("detection audits = %d, want 1", detections)
	}

	w = doRequestWithAuth(t, h, http.MethodPost, "/api/v1/agents/agent-1/recovery/report",
		proxymodel.RecoveryReportEnvelope{Report: proxymodel.RecoveryReport{Diagnostics: []recoverymodel.Diagnostic{}}}, recoveryAgentToken)
	if w.Code != http.StatusNoContent {
		t.Fatalf("omission report = %d: %s", w.Code, w.Body.String())
	}
	w = doRequest(t, h, http.MethodGet, "/api/v1/agents/agent-1/diagnostics?include_resolved=true", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("history list = %d: %s", w.Code, w.Body.String())
	}
	var history []recoverymodel.Diagnostic
	if err := json.NewDecoder(w.Body).Decode(&history); err != nil || len(history) != 1 {
		t.Fatalf("diagnostic history = %#v, err=%v", history, err)
	}
	active, err = database.ListDiagnostics("agent-1", false)
	if err != nil || len(active) != 0 {
		t.Fatalf("active diagnostics after omission = %#v, err=%v", active, err)
	}
	w = doRequestWithAuth(t, h, http.MethodPost, "/api/v1/agents/agent-1/recovery/report",
		proxymodel.RecoveryReportEnvelope{Report: proxymodel.RecoveryReport{Diagnostics: []recoverymodel.Diagnostic{}}}, recoveryAgentToken)
	if w.Code != http.StatusNoContent {
		t.Fatalf("repeat omission report = %d: %s", w.Code, w.Body.String())
	}
	entries, _, err = database.ListAuditLog(50, 0)
	if err != nil {
		t.Fatal(err)
	}
	resolvedAudits := 0
	for _, entry := range entries {
		if entry.EntityID == d.ID && entry.Action == "resolved" {
			resolvedAudits++
		}
	}
	if resolvedAudits != 1 {
		t.Fatalf("resolved audits = %d, want 1", resolvedAudits)
	}
	_, unsub := srv.hub.Subscribe("agent-1")
	defer unsub()
	w = doRequest(t, h, http.MethodPost, "/api/v1/agents/agent-1/repairs", map[string]any{
		"diagnostic_id": d.ID, "action": d.ProposedAction,
	}, cookie)
	if w.Code != http.StatusNotFound {
		t.Fatalf("repair of resolved diagnostic = %d, want 404: %s", w.Code, w.Body.String())
	}
}

func TestRecoveryReportFullSnapshotResolvesOnlyOmittedDiagnostics(t *testing.T) {
	_, database, h, _ := recoveryFixture(t)
	first := recoveryDiagnostic("agent-1")
	second := first
	second.ResourceFingerprint = "fp-second-active"
	second.ID = recoverymodel.StableDiagnosticID("agent-1", second.Code, second.ResourceFingerprint)

	w := doRequestWithAuth(t, h, http.MethodPost, "/api/v1/agents/agent-1/recovery/report",
		proxymodel.RecoveryReportEnvelope{Report: proxymodel.RecoveryReport{Diagnostics: []recoverymodel.Diagnostic{first, second}}}, recoveryAgentToken)
	if w.Code != http.StatusNoContent {
		t.Fatalf("initial snapshot = %d: %s", w.Code, w.Body.String())
	}
	first.LastSeenAt = first.LastSeenAt.Add(time.Microsecond)
	first.Occurrences++
	w = doRequestWithAuth(t, h, http.MethodPost, "/api/v1/agents/agent-1/recovery/report",
		proxymodel.RecoveryReportEnvelope{Report: proxymodel.RecoveryReport{Diagnostics: []recoverymodel.Diagnostic{first}}}, recoveryAgentToken)
	if w.Code != http.StatusNoContent {
		t.Fatalf("next snapshot = %d: %s", w.Code, w.Body.String())
	}
	active, err := database.ListDiagnostics("agent-1", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].ID != first.ID {
		t.Fatalf("active diagnostics = %#v, want only %s", active, first.ID)
	}
	all, err := database.ListDiagnostics("agent-1", true)
	if err != nil || len(all) != 2 {
		t.Fatalf("diagnostic history = %#v, err=%v", all, err)
	}
}

func TestRecoveryDiagnosticHistoryIsExplicitlyBounded(t *testing.T) {
	_, database, h, cookie := recoveryFixture(t)
	for i := 0; i < 205; i++ {
		diagnostic := recoveryDiagnostic("agent-1")
		diagnostic.ResourceFingerprint = fmt.Sprintf("fp-api-history-%03d", i)
		diagnostic.ID = recoverymodel.StableDiagnosticID("agent-1", diagnostic.Code, diagnostic.ResourceFingerprint)
		if err := database.UpsertDiagnostic("agent-1", diagnostic); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.ResolveMissingDiagnostics("agent-1", nil, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	active := recoveryDiagnostic("agent-1")
	active.ResourceFingerprint = "fp-api-active"
	active.ID = recoverymodel.StableDiagnosticID("agent-1", active.Code, active.ResourceFingerprint)
	if err := database.UpsertDiagnostic("agent-1", active); err != nil {
		t.Fatal(err)
	}

	for path, want := range map[string]int{
		"/api/v1/agents/agent-1/diagnostics?include_resolved=true":                    101,
		"/api/v1/agents/agent-1/diagnostics?include_resolved=true&resolved_limit=7":   8,
		"/api/v1/agents/agent-1/diagnostics?include_resolved=true&resolved_limit=200": 201,
	} {
		w := doRequest(t, h, http.MethodGet, path, nil, cookie)
		var got []json.RawMessage
		if w.Code != http.StatusOK {
			t.Fatalf("%s = %d: %s", path, w.Code, w.Body.String())
		}
		if err := json.NewDecoder(w.Body).Decode(&got); err != nil || len(got) != want {
			t.Fatalf("%s count = %d, err=%v, want %d", path, len(got), err, want)
		}
	}
	w := doRequest(t, h, http.MethodGet, "/api/v1/agents/agent-1/diagnostics?include_resolved=true&resolved_limit=201", nil, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized resolved history = %d, want 400", w.Code)
	}
}

func TestRecoveryDiagnosticProjectionRemainsAvailableAboveNominalActiveLimit(t *testing.T) {
	_, database, h, cookie := recoveryFixture(t)
	for i := 0; i < 701; i++ {
		diagnostic := recoveryDiagnostic("agent-1")
		diagnostic.ResourceFingerprint = fmt.Sprintf("fp-api-oversized-active-%03d", i)
		diagnostic.ID = recoverymodel.StableDiagnosticID("agent-1", diagnostic.Code, diagnostic.ResourceFingerprint)
		if err := database.UpsertDiagnostic("agent-1", diagnostic); err != nil {
			t.Fatal(err)
		}
	}
	w := doRequest(t, h, http.MethodGet, "/api/v1/agents/agent-1/diagnostics?include_resolved=false", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("oversized active projection = %d: %s", w.Code, w.Body.String())
	}
	var got []json.RawMessage
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil || len(got) != 701 {
		t.Fatalf("oversized active projection count = %d, err=%v, want 701", len(got), err)
	}
}

func TestManualRepairPersistsBeforeTypedPublishAndRejectsInjectedFields(t *testing.T) {
	srv, database, h, cookie := recoveryFixture(t)
	d := recoveryDiagnostic("agent-1")
	if err := database.UpsertDiagnostic("agent-1", d); err != nil {
		t.Fatal(err)
	}
	if err := database.UpdateAgentRecoveryCapability("agent-1", &recoverymodel.Capability{Stage: 1, Actions: []recoverymodel.Action{d.ProposedAction}}); err != nil {
		t.Fatal(err)
	}
	ch, unsub := srv.hub.Subscribe("agent-1")
	defer unsub()

	w := doRequest(t, h, http.MethodPost, "/api/v1/agents/agent-1/repairs", map[string]any{
		"diagnostic_id": d.ID, "action": d.ProposedAction, "path": "/tmp/injected",
	}, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("injected field = %d, want 400: %s", w.Code, w.Body.String())
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/agent-1/repairs", strings.NewReader(`{"diagnostic_id":"`+d.ID+`","action":"remove_managed_temp"} {"action":"remove_managed_temp"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("trailing request = %d, want 400: %s", w.Code, w.Body.String())
	}

	w = doRequest(t, h, http.MethodPost, "/api/v1/agents/agent-1/repairs", map[string]any{
		"diagnostic_id": d.ID, "action": d.ProposedAction,
	}, cookie)
	if w.Code != http.StatusAccepted {
		t.Fatalf("manual repair = %d: %s", w.Code, w.Body.String())
	}
	var created recoverymodel.OperationReport
	if err := json.NewDecoder(w.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.OperationID == "" || created.Source != recoverymodel.RequestSourceUser || created.State != recoverymodel.OperationStatePlanned {
		t.Fatalf("created operation = %#v", created)
	}
	history, err := database.ListRepairOperations("agent-1", 10)
	if err != nil || len(history) != 1 || history[0].OperationID != created.OperationID {
		t.Fatalf("operation was not persisted before delivery: %#v, err=%v", history, err)
	}
	select {
	case ev := <-ch:
		if ev.Type != agenthub.EventRepairRequest {
			t.Fatalf("event type = %q", ev.Type)
		}
		var envelope proxymodel.RepairRequestEnvelope
		if err := json.Unmarshal(ev.Data, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Request.OperationID != created.OperationID || envelope.Request.Action != d.ProposedAction {
			t.Fatalf("published request = %#v", envelope.Request)
		}
	default:
		t.Fatal("repair request was not published")
	}
}

func TestConcurrentManualRepairCreatesOnlyOneActiveOperation(t *testing.T) {
	srv, database, h, cookie := recoveryFixture(t)
	d := recoveryDiagnostic("agent-1")
	if err := database.UpsertDiagnostic("agent-1", d); err != nil {
		t.Fatal(err)
	}
	if err := database.UpdateAgentRecoveryCapability("agent-1", &recoverymodel.Capability{Stage: 1, Actions: []recoverymodel.Action{d.ProposedAction}}); err != nil {
		t.Fatal(err)
	}
	_, unsub := srv.hub.Subscribe("agent-1")
	defer unsub()

	const requests = 8
	codes := make(chan int, requests)
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := doRequest(t, h, http.MethodPost, "/api/v1/agents/agent-1/repairs", map[string]any{
				"diagnostic_id": d.ID, "action": d.ProposedAction,
			}, cookie)
			codes <- w.Code
		}()
	}
	wg.Wait()
	close(codes)
	accepted := 0
	for code := range codes {
		if code == http.StatusAccepted {
			accepted++
		} else if code != http.StatusConflict {
			t.Fatalf("concurrent status = %d, want 202 or 409", code)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted requests = %d, want 1", accepted)
	}
}

func TestManualRepairRemainsDurablyPendingWhenEveryStreamBufferIsFull(t *testing.T) {
	srv, database, h, cookie := recoveryFixture(t)
	d := recoveryDiagnostic("agent-1")
	if err := database.UpsertDiagnostic("agent-1", d); err != nil {
		t.Fatal(err)
	}
	if err := database.UpdateAgentRecoveryCapability("agent-1", &recoverymodel.Capability{Stage: 1, Actions: []recoverymodel.Action{d.ProposedAction}}); err != nil {
		t.Fatal(err)
	}
	first, unsubFirst := srv.hub.Subscribe("agent-1")
	defer unsubFirst()
	second, unsubSecond := srv.hub.Subscribe("agent-1")
	defer unsubSecond()
	for i := 0; i < cap(first); i++ {
		if !srv.hub.Publish("agent-1", agenthub.Event{Type: agenthub.EventPing}) {
			t.Fatalf("fill publish %d failed", i)
		}
	}
	if len(second) != cap(second) {
		t.Fatal("second stream buffer was not filled")
	}

	w := doRequest(t, h, http.MethodPost, "/api/v1/agents/agent-1/repairs", map[string]any{
		"diagnostic_id": d.ID, "action": d.ProposedAction,
	}, cookie)
	if w.Code != http.StatusAccepted {
		t.Fatalf("buffered repair = %d, want 202: %s", w.Code, w.Body.String())
	}
	pending, err := database.ListPendingUserRepairOperations("agent-1", 10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("durable pending operations = %#v, err=%v", pending, err)
	}
	reconnected, unsubReconnected := srv.hub.Subscribe("agent-1")
	defer unsubReconnected()
	srv.publishPendingManualRepairs("agent-1")
	select {
	case event := <-reconnected:
		if event.Type != agenthub.EventRepairRequest {
			t.Fatalf("reconnect event = %q", event.Type)
		}
		var envelope proxymodel.RepairRequestEnvelope
		if err := json.Unmarshal(event.Data, &envelope); err != nil || envelope.Request.OperationID != pending[0].OperationID {
			t.Fatalf("replayed pending request = %#v, err=%v", envelope.Request, err)
		}
	default:
		t.Fatal("pending repair was not replayed to reconnect")
	}
}

func TestManualRepairRecomputesStableSafetyPredicates(t *testing.T) {
	srv, database, h, cookie := recoveryFixture(t)
	_, unsub := srv.hub.Subscribe("agent-1")
	defer unsub()
	actions := []recoverymodel.Action{
		recoverymodel.ActionRemoveManagedTemp,
		recoverymodel.ActionPruneManagedOrphan,
	}
	if err := database.UpdateAgentRecoveryCapability("agent-1", &recoverymodel.Capability{Stage: 1, Actions: actions}); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		mutate     func(*recoverymodel.Diagnostic)
		action     recoverymodel.Action
		wantStatus int
		wantCode   string
	}{
		{"action mismatch", func(d *recoverymodel.Diagnostic) {}, recoverymodel.ActionPruneManagedOrphan, 422, "action_mismatch"},
		{"operator owned", func(d *recoverymodel.Diagnostic) {
			d.Ownership = recoverymodel.OwnershipOperator
			d.AutoRepairEligible = false
		}, recoverymodel.ActionRemoveManagedTemp, 422, "ownership_not_nurproxy"},
		{"hard change", func(d *recoverymodel.Diagnostic) { d.HardChange = true; d.AutoRepairEligible = false }, recoverymodel.ActionRemoveManagedTemp, 422, "hard_change"},
		{"ineligible", func(d *recoverymodel.Diagnostic) { d.AutoRepairEligible = false }, recoverymodel.ActionRemoveManagedTemp, 422, "not_safe_repair_eligible"},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := recoveryDiagnostic("agent-1")
			d.ResourceFingerprint = fmt.Sprintf("fp-safety-%d", i)
			d.ID = recoverymodel.StableDiagnosticID("agent-1", d.Code, d.ResourceFingerprint)
			tc.mutate(&d)
			if err := database.UpsertDiagnostic("agent-1", d); err != nil {
				t.Fatal(err)
			}
			w := doRequest(t, h, http.MethodPost, "/api/v1/agents/agent-1/repairs", map[string]any{
				"diagnostic_id": d.ID, "action": tc.action,
			}, cookie)
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.wantStatus, w.Body.String())
			}
			var body map[string]string
			if err := json.NewDecoder(w.Body).Decode(&body); err != nil || body["code"] != tc.wantCode {
				t.Fatalf("error body = %#v, err=%v", body, err)
			}
		})
	}
}

func TestManualRepairRequiresConnectedCapableAgentAndKnownAction(t *testing.T) {
	t.Run("disconnected", func(t *testing.T) {
		_, database, h, cookie := recoveryFixture(t)
		d := recoveryDiagnostic("agent-1")
		if err := database.UpsertDiagnostic("agent-1", d); err != nil {
			t.Fatal(err)
		}
		if err := database.UpdateAgentRecoveryCapability("agent-1", &recoverymodel.Capability{Stage: 1, Actions: []recoverymodel.Action{d.ProposedAction}}); err != nil {
			t.Fatal(err)
		}
		w := doRequest(t, h, http.MethodPost, "/api/v1/agents/agent-1/repairs", map[string]any{"diagnostic_id": d.ID, "action": d.ProposedAction}, cookie)
		assertRecoveryError(t, w.Code, w.Body.Bytes(), http.StatusConflict, "agent_disconnected")
	})
	t.Run("capability", func(t *testing.T) {
		srv, database, h, cookie := recoveryFixture(t)
		d := recoveryDiagnostic("agent-1")
		if err := database.UpsertDiagnostic("agent-1", d); err != nil {
			t.Fatal(err)
		}
		_, unsub := srv.hub.Subscribe("agent-1")
		defer unsub()
		w := doRequest(t, h, http.MethodPost, "/api/v1/agents/agent-1/repairs", map[string]any{"diagnostic_id": d.ID, "action": d.ProposedAction}, cookie)
		assertRecoveryError(t, w.Code, w.Body.Bytes(), http.StatusConflict, "recovery_capability_unavailable")
	})
	t.Run("unknown action", func(t *testing.T) {
		_, _, h, cookie := recoveryFixture(t)
		w := doRequest(t, h, http.MethodPost, "/api/v1/agents/agent-1/repairs", map[string]any{"diagnostic_id": "diag", "action": "shell"}, cookie)
		assertRecoveryError(t, w.Code, w.Body.Bytes(), http.StatusBadRequest, "invalid_request")
	})
}

func assertRecoveryError(t *testing.T, gotStatus int, raw []byte, wantStatus int, wantCode string) {
	t.Helper()
	if gotStatus != wantStatus {
		t.Fatalf("status = %d, want %d: %s", gotStatus, wantStatus, raw)
	}
	var body map[string]string
	if err := json.Unmarshal(raw, &body); err != nil || body["code"] != wantCode {
		t.Fatalf("error body = %#v, err=%v, want code %q", body, err, wantCode)
	}
}

func TestRepairACKIsScopedIdempotentAndAuditsOnlyTransitions(t *testing.T) {
	srv, database, h, cookie := recoveryFixture(t)
	d := recoveryDiagnostic("agent-1")
	if err := database.UpsertDiagnostic("agent-1", d); err != nil {
		t.Fatal(err)
	}
	if err := database.UpdateAgentRecoveryCapability("agent-1", &recoverymodel.Capability{Stage: 1, Actions: []recoverymodel.Action{d.ProposedAction}}); err != nil {
		t.Fatal(err)
	}
	_, unsub := srv.hub.Subscribe("agent-1")
	defer unsub()
	w := doRequest(t, h, http.MethodPost, "/api/v1/agents/agent-1/repairs", map[string]any{"diagnostic_id": d.ID, "action": d.ProposedAction}, cookie)
	if w.Code != http.StatusAccepted {
		t.Fatalf("create = %d: %s", w.Code, w.Body.String())
	}
	var operation recoverymodel.OperationReport
	if err := json.NewDecoder(w.Body).Decode(&operation); err != nil {
		t.Fatal(err)
	}
	operation.State = recoverymodel.OperationStateSnapshotted
	operation.SnapshotReference = "recovery/" + operation.OperationID
	operation.Steps = append(operation.Steps, recoverymodel.Step{Name: "snapshotted", Summary: "captured", State: operation.State, At: operation.StartedAt.Add(time.Second)})
	ackPath := "/api/v1/agents/agent-1/repairs/" + operation.OperationID + "/ack"
	for i := 0; i < 2; i++ {
		w = doRequestWithAuth(t, h, http.MethodPost, ackPath, operation, recoveryAgentToken)
		if w.Code != http.StatusNoContent {
			t.Fatalf("ack %d = %d: %s", i, w.Code, w.Body.String())
		}
	}
	history, err := database.ListRepairOperations("agent-1", 10)
	if err != nil || len(history) != 1 || history[0].State != recoverymodel.OperationStateSnapshotted {
		t.Fatalf("history = %#v, err=%v", history, err)
	}
	entries, _, err := database.ListAuditLog(50, 0)
	if err != nil {
		t.Fatal(err)
	}
	snapAudits := 0
	for _, entry := range entries {
		if entry.EntityID == operation.OperationID && entry.Action == "snapshotted" {
			snapAudits++
		}
	}
	if snapAudits != 1 {
		t.Fatalf("snapshotted audits = %d, want 1", snapAudits)
	}
}

func TestAutomaticRecoveryReportEnforcesLifecycleActionAndIdempotency(t *testing.T) {
	_, database, h, _ := recoveryFixture(t)
	d := recoveryDiagnostic("agent-1")
	w := doRequestWithAuth(t, h, http.MethodPost, "/api/v1/agents/agent-1/recovery/report",
		proxymodel.RecoveryReportEnvelope{Report: proxymodel.RecoveryReport{Diagnostics: []recoverymodel.Diagnostic{d}}}, recoveryAgentToken)
	if w.Code != http.StatusNoContent {
		t.Fatalf("diagnostic report = %d: %s", w.Code, w.Body.String())
	}
	now := time.Now().UTC()
	operation := recoverymodel.OperationReport{
		OperationID: "auto-op-1", DiagnosticID: d.ID, Action: d.ProposedAction,
		Source: recoverymodel.RequestSourceAutomatic, State: recoverymodel.OperationStateDetected,
		Steps:     []recoverymodel.Step{{Name: "detected", Summary: "detected", State: recoverymodel.OperationStateDetected, At: now}},
		StartedAt: now,
	}
	for i := 0; i < 2; i++ {
		w = doRequestWithAuth(t, h, http.MethodPost, "/api/v1/agents/agent-1/recovery/report",
			proxymodel.RecoveryReportEnvelope{Report: proxymodel.RecoveryReport{Operations: []recoverymodel.OperationReport{operation}}}, recoveryAgentToken)
		if w.Code != http.StatusNoContent {
			t.Fatalf("detected report %d = %d: %s", i, w.Code, w.Body.String())
		}
	}
	operation.State = recoverymodel.OperationStatePlanned
	operation.Steps = append(operation.Steps, recoverymodel.Step{Name: "planned", Summary: "planned", State: operation.State, At: now.Add(time.Second)})
	w = doRequestWithAuth(t, h, http.MethodPost, "/api/v1/agents/agent-1/recovery/report",
		proxymodel.RecoveryReportEnvelope{Report: proxymodel.RecoveryReport{Operations: []recoverymodel.OperationReport{operation}}}, recoveryAgentToken)
	if w.Code != http.StatusNoContent {
		t.Fatalf("planned report = %d: %s", w.Code, w.Body.String())
	}

	mismatch := operation
	mismatch.Action = recoverymodel.ActionPruneManagedOrphan
	w = doRequestWithAuth(t, h, http.MethodPost, "/api/v1/agents/agent-1/recovery/report",
		proxymodel.RecoveryReportEnvelope{Report: proxymodel.RecoveryReport{Operations: []recoverymodel.OperationReport{mismatch}}}, recoveryAgentToken)
	if w.Code != http.StatusConflict {
		t.Fatalf("action mismatch report = %d, want 409: %s", w.Code, w.Body.String())
	}
	var conflict map[string]string
	if err := json.NewDecoder(w.Body).Decode(&conflict); err != nil || conflict["code"] != "operation_conflict" {
		t.Fatalf("report conflict = %#v, err=%v", conflict, err)
	}
	history, err := database.ListRepairOperations("agent-1", 10)
	if err != nil || len(history) != 1 || history[0].Action != d.ProposedAction || history[0].State != recoverymodel.OperationStatePlanned {
		t.Fatalf("operation after mismatch = %#v, err=%v", history, err)
	}
	entries, _, err := database.ListAuditLog(50, 0)
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]int{}
	for _, entry := range entries {
		if entry.EntityID == operation.OperationID {
			states[entry.Action]++
		}
	}
	if states["detected"] != 1 || states["planned"] != 1 {
		t.Fatalf("operation audits = %#v, want one per transition", states)
	}
}

func TestRepairACKConflictHasStableCode(t *testing.T) {
	srv, database, h, cookie := recoveryFixture(t)
	d := recoveryDiagnostic("agent-1")
	if err := database.UpsertDiagnostic("agent-1", d); err != nil {
		t.Fatal(err)
	}
	if err := database.UpdateAgentRecoveryCapability("agent-1", &recoverymodel.Capability{Stage: 1, Actions: []recoverymodel.Action{d.ProposedAction}}); err != nil {
		t.Fatal(err)
	}
	_, unsub := srv.hub.Subscribe("agent-1")
	defer unsub()
	w := doRequest(t, h, http.MethodPost, "/api/v1/agents/agent-1/repairs", map[string]any{"diagnostic_id": d.ID, "action": d.ProposedAction}, cookie)
	if w.Code != http.StatusAccepted {
		t.Fatalf("create = %d: %s", w.Code, w.Body.String())
	}
	var operation recoverymodel.OperationReport
	if err := json.NewDecoder(w.Body).Decode(&operation); err != nil {
		t.Fatal(err)
	}
	operation.State = recoverymodel.OperationStateApplying
	operation.SnapshotReference = "recovery/" + operation.OperationID
	operation.Steps = append(operation.Steps, recoverymodel.Step{Name: "applying", Summary: "invalid skip", State: operation.State, At: operation.StartedAt.Add(time.Second)})
	w = doRequestWithAuth(t, h, http.MethodPost, "/api/v1/agents/agent-1/repairs/"+operation.OperationID+"/ack", operation, recoveryAgentToken)
	if w.Code != http.StatusConflict {
		t.Fatalf("illegal ack = %d, want 409: %s", w.Code, w.Body.String())
	}
	var conflict map[string]string
	if err := json.NewDecoder(w.Body).Decode(&conflict); err != nil || conflict["code"] != "operation_conflict" {
		t.Fatalf("ack conflict = %#v, err=%v", conflict, err)
	}
}

func TestRepairACKAcceptsAgentSafetyAbortAndPreApplyRollback(t *testing.T) {
	for _, tc := range []struct {
		name     string
		states   []recoverymodel.OperationState
		terminal bool
	}{
		{name: "diagnosis only", states: []recoverymodel.OperationState{recoverymodel.OperationStateDiagnosisOnly}, terminal: true},
		{name: "suppressed", states: []recoverymodel.OperationState{recoverymodel.OperationStateSuppressed}, terminal: true},
		{name: "rollback before apply", states: []recoverymodel.OperationState{recoverymodel.OperationStateSnapshotted, recoverymodel.OperationStateRollingBack}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, database, h, cookie := recoveryFixture(t)
			diagnostic := recoveryDiagnostic("agent-1")
			if err := database.UpsertDiagnostic("agent-1", diagnostic); err != nil {
				t.Fatal(err)
			}
			if err := database.UpdateAgentRecoveryCapability("agent-1", &recoverymodel.Capability{Stage: 1, Actions: []recoverymodel.Action{diagnostic.ProposedAction}}); err != nil {
				t.Fatal(err)
			}
			_, unsubscribe := srv.hub.Subscribe("agent-1")
			defer unsubscribe()
			w := doRequest(t, h, http.MethodPost, "/api/v1/agents/agent-1/repairs", map[string]any{"diagnostic_id": diagnostic.ID, "action": diagnostic.ProposedAction}, cookie)
			if w.Code != http.StatusAccepted {
				t.Fatalf("create = %d: %s", w.Code, w.Body.String())
			}
			var operation recoverymodel.OperationReport
			if err := json.NewDecoder(w.Body).Decode(&operation); err != nil {
				t.Fatal(err)
			}
			for i, state := range tc.states {
				operation.State = state
				if state == recoverymodel.OperationStateSnapshotted {
					operation.SnapshotReference = "recovery/" + operation.OperationID
				}
				at := operation.StartedAt.Add(time.Duration(i+1) * time.Second)
				operation.Steps = append(operation.Steps, recoverymodel.Step{Name: string(state), Summary: "agent safety transition", State: state, At: at})
				if tc.terminal && i == len(tc.states)-1 {
					operation.FinishedAt = &at
				}
				w = doRequestWithAuth(t, h, http.MethodPost, "/api/v1/agents/agent-1/repairs/"+operation.OperationID+"/ack", operation, recoveryAgentToken)
				if w.Code != http.StatusNoContent {
					t.Fatalf("ack %s = %d: %s", state, w.Code, w.Body.String())
				}
			}
		})
	}
}

func TestManualRepairCanValidateAfterRollbackFailedLatch(t *testing.T) {
	srv, database, h, cookie := recoveryFixture(t)
	diagnostic := recoveryDiagnostic("agent-1")
	if err := database.UpsertDiagnostic("agent-1", diagnostic); err != nil {
		t.Fatal(err)
	}
	if err := database.UpdateAgentRecoveryCapability("agent-1", &recoverymodel.Capability{Stage: 1, Actions: []recoverymodel.Action{diagnostic.ProposedAction}}); err != nil {
		t.Fatal(err)
	}
	_, unsubscribe := srv.hub.Subscribe("agent-1")
	defer unsubscribe()
	failure := recoverymodel.OperationReport{
		OperationID: "op-api-rollback-failed", DiagnosticID: diagnostic.ID, Action: diagnostic.ProposedAction,
		Source: recoverymodel.RequestSourceAutomatic, State: recoverymodel.OperationStateDetected, StartedAt: diagnostic.LastSeenAt,
		Steps: []recoverymodel.Step{{Name: "detected", Summary: "detected", State: recoverymodel.OperationStateDetected, At: diagnostic.LastSeenAt}},
	}
	if err := database.CreateRepairOperation("agent-1", failure, diagnostic.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	failure = ackRecoveryState(t, h, failure, recoverymodel.OperationStatePlanned, recoveryAgentToken)
	failure = ackRecoveryState(t, h, failure, recoverymodel.OperationStateSnapshotted, recoveryAgentToken)
	failure = ackRecoveryState(t, h, failure, recoverymodel.OperationStateApplying, recoveryAgentToken)
	failure = ackRecoveryState(t, h, failure, recoverymodel.OperationStateRollingBack, recoveryAgentToken)
	_ = ackRecoveryState(t, h, failure, recoverymodel.OperationStateRollbackFailed, recoveryAgentToken)

	open, err := database.RepairBreakerOpen("agent-1", diagnostic.ProposedAction, diagnostic.ResourceFingerprint, time.Now().UTC())
	if err != nil || !open {
		t.Fatalf("automatic breaker open = %t, err=%v", open, err)
	}
	w := doRequest(t, h, http.MethodPost, "/api/v1/agents/agent-1/repairs", map[string]any{"diagnostic_id": diagnostic.ID, "action": diagnostic.ProposedAction}, cookie)
	if w.Code != http.StatusAccepted {
		t.Fatalf("manual validation repair = %d, want 202: %s", w.Code, w.Body.String())
	}
}

func TestRecoveryReportRejectsDuplicateAndUnboundedDiagnostics(t *testing.T) {
	_, _, h, _ := recoveryFixture(t)
	d := recoveryDiagnostic("agent-1")
	for name, diagnostics := range map[string][]recoverymodel.Diagnostic{
		"duplicate": {d, d},
		"unbounded": func() []recoverymodel.Diagnostic {
			result := make([]recoverymodel.Diagnostic, 501)
			for i := range result {
				result[i] = d
			}
			return result
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			w := doRequestWithAuth(t, h, http.MethodPost, "/api/v1/agents/agent-1/recovery/report",
				proxymodel.RecoveryReportEnvelope{Report: proxymodel.RecoveryReport{Diagnostics: diagnostics}}, recoveryAgentToken)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestRecoveryPolicyInheritanceHeartbeatAndImmediatePublish(t *testing.T) {
	srv, database, h, cookie := recoveryFixture(t)
	ch, unsub := srv.hub.Subscribe("agent-1")
	defer unsub()
	capability := recoverymodel.Capability{Stage: 1, Actions: []recoverymodel.Action{recoverymodel.ActionRemoveManagedTemp}}

	w := doRequestWithAuth(t, h, http.MethodPost, "/api/v1/agents/agent-1/heartbeat", map[string]any{
		"recovery_capability": capability,
	}, recoveryAgentToken)
	if w.Code != http.StatusOK {
		t.Fatalf("heartbeat = %d: %s", w.Code, w.Body.String())
	}
	var heartbeat map[string]any
	if err := json.NewDecoder(w.Body).Decode(&heartbeat); err != nil || heartbeat["safe_auto_repair_effective"] != true {
		t.Fatalf("heartbeat response = %#v, err=%v", heartbeat, err)
	}
	agent, err := database.GetAgent("agent-1")
	if err != nil || agent.RecoveryCapability == nil || agent.RecoveryCapability.Stage != 1 {
		t.Fatalf("stored heartbeat capability = %#v, err=%v", agent, err)
	}

	w = doRequest(t, h, http.MethodPut, "/api/v1/agents/agent-1/safe-auto-repair", map[string]string{"mode": "disabled"}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("disable override = %d: %s", w.Code, w.Body.String())
	}
	assertRecoveryPolicyEvent(t, ch, false)
	w = doRequest(t, h, http.MethodPut, "/api/v1/agents/agent-1/safe-auto-repair", map[string]string{"mode": "disabled", "future": "field"}, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown override field = %d, want 400", w.Code)
	}
	w = doRequest(t, h, http.MethodPut, "/api/v1/agents/agent-1/safe-auto-repair", map[string]string{"mode": "inherit"}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("inherit override = %d: %s", w.Code, w.Body.String())
	}
	assertRecoveryPolicyEvent(t, ch, true)

	w = doRequest(t, h, http.MethodPut, "/api/v1/settings/safe_auto_repair", map[string]string{"value": "false"}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("global disable = %d: %s", w.Code, w.Body.String())
	}
	assertRecoveryPolicyEvent(t, ch, false)
	w = doRequest(t, h, http.MethodPut, "/api/v1/settings/safe_auto_repair", map[string]string{"value": "sometimes"}, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid global policy = %d, want 400", w.Code)
	}
}

func assertRecoveryPolicyEvent(t *testing.T, ch <-chan agenthub.Event, want bool) {
	t.Helper()
	select {
	case event := <-ch:
		if event.Type != agenthub.EventRecoveryPolicy {
			t.Fatalf("event type = %q", event.Type)
		}
		var envelope proxymodel.RecoveryPolicyEnvelope
		if err := json.Unmarshal(event.Data, &envelope); err != nil || envelope.Policy.SafeAutoRepair != want {
			t.Fatalf("policy = %#v, err=%v, want %t", envelope, err, want)
		}
	default:
		t.Fatal("recovery policy event missing")
	}
}

func TestManualRepairCircuitBreakerRejectsFourthRecentFailure(t *testing.T) {
	srv, database, h, cookie := recoveryFixture(t)
	d := recoveryDiagnostic("agent-1")
	if err := database.UpsertDiagnostic("agent-1", d); err != nil {
		t.Fatal(err)
	}
	if err := database.UpdateAgentRecoveryCapability("agent-1", &recoverymodel.Capability{Stage: 1, Actions: []recoverymodel.Action{d.ProposedAction}}); err != nil {
		t.Fatal(err)
	}
	_, unsub := srv.hub.Subscribe("agent-1")
	defer unsub()
	for i := 0; i < 3; i++ {
		w := doRequest(t, h, http.MethodPost, "/api/v1/agents/agent-1/repairs", map[string]any{"diagnostic_id": d.ID, "action": d.ProposedAction}, cookie)
		if w.Code != http.StatusAccepted {
			t.Fatalf("create failure %d = %d: %s", i, w.Code, w.Body.String())
		}
		var operation recoverymodel.OperationReport
		if err := json.NewDecoder(w.Body).Decode(&operation); err != nil {
			t.Fatal(err)
		}
		operation = ackRecoveryState(t, h, operation, recoverymodel.OperationStateSnapshotted, recoveryAgentToken)
		operation = ackRecoveryState(t, h, operation, recoverymodel.OperationStateApplying, recoveryAgentToken)
		operation = ackRecoveryState(t, h, operation, recoverymodel.OperationStateRollingBack, recoveryAgentToken)
		_ = ackRecoveryState(t, h, operation, recoverymodel.OperationStateRolledBack, recoveryAgentToken)
	}
	diagnosticsResponse := doRequest(t, h, http.MethodGet, "/api/v1/agents/agent-1/diagnostics", nil, cookie)
	if diagnosticsResponse.Code != http.StatusOK {
		t.Fatalf("list diagnostics with breaker = %d: %s", diagnosticsResponse.Code, diagnosticsResponse.Body.String())
	}
	var diagnostics []struct {
		ID      string `json:"id"`
		Breaker struct {
			Open      bool       `json:"open"`
			Reason    string     `json:"reason"`
			ExpiresAt *time.Time `json:"expires_at"`
		} `json:"breaker"`
	}
	if err := json.NewDecoder(diagnosticsResponse.Body).Decode(&diagnostics); err != nil {
		t.Fatal(err)
	}
	if len(diagnostics) != 1 || diagnostics[0].ID != d.ID || !diagnostics[0].Breaker.Open ||
		diagnostics[0].Breaker.Reason != "failure_threshold" || diagnostics[0].Breaker.ExpiresAt == nil || !diagnostics[0].Breaker.ExpiresAt.After(time.Now().UTC()) {
		t.Fatalf("diagnostic breaker projection = %#v", diagnostics)
	}
	w := doRequest(t, h, http.MethodPost, "/api/v1/agents/agent-1/repairs", map[string]any{"diagnostic_id": d.ID, "action": d.ProposedAction}, cookie)
	if w.Code != http.StatusConflict {
		t.Fatalf("fourth repair = %d, want 409: %s", w.Code, w.Body.String())
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil || body["code"] != "circuit_breaker_open" {
		t.Fatalf("breaker body = %#v, err=%v", body, err)
	}
}

func ackRecoveryState(t *testing.T, h http.Handler, operation recoverymodel.OperationReport, state recoverymodel.OperationState, token string) recoverymodel.OperationReport {
	t.Helper()
	operation.State = state
	if state == recoverymodel.OperationStateSnapshotted {
		operation.SnapshotReference = "recovery/" + operation.OperationID
	}
	at := operation.StartedAt.Add(time.Duration(len(operation.Steps)) * time.Second)
	operation.Steps = append(operation.Steps, recoverymodel.Step{Name: string(state), Summary: "transition", State: state, At: at})
	if terminalRecoveryState(state) {
		operation.FinishedAt = &at
	}
	w := doRequestWithAuth(t, h, http.MethodPost, "/api/v1/agents/agent-1/repairs/"+operation.OperationID+"/ack", operation, token)
	if w.Code != http.StatusNoContent {
		t.Fatalf("ack %s = %d: %s", state, w.Code, w.Body.String())
	}
	return operation
}

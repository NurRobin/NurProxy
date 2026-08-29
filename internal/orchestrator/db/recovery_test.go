package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

func recoveryTime(second int) time.Time {
	return time.Date(2026, 8, 28, 20, 15, second, 123456789, time.UTC)
}

func testDiagnostic(agentID, fingerprint string) recoverymodel.Diagnostic {
	at := recoveryTime(0)
	return recoverymodel.Diagnostic{
		ID:   recoverymodel.StableDiagnosticID(agentID, recoverymodel.CodeManagedStaleTemp, fingerprint),
		Code: recoverymodel.CodeManagedStaleTemp, Subsystem: "nginx",
		Severity: recoverymodel.SeverityWarning, Ownership: recoverymodel.OwnershipNurProxy,
		Summary: "managed temporary file remains", Evidence: "temporary artifact survived restart",
		AffectedPaths:       []string{"/etc/nginx/sites-available/.nurproxy-app.conf.tmp"},
		ResourceFingerprint: fingerprint, ProposedAction: recoverymodel.ActionRemoveManagedTemp,
		AutoRepairEligible: true, FirstSeenAt: at, LastSeenAt: at, Occurrences: 1,
	}
}

func testOperation(id, diagnosticID string, state recoverymodel.OperationState) recoverymodel.OperationReport {
	report := recoverymodel.OperationReport{
		OperationID: id, DiagnosticID: diagnosticID,
		Action: recoverymodel.ActionRemoveManagedTemp, Source: recoverymodel.RequestSourceAutomatic,
		State: state, StartedAt: recoveryTime(0),
	}
	report.Steps = []recoverymodel.Step{{Name: string(state), Summary: "started", State: state, At: report.StartedAt}}
	return report
}

func TestRecoveryDiagnosticUpsertResolveAndList(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-1")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}

	diag.LastSeenAt = recoveryTime(1)
	diag.Summary = "updated summary"
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetDiagnostic(a.ID, diag.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Occurrences != 2 || got.Summary != "updated summary" || !got.LastSeenAt.Equal(diag.LastSeenAt) || !got.FirstSeenAt.Equal(recoveryTime(0)) {
		t.Fatalf("upserted diagnostic = %#v", got)
	}

	second := testDiagnostic(a.ID, "fp-2")
	second.ID = recoverymodel.StableDiagnosticID(a.ID, second.Code, second.ResourceFingerprint)
	if err := d.UpsertDiagnostic(a.ID, second); err != nil {
		t.Fatal(err)
	}
	if err := d.ResolveMissingDiagnostics(a.ID, []string{diag.ID}, recoveryTime(2)); err != nil {
		t.Fatal(err)
	}
	active, err := d.ListDiagnostics(a.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].ID != diag.ID {
		t.Fatalf("active diagnostics = %#v, want only %s", active, diag.ID)
	}
	all, err := d.ListDiagnostics(a.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("all diagnostics count = %d, want 2", len(all))
	}

	// Seeing a resolved identity again must reactivate it and increment it.
	second.LastSeenAt = recoveryTime(3)
	if err := d.UpsertDiagnostic(a.ID, second); err != nil {
		t.Fatal(err)
	}
	active, err = d.ListDiagnostics(a.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 {
		t.Fatalf("reactivated active count = %d, want 2", len(active))
	}
}

func TestListDiagnosticsForRecoveryViewBoundsResolvedHistory(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	for i := 0; i < 5; i++ {
		diagnostic := testDiagnostic(a.ID, fmt.Sprintf("fp-resolved-%d", i))
		if err := d.UpsertDiagnostic(a.ID, diagnostic); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.ResolveMissingDiagnostics(a.ID, nil, recoveryTime(10)); err != nil {
		t.Fatal(err)
	}
	active := testDiagnostic(a.ID, "fp-active-view")
	if err := d.UpsertDiagnostic(a.ID, active); err != nil {
		t.Fatal(err)
	}

	got, err := d.ListDiagnosticsForRecoveryView(a.ID, 2)
	if err != nil || len(got) != 3 || got[0].ID != active.ID {
		t.Fatalf("bounded diagnostic view = %#v, err=%v", got, err)
	}
	for _, limit := range []int{-1, 201} {
		if _, err := d.ListDiagnosticsForRecoveryView(a.ID, limit); err == nil {
			t.Fatalf("resolved limit %d was accepted", limit)
		}
	}
}

func TestRepairBreakerOpenPersistsOneHourFromThirdClusteredFailure(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-breaker-open")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 29, 4, 0, 0, 0, time.UTC)
	for i, ago := range []time.Duration{70 * time.Minute, 60 * time.Minute, 55 * time.Minute} {
		op := newUserOperation(fmt.Sprintf("op-breaker-%d", i), diag, recoveryTime(i))
		if err := d.CreateRepairOperation(a.ID, op, diag.ResourceFingerprint); err != nil {
			t.Fatal(err)
		}
		op = advanceOperationToTerminal(t, d, a.ID, op, recoverymodel.OperationStateRolledBack)
		if _, err := d.sql.Exec(`UPDATE recovery_operations SET received_at = ? WHERE id = ?`, now.Add(-ago).UnixNano(), op.OperationID); err != nil {
			t.Fatal(err)
		}
	}
	open, err := d.RepairBreakerOpen(a.ID, diag.ProposedAction, diag.ResourceFingerprint, now)
	if err != nil || !open {
		t.Fatalf("breaker open = %t, err=%v, want true", open, err)
	}
	status, err := d.GetRepairBreakerStatus(a.ID, diag.ProposedAction, diag.ResourceFingerprint, now)
	if err != nil || !status.Open || status.Reason != "failure_threshold" || status.ExpiresAt == nil || !status.ExpiresAt.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("breaker status = %#v, err=%v", status, err)
	}
	open, err = d.RepairBreakerOpen(a.ID, diag.ProposedAction, diag.ResourceFingerprint, now.Add(6*time.Minute))
	if err != nil || open {
		t.Fatalf("expired breaker open = %t, err=%v, want false", open, err)
	}
}

func TestRepairBreakerStatusUsesNewestQualifyingFailureAndClosesAtExpiry(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-breaker-extension")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 8, 29, 5, 0, 0, 0, time.UTC)
	for i, minute := range []int{0, 1, 2, 10} {
		op := newUserOperation(fmt.Sprintf("op-extension-%d", i), diag, recoveryTime(i))
		if err := d.CreateRepairOperation(a.ID, op, diag.ResourceFingerprint); err != nil {
			t.Fatal(err)
		}
		op = advanceOperationToTerminal(t, d, a.ID, op, recoverymodel.OperationStateRolledBack)
		if _, err := d.sql.Exec(`UPDATE recovery_operations SET received_at = ? WHERE id = ?`, base.Add(time.Duration(minute)*time.Minute).UnixNano(), op.OperationID); err != nil {
			t.Fatal(err)
		}
	}
	status, err := d.GetRepairBreakerStatus(a.ID, diag.ProposedAction, diag.ResourceFingerprint, base.Add(11*time.Minute))
	wantExpiry := base.Add(70 * time.Minute)
	if err != nil || !status.Open || status.ExpiresAt == nil || !status.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("extended breaker status = %#v, err=%v, want expiry %s", status, err, wantExpiry)
	}
	status, err = d.GetRepairBreakerStatus(a.ID, diag.ProposedAction, diag.ResourceFingerprint, wantExpiry)
	if err != nil || status.Open || status.ExpiresAt != nil {
		t.Fatalf("breaker at expiry = %#v, err=%v, want closed", status, err)
	}
}

func TestRepairBreakerStatusesBatchProjectsActiveKeys(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	base := time.Date(2026, 8, 29, 5, 0, 0, 0, time.UTC)
	threshold := testDiagnostic(a.ID, "fp-batch-threshold")
	latched := testDiagnostic(a.ID, "fp-batch-latched")
	for _, diagnostic := range []recoverymodel.Diagnostic{threshold, latched} {
		if err := d.UpsertDiagnostic(a.ID, diagnostic); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		op := newUserOperation(fmt.Sprintf("op-batch-%d", i), threshold, recoveryTime(i))
		if err := d.CreateRepairOperation(a.ID, op, threshold.ResourceFingerprint); err != nil {
			t.Fatal(err)
		}
		op = advanceOperationToTerminal(t, d, a.ID, op, recoverymodel.OperationStateRolledBack)
		if _, err := d.sql.Exec(`UPDATE recovery_operations SET received_at = ? WHERE id = ?`, base.Add(time.Duration(i)*time.Minute).UnixNano(), op.OperationID); err != nil {
			t.Fatal(err)
		}
	}
	failure := newUserOperation("op-batch-latched", latched, recoveryTime(4))
	if err := d.CreateRepairOperation(a.ID, failure, latched.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	failure = advanceOperationToTerminal(t, d, a.ID, failure, recoverymodel.OperationStateRollbackFailed)
	if _, err := d.sql.Exec(`UPDATE recovery_operations SET received_at = ? WHERE id = ?`, base.Add(3*time.Minute).UnixNano(), failure.OperationID); err != nil {
		t.Fatal(err)
	}

	statuses, err := d.GetRepairBreakerStatuses(a.ID, []recoverymodel.Diagnostic{threshold, latched}, base.Add(4*time.Minute))
	if err != nil || len(statuses) != 2 {
		t.Fatalf("batch statuses = %#v, err=%v", statuses, err)
	}
	thresholdStatus := statuses[RepairBreakerKey{Action: threshold.ProposedAction, ResourceFingerprint: threshold.ResourceFingerprint}]
	latchedStatus := statuses[RepairBreakerKey{Action: latched.ProposedAction, ResourceFingerprint: latched.ResourceFingerprint}]
	if !thresholdStatus.Open || thresholdStatus.Reason != "failure_threshold" || thresholdStatus.ExpiresAt == nil || !thresholdStatus.ExpiresAt.Equal(base.Add(62*time.Minute)) {
		t.Fatalf("threshold batch status = %#v", thresholdStatus)
	}
	if !latchedStatus.Open || latchedStatus.Reason != "rollback_failed_latched" || latchedStatus.ExpiresAt != nil {
		t.Fatalf("latched batch status = %#v", latchedStatus)
	}
}

func TestRepairBreakerStatusesBatchBoundsWholeProjection(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diagnostics := make([]recoverymodel.Diagnostic, maxActiveDiagnosticIDs+200)
	for i := range diagnostics {
		diagnostics[i] = testDiagnostic(a.ID, fmt.Sprintf("fp-batch-bound-%d", i))
	}
	statuses, err := d.GetRepairBreakerStatuses(a.ID, diagnostics, recoveryTime(10))
	if err != nil || len(statuses) != len(diagnostics) {
		t.Fatalf("max bounded batch count = %d, err=%v, want %d", len(statuses), err, len(diagnostics))
	}
	diagnostics = append(diagnostics, testDiagnostic(a.ID, "fp-batch-overflow"))
	if _, err := d.GetRepairBreakerStatuses(a.ID, diagnostics, recoveryTime(10)); err == nil {
		t.Fatal("oversized breaker projection was accepted")
	}
}

func TestRepairBreakerOpenRequiresClusterAndSuccessClears(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-breaker-cluster")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 29, 4, 0, 0, 0, time.UTC)
	for i, ago := range []time.Duration{50 * time.Minute, 30 * time.Minute, 10 * time.Minute} {
		op := newUserOperation(fmt.Sprintf("op-spread-%d", i), diag, recoveryTime(i))
		if err := d.CreateRepairOperation(a.ID, op, diag.ResourceFingerprint); err != nil {
			t.Fatal(err)
		}
		op = advanceOperationToTerminal(t, d, a.ID, op, recoverymodel.OperationStateRolledBack)
		if _, err := d.sql.Exec(`UPDATE recovery_operations SET received_at = ? WHERE id = ?`, now.Add(-ago).UnixNano(), op.OperationID); err != nil {
			t.Fatal(err)
		}
	}
	open, err := d.RepairBreakerOpen(a.ID, diag.ProposedAction, diag.ResourceFingerprint, now)
	if err != nil || open {
		t.Fatalf("spread failures open = %t, err=%v, want false", open, err)
	}

	failure := newUserOperation("op-rollback-failed", diag, recoveryTime(4))
	if err := d.CreateRepairOperation(a.ID, failure, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	failure = advanceOperationToTerminal(t, d, a.ID, failure, recoverymodel.OperationStateRollbackFailed)
	if _, err := d.sql.Exec(`UPDATE recovery_operations SET received_at = ? WHERE id = ?`, now.Add(-2*time.Hour).UnixNano(), failure.OperationID); err != nil {
		t.Fatal(err)
	}
	open, err = d.RepairBreakerOpen(a.ID, diag.ProposedAction, diag.ResourceFingerprint, now)
	if err != nil || !open {
		t.Fatalf("rollback_failed open = %t, err=%v, want true", open, err)
	}
	status, err := d.GetRepairBreakerStatus(a.ID, diag.ProposedAction, diag.ResourceFingerprint, now)
	if err != nil || !status.Open || status.Reason != "rollback_failed_latched" || status.ExpiresAt != nil {
		t.Fatalf("latched breaker status = %#v, err=%v", status, err)
	}

	success := newUserOperation("op-breaker-success", diag, recoveryTime(5))
	if err := d.CreateRepairOperation(a.ID, success, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	success = advanceOperationToTerminal(t, d, a.ID, success, recoverymodel.OperationStateSucceeded)
	if _, err := d.sql.Exec(`UPDATE recovery_operations SET received_at = ? WHERE id = ?`, now.Add(-time.Minute).UnixNano(), success.OperationID); err != nil {
		t.Fatal(err)
	}
	open, err = d.RepairBreakerOpen(a.ID, diag.ProposedAction, diag.ResourceFingerprint, now)
	if err != nil || open {
		t.Fatalf("breaker after success open = %t, err=%v, want false", open, err)
	}
}

func TestRecoveryDiagnosticValidationAndStrictStoredJSON(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-strict")
	diag.Code = "future_code"
	if err := d.UpsertDiagnostic(a.ID, diag); err == nil {
		t.Fatal("invalid diagnostic was persisted")
	}
	diag = testDiagnostic(a.ID, "fp-strict")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	if _, err := d.sql.Exec(`UPDATE recovery_diagnostics SET affected_paths = '["/safe"] {"trailing":true}' WHERE id = ?`, diag.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetDiagnostic(a.ID, diag.ID); err == nil {
		t.Fatal("GetDiagnostic accepted trailing JSON")
	}
}

func TestRecoveryOperationTransitionsIdempotencyAndHistory(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-op")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	op := testOperation("op-1", diag.ID, recoverymodel.OperationStatePlanned)
	op.Source = recoverymodel.RequestSourceUser
	if err := d.CreateRepairOperation(a.ID, op, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	if err := d.AdvanceRepairOperation(a.ID, op); err != nil {
		t.Fatalf("idempotent duplicate of initial state: %v", err)
	}
	if err := d.CreateRepairOperation(a.ID, op, diag.ResourceFingerprint); err != nil {
		t.Fatalf("identical duplicate operation create: %v", err)
	}

	states := []recoverymodel.OperationState{
		recoverymodel.OperationStateSnapshotted,
		recoverymodel.OperationStateApplying,
		recoverymodel.OperationStateValidating,
		recoverymodel.OperationStateSucceeded,
	}
	for i, state := range states {
		op.State = state
		if state == recoverymodel.OperationStateSnapshotted {
			op.SnapshotReference = "recovery/op-1"
		}
		op.Steps = append(op.Steps, recoverymodel.Step{
			Name: string(state), Summary: "completed", State: state, At: recoveryTime(i + 1),
		})
		if state == recoverymodel.OperationStateSucceeded {
			finished := recoveryTime(i + 1)
			op.FinishedAt = &finished
		}
		if err := d.AdvanceRepairOperation(a.ID, op); err != nil {
			t.Fatalf("advance to %s: %v", state, err)
		}
		if err := d.AdvanceRepairOperation(a.ID, op); err != nil {
			t.Fatalf("idempotent duplicate %s: %v", state, err)
		}
	}

	history, err := d.ListRepairOperations(a.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].State != recoverymodel.OperationStateSucceeded || len(history[0].Steps) != len(states)+1 {
		t.Fatalf("operation history = %#v", history)
	}

	illegal := op
	illegal.State = recoverymodel.OperationStateRollingBack
	illegal.FinishedAt = nil
	illegal.Steps = append([]recoverymodel.Step(nil), op.Steps[:3]...)
	illegal.Steps = append(illegal.Steps, recoverymodel.Step{
		Name: string(illegal.State), Summary: "conflicting branch", State: illegal.State, At: recoveryTime(3),
	})
	if err := d.AdvanceRepairOperation(a.ID, illegal); err == nil || !strings.Contains(err.Error(), "illegal") {
		t.Fatalf("terminal regression error = %v, want illegal transition", err)
	}
}

func TestUserRepairAcceptsSafetyAbortAndPreApplyRollbackTransitions(t *testing.T) {
	for _, tc := range []struct {
		name      string
		states    []recoverymodel.OperationState
		terminal  bool
		wantFinal recoverymodel.OperationState
	}{
		{name: "path safety diagnosis only", states: []recoverymodel.OperationState{recoverymodel.OperationStateDiagnosisOnly}, terminal: true, wantFinal: recoverymodel.OperationStateDiagnosisOnly},
		{name: "policy suppression", states: []recoverymodel.OperationState{recoverymodel.OperationStateSuppressed}, terminal: true, wantFinal: recoverymodel.OperationStateSuppressed},
		{name: "snapshot persistence rollback", states: []recoverymodel.OperationState{recoverymodel.OperationStateSnapshotted, recoverymodel.OperationStateRollingBack}, wantFinal: recoverymodel.OperationStateRollingBack},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := testDB(t)
			a := createTestAgent(t, d)
			diagnostic := testDiagnostic(a.ID, "fp-"+strings.ReplaceAll(tc.name, " ", "-"))
			if err := d.UpsertDiagnostic(a.ID, diagnostic); err != nil {
				t.Fatal(err)
			}
			operation := newUserOperation("op-"+strings.ReplaceAll(tc.name, " ", "-"), diagnostic, recoveryTime(0))
			if err := d.CreateRepairOperation(a.ID, operation, diagnostic.ResourceFingerprint); err != nil {
				t.Fatal(err)
			}
			for i, state := range tc.states {
				operation.State = state
				if state == recoverymodel.OperationStateSnapshotted {
					operation.SnapshotReference = "recovery/" + operation.OperationID
				}
				at := recoveryTime(i + 1)
				operation.Steps = append(operation.Steps, recoverymodel.Step{Name: string(state), Summary: "safety transition", State: state, At: at})
				if tc.terminal && i == len(tc.states)-1 {
					operation.FinishedAt = &at
				}
				if err := d.AdvanceRepairOperation(a.ID, operation); err != nil {
					t.Fatalf("advance to %s: %v", state, err)
				}
			}
			stored, err := d.GetRepairOperation(a.ID, operation.OperationID)
			if err != nil || stored.State != tc.wantFinal {
				t.Fatalf("stored operation = %#v, err=%v", stored, err)
			}
		})
	}
}

func TestRollbackFailedLatchRemainsOpenWhileAdmittingExplicitUserRepair(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diagnostic := testDiagnostic(a.ID, "fp-manual-validation")
	if err := d.UpsertDiagnostic(a.ID, diagnostic); err != nil {
		t.Fatal(err)
	}
	failure := newUserOperation("op-rollback-failed-latch", diagnostic, recoveryTime(0))
	if err := d.CreateRepairOperation(a.ID, failure, diagnostic.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	failure = advanceOperationToTerminal(t, d, a.ID, failure, recoverymodel.OperationStateRollbackFailed)
	open, err := d.RepairBreakerOpen(a.ID, diagnostic.ProposedAction, diagnostic.ResourceFingerprint, recoveryTime(10))
	if err != nil || !open {
		t.Fatalf("automatic breaker open = %t, err=%v", open, err)
	}
	latched, err := d.RepairRollbackFailedLatched(a.ID, diagnostic.ProposedAction, diagnostic.ResourceFingerprint)
	if err != nil || !latched {
		t.Fatalf("rollback-failed latch = %t, err=%v", latched, err)
	}
	manual := newUserOperation("op-manual-validation", diagnostic, recoveryTime(11))
	if err := d.CreateRepairOperationIfNoActive(a.ID, manual, diagnostic.ResourceFingerprint); err != nil {
		t.Fatalf("explicit user repair was not admitted: %v", err)
	}
}

func TestGetRepairOperationIsExactlyAgentScoped(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	other := &models.Agent{ID: "agent-other", Name: "Other", FQDN: "other.example.com", Status: models.AgentStatusPending}
	if err := d.CreateAgent(other); err != nil {
		t.Fatal(err)
	}
	diag := testDiagnostic(a.ID, "fp-get-op")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	op := newUserOperation("op-get-exact", diag, recoveryTime(0))
	if err := d.CreateRepairOperation(a.ID, op, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetRepairOperation(a.ID, op.OperationID)
	if err != nil || got.OperationID != op.OperationID || got.State != op.State {
		t.Fatalf("operation = %#v, err=%v", got, err)
	}
	if _, err := d.GetRepairOperation(other.ID, op.OperationID); err == nil {
		t.Fatal("cross-agent operation lookup succeeded")
	}
}

func TestCreateRepairOperationIfNoActiveIsAtomicPerActionAndFingerprint(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	firstDiagnostic := testDiagnostic(a.ID, "fp-active-create")
	secondDiagnostic := firstDiagnostic
	secondDiagnostic.Code = recoverymodel.CodeManagedOrphanConfig
	secondDiagnostic.ID = recoverymodel.StableDiagnosticID(a.ID, secondDiagnostic.Code, secondDiagnostic.ResourceFingerprint)
	if err := d.UpsertDiagnostic(a.ID, firstDiagnostic); err != nil {
		t.Fatal(err)
	}
	if err := d.UpsertDiagnostic(a.ID, secondDiagnostic); err != nil {
		t.Fatal(err)
	}
	first := newUserOperation("op-active-first", firstDiagnostic, recoveryTime(0))
	second := newUserOperation("op-active-second", secondDiagnostic, recoveryTime(1))

	type result struct {
		report recoverymodel.OperationReport
		err    error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for _, operation := range []recoverymodel.OperationReport{first, second} {
		operation := operation
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- result{report: operation, err: d.CreateRepairOperationIfNoActive(a.ID, operation, firstDiagnostic.ResourceFingerprint)}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	var winner, loser recoverymodel.OperationReport
	for got := range results {
		if got.err == nil {
			if winner.OperationID != "" {
				t.Fatal("both competing operations were created")
			}
			winner = got.report
		} else {
			if !errors.Is(got.err, ErrActiveRepairOperation) {
				t.Fatalf("competing create error = %v", got.err)
			}
			loser = got.report
		}
	}
	if winner.OperationID == "" || loser.OperationID == "" {
		t.Fatalf("winner=%q loser=%q", winner.OperationID, loser.OperationID)
	}
	advanceOperationToTerminal(t, d, a.ID, winner, recoverymodel.OperationStateSucceeded)
	if err := d.CreateRepairOperationIfNoActive(a.ID, loser, firstDiagnostic.ResourceFingerprint); err != nil {
		t.Fatalf("operation after terminal predecessor: %v", err)
	}
}

func TestListPendingUserRepairOperationsReturnsOnlyDurablePlannedRequests(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	firstDiagnostic := testDiagnostic(a.ID, "fp-pending-first")
	secondDiagnostic := testDiagnostic(a.ID, "fp-pending-second")
	for _, diagnostic := range []recoverymodel.Diagnostic{firstDiagnostic, secondDiagnostic} {
		if err := d.UpsertDiagnostic(a.ID, diagnostic); err != nil {
			t.Fatal(err)
		}
	}
	pending := newUserOperation("op-pending-user", firstDiagnostic, recoveryTime(0))
	if err := d.CreateRepairOperation(a.ID, pending, firstDiagnostic.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	automatic := testOperation("op-pending-auto", firstDiagnostic.ID, recoverymodel.OperationStateDetected)
	if err := d.CreateRepairOperation(a.ID, automatic, firstDiagnostic.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	progressed := newUserOperation("op-progressed-user", secondDiagnostic, recoveryTime(1))
	if err := d.CreateRepairOperation(a.ID, progressed, secondDiagnostic.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	progressed = advanceOperation(t, d, a.ID, progressed, recoverymodel.OperationStateSnapshotted)

	got, err := d.ListPendingUserRepairOperations(a.ID, 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].OperationID != pending.OperationID {
		t.Fatalf("pending user operations = %#v", got)
	}
}

func TestRecoveryOperationRejectsConflictsInvalidAndCorruptJSON(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-invalid-op")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	op := testOperation("op-invalid", diag.ID, recoverymodel.OperationStatePlanned)
	op.Source = recoverymodel.RequestSourceUser
	op.Action = "shell"
	if err := d.CreateRepairOperation(a.ID, op, diag.ResourceFingerprint); err == nil {
		t.Fatal("invalid operation was persisted")
	}
	op = testOperation("op-corrupt", diag.ID, recoverymodel.OperationStatePlanned)
	op.Source = recoverymodel.RequestSourceUser
	if err := d.CreateRepairOperation(a.ID, op, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	conflict := op
	conflict.State = recoverymodel.OperationStatePlanned
	conflict.ValidationOutcome = "different duplicate payload"
	if err := d.AdvanceRepairOperation(a.ID, conflict); err == nil {
		t.Fatal("conflicting duplicate state was accepted")
	}
	if _, err := d.sql.Exec(`UPDATE recovery_operations SET step_summaries = '[{"name":"x","summary":"ok","state":"planned","at":"2026-08-28T20:15:00Z","future":true}]' WHERE id = ?`, op.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ListRepairOperations(a.ID, 10); err == nil {
		t.Fatal("ListRepairOperations accepted an unknown stored step field")
	}
}

func TestRecoveryOperationCountsRecentRollbackFailures(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-breaker")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	for i, state := range []recoverymodel.OperationState{
		recoverymodel.OperationStateRolledBack,
		recoverymodel.OperationStateRollbackFailed,
	} {
		createFinishedOperation(t, d, a.ID, diag, "op-count-"+string(rune('a'+i)), state, recoveryTime(i))
	}
	count, err := d.CountRecentRepairFailures(a.ID, recoverymodel.ActionRemoveManagedTemp, diag.ResourceFingerprint, recoveryTime(0))
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("recent repair failure count = %d, want 2", count)
	}
}

func TestRecoveryAgentDeleteExplicitlyRemovesRows(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-delete")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	op := testOperation("op-delete", diag.ID, recoverymodel.OperationStatePlanned)
	op.Source = recoverymodel.RequestSourceUser
	if err := d.CreateRepairOperation(a.ID, op, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteAgent(a.ID); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"recovery_diagnostics", "recovery_operations"} {
		var n int
		if err := d.sql.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE agent_id = ?", a.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("%s retained %d rows after agent deletion", table, n)
		}
	}
}

func TestRecoveryLookupMissing(t *testing.T) {
	d := testDB(t)
	if _, err := d.GetDiagnostic("missing-agent", "missing-diagnostic"); err == nil || err == sql.ErrNoRows {
		t.Fatalf("missing diagnostic error = %v", err)
	}
}

func TestRecoveryAggregatesUseDurableBoundedDimensions(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	now := time.Date(2026, 8, 29, 3, 30, 0, 0, time.UTC)

	active := testDiagnostic(a.ID, "fp-metrics-active")
	if err := d.UpsertDiagnostic(a.ID, active); err != nil {
		t.Fatal(err)
	}
	resolved := testDiagnostic(a.ID, "fp-metrics-resolved")
	resolved.Severity = recoverymodel.SeverityError
	resolved.ID = recoverymodel.StableDiagnosticID(a.ID, resolved.Code, resolved.ResourceFingerprint)
	if err := d.UpsertDiagnostic(a.ID, resolved); err != nil {
		t.Fatal(err)
	}
	if err := d.ResolveMissingDiagnostics(a.ID, []string{active.ID}, recoveryTime(2)); err != nil {
		t.Fatal(err)
	}

	succeeded := newUserOperation("op-metrics-success", active, recoveryTime(3))
	if err := d.CreateRepairOperation(a.ID, succeeded, active.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	advanceOperationToTerminal(t, d, a.ID, succeeded, recoverymodel.OperationStateSucceeded)

	inProgress := testOperation("op-metrics-progress", active.ID, recoverymodel.OperationStateDetected)
	if err := d.CreateRepairOperation(a.ID, inProgress, active.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}

	breakerDiagnostic := testDiagnostic(a.ID, "fp-metrics-breaker")
	if err := d.UpsertDiagnostic(a.ID, breakerDiagnostic); err != nil {
		t.Fatal(err)
	}
	failed := newUserOperation("op-metrics-breaker", breakerDiagnostic, recoveryTime(4))
	if err := d.CreateRepairOperation(a.ID, failed, breakerDiagnostic.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	advanceOperationToTerminal(t, d, a.ID, failed, recoverymodel.OperationStateRollbackFailed)

	got, err := d.RecoveryAggregates(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.DiagnosticsActive) != 1 || got.DiagnosticsActive[0].Code != active.Code ||
		got.DiagnosticsActive[0].Severity != active.Severity || got.DiagnosticsActive[0].Ownership != active.Ownership ||
		got.DiagnosticsActive[0].Count != 2 {
		t.Fatalf("active diagnostic aggregates = %#v", got.DiagnosticsActive)
	}
	wantOperations := map[string]int{
		"remove_managed_temp/succeeded/user":       1,
		"remove_managed_temp/rollback_failed/user": 1,
	}
	for _, aggregate := range got.OperationsTotal {
		key := string(aggregate.Action) + "/" + string(aggregate.Outcome) + "/" + string(aggregate.RequestSource)
		if wantOperations[key] != aggregate.Count {
			t.Fatalf("unexpected operation aggregate %#v", aggregate)
		}
		delete(wantOperations, key)
	}
	if len(wantOperations) != 0 {
		t.Fatalf("missing operation aggregates: %#v (all=%#v)", wantOperations, got.OperationsTotal)
	}
	if len(got.OperationsInProgress) != 1 || got.OperationsInProgress[0].Action != active.ProposedAction || got.OperationsInProgress[0].Count != 1 {
		t.Fatalf("in-progress aggregates = %#v", got.OperationsInProgress)
	}
	if len(got.CircuitBreakersOpen) != 1 || got.CircuitBreakersOpen[0].Action != active.ProposedAction || got.CircuitBreakersOpen[0].Count != 1 {
		t.Fatalf("breaker aggregates = %#v", got.CircuitBreakersOpen)
	}
}

func TestRecoveryOperationTotalsSurviveAgentDeletion(t *testing.T) {
	d := testDB(t)
	first := createTestAgent(t, d)
	second := &models.Agent{ID: "agent-2", Name: "Agent Two", FQDN: "agent2.example.com", Status: models.AgentStatusPending}
	if err := d.CreateAgent(second); err != nil {
		t.Fatal(err)
	}

	for i, agent := range []*models.Agent{first, second} {
		diagnostic := testDiagnostic(agent.ID, fmt.Sprintf("fp-total-delete-%d", i))
		if err := d.UpsertDiagnostic(agent.ID, diagnostic); err != nil {
			t.Fatal(err)
		}
		operation := newUserOperation(fmt.Sprintf("op-total-delete-%d", i), diagnostic, recoveryTime(i+10))
		if err := d.CreateRepairOperation(agent.ID, operation, diagnostic.ResourceFingerprint); err != nil {
			t.Fatal(err)
		}
		advanceOperationToTerminal(t, d, agent.ID, operation, recoverymodel.OperationStateSucceeded)
	}

	if got := recoveryOperationTotal(t, d, recoverymodel.ActionRemoveManagedTemp, recoverymodel.OperationStateSucceeded, recoverymodel.RequestSourceUser); got != 2 {
		t.Fatalf("operation total before deletion = %d, want 2", got)
	}
	if err := d.DeleteAgent(first.ID); err != nil {
		t.Fatal(err)
	}
	if got := recoveryOperationTotal(t, d, recoverymodel.ActionRemoveManagedTemp, recoverymodel.OperationStateSucceeded, recoverymodel.RequestSourceUser); got != 2 {
		t.Fatalf("operation total after deletion = %d, want 2", got)
	}
}

func TestRecoveryOperationTotalTerminalReplayCountsOnce(t *testing.T) {
	d := testDB(t)
	agent := createTestAgent(t, d)
	diagnostic := testDiagnostic(agent.ID, "fp-total-replay")
	if err := d.UpsertDiagnostic(agent.ID, diagnostic); err != nil {
		t.Fatal(err)
	}
	operation := newUserOperation("op-total-replay", diagnostic, recoveryTime(20))
	if err := d.CreateRepairOperation(agent.ID, operation, diagnostic.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	terminal := advanceOperationToTerminal(t, d, agent.ID, operation, recoverymodel.OperationStateSucceeded)
	if err := d.AdvanceRepairOperation(agent.ID, terminal); err != nil {
		t.Fatalf("replaying terminal ACK: %v", err)
	}
	if err := d.DeleteAgent(agent.ID); err != nil {
		t.Fatal(err)
	}
	if got := recoveryOperationTotal(t, d, recoverymodel.ActionRemoveManagedTemp, recoverymodel.OperationStateSucceeded, recoverymodel.RequestSourceUser); got != 1 {
		t.Fatalf("operation total after replay and deletion = %d, want 1", got)
	}
}

func TestRecoveryOperationTotalConcurrentTerminalACKCountsOnce(t *testing.T) {
	d := testDB(t)
	agent := createTestAgent(t, d)
	diagnostic := testDiagnostic(agent.ID, "fp-total-concurrent")
	if err := d.UpsertDiagnostic(agent.ID, diagnostic); err != nil {
		t.Fatal(err)
	}
	operation := newUserOperation("op-total-concurrent", diagnostic, recoveryTime(30))
	if err := d.CreateRepairOperation(agent.ID, operation, diagnostic.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	operation = advanceOperation(t, d, agent.ID, operation, recoverymodel.OperationStateSnapshotted)
	operation = advanceOperation(t, d, agent.ID, operation, recoverymodel.OperationStateApplying)
	operation = advanceOperation(t, d, agent.ID, operation, recoverymodel.OperationStateValidating)
	finished := operation.StartedAt.Add(time.Duration(len(operation.Steps)) * time.Second)
	operation.State = recoverymodel.OperationStateSucceeded
	operation.Steps = appendStepAt(operation.Steps, operation.State, finished)
	operation.FinishedAt = &finished

	const acknowledgements = 16
	start := make(chan struct{})
	errs := make(chan error, acknowledgements)
	var wg sync.WaitGroup
	for i := 0; i < acknowledgements; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- d.AdvanceRepairOperation(agent.ID, operation)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent terminal ACK: %v", err)
		}
	}
	if err := d.DeleteAgent(agent.ID); err != nil {
		t.Fatal(err)
	}
	if got := recoveryOperationTotal(t, d, recoverymodel.ActionRemoveManagedTemp, recoverymodel.OperationStateSucceeded, recoverymodel.RequestSourceUser); got != 1 {
		t.Fatalf("operation total after concurrent ACKs and deletion = %d, want 1", got)
	}
}

func recoveryOperationTotal(t *testing.T, d *DB, action recoverymodel.Action, outcome recoverymodel.OperationState, source recoverymodel.RequestSource) int {
	t.Helper()
	aggregates, err := d.RecoveryAggregates(recoveryTime(59))
	if err != nil {
		t.Fatal(err)
	}
	for _, aggregate := range aggregates.OperationsTotal {
		if aggregate.Action == action && aggregate.Outcome == outcome && aggregate.RequestSource == source {
			return aggregate.Count
		}
	}
	return 0
}

func TestRecoveryAggregatesRejectUnknownStoredEnums(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diagnostic := testDiagnostic(a.ID, "fp-metrics-corrupt")
	if err := d.UpsertDiagnostic(a.ID, diagnostic); err != nil {
		t.Fatal(err)
	}
	if _, err := d.sql.Exec(`PRAGMA ignore_check_constraints = ON`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.sql.Exec(`UPDATE recovery_diagnostics SET code = 'attacker-controlled-label' WHERE id = ?`, diagnostic.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.RecoveryAggregates(recoveryTime(5)); err == nil || !strings.Contains(err.Error(), "unknown diagnostic aggregate") {
		t.Fatalf("aggregate corruption error = %v", err)
	}
}

func TestRecoveryAggregatesAreSafeForConcurrentScrapes(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diagnostic := testDiagnostic(a.ID, "fp-metrics-concurrent")
	if err := d.UpsertDiagnostic(a.ID, diagnostic); err != nil {
		t.Fatal(err)
	}

	const scrapes = 16
	start := make(chan struct{})
	errs := make(chan error, scrapes)
	var wg sync.WaitGroup
	for i := 0; i < scrapes; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := d.RecoveryAggregates(recoveryTime(6))
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent aggregate: %v", err)
		}
	}
}

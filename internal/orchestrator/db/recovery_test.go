package db

import (
	"database/sql"
	"fmt"
	"strings"
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
	open, err = d.RepairBreakerOpen(a.ID, diag.ProposedAction, diag.ResourceFingerprint, now.Add(6*time.Minute))
	if err != nil || open {
		t.Fatalf("expired breaker open = %t, err=%v, want false", open, err)
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

func TestCreateRepairOperationIfNoActiveIsAtomicPerDiagnostic(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-active-create")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	first := newUserOperation("op-active-first", diag, recoveryTime(0))
	if err := d.CreateRepairOperationIfNoActive(a.ID, first, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	second := newUserOperation("op-active-second", diag, recoveryTime(1))
	if err := d.CreateRepairOperationIfNoActive(a.ID, second, diag.ResourceFingerprint); err == nil {
		t.Fatal("second active operation was created")
	}
	advanceOperationToTerminal(t, d, a.ID, first, recoverymodel.OperationStateSucceeded)
	if err := d.CreateRepairOperationIfNoActive(a.ID, second, diag.ResourceFingerprint); err != nil {
		t.Fatalf("operation after terminal predecessor: %v", err)
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

package db

import (
	"database/sql"
	"strings"
	"testing"
	"time"

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
	return recoverymodel.OperationReport{
		OperationID: id, DiagnosticID: diagnosticID,
		Action: recoverymodel.ActionRemoveManagedTemp, Source: recoverymodel.RequestSourceAutomatic,
		State: state, StartedAt: recoveryTime(0),
	}
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
	if len(history) != 1 || history[0].State != recoverymodel.OperationStateSucceeded || len(history[0].Steps) != len(states) {
		t.Fatalf("operation history = %#v", history)
	}

	illegal := op
	illegal.State = recoverymodel.OperationStateApplying
	illegal.FinishedAt = nil
	if err := d.AdvanceRepairOperation(a.ID, illegal); err == nil || !strings.Contains(err.Error(), "illegal") {
		t.Fatalf("terminal regression error = %v, want illegal transition", err)
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

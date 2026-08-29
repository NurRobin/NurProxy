package db

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

func TestRecoverySchemaUsesIntegerChronologyForeignKeysAndChecks(t *testing.T) {
	d := testDB(t)
	for table, columns := range map[string][]string{
		"recovery_diagnostics": {"first_seen_at", "last_seen_at", "resolved_at"},
		"recovery_operations":  {"started_at", "created_at", "received_at", "finished_at"},
	} {
		rows, err := d.sql.Query("PRAGMA table_info(" + table + ")")
		if err != nil {
			t.Fatal(err)
		}
		types := map[string]string{}
		for rows.Next() {
			var cid, notNull, pk int
			var name, typ string
			var defaultValue any
			if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
				t.Fatal(err)
			}
			types[name] = strings.ToUpper(typ)
		}
		rows.Close()
		for _, column := range columns {
			if types[column] != "INTEGER" {
				t.Errorf("%s.%s type = %q, want INTEGER", table, column, types[column])
			}
		}
	}

	var diagnosticsSQL, operationsSQL string
	if err := d.sql.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='recovery_diagnostics'`).Scan(&diagnosticsSQL); err != nil {
		t.Fatal(err)
	}
	if err := d.sql.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='recovery_operations'`).Scan(&operationsSQL); err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"REFERENCES agents", "UNIQUE(agent_id, id)", "CHECK"} {
		if !strings.Contains(diagnosticsSQL, fragment) {
			t.Errorf("diagnostics schema lacks %q: %s", fragment, diagnosticsSQL)
		}
	}
	for _, fragment := range []string{"REFERENCES agents", "FOREIGN KEY (agent_id, diagnostic_id)", "CHECK"} {
		if !strings.Contains(operationsSQL, fragment) {
			t.Errorf("operations schema lacks %q: %s", fragment, operationsSQL)
		}
	}
	for _, index := range []string{
		"idx_recovery_diagnostics_agent_active",
		"idx_recovery_diagnostics_agent_seen",
		"idx_recovery_operations_agent_created",
		"idx_recovery_operations_agent_received",
		"idx_recovery_operations_breaker",
	} {
		var found string
		if err := d.sql.QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND name=?`, index).Scan(&found); err != nil {
			t.Errorf("recovery index %s missing: %v", index, err)
		}
	}
	var breakerSQL string
	if err := d.sql.QueryRow(`SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_recovery_operations_breaker'`).Scan(&breakerSQL); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(breakerSQL, "received_at") {
		t.Errorf("breaker index does not use terminal receipt chronology: %s", breakerSQL)
	}
}

func TestRecoveryDiagnosticRejectsUnstableIDAndStaleGenerations(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-generation")
	diag.ID = "diag_caller_chosen"
	if err := d.UpsertDiagnostic(a.ID, diag); err == nil {
		t.Fatal("caller-chosen diagnostic ID was accepted")
	}

	diag = testDiagnostic(a.ID, "fp-generation")
	diag.LastSeenAt = recoveryTime(4)
	diag.Summary = "newest"
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	stale := diag
	stale.LastSeenAt = recoveryTime(3)
	stale.Summary = "stale overwrite"
	if err := d.UpsertDiagnostic(a.ID, stale); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetDiagnostic(a.ID, diag.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary != "newest" || got.Occurrences != 1 || !got.LastSeenAt.Equal(recoveryTime(4)) {
		t.Fatalf("stale report changed diagnostic: %#v", got)
	}

	if err := d.ResolveMissingDiagnostics(a.ID, nil, recoveryTime(6)); err != nil {
		t.Fatal(err)
	}
	delayed := diag
	delayed.LastSeenAt = recoveryTime(5)
	delayed.Summary = "delayed before resolution"
	if err := d.UpsertDiagnostic(a.ID, delayed); err != nil {
		t.Fatal(err)
	}
	active, err := d.ListDiagnostics(a.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if active == nil || len(active) != 0 {
		t.Fatalf("delayed report reopened resolved diagnostic: %#v", active)
	}
	fresh := diag
	fresh.LastSeenAt = recoveryTime(7)
	fresh.Summary = "fresh after resolution"
	if err := d.UpsertDiagnostic(a.ID, fresh); err != nil {
		t.Fatal(err)
	}
	active, err = d.ListDiagnostics(a.ID, false)
	if err != nil || len(active) != 1 || active[0].Summary != fresh.Summary {
		t.Fatalf("fresh report did not reopen diagnostic: %#v, %v", active, err)
	}
}

func TestResolveMissingDiagnosticsValidatesSnapshotAndDoesNotResolveFutureRows(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-future")
	diag.LastSeenAt = recoveryTime(8)
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	if err := d.ResolveMissingDiagnostics(a.ID, nil, recoveryTime(7)); err != nil {
		t.Fatal(err)
	}
	active, err := d.ListDiagnostics(a.ID, false)
	if err != nil || len(active) != 1 {
		t.Fatalf("future diagnostic was resolved: %#v, %v", active, err)
	}
	if err := d.ResolveMissingDiagnostics(a.ID, []string{""}, recoveryTime(9)); err == nil {
		t.Fatal("empty active diagnostic ID was accepted")
	}
	if err := d.ResolveMissingDiagnostics(a.ID, []string{diag.ID, diag.ID}, recoveryTime(9)); err == nil {
		t.Fatal("duplicate active diagnostic IDs were accepted")
	}
	tooMany := make([]string, 501)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("diag_%d", i)
	}
	if err := d.ResolveMissingDiagnostics(a.ID, tooMany, recoveryTime(9)); err == nil {
		t.Fatal("unbounded active diagnostic set was accepted")
	}
}

func TestCreateRepairOperationEnforcesBindingInitialStateAndIdempotency(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-create")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}

	automatic := testOperation("op-auto", diag.ID, recoverymodel.OperationStateDetected)
	if err := d.CreateRepairOperation(a.ID, automatic, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateRepairOperation(a.ID, automatic, diag.ResourceFingerprint); err != nil {
		t.Fatalf("identical duplicate create is not idempotent: %v", err)
	}
	conflict := automatic
	conflict.Error = "different"
	if err := d.CreateRepairOperation(a.ID, conflict, diag.ResourceFingerprint); err == nil {
		t.Fatal("conflicting duplicate create succeeded")
	}

	wrongInitial := testOperation("op-wrong-auto", diag.ID, recoverymodel.OperationStatePlanned)
	if err := d.CreateRepairOperation(a.ID, wrongInitial, diag.ResourceFingerprint); err == nil {
		t.Fatal("automatic operation skipped detected state")
	}
	wrongUser := testOperation("op-wrong-user", diag.ID, recoverymodel.OperationStateDetected)
	wrongUser.Source = recoverymodel.RequestSourceUser
	if err := d.CreateRepairOperation(a.ID, wrongUser, diag.ResourceFingerprint); err == nil {
		t.Fatal("user operation started in detected state")
	}
	user := testOperation("op-user", diag.ID, recoverymodel.OperationStatePlanned)
	user.Source = recoverymodel.RequestSourceUser
	if err := d.CreateRepairOperation(a.ID, user, diag.ResourceFingerprint); err != nil {
		t.Fatalf("valid user operation: %v", err)
	}

	for name, mutate := range map[string]func(*recoverymodel.OperationReport, *string){
		"fingerprint": func(_ *recoverymodel.OperationReport, fp *string) { *fp = "wrong" },
		"action":      func(op *recoverymodel.OperationReport, _ *string) { op.Action = recoverymodel.ActionPruneManagedOrphan },
		"diagnostic":  func(op *recoverymodel.OperationReport, _ *string) { op.DiagnosticID = "diag_missing" },
		"terminal": func(op *recoverymodel.OperationReport, _ *string) {
			op.State = recoverymodel.OperationStateSucceeded
			finished := recoveryTime(1)
			op.FinishedAt = &finished
		},
	} {
		t.Run(name, func(t *testing.T) {
			op := testOperation("op-bad-"+name, diag.ID, recoverymodel.OperationStateDetected)
			fp := diag.ResourceFingerprint
			mutate(&op, &fp)
			if err := d.CreateRepairOperation(a.ID, op, fp); err == nil {
				t.Fatal("invalid operation create succeeded")
			}
		})
	}

	other := &models.Agent{ID: "agent-2", Name: "two", FQDN: "two.example.com", DNSMode: models.DNSModeStatic, Status: models.AgentStatusPending}
	if err := d.CreateAgent(other); err != nil {
		t.Fatal(err)
	}
	cross := testOperation("op-cross", diag.ID, recoverymodel.OperationStateDetected)
	if err := d.CreateRepairOperation(other.ID, cross, diag.ResourceFingerprint); err == nil {
		t.Fatal("cross-agent diagnostic binding succeeded")
	}
}

func TestRecoveryTransitionGraphIsClosed(t *testing.T) {
	states := []recoverymodel.OperationState{
		recoverymodel.OperationStateDetected, recoverymodel.OperationStateDiagnosisOnly,
		recoverymodel.OperationStatePlanned, recoverymodel.OperationStateSnapshotted,
		recoverymodel.OperationStateApplying, recoverymodel.OperationStateValidating,
		recoverymodel.OperationStateSucceeded, recoverymodel.OperationStateRollingBack,
		recoverymodel.OperationStateRolledBack, recoverymodel.OperationStateRollbackFailed,
		recoverymodel.OperationStateSuppressed,
	}
	allowed := map[[2]recoverymodel.OperationState]bool{
		{recoverymodel.OperationStateDetected, recoverymodel.OperationStateDiagnosisOnly}:     true,
		{recoverymodel.OperationStateDetected, recoverymodel.OperationStatePlanned}:           true,
		{recoverymodel.OperationStateDetected, recoverymodel.OperationStateSuppressed}:        true,
		{recoverymodel.OperationStatePlanned, recoverymodel.OperationStateDiagnosisOnly}:      true,
		{recoverymodel.OperationStatePlanned, recoverymodel.OperationStateSuppressed}:         true,
		{recoverymodel.OperationStatePlanned, recoverymodel.OperationStateSnapshotted}:        true,
		{recoverymodel.OperationStateSnapshotted, recoverymodel.OperationStateApplying}:       true,
		{recoverymodel.OperationStateSnapshotted, recoverymodel.OperationStateRollingBack}:    true,
		{recoverymodel.OperationStateApplying, recoverymodel.OperationStateValidating}:        true,
		{recoverymodel.OperationStateApplying, recoverymodel.OperationStateRollingBack}:       true,
		{recoverymodel.OperationStateValidating, recoverymodel.OperationStateSucceeded}:       true,
		{recoverymodel.OperationStateValidating, recoverymodel.OperationStateRollingBack}:     true,
		{recoverymodel.OperationStateRollingBack, recoverymodel.OperationStateRolledBack}:     true,
		{recoverymodel.OperationStateRollingBack, recoverymodel.OperationStateRollbackFailed}: true,
	}
	for _, from := range states {
		for _, to := range states {
			if got, want := legalOperationTransition(from, to), allowed[[2]recoverymodel.OperationState{from, to}]; got != want {
				t.Errorf("transition %s -> %s = %v, want %v", from, to, got, want)
			}
		}
	}
}

func TestAdvanceRepairOperationRequiresAppendOnlyStepsAndImmutableResults(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-append")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	op := testOperation("op-append", diag.ID, recoverymodel.OperationStatePlanned)
	op.Source = recoverymodel.RequestSourceUser
	if err := d.CreateRepairOperation(a.ID, op, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	op.State = recoverymodel.OperationStateSnapshotted
	op.SnapshotReference = "recovery/op-append"
	op.Steps = appendRecoveryStep(op.Steps, op.State, 1)
	if err := d.AdvanceRepairOperation(a.ID, op); err != nil {
		t.Fatal(err)
	}

	cleared := op
	cleared.State = recoverymodel.OperationStateApplying
	cleared.SnapshotReference = ""
	cleared.Steps = appendRecoveryStep(cleared.Steps, cleared.State, 2)
	if err := d.AdvanceRepairOperation(a.ID, cleared); err == nil {
		t.Fatal("snapshot reference was cleared")
	}
	changedPrefix := op
	changedPrefix.State = recoverymodel.OperationStateApplying
	changedPrefix.Steps = appendRecoveryStep(changedPrefix.Steps, changedPrefix.State, 2)
	changedPrefix.Steps[0].Summary = "rewritten history"
	if err := d.AdvanceRepairOperation(a.ID, changedPrefix); err == nil {
		t.Fatal("existing step prefix was rewritten")
	}
	noAppend := op
	noAppend.State = recoverymodel.OperationStateApplying
	if err := d.AdvanceRepairOperation(a.ID, noAppend); err == nil {
		t.Fatal("state advanced without appending a step")
	}

	op.State = recoverymodel.OperationStateApplying
	op.Steps = appendRecoveryStep(op.Steps, op.State, 2)
	if err := d.AdvanceRepairOperation(a.ID, op); err != nil {
		t.Fatal(err)
	}
	op.State = recoverymodel.OperationStateValidating
	op.ValidationOutcome = "valid"
	op.Steps = appendRecoveryStep(op.Steps, op.State, 3)
	if err := d.AdvanceRepairOperation(a.ID, op); err != nil {
		t.Fatal(err)
	}
	changedOutcome := op
	changedOutcome.State = recoverymodel.OperationStateSucceeded
	changedOutcome.ValidationOutcome = "different"
	changedOutcome.Steps = appendRecoveryStep(changedOutcome.Steps, changedOutcome.State, 4)
	finished := recoveryTime(4)
	changedOutcome.FinishedAt = &finished
	if err := d.AdvanceRepairOperation(a.ID, changedOutcome); err == nil {
		t.Fatal("validation outcome was changed")
	}
	missingFinish := op
	missingFinish.State = recoverymodel.OperationStateSucceeded
	missingFinish.Steps = appendRecoveryStep(missingFinish.Steps, missingFinish.State, 4)
	if err := d.AdvanceRepairOperation(a.ID, missingFinish); err == nil {
		t.Fatal("terminal transition without finished_at succeeded")
	}
	unexpectedFinish := op
	unexpectedFinish.State = recoverymodel.OperationStateRollingBack
	unexpectedFinish.Steps = appendRecoveryStep(unexpectedFinish.Steps, unexpectedFinish.State, 4)
	unexpectedFinish.FinishedAt = &finished
	if err := d.AdvanceRepairOperation(a.ID, unexpectedFinish); err == nil {
		t.Fatal("nonterminal transition with finished_at succeeded")
	}
}

func TestListRepairOperationsRejectsStoredLifecycleMismatch(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-stored-lifecycle")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	op := testOperation("op-stored-lifecycle", diag.ID, recoverymodel.OperationStateDetected)
	if err := d.CreateRepairOperation(a.ID, op, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err := d.sql.Exec(`UPDATE recovery_operations SET state = 'succeeded' WHERE id = ?`, op.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ListRepairOperations(a.ID, 10); err == nil {
		t.Fatal("stored terminal operation without finished_at was accepted")
	}
}

func TestRepairBreakerAndHistoryUseOrchestratorChronology(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-chronology")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	states := []recoverymodel.OperationState{
		recoverymodel.OperationStateRolledBack,
		recoverymodel.OperationStateRollbackFailed,
		recoverymodel.OperationStateSucceeded,
		recoverymodel.OperationStateRolledBack,
	}
	for i, state := range states {
		id := fmt.Sprintf("op-chrono-%d", i)
		started := time.Unix(int64(1000-i*500), 0).UTC()
		createFinishedOperation(t, d, a.ID, diag, id, state, started)
		if _, err := d.sql.Exec(`UPDATE recovery_operations SET created_at = ?, received_at = ? WHERE id = ?`, int64(100+i*100), int64(100+i*100), id); err != nil {
			t.Fatal(err)
		}
	}
	count, err := d.CountRecentRepairFailures(a.ID, diag.ProposedAction, diag.ResourceFingerprint, time.Unix(0, 50).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("failures after latest success = %d, want 1", count)
	}
	history, err := d.ListRepairOperations(a.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 4 || history[0].OperationID != "op-chrono-3" {
		t.Fatalf("history is not ordered by orchestrator creation: %#v", history)
	}
}

func TestRecoveryConcurrentUpsertAndDuplicateCreate(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-concurrent")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- d.UpsertDiagnostic(a.ID, diag)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := d.GetDiagnostic(a.ID, diag.ID)
	if err != nil || got.Occurrences != workers+1 {
		t.Fatalf("concurrent occurrences = %v/%v, want %d", got, err, workers+1)
	}

	op := testOperation("op-concurrent", diag.ID, recoverymodel.OperationStateDetected)
	errs = make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- d.CreateRepairOperation(a.ID, op, diag.ResourceFingerprint)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent identical create: %v", err)
		}
	}
}

func TestRecoveryAgentDeleteRollsBackCleanupWhenParentDeleteFails(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-delete-rollback")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	op := testOperation("op-delete-rollback", diag.ID, recoverymodel.OperationStateDetected)
	if err := d.CreateRepairOperation(a.ID, op, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err := d.sql.Exec(`CREATE TRIGGER reject_agent_delete BEFORE DELETE ON agents BEGIN SELECT RAISE(ABORT, 'blocked'); END`); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteAgent(a.ID); err == nil {
		t.Fatal("agent deletion unexpectedly succeeded")
	}
	for _, table := range []string{"recovery_diagnostics", "recovery_operations"} {
		var count int
		if err := d.sql.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE agent_id = ?", a.ID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("%s rows after rollback = %d, want 1", table, count)
		}
	}
}

func appendRecoveryStep(steps []recoverymodel.Step, state recoverymodel.OperationState, second int) []recoverymodel.Step {
	return append(steps, recoverymodel.Step{Name: string(state), Summary: "completed", State: state, At: recoveryTime(second)})
}

func createFinishedOperation(t *testing.T, d *DB, agentID string, diag recoverymodel.Diagnostic, id string, terminal recoverymodel.OperationState, started time.Time) {
	t.Helper()
	op := testOperation(id, diag.ID, recoverymodel.OperationStatePlanned)
	op.Source = recoverymodel.RequestSourceUser
	op.StartedAt = started
	op.Steps = []recoverymodel.Step{{Name: string(op.State), Summary: "started", State: op.State, At: started}}
	if err := d.CreateRepairOperation(agentID, op, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	path := []recoverymodel.OperationState{recoverymodel.OperationStateSnapshotted, recoverymodel.OperationStateApplying}
	if terminal == recoverymodel.OperationStateSucceeded {
		path = append(path, recoverymodel.OperationStateValidating, recoverymodel.OperationStateSucceeded)
	} else {
		path = append(path, recoverymodel.OperationStateRollingBack, terminal)
	}
	for i, state := range path {
		op.State = state
		if state == recoverymodel.OperationStateSnapshotted {
			op.SnapshotReference = "recovery/" + id
		}
		op.Steps = append(op.Steps, recoverymodel.Step{Name: string(state), Summary: "completed", State: state, At: started.Add(time.Duration(i+1) * time.Second)})
		if state == recoverymodel.OperationStateSucceeded || state == recoverymodel.OperationStateRolledBack || state == recoverymodel.OperationStateRollbackFailed {
			finished := started.Add(time.Duration(i+1) * time.Second)
			op.FinishedAt = &finished
		}
		if err := d.AdvanceRepairOperation(agentID, op); err != nil {
			t.Fatalf("advance %s: %v", state, err)
		}
	}
}

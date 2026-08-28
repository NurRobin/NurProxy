package db

import (
	"math"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

func TestRepairBreakerUsesTerminalReceiptOrder(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-terminal-order")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}

	aSuccess := newUserOperation("op-created-first", diag, recoveryTime(0))
	if err := d.CreateRepairOperation(a.ID, aSuccess, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	bFailure := newUserOperation("op-created-second", diag, recoveryTime(1))
	if err := d.CreateRepairOperation(a.ID, bFailure, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	bFailure = advanceOperationToTerminal(t, d, a.ID, bFailure, recoverymodel.OperationStateRolledBack)
	aSuccess = advanceOperationToTerminal(t, d, a.ID, aSuccess, recoverymodel.OperationStateSucceeded)

	since := time.Now().Add(-time.Minute)
	count, err := d.CountRecentRepairFailures(a.ID, diag.ProposedAction, diag.ResourceFingerprint, since)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("failure received before later success ACK = %d, want 0", count)
	}

	late := newUserOperation("op-late-failure", diag, recoveryTime(2))
	if err := d.CreateRepairOperation(a.ID, late, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	advanceOperationToTerminal(t, d, a.ID, late, recoverymodel.OperationStateRollbackFailed)
	count, err = d.CountRecentRepairFailures(a.ID, diag.ProposedAction, diag.ResourceFingerprint, since)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("late failure count = %d, want 1", count)
	}
}

func TestRecoveryUnixNanoRejectsOutOfRangeAndAcceptsBounds(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	minTime := time.Unix(0, math.MinInt64).UTC()
	maxTime := time.Unix(0, math.MaxInt64).UTC()

	within := testDiagnostic(a.ID, "fp-time-bounds")
	within.FirstSeenAt = minTime
	within.LastSeenAt = maxTime
	if err := d.UpsertDiagnostic(a.ID, within); err != nil {
		t.Fatalf("representable diagnostic bounds rejected: %v", err)
	}
	got, err := d.GetDiagnostic(a.ID, within.ID)
	if err != nil || !got.FirstSeenAt.Equal(minTime) || !got.LastSeenAt.Equal(maxTime) {
		t.Fatalf("diagnostic bounds did not round trip: %#v, %v", got, err)
	}

	for name, value := range map[string]time.Time{
		"below minimum": minTime.Add(-time.Nanosecond),
		"above maximum": maxTime.Add(time.Nanosecond),
	} {
		t.Run(name+" diagnostic", func(t *testing.T) {
			diag := testDiagnostic(a.ID, "fp-outside-"+name)
			diag.FirstSeenAt = value
			diag.LastSeenAt = value
			if err := d.UpsertDiagnostic(a.ID, diag); err == nil {
				t.Fatal("out-of-range diagnostic timestamp was accepted")
			}
		})
		t.Run(name+" operation start", func(t *testing.T) {
			op := newUserOperation("op-outside-start-"+name, within, value)
			if err := d.CreateRepairOperation(a.ID, op, within.ResourceFingerprint); err == nil {
				t.Fatal("out-of-range operation start was accepted")
			}
		})
		t.Run(name+" breaker since", func(t *testing.T) {
			if _, err := d.CountRecentRepairFailures(a.ID, within.ProposedAction, within.ResourceFingerprint, value); err == nil {
				t.Fatal("out-of-range breaker boundary was accepted")
			}
		})
	}

	for _, started := range []time.Time{minTime, maxTime} {
		op := newUserOperation("op-bound-"+started.Format("150405.000000000"), within, started)
		if err := d.CreateRepairOperation(a.ID, op, within.ResourceFingerprint); err != nil {
			t.Fatalf("representable operation start rejected: %v", err)
		}
	}
}

func TestRecoveryUnixNanoRejectsOutOfRangeFinishedAt(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-finished-range")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	op := newUserOperation("op-finished-range", diag, recoveryTime(0))
	if err := d.CreateRepairOperation(a.ID, op, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	op = advanceOperation(t, d, a.ID, op, recoverymodel.OperationStateSnapshotted)
	op = advanceOperation(t, d, a.ID, op, recoverymodel.OperationStateApplying)
	op = advanceOperation(t, d, a.ID, op, recoverymodel.OperationStateValidating)
	op.State = recoverymodel.OperationStateSucceeded
	op.Steps = appendStepAt(op.Steps, op.State, recoveryTime(4))
	outside := time.Unix(0, math.MaxInt64).UTC().Add(time.Nanosecond)
	op.FinishedAt = &outside
	if err := d.AdvanceRepairOperation(a.ID, op); err == nil {
		t.Fatal("out-of-range finished_at was accepted")
	}
}

func TestRepairOperationHistoricalReplaysAreIdempotent(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-replay")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	initial := newUserOperation("op-replay", diag, recoveryTime(0))
	if err := d.CreateRepairOperation(a.ID, initial, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	snapshotted := advanceOperation(t, d, a.ID, initial, recoverymodel.OperationStateSnapshotted)
	applying := advanceOperation(t, d, a.ID, snapshotted, recoverymodel.OperationStateApplying)

	if err := d.CreateRepairOperation(a.ID, initial, diag.ResourceFingerprint); err != nil {
		t.Fatalf("initial create replay after applying: %v", err)
	}
	if err := d.AdvanceRepairOperation(a.ID, snapshotted); err != nil {
		t.Fatalf("snapshotted replay after applying: %v", err)
	}

	validating := advanceOperation(t, d, a.ID, applying, recoverymodel.OperationStateValidating)
	succeeded := advanceOperation(t, d, a.ID, validating, recoverymodel.OperationStateSucceeded)
	if err := d.CreateRepairOperation(a.ID, initial, diag.ResourceFingerprint); err != nil {
		t.Fatalf("initial create replay after success: %v", err)
	}
	if err := d.AdvanceRepairOperation(a.ID, snapshotted); err != nil {
		t.Fatalf("snapshotted replay after success: %v", err)
	}
	if err := d.AdvanceRepairOperation(a.ID, succeeded); err != nil {
		t.Fatalf("exact terminal replay: %v", err)
	}

	conflictingPayload := snapshotted
	conflictingPayload.SnapshotReference = "recovery/different"
	if err := d.AdvanceRepairOperation(a.ID, conflictingPayload); err == nil {
		t.Fatal("historical replay with conflicting immutable payload succeeded")
	}
	branch := applying
	branch.State = recoverymodel.OperationStateRollingBack
	branch.Steps = appendStepAt(branch.Steps, branch.State, recoveryTime(3))
	if err := d.AdvanceRepairOperation(a.ID, branch); err == nil {
		t.Fatal("sibling rollback branch replayed over succeeded branch")
	}
}

func TestRepairHistoryBindsInitialStepAdvanceAndSnapshot(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-history-shape")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	valid := newUserOperation("op-history-valid", diag, recoveryTime(0))

	for name, mutate := range map[string]func(*recoverymodel.OperationReport){
		"no initial step": func(op *recoverymodel.OperationReport) { op.Steps = nil },
		"extra initial step": func(op *recoverymodel.OperationReport) {
			op.Steps = appendStepAt(op.Steps, op.State, recoveryTime(1))
		},
		"mismatched initial state": func(op *recoverymodel.OperationReport) {
			op.Steps[0].State = recoverymodel.OperationStateDetected
		},
	} {
		t.Run(name, func(t *testing.T) {
			op := valid
			op.Steps = append([]recoverymodel.Step(nil), valid.Steps...)
			op.OperationID = "op-history-" + name
			mutate(&op)
			if err := d.CreateRepairOperation(a.ID, op, diag.ResourceFingerprint); err == nil {
				t.Fatal("invalid initial history was accepted")
			}
		})
	}

	if err := d.CreateRepairOperation(a.ID, valid, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	missingSnapshot := valid
	missingSnapshot.State = recoverymodel.OperationStateSnapshotted
	missingSnapshot.Steps = appendStepAt(missingSnapshot.Steps, missingSnapshot.State, recoveryTime(1))
	if err := d.AdvanceRepairOperation(a.ID, missingSnapshot); err == nil {
		t.Fatal("snapshotted state without snapshot reference succeeded")
	}
	extraSteps := missingSnapshot
	extraSteps.SnapshotReference = "recovery/op-history-valid"
	extraSteps.Steps = appendStepAt(extraSteps.Steps, extraSteps.State, recoveryTime(2))
	if err := d.AdvanceRepairOperation(a.ID, extraSteps); err == nil {
		t.Fatal("advance appended more than one step")
	}
	mismatched := missingSnapshot
	mismatched.SnapshotReference = "recovery/op-history-valid"
	mismatched.Steps[len(mismatched.Steps)-1].State = recoverymodel.OperationStateApplying
	if err := d.AdvanceRepairOperation(a.ID, mismatched); err == nil {
		t.Fatal("advance step does not match new state")
	}
}

func TestRepairOperationSnapshotReferenceMatchesLifecycle(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-snapshot-lifecycle")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}

	automatic := testOperation("op-auto-snapshot", diag.ID, recoverymodel.OperationStateDetected)
	automatic.SnapshotReference = "recovery/too-early-auto"
	if err := d.CreateRepairOperation(a.ID, automatic, diag.ResourceFingerprint); err == nil {
		t.Fatal("automatic detected create accepted a snapshot reference")
	}
	user := newUserOperation("op-user-snapshot", diag, recoveryTime(0))
	user.SnapshotReference = "recovery/too-early-user"
	if err := d.CreateRepairOperation(a.ID, user, diag.ResourceFingerprint); err == nil {
		t.Fatal("user planned create accepted a snapshot reference")
	}

	for _, terminal := range []recoverymodel.OperationState{
		recoverymodel.OperationStateDiagnosisOnly,
		recoverymodel.OperationStateSuppressed,
	} {
		op := testOperation("op-early-"+string(terminal), diag.ID, recoverymodel.OperationStateDetected)
		if err := d.CreateRepairOperation(a.ID, op, diag.ResourceFingerprint); err != nil {
			t.Fatal(err)
		}
		op.State = terminal
		op.SnapshotReference = "recovery/too-early-" + string(terminal)
		op.Steps = appendStepAt(op.Steps, terminal, recoveryTime(1))
		finished := recoveryTime(1)
		op.FinishedAt = &finished
		if err := d.AdvanceRepairOperation(a.ID, op); err == nil {
			t.Fatalf("%s transition accepted a snapshot reference", terminal)
		}
	}

	automatic = testOperation("op-auto-snapshot-flow", diag.ID, recoverymodel.OperationStateDetected)
	if err := d.CreateRepairOperation(a.ID, automatic, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	automatic.State = recoverymodel.OperationStatePlanned
	automatic.Steps = appendStepAt(automatic.Steps, automatic.State, recoveryTime(1))
	if err := d.AdvanceRepairOperation(a.ID, automatic); err != nil {
		t.Fatal(err)
	}
	tooEarly := automatic
	tooEarly.SnapshotReference = "recovery/planned-too-early"
	if err := d.AdvanceRepairOperation(a.ID, tooEarly); err == nil {
		t.Fatal("planned replay accepted a snapshot reference")
	}
	automatic.State = recoverymodel.OperationStateSnapshotted
	automatic.SnapshotReference = "recovery/op-auto-snapshot-flow"
	automatic.Steps = appendStepAt(automatic.Steps, automatic.State, recoveryTime(2))
	if err := d.AdvanceRepairOperation(a.ID, automatic); err != nil {
		t.Fatalf("snapshotted transition did not accept its first snapshot reference: %v", err)
	}
}

func TestRecoveryCreatedChronologyIsAgentScoped(t *testing.T) {
	d := testDB(t)
	a1 := createTestAgent(t, d)
	d1 := testDiagnostic(a1.ID, "fp-agent-clock-1")
	if err := d.UpsertDiagnostic(a1.ID, d1); err != nil {
		t.Fatal(err)
	}
	op1 := newUserOperation("op-agent-clock-1", d1, recoveryTime(0))
	if err := d.CreateRepairOperation(a1.ID, op1, d1.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour).UnixNano()
	if _, err := d.sql.Exec(`UPDATE recovery_operations SET created_at = ? WHERE id = ?`, future, op1.OperationID); err != nil {
		t.Fatal(err)
	}

	a2 := &models.Agent{ID: "agent-clock-2", Name: "clock two", FQDN: "clock-two.example.com", DNSMode: models.DNSModeStatic, Status: models.AgentStatusPending}
	if err := d.CreateAgent(a2); err != nil {
		t.Fatal(err)
	}
	d2 := testDiagnostic(a2.ID, "fp-agent-clock-2")
	if err := d.UpsertDiagnostic(a2.ID, d2); err != nil {
		t.Fatal(err)
	}
	op2 := newUserOperation("op-agent-clock-2", d2, recoveryTime(0))
	if err := d.CreateRepairOperation(a2.ID, op2, d2.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	var created2 int64
	if err := d.sql.QueryRow(`SELECT created_at FROM recovery_operations WHERE id = ?`, op2.OperationID).Scan(&created2); err != nil {
		t.Fatal(err)
	}
	if created2 >= future {
		t.Fatalf("agent-2 chronology inherited agent-1 future value: %d >= %d", created2, future)
	}
}

func TestRecoveryCreatedChronologyRejectsIntegerOverflow(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-created-overflow")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	first := newUserOperation("op-created-max", diag, recoveryTime(0))
	if err := d.CreateRepairOperation(a.ID, first, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err := d.sql.Exec(`UPDATE recovery_operations SET created_at = ? WHERE id = ?`, int64(math.MaxInt64), first.OperationID); err != nil {
		t.Fatal(err)
	}
	second := newUserOperation("op-created-overflow", diag, recoveryTime(1))
	if err := d.CreateRepairOperation(a.ID, second, diag.ResourceFingerprint); err == nil {
		t.Fatal("operation creation chronology wrapped past MaxInt64")
	}
}

func TestRecoveryReceivedChronologyIsMonotonePerOperation(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-received-monotone")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	op := newUserOperation("op-received-monotone", diag, recoveryTime(0))
	if err := d.CreateRepairOperation(a.ID, op, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour).UnixNano()
	if _, err := d.sql.Exec(`UPDATE recovery_operations SET received_at = ? WHERE id = ?`, future, op.OperationID); err != nil {
		t.Fatal(err)
	}
	advanceOperation(t, d, a.ID, op, recoverymodel.OperationStateSnapshotted)
	var received int64
	if err := d.sql.QueryRow(`SELECT received_at FROM recovery_operations WHERE id = ?`, op.OperationID).Scan(&received); err != nil {
		t.Fatal(err)
	}
	if received != future+1 {
		t.Fatalf("received chronology = %d, want %d", received, future+1)
	}
}

func TestRecoveryReceivedChronologyIsSerializedPerAgent(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-agent-receipts")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	first := newUserOperation("op-agent-receipt-first", diag, recoveryTime(0))
	if err := d.CreateRepairOperation(a.ID, first, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour).UnixNano()
	if _, err := d.sql.Exec(`UPDATE recovery_operations SET received_at = ? WHERE id = ?`, future, first.OperationID); err != nil {
		t.Fatal(err)
	}
	second := newUserOperation("op-agent-receipt-second", diag, recoveryTime(1))
	if err := d.CreateRepairOperation(a.ID, second, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	var received int64
	if err := d.sql.QueryRow(`SELECT received_at FROM recovery_operations WHERE id = ?`, second.OperationID).Scan(&received); err != nil {
		t.Fatal(err)
	}
	if received != future+1 {
		t.Fatalf("second operation receipt = %d, want %d", received, future+1)
	}

	first = advanceOperation(t, d, a.ID, first, recoverymodel.OperationStateSnapshotted)
	if err := d.sql.QueryRow(`SELECT received_at FROM recovery_operations WHERE id = ?`, first.OperationID).Scan(&received); err != nil {
		t.Fatal(err)
	}
	if received != future+2 {
		t.Fatalf("cross-operation advance receipt = %d, want %d", received, future+2)
	}
}

func TestRepairBreakerOrdersTerminalACKsBySerializedAgentReceipt(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	diag := testDiagnostic(a.ID, "fp-serialized-terminal-order")
	if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
		t.Fatal(err)
	}
	success := newUserOperation("op-serialized-success", diag, recoveryTime(0))
	failure := newUserOperation("op-serialized-failure", diag, recoveryTime(1))
	if err := d.CreateRepairOperation(a.ID, success, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateRepairOperation(a.ID, failure, diag.ResourceFingerprint); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour).UnixNano()
	if _, err := d.sql.Exec(`UPDATE recovery_operations SET received_at = ? WHERE id = ?`, future, success.OperationID); err != nil {
		t.Fatal(err)
	}
	success = advanceOperationToTerminal(t, d, a.ID, success, recoverymodel.OperationStateSucceeded)
	failure = advanceOperationToTerminal(t, d, a.ID, failure, recoverymodel.OperationStateRolledBack)

	count, err := d.CountRecentRepairFailures(a.ID, diag.ProposedAction, diag.ResourceFingerprint, time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("failure ACK received after success = %d, want 1", count)
	}
}

func TestRecoveryReceivedChronologyRejectsIntegerOverflow(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		d := testDB(t)
		a := createTestAgent(t, d)
		diag := testDiagnostic(a.ID, "fp-receipt-create-overflow")
		if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
			t.Fatal(err)
		}
		first := newUserOperation("op-receipt-create-max", diag, recoveryTime(0))
		if err := d.CreateRepairOperation(a.ID, first, diag.ResourceFingerprint); err != nil {
			t.Fatal(err)
		}
		if _, err := d.sql.Exec(`UPDATE recovery_operations SET received_at = ? WHERE id = ?`, int64(math.MaxInt64), first.OperationID); err != nil {
			t.Fatal(err)
		}
		second := newUserOperation("op-receipt-create-overflow", diag, recoveryTime(1))
		if err := d.CreateRepairOperation(a.ID, second, diag.ResourceFingerprint); err == nil {
			t.Fatal("operation receipt chronology wrapped during create")
		}
	})

	t.Run("advance", func(t *testing.T) {
		d := testDB(t)
		a := createTestAgent(t, d)
		diag := testDiagnostic(a.ID, "fp-receipt-advance-overflow")
		if err := d.UpsertDiagnostic(a.ID, diag); err != nil {
			t.Fatal(err)
		}
		op := newUserOperation("op-receipt-advance-max", diag, recoveryTime(0))
		if err := d.CreateRepairOperation(a.ID, op, diag.ResourceFingerprint); err != nil {
			t.Fatal(err)
		}
		if _, err := d.sql.Exec(`UPDATE recovery_operations SET received_at = ? WHERE id = ?`, int64(math.MaxInt64), op.OperationID); err != nil {
			t.Fatal(err)
		}
		op.State = recoverymodel.OperationStateSnapshotted
		op.SnapshotReference = "recovery/receipt-advance-max"
		op.Steps = appendStepAt(op.Steps, op.State, recoveryTime(1))
		if err := d.AdvanceRepairOperation(a.ID, op); err == nil {
			t.Fatal("operation receipt chronology wrapped during advance")
		}
	})
}

func newUserOperation(id string, diag recoverymodel.Diagnostic, started time.Time) recoverymodel.OperationReport {
	op := testOperation(id, diag.ID, recoverymodel.OperationStatePlanned)
	op.Source = recoverymodel.RequestSourceUser
	op.StartedAt = started
	op.Steps = []recoverymodel.Step{{Name: string(op.State), Summary: "started", State: op.State, At: started}}
	return op
}

func advanceOperation(t *testing.T, d *DB, agentID string, op recoverymodel.OperationReport, state recoverymodel.OperationState) recoverymodel.OperationReport {
	t.Helper()
	op.State = state
	if state == recoverymodel.OperationStateSnapshotted {
		op.SnapshotReference = "recovery/" + op.OperationID
	}
	at := op.StartedAt.Add(time.Duration(len(op.Steps)) * time.Second)
	op.Steps = appendStepAt(op.Steps, state, at)
	if state == recoverymodel.OperationStateSucceeded || state == recoverymodel.OperationStateRolledBack || state == recoverymodel.OperationStateRollbackFailed || state == recoverymodel.OperationStateDiagnosisOnly || state == recoverymodel.OperationStateSuppressed {
		op.FinishedAt = &at
	}
	if err := d.AdvanceRepairOperation(agentID, op); err != nil {
		t.Fatalf("advance to %s: %v", state, err)
	}
	return op
}

func advanceOperationToTerminal(t *testing.T, d *DB, agentID string, op recoverymodel.OperationReport, terminal recoverymodel.OperationState) recoverymodel.OperationReport {
	t.Helper()
	op = advanceOperation(t, d, agentID, op, recoverymodel.OperationStateSnapshotted)
	op = advanceOperation(t, d, agentID, op, recoverymodel.OperationStateApplying)
	if terminal == recoverymodel.OperationStateSucceeded {
		op = advanceOperation(t, d, agentID, op, recoverymodel.OperationStateValidating)
		return advanceOperation(t, d, agentID, op, terminal)
	}
	op = advanceOperation(t, d, agentID, op, recoverymodel.OperationStateRollingBack)
	return advanceOperation(t, d, agentID, op, terminal)
}

func appendStepAt(steps []recoverymodel.Step, state recoverymodel.OperationState, at time.Time) []recoverymodel.Step {
	return append(steps, recoverymodel.Step{Name: string(state), Summary: "completed", State: state, At: at})
}

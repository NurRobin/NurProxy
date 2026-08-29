package recovery

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

func TestBoundedReporterRetriesAndDeduplicates(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	sent := 0
	r := NewBoundedReporter(4, func(context.Context, proxymodel.RecoveryReport) error {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts < 3 {
			return errors.New("offline")
		}
		sent++
		return nil
	})
	r.SetBackoff(time.Millisecond)
	report := validRecoveryReport("op-1", recoverymodel.OperationStateApplying)
	if !r.Enqueue(report) {
		t.Fatal("valid report rejected")
	}
	if !r.Enqueue(report) {
		t.Fatal("valid report rejected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if !r.Enqueue(report) {
		t.Fatal("completed idempotent report rejected")
	}
	if err := r.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || sent != 1 {
		t.Fatalf("attempts=%d sent=%d", attempts, sent)
	}
}

func TestBoundedReporterRetainsWholeOperationThroughFinalFailure(t *testing.T) {
	var got []proxymodel.RecoveryReport
	r := NewBoundedReporter(1, func(_ context.Context, report proxymodel.RecoveryReport) error { got = append(got, report); return nil })
	for _, state := range []recoverymodel.OperationState{recoverymodel.OperationStateDetected, recoverymodel.OperationStateApplying, recoverymodel.OperationStateRollingBack, recoverymodel.OperationStateRollbackFailed} {
		if !r.Enqueue(validRecoveryReport("failure", state)) {
			t.Fatalf("same-operation state %s rejected", state)
		}
	}
	if r.Enqueue(validRecoveryReport("other", recoverymodel.OperationStateDetected)) {
		t.Fatal("second operation admitted past lane limit")
	}
	if err := r.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got[0].Operations[0].State != recoverymodel.OperationStateDetected || got[3].Operations[0].State != recoverymodel.OperationStateRollbackFailed {
		t.Fatalf("queue=%+v", got)
	}
}

func TestBoundedReporterPermanentFailureDoesNotHeadOfLineBlock(t *testing.T) {
	var got []string
	conflictAttempts := 0
	r := NewBoundedReporter(2, func(_ context.Context, report proxymodel.RecoveryReport) error {
		id := report.Operations[0].OperationID
		if id == "conflict" {
			conflictAttempts++
			return &ReportHTTPError{StatusCode: http.StatusConflict}
		}
		got = append(got, id)
		return nil
	})
	r.Enqueue(validRecoveryReport("conflict", recoverymodel.OperationStateDetected))
	r.Enqueue(validRecoveryReport("healthy", recoverymodel.OperationStateDetected))
	if err := r.Flush(context.Background()); err == nil {
		t.Fatal("permanent conflict was not returned")
	}
	if len(got) != 1 || got[0] != "healthy" {
		t.Fatalf("delivered=%v", got)
	}
	if err := r.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if conflictAttempts != 1 {
		t.Fatalf("quarantined report attempts=%d, want 1", conflictAttempts)
	}
}

func TestBoundedReporterFailureBlocksLaterStatesOfSameOperation(t *testing.T) {
	var states []recoverymodel.OperationState
	r := NewBoundedReporter(1, func(_ context.Context, report proxymodel.RecoveryReport) error {
		state := report.Operations[0].State
		states = append(states, state)
		if state == recoverymodel.OperationStateDetected {
			return errors.New("offline")
		}
		return nil
	})
	r.SetBackoff(time.Millisecond)
	r.Enqueue(validRecoveryReport("ordered", recoverymodel.OperationStateDetected))
	r.Enqueue(validRecoveryReport("ordered", recoverymodel.OperationStateApplying))
	r.Enqueue(validRecoveryReport("ordered", recoverymodel.OperationStateRollbackFailed))
	if err := r.Flush(context.Background()); err == nil {
		t.Fatal("failed initial state was not returned")
	}
	for _, state := range states {
		if state != recoverymodel.OperationStateDetected {
			t.Fatalf("later state %s sent before detected", state)
		}
	}
}

func TestBoundedReporterKeepsAdmissionUntilTerminalDelivered(t *testing.T) {
	r := NewBoundedReporter(1, func(context.Context, proxymodel.RecoveryReport) error { return nil })
	if !r.Enqueue(validRecoveryReport("active", recoverymodel.OperationStateDetected)) {
		t.Fatal("initial state rejected")
	}
	if err := r.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.Enqueue(validRecoveryReport("other", recoverymodel.OperationStateDetected)) {
		t.Fatal("new operation displaced an admitted in-progress operation")
	}
	if !r.Enqueue(validRecoveryReport("active", recoverymodel.OperationStateRollbackFailed)) {
		t.Fatal("terminal state for admitted operation rejected")
	}
	if err := r.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !r.Enqueue(validRecoveryReport("other", recoverymodel.OperationStateDetected)) {
		t.Fatal("lane was not released after terminal delivery")
	}
}

func TestBoundedReporterAlwaysRetainsLatestDiagnosticSnapshot(t *testing.T) {
	r := NewBoundedReporter(1, func(context.Context, proxymodel.RecoveryReport) error { return nil })
	r.Enqueue(validRecoveryReport("active", recoverymodel.OperationStateDetected))
	r.Enqueue(validRecoveryReport("active", recoverymodel.OperationStateApplying))
	if !r.Enqueue(proxymodel.RecoveryReport{Diagnostics: []recoverymodel.Diagnostic{}}) {
		t.Fatal("authoritative resolution snapshot rejected behind operation history")
	}
	if !r.Enqueue(proxymodel.RecoveryReport{Diagnostics: []recoverymodel.Diagnostic{}}) {
		t.Fatal("replacement resolution snapshot rejected")
	}
}

func TestBoundedReporterPreservesDiagnosticOperationResolutionCausality(t *testing.T) {
	var order []string
	r := NewBoundedReporter(2, func(_ context.Context, report proxymodel.RecoveryReport) error {
		switch {
		case len(report.Diagnostics) == 1:
			order = append(order, "diagnostic")
		case len(report.Operations) == 1:
			order = append(order, "operation")
		case report.Diagnostics != nil:
			order = append(order, "resolved")
		}
		return nil
	})
	now := time.Date(2026, 8, 29, 3, 30, 0, 0, time.UTC)
	diagnostic := recoverymodel.Diagnostic{ID: "diag-1", Code: recoverymodel.CodeManagedStaleTemp, Subsystem: "proxy", Severity: recoverymodel.SeverityError, Ownership: recoverymodel.OwnershipNurProxy, Summary: "stale managed temporary file", ResourceFingerprint: "fingerprint", ProposedAction: recoverymodel.ActionRemoveManagedTemp, AutoRepairEligible: true, FirstSeenAt: now, LastSeenAt: now, Occurrences: 1}
	r.Enqueue(proxymodel.RecoveryReport{Diagnostics: []recoverymodel.Diagnostic{diagnostic}})
	r.Enqueue(validRecoveryReport("op-1", recoverymodel.OperationStateDetected))
	r.Enqueue(proxymodel.RecoveryReport{Diagnostics: []recoverymodel.Diagnostic{}})
	if err := r.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(order, ","); got != "diagnostic,operation,resolved" {
		t.Fatalf("delivery order=%s", got)
	}
}

func TestBoundedReporterDiagnosticEpochsAreNeverSentDeduplicated(t *testing.T) {
	var order []string
	r := NewBoundedReporter(2, func(_ context.Context, report proxymodel.RecoveryReport) error {
		if len(report.Diagnostics) == 1 {
			order = append(order, "positive")
		} else {
			order = append(order, "empty")
		}
		return nil
	})
	now := time.Date(2026, 8, 29, 3, 30, 0, 0, time.UTC)
	d := recoverymodel.Diagnostic{ID: "diag-epoch", Code: recoverymodel.CodeManagedStaleTemp, Subsystem: "proxy", Severity: recoverymodel.SeverityError, Ownership: recoverymodel.OwnershipNurProxy, Summary: "stale managed temporary file", ResourceFingerprint: "fingerprint", ProposedAction: recoverymodel.ActionRemoveManagedTemp, AutoRepairEligible: true, FirstSeenAt: now, LastSeenAt: now, Occurrences: 1}
	for _, report := range []proxymodel.RecoveryReport{{Diagnostics: []recoverymodel.Diagnostic{d}}, {Diagnostics: []recoverymodel.Diagnostic{}}, {Diagnostics: []recoverymodel.Diagnostic{d}}, {Diagnostics: []recoverymodel.Diagnostic{}}} {
		if !r.Enqueue(report) {
			t.Fatal("diagnostic epoch rejected")
		}
		if err := r.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := strings.Join(order, ","); got != "positive,empty,positive,empty" {
		t.Fatalf("epochs=%s", got)
	}
}

func TestBoundedReporterRetryKeepsDiagnosticBeforeDependentOperationAndResolution(t *testing.T) {
	var order []string
	failDiagnostic := true
	r := NewBoundedReporter(2, func(_ context.Context, report proxymodel.RecoveryReport) error {
		if len(report.Diagnostics) == 1 {
			if failDiagnostic {
				return errors.New("offline")
			}
			order = append(order, "diagnostic")
		} else if len(report.Operations) == 1 {
			order = append(order, "operation")
		} else {
			order = append(order, "resolved")
		}
		return nil
	})
	r.SetBackoff(time.Millisecond)
	now := time.Date(2026, 8, 29, 3, 30, 0, 0, time.UTC)
	d := recoverymodel.Diagnostic{ID: "diag-1", Code: recoverymodel.CodeManagedStaleTemp, Subsystem: "proxy", Severity: recoverymodel.SeverityError, Ownership: recoverymodel.OwnershipNurProxy, Summary: "stale managed temporary file", ResourceFingerprint: "fingerprint", ProposedAction: recoverymodel.ActionRemoveManagedTemp, AutoRepairEligible: true, FirstSeenAt: now, LastSeenAt: now, Occurrences: 1}
	r.Enqueue(proxymodel.RecoveryReport{Diagnostics: []recoverymodel.Diagnostic{d}})
	r.Enqueue(validRecoveryReport("op-1", recoverymodel.OperationStateDetected))
	r.Enqueue(proxymodel.RecoveryReport{Diagnostics: []recoverymodel.Diagnostic{}})
	if err := r.Flush(context.Background()); err == nil {
		t.Fatal("failed diagnostic was not returned")
	}
	if len(order) != 0 {
		t.Fatalf("dependent reports passed failed diagnostic: %v", order)
	}
	failDiagnostic = false
	if err := r.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(order, ","); got != "diagnostic,operation,resolved" {
		t.Fatalf("delivery order=%s", got)
	}
}

func TestBoundedReporterRejectsUnsanitizedRecords(t *testing.T) {
	r := NewBoundedReporter(2, func(context.Context, proxymodel.RecoveryReport) error { return nil })
	report := validRecoveryReport("op-1", recoverymodel.OperationStateRollbackFailed)
	report.Operations[0].Error = "Authorization: Bearer secret"
	if r.Enqueue(report) {
		t.Fatal("unsanitized report accepted")
	}
}

func TestHTTPReportSenderUsesAgentScopedAuthenticatedEnvelope(t *testing.T) {
	var envelope proxymodel.RecoveryReportEnvelope
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agents/agent-1/recovery/report" || r.Header.Get("Authorization") != "Bearer token" {
			t.Errorf("request=%s auth=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	sender := NewHTTPReportSender(server.URL, "agent-1", "token", server.Client())
	if err := sender(context.Background(), validRecoveryReport("op-http", recoverymodel.OperationStateApplying)); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Report.Operations) != 1 || envelope.Report.Operations[0].OperationID != "op-http" {
		t.Fatalf("envelope=%+v", envelope)
	}
}

func validRecoveryReport(id string, state recoverymodel.OperationState) proxymodel.RecoveryReport {
	now := time.Date(2026, 8, 29, 3, 30, 0, 0, time.UTC)
	finished := now
	op := recoverymodel.OperationReport{OperationID: id, DiagnosticID: "diag-1", Action: recoverymodel.ActionRemoveManagedTemp, Source: recoverymodel.RequestSourceAutomatic, State: state, StartedAt: now}
	if state == recoverymodel.OperationStateSucceeded || state == recoverymodel.OperationStateRolledBack || state == recoverymodel.OperationStateRollbackFailed || state == recoverymodel.OperationStateDiagnosisOnly || state == recoverymodel.OperationStateSuppressed {
		op.FinishedAt = &finished
	}
	return proxymodel.RecoveryReport{Operations: []recoverymodel.OperationReport{op}}
}

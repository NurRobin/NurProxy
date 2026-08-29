package recovery

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
	if !r.Enqueue(report) || !r.Enqueue(report) {
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

func TestBoundedReporterRetainsFinalFailureOverProgress(t *testing.T) {
	var got []proxymodel.RecoveryReport
	r := NewBoundedReporter(2, func(_ context.Context, report proxymodel.RecoveryReport) error { got = append(got, report); return nil })
	r.Enqueue(validRecoveryReport("progress-1", recoverymodel.OperationStateApplying))
	r.Enqueue(validRecoveryReport("progress-2", recoverymodel.OperationStateValidating))
	r.Enqueue(validRecoveryReport("failure", recoverymodel.OperationStateRollbackFailed))
	if err := r.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1].Operations[0].OperationID != "failure" {
		t.Fatalf("queue=%+v", got)
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

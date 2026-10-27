package helper

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

type convergentManagedHandler struct {
	*fakeManagedApplyHandler
	converged bool
	err       error
	checks    int
}

func (h *convergentManagedHandler) Converged(context.Context, helperprotocol.ManagedApplyPlan, helperprotocol.ApplyIntent) (ActionResult, bool, error) {
	h.checks++
	if h.err != nil {
		return ActionResult{}, false, h.err
	}
	return ActionResult{Mutated: false, Validated: true, SanitizedResult: "managed proxy state already converged"}, h.converged, nil
}

func journalEntryCount(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestEngineManagedApplySkipsJournalForConvergedState(t *testing.T) {
	tests := []struct {
		name           string
		converged      bool
		checkErr       error
		preBegin       bool
		wantChecks     int
		wantExecutes   int
		wantOperations int
		wantMessage    string
	}{
		{name: "converged state writes nothing", converged: true, wantChecks: 1, wantMessage: "managed proxy state already converged"},
		{name: "drift runs the journaled transaction", wantChecks: 1, wantExecutes: 1, wantOperations: 1, wantMessage: "managed proxy state applied"},
		{name: "check error falls back to the journaled transaction", checkErr: errors.New("inspect failed"), wantChecks: 1, wantExecutes: 1, wantOperations: 1, wantMessage: "managed proxy state applied"},
		{name: "existing authorized record is resumed, not short-circuited", converged: true, preBegin: true, wantExecutes: 1, wantOperations: 1, wantMessage: "managed proxy state applied"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newEngineFixture(t)
			handler := &convergentManagedHandler{fakeManagedApplyHandler: fixture.managed, converged: tt.converged, err: tt.checkErr}
			if err := fixture.engine.SetManagedApplyHandler(handler); err != nil {
				t.Fatal(err)
			}
			intent := fixture.managedIntent(t)
			planSigned, err := fixture.engine.PlanManagedApply(context.Background(), helperprotocol.PlanManagedApplyRequest{RequestID: "managed-plan-1", Intent: intent})
			if err != nil {
				t.Fatal(err)
			}
			request := fixture.managedExecuteRequest(t, planSigned.Envelope.Payload, intent.Envelope.Payload, nil)
			requestDigest, err := helperprotocol.Digest(request)
			if err != nil {
				t.Fatal(err)
			}
			if tt.preBegin {
				if _, _, err := fixture.journal.BeginOperation(intent.Envelope.Payload.OperationID, request.Payload.Grant.Envelope.Payload.GrantID, requestDigest, helperprotocol.ActionApplyManagedProxyState); err != nil {
					t.Fatal(err)
				}
			}

			receipt, err := fixture.engine.ExecuteManagedApply(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if err := helperprotocol.Verify(fixture.attestationPub, receipt, helperprotocol.MessageHelperReceipt); err != nil {
				t.Fatalf("receipt attestation failed: %v", err)
			}
			payload := receipt.Envelope.Payload
			if payload.State != helperprotocol.JournalSucceeded || payload.OperationID != intent.Envelope.Payload.OperationID ||
				payload.CanonicalRequestDigest != requestDigest || payload.Action != helperprotocol.ActionApplyManagedProxyState ||
				payload.HelperInstanceID != fixture.config.HelperInstanceID || payload.SanitizedResult != tt.wantMessage {
				t.Fatalf("unexpected receipt: %+v", payload)
			}
			if tt.wantOperations == 0 && (payload.RollbackCoverage != helperprotocol.RollbackCoverageNone || payload.SnapshotDigest != "") {
				t.Fatalf("snapshot-free receipt claims rollback coverage: %s %q", payload.RollbackCoverage, payload.SnapshotDigest)
			}
			if handler.checks != tt.wantChecks || handler.executeCount != tt.wantExecutes || handler.prepareCount != tt.wantExecutes {
				t.Fatalf("checks=%d prepare=%d execute=%d", handler.checks, handler.prepareCount, handler.executeCount)
			}
			if got := journalEntryCount(t, fixture.journal.operationsDir); got != tt.wantOperations {
				t.Fatalf("operation records = %d, want %d", got, tt.wantOperations)
			}
			if got := journalEntryCount(t, fixture.journal.grantsDir); got != tt.wantOperations {
				t.Fatalf("grant claims = %d, want %d", got, tt.wantOperations)
			}

			// A retry of the same grant answers the same way and still journals
			// nothing new for a converged state.
			if _, err := fixture.engine.ExecuteManagedApply(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			if got := journalEntryCount(t, fixture.journal.operationsDir); got != tt.wantOperations {
				t.Fatalf("operation records after retry = %d, want %d", got, tt.wantOperations)
			}
			if handler.executeCount != tt.wantExecutes {
				t.Fatalf("retry executed again: %d", handler.executeCount)
			}
		})
	}
}

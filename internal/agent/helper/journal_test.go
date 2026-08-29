package helper

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

func testJournal(t *testing.T) *Journal {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := NewJournal(filepath.Join(parent, "helper-store"), uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func testPlan() helperprotocol.HelperPlan {
	plan := helperprotocol.HelperPlan{
		HelperPlanID:        "plan-1",
		HelperInstanceID:    "helper-1",
		DiagnosticID:        "diagnostic-1",
		Action:              helperprotocol.ActionValidateReloadProxy,
		LogicalTarget:       helperprotocol.LogicalTargetDetectedProxy,
		DisplayPlanHash:     strings.Repeat("a", 64),
		ExecutionPlanHash:   strings.Repeat("b", 64),
		ResourceFingerprint: strings.Repeat("c", 64),
		RollbackCoverage:    helperprotocol.RollbackCoverageFull,
		Steps:               []helperprotocol.PlanStep{{Kind: "validate", Summary: "Validate the detected proxy configuration"}},
		ExpiresAt:           time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}
	plan.DisplayPlanHash, _ = helperprotocol.DisplayPlanDigest(plan)
	return plan
}

func TestJournalPersistsPlansAndRejectsPlanIdentityConflict(t *testing.T) {
	journal := testJournal(t)
	plan := testPlan()
	if err := journal.StorePlan(plan); err != nil {
		t.Fatal(err)
	}
	loaded, err := journal.LoadPlan(plan.HelperPlanID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ExecutionPlanHash != plan.ExecutionPlanHash {
		t.Fatalf("loaded plan = %+v", loaded)
	}
	if err := journal.StorePlan(plan); err != nil {
		t.Fatalf("identical plan retry failed: %v", err)
	}
	plan.ExecutionPlanHash = strings.Repeat("d", 64)
	if err := journal.StorePlan(plan); !errors.Is(err, ErrRequestConflict) {
		t.Fatalf("conflicting plan error = %v, want request conflict", err)
	}
}

func TestJournalBoundsUnexpiredPlansAndKeepsIdempotentRetry(t *testing.T) {
	journal := testJournal(t)
	for i := 0; i < maxStoredPlans; i++ {
		plan := testPlan()
		plan.HelperPlanID = fmt.Sprintf("plan-%03d", i)
		plan.ExpiresAt = time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
		plan.DisplayPlanHash, _ = helperprotocol.DisplayPlanDigest(plan)
		if err := journal.StorePlan(plan); err != nil {
			t.Fatalf("store plan %d: %v", i, err)
		}
	}
	retry := testPlan()
	retry.HelperPlanID = "plan-000"
	retry.ExpiresAt = time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	retry, err := journal.LoadPlan(retry.HelperPlanID)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.StorePlan(retry); err != nil {
		t.Fatalf("idempotent retry at quota: %v", err)
	}
	overflow := testPlan()
	overflow.HelperPlanID = "plan-overflow"
	overflow.ExpiresAt = time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	overflow.DisplayPlanHash, _ = helperprotocol.DisplayPlanDigest(overflow)
	if err := journal.StorePlan(overflow); !errors.Is(err, ErrPlanQuota) {
		t.Fatalf("overflow error = %v, want plan quota", err)
	}
}

func TestJournalMakesExecutionAndGrantReplayIdempotent(t *testing.T) {
	journal := testJournal(t)
	digest := strings.Repeat("a", 64)
	record, existing, err := journal.BeginOperation("op-1", "grant-1", digest, helperprotocol.ActionValidateReloadProxy)
	if err != nil || existing || record.State != helperprotocol.JournalAuthorized {
		t.Fatalf("first begin = (%+v, %t, %v)", record, existing, err)
	}
	record, existing, err = journal.BeginOperation("op-1", "grant-1", digest, helperprotocol.ActionValidateReloadProxy)
	if err != nil || !existing || record.State != helperprotocol.JournalAuthorized {
		t.Fatalf("idempotent begin = (%+v, %t, %v)", record, existing, err)
	}
	if _, _, err := journal.BeginOperation("op-1", "grant-1", strings.Repeat("b", 64), helperprotocol.ActionValidateReloadProxy); !errors.Is(err, ErrRequestConflict) {
		t.Fatalf("same operation with new request error = %v", err)
	}
	if _, _, err := journal.BeginOperation("op-2", "grant-1", digest, helperprotocol.ActionValidateReloadProxy); !errors.Is(err, ErrGrantReplay) {
		t.Fatalf("cross-operation grant replay error = %v", err)
	}
}

func TestJournalTransitionsAndReturnsDurableReceipt(t *testing.T) {
	journal := testJournal(t)
	digest := strings.Repeat("a", 64)
	if _, _, err := journal.BeginOperation("op-1", "grant-1", digest, helperprotocol.ActionValidateReloadProxy); err != nil {
		t.Fatal(err)
	}
	for _, state := range []helperprotocol.JournalState{
		helperprotocol.JournalRunning,
		helperprotocol.JournalMutated,
		helperprotocol.JournalValidated,
		helperprotocol.JournalSucceeded,
	} {
		receipt := helperprotocol.HelperReceipt{
			OperationID:            "op-1",
			CanonicalRequestDigest: digest,
			HelperInstanceID:       "helper-1",
			Action:                 helperprotocol.ActionValidateReloadProxy,
			State:                  state,
			RollbackCoverage:       helperprotocol.RollbackCoverageFull,
			SanitizedResult:        "bounded result",
			UpdatedAt:              time.Now().UTC().Format(time.RFC3339Nano),
		}
		if _, err := journal.Transition("op-1", state, receipt); err != nil {
			t.Fatalf("transition to %s: %v", state, err)
		}
	}
	receipt, err := journal.GetReceipt("op-1", digest)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != helperprotocol.JournalSucceeded {
		t.Fatalf("receipt state = %s", receipt.State)
	}
	if _, err := journal.GetReceipt("op-1", strings.Repeat("b", 64)); !errors.Is(err, ErrRequestConflict) {
		t.Fatalf("mismatched receipt digest error = %v", err)
	}
}

func TestJournalCrashRecoveryMarksUnsafeStatesIndeterminateAndOpensBreaker(t *testing.T) {
	journal := testJournal(t)
	digest := strings.Repeat("a", 64)
	if _, _, err := journal.BeginOperation("op-1", "grant-1", digest, helperprotocol.ActionRestartProxy); err != nil {
		t.Fatal(err)
	}
	receipt := helperprotocol.HelperReceipt{
		OperationID:            "op-1",
		CanonicalRequestDigest: digest,
		HelperInstanceID:       "helper-1",
		Action:                 helperprotocol.ActionRestartProxy,
		State:                  helperprotocol.JournalRunning,
		RollbackCoverage:       helperprotocol.RollbackCoveragePartial,
		SanitizedResult:        "started",
		UpdatedAt:              time.Now().UTC().Format(time.RFC3339Nano),
	}
	if _, err := journal.Transition("op-1", helperprotocol.JournalRunning, receipt); err != nil {
		t.Fatal(err)
	}
	if err := journal.Recover(); err != nil {
		t.Fatal(err)
	}
	if !journal.BreakerOpen() {
		t.Fatal("breaker remained closed after indeterminate execution")
	}
	got, err := journal.GetReceipt("op-1", digest)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != helperprotocol.JournalOutcomeIndeterminate {
		t.Fatalf("recovered state = %s", got.State)
	}
}

func TestJournalCorruptionFailsClosedAndPersistsBreaker(t *testing.T) {
	journal := testJournal(t)
	if err := os.WriteFile(filepath.Join(journal.operationsDir, "corrupt.json"), []byte(`{"state":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := journal.Recover(); !errors.Is(err, ErrJournalCorrupt) {
		t.Fatalf("recover error = %v, want journal corrupt", err)
	}
	if !journal.BreakerOpen() {
		t.Fatal("breaker remained closed after journal corruption")
	}
}

func TestJournalStoresImmutablePrivilegedSnapshot(t *testing.T) {
	journal := testJournal(t)
	value := struct {
		Unit   string `json:"unit"`
		Active bool   `json:"active"`
	}{Unit: "nginx.service", Active: true}
	digest, err := journal.StoreSnapshot("operation-1", value)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := journal.LoadSnapshot("operation-1", digest)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := helperprotocol.Decode[struct {
		Unit   string `json:"unit"`
		Active bool   `json:"active"`
	}](payload)
	if err != nil || decoded.Unit != value.Unit || decoded.Active != value.Active {
		t.Fatalf("unexpected snapshot: %#v, %v", decoded, err)
	}
	changed := value
	changed.Active = false
	if _, err := journal.StoreSnapshot("operation-1", changed); !errors.Is(err, ErrRequestConflict) {
		t.Fatalf("mutable snapshot accepted: %v", err)
	}
}

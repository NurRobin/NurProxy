package helper

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

type seededOperation struct {
	id       string
	action   helperprotocol.Action
	state    helperprotocol.JournalState
	age      time.Duration
	snapshot bool
}

func seedOperations(t *testing.T, journal *Journal, now time.Time, ops []seededOperation) {
	t.Helper()
	write := func(path string, value any) {
		payload, err := helperprotocol.CanonicalBytes(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, op := range ops {
		digest := strings.Repeat("a", 64)
		grantID := "grant-" + op.id
		write(filepath.Join(journal.grantsDir, grantID+".json"), grantClaim{GrantID: grantID, OperationID: op.id, CanonicalRequestDigest: digest})
		updated := now.Add(-op.age).Format(time.RFC3339Nano)
		record := OperationRecord{OperationID: op.id, GrantID: grantID, CanonicalRequestDigest: digest, Action: op.action, State: op.state, UpdatedAt: updated}
		if op.state != helperprotocol.JournalAuthorized {
			record.Receipt = &helperprotocol.HelperReceipt{
				OperationID: op.id, CanonicalRequestDigest: digest, HelperInstanceID: "helper-1", Action: op.action, State: op.state,
				RollbackCoverage: helperprotocol.RollbackCoveragePartial, SanitizedResult: "seeded", UpdatedAt: updated,
			}
		}
		write(filepath.Join(journal.operationsDir, op.id+".json"), record)
		if op.snapshot {
			write(filepath.Join(journal.snapshotsDir, op.id+".json"), map[string]string{"seeded": op.id})
		}
	}
}

func journalFileExists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Lstat(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

// finishedManaged returns count succeeded managed operations, newest first:
// prefix-0000 is base old, every following one a minute older.
func finishedManaged(prefix string, count int, base time.Duration, snapshot bool) []seededOperation {
	return finishedManagedEvery(prefix, count, base, time.Minute, snapshot)
}

func finishedManagedEvery(prefix string, count int, base, step time.Duration, snapshot bool) []seededOperation {
	ops := make([]seededOperation, 0, count)
	for index := range count {
		ops = append(ops, seededOperation{
			id: fmt.Sprintf("%s-%04d", prefix, index), action: helperprotocol.ActionApplyManagedProxyState,
			state: helperprotocol.JournalSucceeded, age: base + time.Duration(index)*step, snapshot: snapshot,
		})
	}
	return ops
}

func TestJournalPruneRetention(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	managed := helperprotocol.ActionApplyManagedProxyState
	n := operationRetentionPerAction
	id := func(prefix string, index int) string { return fmt.Sprintf("%s-%04d", prefix, index) }

	tests := []struct {
		name       string
		ops        []seededOperation
		wantKept   []string
		wantPruned []string
		wantCount  int
	}{
		{
			name:       "keeps last N per action even when all are old",
			ops:        finishedManaged("old", n+2, 30*day, true),
			wantKept:   []string{id("old", 0), id("old", n-1)},
			wantPruned: []string{id("old", n), id("old", n+1)},
			wantCount:  n,
		},
		{
			name: "keeps everything inside the age window beyond N",
			ops: append(finishedManaged("recent", n+5, 2*time.Hour, true),
				seededOperation{id: "ancient", action: managed, state: helperprotocol.JournalSucceeded, age: 40 * day, snapshot: true}),
			wantKept:   []string{id("recent", 0), id("recent", n+4)},
			wantPruned: []string{"ancient"},
			wantCount:  n + 5,
		},
		{
			name: "never prunes non-terminal or incident records",
			ops: append(finishedManaged("old", n, 20*day, false),
				seededOperation{id: "authorized-old", action: managed, state: helperprotocol.JournalAuthorized, age: 90 * day},
				seededOperation{id: "running-old", action: managed, state: helperprotocol.JournalRunning, age: 90 * day, snapshot: true},
				seededOperation{id: "rollback-failed-old", action: managed, state: helperprotocol.JournalRollbackFailed, age: 90 * day, snapshot: true},
				seededOperation{id: "indeterminate-old", action: managed, state: helperprotocol.JournalOutcomeIndeterminate, age: 90 * day},
				seededOperation{id: "rolled-back-old", action: managed, state: helperprotocol.JournalRolledBack, age: 90 * day, snapshot: true},
				seededOperation{id: "failed-old", action: managed, state: helperprotocol.JournalFailedBeforeMutation, age: 90 * day},
			),
			wantKept:   []string{"authorized-old", "running-old", "rollback-failed-old", "indeterminate-old"},
			wantPruned: []string{"rolled-back-old", "failed-old"},
			wantCount:  n + 4,
		},
		{
			name: "retention floor is per action",
			ops: append(finishedManaged("old", n+1, 30*day, false),
				seededOperation{id: "reload-ancient", action: helperprotocol.ActionValidateReloadProxy, state: helperprotocol.JournalSucceeded, age: 300 * day}),
			wantKept:   []string{"reload-ancient", id("old", 0)},
			wantPruned: []string{id("old", n)},
			wantCount:  n + 1,
		},
		{
			name: "missing snapshot is tolerated",
			ops: append(finishedManaged("old", n, 20*day, true),
				seededOperation{id: "no-snapshot", action: managed, state: helperprotocol.JournalSucceeded, age: 31 * day}),
			wantPruned: []string{"no-snapshot"},
			wantCount:  n,
		},
		{
			name: "hard cap trims the age window but spares the newest hour",
			ops: append(finishedManaged("fresh", 20, time.Minute, false),
				finishedManaged("hour", maxRetainedOperations+10, 2*time.Hour, false)...),
			wantKept:   []string{id("fresh", 0), id("fresh", 19), id("hour", 0)},
			wantPruned: []string{id("hour", maxRetainedOperations+9)},
			wantCount:  maxRetainedOperations,
		},
		{
			name:      "hard cap never prunes records younger than the minimum age",
			ops:       finishedManagedEvery("fresh", maxRetainedOperations+10, 0, time.Second, false),
			wantKept:  []string{id("fresh", 0), id("fresh", maxRetainedOperations+9)},
			wantCount: maxRetainedOperations + 10,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			journal := testJournal(t)
			seedOperations(t, journal, now, tt.ops)
			if _, err := journal.Prune(now); err != nil {
				t.Fatal(err)
			}
			for _, kept := range tt.wantKept {
				if !journalFileExists(t, filepath.Join(journal.operationsDir, kept+".json")) ||
					!journalFileExists(t, filepath.Join(journal.grantsDir, "grant-"+kept+".json")) {
					t.Errorf("operation %s or its grant was pruned", kept)
				}
			}
			for _, pruned := range tt.wantPruned {
				for _, path := range []string{
					filepath.Join(journal.operationsDir, pruned+".json"),
					filepath.Join(journal.grantsDir, "grant-"+pruned+".json"),
					filepath.Join(journal.snapshotsDir, pruned+".json"),
				} {
					if journalFileExists(t, path) {
						t.Errorf("%s survived pruning", path)
					}
				}
			}
			entries, err := os.ReadDir(journal.operationsDir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != tt.wantCount {
				t.Errorf("operations left = %d, want %d", len(entries), tt.wantCount)
			}
		})
	}
}

func TestJournalPruneIfDueIsThrottled(t *testing.T) {
	journal := testJournal(t)
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	steps := []struct {
		at      time.Duration
		wantRan bool
	}{
		{at: 0, wantRan: true},
		{at: journalPruneInterval / 2, wantRan: false},
		{at: journalPruneInterval, wantRan: true},
	}
	for _, step := range steps {
		if _, ran, err := journal.PruneIfDue(now.Add(step.at)); err != nil || ran != step.wantRan {
			t.Fatalf("prune at +%s ran=%t err=%v, want ran=%t", step.at, ran, err, step.wantRan)
		}
	}
}

func TestJournalToleratesMissingSnapshots(t *testing.T) {
	now := time.Now().UTC()
	digest := strings.Repeat("a", 64)
	tests := []struct {
		name        string
		state       helperprotocol.JournalState
		wantState   helperprotocol.JournalState
		wantBreaker bool
		wantPruned  bool
	}{
		{name: "succeeded", state: helperprotocol.JournalSucceeded, wantState: helperprotocol.JournalSucceeded, wantPruned: true},
		{name: "rolled back", state: helperprotocol.JournalRolledBack, wantState: helperprotocol.JournalRolledBack, wantPruned: true},
		{name: "interrupted after mutation", state: helperprotocol.JournalMutated, wantState: helperprotocol.JournalOutcomeIndeterminate, wantBreaker: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			journal := testJournal(t)
			ops := append(finishedManaged("newer", operationRetentionPerAction, 20*24*time.Hour, true),
				seededOperation{id: "op-missing", action: helperprotocol.ActionApplyManagedProxyState, state: tt.state, age: 31 * 24 * time.Hour})
			seedOperations(t, journal, now, ops)
			if err := journal.Recover(); err != nil {
				t.Fatalf("recover with missing snapshot: %v", err)
			}
			if journal.BreakerOpen() != tt.wantBreaker {
				t.Fatalf("breaker open = %t, want %t", journal.BreakerOpen(), tt.wantBreaker)
			}
			receipt, err := journal.GetReceipt("op-missing", digest)
			if err != nil || receipt.State != tt.wantState {
				t.Fatalf("receipt = %+v, %v; want state %s", receipt, err, tt.wantState)
			}
			if _, err := journal.LoadSnapshot("op-missing", strings.Repeat("b", 64)); err == nil {
				t.Fatal("missing snapshot loaded")
			}
			if _, err := journal.Prune(now); err != nil {
				t.Fatalf("prune with missing snapshot: %v", err)
			}
			pruned := !journalFileExists(t, filepath.Join(journal.operationsDir, "op-missing.json"))
			if pruned != tt.wantPruned {
				t.Fatalf("operation pruned = %t, want %t", pruned, tt.wantPruned)
			}
			if err := journal.Recover(); err != nil {
				t.Fatalf("recover after prune: %v", err)
			}
		})
	}
}

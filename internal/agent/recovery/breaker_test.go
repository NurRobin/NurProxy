package recovery

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

func TestBreakerOpensAfterThreeFailuresInFifteenMinutesForOneHour(t *testing.T) {
	now := testTime()
	b := NewBreaker()
	key := BreakerKey{Action: recoverymodel.ActionPruneManagedOrphan, Fingerprint: "fp"}
	for i := 0; i < 3; i++ {
		b.Record(key, recoverymodel.OperationStateRolledBack, now.Add(time.Duration(i)*time.Minute), false)
	}
	if decision := b.Allow(key, recoverymodel.RequestSourceAutomatic, now.Add(3*time.Minute)); decision.Allowed || decision.RetryAt != now.Add(62*time.Minute) {
		t.Fatalf("automatic decision = %#v", decision)
	}
	if decision := b.Allow(key, recoverymodel.RequestSourceUser, now.Add(3*time.Minute)); !decision.Allowed {
		t.Fatalf("manual retry should bypass time: %#v", decision)
	}
	if decision := b.Allow(key, recoverymodel.RequestSourceAutomatic, now.Add(63*time.Minute)); !decision.Allowed {
		t.Fatalf("breaker remained open: %#v", decision)
	}
}

func TestBreakerIgnoresFailuresOutsideWindowAndSuccessClears(t *testing.T) {
	now := testTime()
	b := NewBreaker()
	key := BreakerKey{Action: recoverymodel.ActionRemoveManagedTemp, Fingerprint: "fp"}
	b.Record(key, recoverymodel.OperationStateRolledBack, now.Add(-16*time.Minute), false)
	b.Record(key, recoverymodel.OperationStateRollbackFailed, now.Add(-2*time.Minute), false)
	b.Record(key, recoverymodel.OperationStateRolledBack, now.Add(-time.Minute), false)
	if b.Allow(key, recoverymodel.RequestSourceAutomatic, now).Allowed {
		t.Fatal("rollback_failed latch must remain open")
	}
	b.Record(key, recoverymodel.OperationStateSucceeded, now.Add(time.Minute), true)
	if !b.Allow(key, recoverymodel.RequestSourceAutomatic, now.Add(2*time.Minute)).Allowed {
		t.Fatal("successful manual validation did not clear breaker")
	}
}

func TestRollbackFailedBlocksManualUntilSuccessfulManualValidation(t *testing.T) {
	now := testTime()
	b := NewBreaker()
	key := BreakerKey{Action: recoverymodel.ActionRematerializeRuntimeKey, Fingerprint: "fp"}
	b.Record(key, recoverymodel.OperationStateRollbackFailed, now, false)
	if b.Allow(key, recoverymodel.RequestSourceUser, now.Add(2*time.Hour)).Allowed {
		t.Fatal("manual retry bypassed rollback_failed latch")
	}
	b.Record(key, recoverymodel.OperationStateSucceeded, now.Add(3*time.Hour), false)
	if b.Allow(key, recoverymodel.RequestSourceUser, now.Add(3*time.Hour)).Allowed {
		t.Fatal("automatic success cleared rollback_failed latch")
	}
	b.Record(key, recoverymodel.OperationStateSucceeded, now.Add(4*time.Hour), true)
	if !b.Allow(key, recoverymodel.RequestSourceAutomatic, now.Add(4*time.Hour)).Allowed {
		t.Fatal("manual validation did not clear latch")
	}
}

func TestBreakerPersistsWindowAndRollbackFailedLatchAcrossRestart(t *testing.T) {
	root := t.TempDir()
	now := testTime()
	b, err := NewPersistentBreaker(root)
	if err != nil {
		t.Fatal(err)
	}
	windowKey := BreakerKey{Action: recoverymodel.ActionRemoveManagedTemp, Fingerprint: "window"}
	for i := 0; i < 3; i++ {
		if err := b.Record(windowKey, recoverymodel.OperationStateRolledBack, now.Add(time.Duration(i)*time.Minute), false); err != nil {
			t.Fatal(err)
		}
	}
	latchKey := BreakerKey{Action: recoverymodel.ActionRematerializeRuntimeKey, Fingerprint: "latch"}
	if err := b.Record(latchKey, recoverymodel.OperationStateRollbackFailed, now, false); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewPersistentBreaker(root)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Allow(windowKey, recoverymodel.RequestSourceAutomatic, now.Add(3*time.Minute)).Allowed {
		t.Fatal("time breaker lost across restart")
	}
	if restarted.Allow(latchKey, recoverymodel.RequestSourceUser, now.Add(2*time.Hour)).Allowed {
		t.Fatal("rollback_failed latch lost across restart")
	}
}

func TestBreakerPersistsAfterFailedManualRetry(t *testing.T) {
	root := t.TempDir()
	now := testTime()
	b, err := NewPersistentBreaker(root)
	if err != nil {
		t.Fatal(err)
	}
	key := BreakerKey{Action: recoverymodel.ActionRemoveManagedTemp, Fingerprint: "manual"}
	for i := 0; i < 4; i++ {
		if err := b.Record(key, recoverymodel.OperationStateRolledBack, now.Add(time.Duration(i)*time.Minute), false); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := NewPersistentBreaker(root); err != nil {
		t.Fatalf("failed manual retry made durable breaker unreadable: %v", err)
	}
}

func TestPersistentBreakerAtomicallyReplacesStateSymlinkWithoutFollowingIt(t *testing.T) {
	root := t.TempDir()
	b, err := NewPersistentBreaker(root)
	if err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(root, "external")
	if err := os.WriteFile(external, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, "recovery", breakerFilename)
	if err := os.Symlink(external, statePath); err != nil {
		t.Fatal(err)
	}
	key := BreakerKey{Action: recoverymodel.ActionRemoveManagedTemp, Fingerprint: "nofollow"}
	if err := b.Record(key, recoverymodel.OperationStateRolledBack, testTime(), false); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(external)
	if err != nil || string(got) != "sentinel" {
		t.Fatalf("breaker followed state symlink: %q, %v", got, err)
	}
	assertMode(t, statePath, 0o600)
	matches, err := filepath.Glob(filepath.Join(root, "recovery", ".nurproxy-atomic-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("breaker temp files remain: %v, %v", matches, err)
	}
}

func testTime() time.Time { return time.Date(2026, 8, 29, 1, 0, 0, 0, time.UTC) }

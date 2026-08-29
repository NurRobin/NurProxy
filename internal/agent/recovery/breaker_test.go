package recovery

import (
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

func testTime() time.Time { return time.Date(2026, 8, 29, 1, 0, 0, 0, time.UTC) }

package ratelimit

import (
	"testing"
	"time"
)

// newAt returns a limiter with a controllable clock for deterministic tests.
func newAt(max int, window, lockout time.Duration, clock *time.Time) *Limiter {
	l := New(max, window, lockout)
	l.now = func() time.Time { return *clock }
	return l
}

func TestLimiter_locksOutAfterMaxFailures(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newAt(3, time.Minute, 5*time.Minute, &now)

	for i := 0; i < 2; i++ {
		l.Fail("1.2.3.4")
		if ok, _ := l.Allow("1.2.3.4"); !ok {
			t.Fatalf("should still be allowed after %d failures", i+1)
		}
	}
	// 3rd failure hits the threshold → locked.
	l.Fail("1.2.3.4")
	ok, retry := l.Allow("1.2.3.4")
	if ok {
		t.Fatal("expected lockout after max failures")
	}
	if retry <= 0 || retry > 5*time.Minute {
		t.Errorf("retry-after = %v, want (0, 5m]", retry)
	}

	// A different key is unaffected.
	if ok, _ := l.Allow("9.9.9.9"); !ok {
		t.Error("unrelated key should not be locked")
	}
}

func TestLimiter_unlocksAfterLockout(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newAt(2, time.Minute, 5*time.Minute, &now)

	l.Fail("ip")
	l.Fail("ip")
	if ok, _ := l.Allow("ip"); ok {
		t.Fatal("expected lockout")
	}

	now = now.Add(5*time.Minute + time.Second)
	if ok, _ := l.Allow("ip"); !ok {
		t.Fatal("expected unlock after lockout elapsed")
	}
}

func TestLimiter_windowResetsFailureCount(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newAt(3, time.Minute, 5*time.Minute, &now)

	l.Fail("ip")
	l.Fail("ip")
	// Window elapses before the 3rd failure → count resets, no lockout.
	now = now.Add(2 * time.Minute)
	l.Fail("ip")
	if ok, _ := l.Allow("ip"); !ok {
		t.Fatal("failures spread beyond the window must not lock out")
	}
}

func TestLimiter_resetClearsState(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newAt(2, time.Minute, 5*time.Minute, &now)
	l.Fail("ip")
	l.Reset("ip")
	l.Fail("ip") // counts as the first failure again
	if ok, _ := l.Allow("ip"); !ok {
		t.Fatal("after reset, a single failure must not lock out")
	}
}

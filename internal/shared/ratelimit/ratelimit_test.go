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

// TestLimiter_failsClosedAtCap proves that once the key cap is reached and no
// entries are expirable, a flooding key is still tracked and locked out instead
// of slipping past the check (the old behavior returned early, fail-open).
func TestLimiter_failsClosedAtCap(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newAt(3, time.Minute, 5*time.Minute, &now)
	l.maxKeys = 4

	// Fill the map to capacity with keys that are kept active (within window) so
	// pruning frees nothing: each gets a single recent failure.
	for _, k := range []string{"a", "b", "c", "d"} {
		l.Fail(k)
	}
	if got := len(l.entries); got != 4 {
		t.Fatalf("map size = %d, want 4 (at cap)", got)
	}

	// A brand-new flooding key must still be tracked and lockable past the cap.
	attacker := "attacker"
	for i := 0; i < 3; i++ {
		l.Fail(attacker)
	}
	if ok, retry := l.Allow(attacker); ok {
		t.Fatal("flooding key past the cap must be locked out (fail-closed)")
	} else if retry <= 0 || retry > 5*time.Minute {
		t.Errorf("retry-after = %v, want (0, 5m]", retry)
	}

	// Memory stays bounded: eviction kept the map at the cap.
	if got := len(l.entries); got > l.maxKeys {
		t.Errorf("map size = %d, exceeds cap %d", got, l.maxKeys)
	}
}

// TestLimiter_floodCannotEvictLockedVictim proves that a distinct-key flood
// cannot free a legitimately locked-out victim by evicting it to make room.
// Under the old eviction (earliest windowStart, ignoring lockout state) the
// victim — whose windowStart is the oldest — would be the first evicted, and its
// next Allow() would return true: a lockout bypass. Eviction must skip active
// lockouts, and when every slot is locked the new flooding key is declined
// (fail-closed) rather than freeing a victim.
func TestLimiter_floodCannotEvictLockedVictim(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newAt(3, time.Minute, 5*time.Minute, &now)
	l.maxKeys = 4

	// Victim locks out first, so it carries the earliest windowStart.
	victim := "victim"
	for i := 0; i < 3; i++ {
		l.Fail(victim)
	}
	if ok, _ := l.Allow(victim); ok {
		t.Fatal("victim should be locked out")
	}

	// Sustained distinct-key flood to (and past) the cap. Each flood key also
	// locks out, so every slot becomes an active lockout.
	now = now.Add(time.Second)
	for i := 0; i < 50; i++ {
		k := "flood-" + time.Duration(i).String()
		for j := 0; j < 3; j++ {
			l.Fail(k)
		}
		// The victim must stay locked throughout the flood.
		if ok, _ := l.Allow(victim); ok {
			t.Fatalf("victim lockout was bypassed by flood at iteration %d", i)
		}
		// Memory stays bounded regardless.
		if got := len(l.entries); got > l.maxKeys {
			t.Fatalf("map size = %d at iteration %d, exceeds cap %d", got, i, l.maxKeys)
		}
	}

	// Final assertion: victim is still locked after the whole flood.
	if ok, retry := l.Allow(victim); ok {
		t.Fatal("victim must remain locked out after sustained distinct-key flood")
	} else if retry <= 0 || retry > 5*time.Minute {
		t.Errorf("victim retry-after = %v, want (0, 5m]", retry)
	}
}

// TestLimiter_prunesExpiredAtCap proves expired entries are reclaimed when the
// map is full, so legitimate growth stays bounded without evicting active keys.
func TestLimiter_prunesExpiredAtCap(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newAt(3, time.Minute, 5*time.Minute, &now)
	l.maxKeys = 4

	for _, k := range []string{"a", "b", "c", "d"} {
		l.Fail(k)
	}
	if got := len(l.entries); got != 4 {
		t.Fatalf("map size = %d, want 4", got)
	}

	// Let every tracked entry's window elapse so they become prunable.
	now = now.Add(2 * time.Minute)

	// A new key triggers a prune that reclaims all expired entries before adding.
	l.Fail("fresh")
	if got := len(l.entries); got != 1 {
		t.Fatalf("map size = %d, want 1 after expired entries pruned", got)
	}
	// The reclaimed-from key is no longer tracked.
	if _, ok := l.entries["a"]; ok {
		t.Error("expired entry should have been pruned")
	}
}

// TestLimiter_evictionKeepsMemoryBounded floods far past the cap with distinct
// keys and asserts the map never grows beyond maxKeys.
func TestLimiter_evictionKeepsMemoryBounded(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newAt(3, time.Minute, 5*time.Minute, &now)
	l.maxKeys = 8

	for i := 0; i < 1000; i++ {
		l.Fail(string(rune('a'+i%26)) + time.Duration(i).String())
		if got := len(l.entries); got > l.maxKeys {
			t.Fatalf("map size = %d at iteration %d, exceeds cap %d", got, i, l.maxKeys)
		}
	}
}

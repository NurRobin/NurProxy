// Package ratelimit provides a small per-key failed-attempt limiter with
// lockout, used to blunt online brute-force attacks against credential checks
// (admin login, API-key auth). It is dependency-free and safe for concurrent
// use.
//
// Usage pattern at a call site that verifies a secret:
//
//	if ok, retryAfter := lim.Allow(key); !ok { // reject with 429 + Retry-After }
//	if !verify(secret) { lim.Fail(key); // reject }
//	lim.Reset(key) // success
package ratelimit

import (
	"sync"
	"time"
)

// Limiter counts failures per key over a sliding window and blocks a key for a
// lockout period once the failure threshold is reached.
type Limiter struct {
	mu      sync.Mutex
	entries map[string]*entry
	max     int           // failures within window before lockout
	window  time.Duration // window over which failures accumulate
	lockout time.Duration // how long a key is blocked once max is hit
	maxKeys int           // hard cap on tracked keys, bounding memory
	now     func() time.Time
}

type entry struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
}

// New returns a Limiter that locks a key out for lockout once it accumulates max
// failures within window. maxKeys bounds memory under a distributed flood: when
// the map is full, expired entries are pruned first, and if that frees nothing
// the oldest entry is evicted to make room. Enforcement is never skipped, so a
// flooding key is still tracked and locked out (fail-closed) rather than slipping
// past the check.
func New(max int, window, lockout time.Duration) *Limiter {
	return &Limiter{
		entries: make(map[string]*entry),
		max:     max,
		window:  window,
		lockout: lockout,
		maxKeys: 10000,
		now:     time.Now,
	}
}

// Allow reports whether key may attempt now. When blocked it also returns the
// remaining lockout duration (for a Retry-After hint).
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil {
		return true, 0
	}
	now := l.now()
	if e.lockedUntil.After(now) {
		return false, e.lockedUntil.Sub(now)
	}
	return true, 0
}

// Fail records a failed attempt for key, arming a lockout once the threshold is
// reached within the window.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()

	e := l.entries[key]
	if e == nil {
		if len(l.entries) >= l.maxKeys {
			l.pruneLocked(now)
		}
		if len(l.entries) >= l.maxKeys {
			// Pruning expired entries freed nothing (every tracked key is still
			// active). Evict the oldest UNLOCKED entry to make room rather than
			// skipping the check: a flooding key must still be tracked and lockable
			// (fail-closed). If every entry is locked out, that is itself an active
			// attack: keep the lockouts (a distinct-key flood must not be able to
			// free a locked victim) and decline the new key instead.
			if !l.evictOldestUnlockedLocked(now) {
				return
			}
		}
		e = &entry{windowStart: now}
		l.entries[key] = e
	}

	// Reset the count if the window has elapsed since it started.
	if now.Sub(e.windowStart) > l.window {
		e.failures = 0
		e.windowStart = now
	}
	e.failures++
	if e.failures >= l.max {
		e.lockedUntil = now.Add(l.lockout)
		// Start a fresh window after the lockout arms, so post-lockout attempts
		// get the full allowance again rather than re-locking on the next miss.
		e.failures = 0
		e.windowStart = now
	}
}

// Reset clears any failure state for key (call on a successful auth).
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// pruneLocked drops entries that are neither locked nor within an active window.
// Caller must hold l.mu.
func (l *Limiter) pruneLocked(now time.Time) {
	for k, e := range l.entries {
		if e.lockedUntil.After(now) {
			continue
		}
		if now.Sub(e.windowStart) <= l.window {
			continue
		}
		delete(l.entries, k)
	}
}

// evictOldestUnlockedLocked removes the entry with the earliest windowStart
// among entries that are NOT currently locked out, freeing a slot when the map
// is full and nothing is prunable. It returns true if an entry was evicted.
//
// Actively locked-out entries are skipped on purpose: under the distributed-flood
// threat model this limiter targets, an attacker spraying many distinct keys must
// not be able to evict a legitimately locked-out victim and thereby clear the
// victim's lockout. If every entry is locked (an active attack), nothing is
// evicted and false is returned, so the caller declines the new key (fail-closed)
// rather than freeing a locked victim. Caller must hold l.mu.
func (l *Limiter) evictOldestUnlockedLocked(now time.Time) bool {
	var oldestKey string
	var oldest time.Time
	found := false
	for k, e := range l.entries {
		if e.lockedUntil.After(now) {
			continue // never evict an active lockout
		}
		if !found || e.windowStart.Before(oldest) {
			oldestKey = k
			oldest = e.windowStart
			found = true
		}
	}
	if found {
		delete(l.entries, oldestKey)
	}
	return found
}

package recovery

import (
	"sync"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

const (
	breakerWindow   = 15 * time.Minute
	breakerOpenTime = time.Hour
	breakerFailures = 3
)

type BreakerKey struct {
	Action      recoverymodel.Action
	Fingerprint string
}

type BreakerDecision struct {
	Allowed bool
	RetryAt time.Time
	Reason  string
}

type breakerState struct {
	failures       []time.Time
	openedAt       time.Time
	rollbackFailed bool
}

type Breaker struct {
	mu     sync.Mutex
	states map[BreakerKey]*breakerState
}

func NewBreaker() *Breaker { return &Breaker{states: make(map[BreakerKey]*breakerState)} }

func (b *Breaker) Allow(key BreakerKey, source recoverymodel.RequestSource, now time.Time) BreakerDecision {
	if b == nil || !key.Action.Valid() || !validOpaqueID(key.Fingerprint) || !source.Valid() || now.IsZero() {
		return BreakerDecision{Reason: "invalid breaker input"}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	state := b.states[key]
	if state == nil {
		return BreakerDecision{Allowed: true}
	}
	state.compact(now)
	if state.rollbackFailed {
		return BreakerDecision{Reason: "rollback_failed requires successful manual validation"}
	}
	if !state.openedAt.IsZero() {
		retryAt := state.openedAt.Add(breakerOpenTime)
		if now.Before(retryAt) && source == recoverymodel.RequestSourceAutomatic {
			return BreakerDecision{RetryAt: retryAt, Reason: "circuit breaker open"}
		}
		if !now.Before(retryAt) {
			state.openedAt = time.Time{}
			state.failures = nil
		}
	}
	return BreakerDecision{Allowed: true}
}

func (b *Breaker) Record(key BreakerKey, outcome recoverymodel.OperationState, at time.Time, successfulManualValidation bool) {
	if b == nil || !key.Action.Valid() || !validOpaqueID(key.Fingerprint) || at.IsZero() {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	state := b.states[key]
	if state == nil {
		state = &breakerState{}
		b.states[key] = state
	}
	if outcome == recoverymodel.OperationStateSucceeded {
		if !state.rollbackFailed || successfulManualValidation {
			delete(b.states, key)
		}
		return
	}
	if outcome != recoverymodel.OperationStateRolledBack && outcome != recoverymodel.OperationStateRollbackFailed {
		return
	}
	state.compact(at)
	state.failures = append(state.failures, at)
	if outcome == recoverymodel.OperationStateRollbackFailed {
		state.rollbackFailed = true
	}
	if len(state.failures) >= breakerFailures {
		state.openedAt = at
	}
}

func (s *breakerState) compact(now time.Time) {
	cutoff := now.Add(-breakerWindow)
	kept := s.failures[:0]
	for _, failure := range s.failures {
		if !failure.Before(cutoff) && !failure.After(now) {
			kept = append(kept, failure)
		}
	}
	s.failures = kept
}

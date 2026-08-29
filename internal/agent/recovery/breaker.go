package recovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
	"golang.org/x/sys/unix"
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
	dir    *os.File
}

func NewBreaker() *Breaker { return &Breaker{states: make(map[BreakerKey]*breakerState)} }

const breakerFilename = "breakers.json"

type breakerDiskEntry struct {
	Action         recoverymodel.Action `json:"action"`
	Fingerprint    string               `json:"fingerprint"`
	Failures       []time.Time          `json:"failures"`
	OpenedAt       time.Time            `json:"opened_at,omitempty"`
	RollbackFailed bool                 `json:"rollback_failed"`
}

type breakerDisk struct {
	Version int                `json:"version"`
	Entries []breakerDiskEntry `json:"entries"`
}

func NewPersistentBreaker(agentDataDir string) (*Breaker, error) {
	if !safeAbsoluteCleanPath(agentDataDir) {
		return nil, fmt.Errorf("agent data directory must be an absolute clean path")
	}
	recoveryDir := filepath.Join(agentDataDir, "recovery")
	if err := mkdirPrivate(recoveryDir); err != nil {
		return nil, err
	}
	dir, err := openDirNoSymlinks(recoveryDir)
	if err != nil {
		return nil, err
	}
	b := &Breaker{states: make(map[BreakerKey]*breakerState), dir: dir}
	raw, err := readRegularAt(dir, breakerFilename, 0o600)
	if errors.Is(err, unix.ENOENT) {
		return b, nil
	}
	if err != nil {
		dir.Close()
		return nil, fmt.Errorf("read breaker state: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var disk breakerDisk
	if err := decoder.Decode(&disk); err != nil {
		dir.Close()
		return nil, fmt.Errorf("decode breaker state: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		dir.Close()
		return nil, fmt.Errorf("breaker state has trailing data")
	}
	if disk.Version != 1 || len(disk.Entries) > 10000 {
		dir.Close()
		return nil, fmt.Errorf("invalid breaker state")
	}
	for _, entry := range disk.Entries {
		key := BreakerKey{Action: entry.Action, Fingerprint: entry.Fingerprint}
		if !key.Action.Valid() || !validOpaqueID(key.Fingerprint) || len(entry.Failures) > breakerFailures || b.states[key] != nil {
			dir.Close()
			return nil, fmt.Errorf("invalid breaker entry")
		}
		for i, failure := range entry.Failures {
			if failure.IsZero() || (i > 0 && failure.Before(entry.Failures[i-1])) {
				dir.Close()
				return nil, fmt.Errorf("invalid breaker failure history")
			}
		}
		if !entry.OpenedAt.IsZero() && len(entry.Failures) < breakerFailures {
			dir.Close()
			return nil, fmt.Errorf("invalid open breaker")
		}
		b.states[key] = &breakerState{failures: append([]time.Time(nil), entry.Failures...), openedAt: entry.OpenedAt, rollbackFailed: entry.RollbackFailed}
	}
	return b, nil
}

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

func (b *Breaker) Record(key BreakerKey, outcome recoverymodel.OperationState, at time.Time, successfulManualValidation bool) error {
	if b == nil || !key.Action.Valid() || !validOpaqueID(key.Fingerprint) || at.IsZero() {
		return fmt.Errorf("invalid breaker input")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	before := cloneBreakerStates(b.states)
	state := b.states[key]
	if state == nil {
		state = &breakerState{}
		b.states[key] = state
	}
	if outcome == recoverymodel.OperationStateSucceeded {
		if !state.rollbackFailed || successfulManualValidation {
			delete(b.states, key)
		}
		return b.persistOrRestore(before)
	}
	if outcome != recoverymodel.OperationStateRolledBack && outcome != recoverymodel.OperationStateRollbackFailed {
		return nil
	}
	state.compact(at)
	state.failures = append(state.failures, at)
	if len(state.failures) > breakerFailures {
		state.failures = append([]time.Time(nil), state.failures[len(state.failures)-breakerFailures:]...)
	}
	if outcome == recoverymodel.OperationStateRollbackFailed {
		state.rollbackFailed = true
	}
	if len(state.failures) >= breakerFailures {
		state.openedAt = at
	}
	return b.persistOrRestore(before)
}

func (b *Breaker) persistOrRestore(before map[BreakerKey]*breakerState) error {
	if b.dir == nil {
		return nil
	}
	entries := make([]breakerDiskEntry, 0, len(b.states))
	for key, state := range b.states {
		entries = append(entries, breakerDiskEntry{Action: key.Action, Fingerprint: key.Fingerprint, Failures: append([]time.Time(nil), state.failures...), OpenedAt: state.openedAt, RollbackFailed: state.rollbackFailed})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Action != entries[j].Action {
			return entries[i].Action < entries[j].Action
		}
		return entries[i].Fingerprint < entries[j].Fingerprint
	})
	raw, err := json.Marshal(breakerDisk{Version: 1, Entries: entries})
	if err == nil {
		err = atomicWriteAt(b.dir, breakerFilename, raw, 0o600)
	}
	if err != nil {
		b.states = before
		return fmt.Errorf("persist breaker state: %w", err)
	}
	return nil
}

func cloneBreakerStates(states map[BreakerKey]*breakerState) map[BreakerKey]*breakerState {
	result := make(map[BreakerKey]*breakerState, len(states))
	for key, state := range states {
		result[key] = &breakerState{failures: append([]time.Time(nil), state.failures...), openedAt: state.openedAt, rollbackFailed: state.rollbackFailed}
	}
	return result
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

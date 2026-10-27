package recovery

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

func TestTransitionRejectsSkippedOrStaleState(t *testing.T) {
	if !ValidTransition(recoverymodel.OperationStatePlanned, recoverymodel.OperationStateSnapshotted) {
		t.Fatal("planned -> snapshotted rejected")
	}
	if ValidTransition(recoverymodel.OperationStatePlanned, recoverymodel.OperationStateApplying) {
		t.Fatal("skipped snapshot accepted")
	}
	if ValidTransition(recoverymodel.OperationStateSucceeded, recoverymodel.OperationStateApplying) {
		t.Fatal("terminal state reopened")
	}
}

func TestConcurrentConflictingTransitionsHaveOneWinner(t *testing.T) {
	for attempt := 0; attempt < 40; attempt++ {
		store, err := NewSnapshotStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		id := fmt.Sprintf("op-concurrent-%d", attempt)
		if err := persistTestManifest(store, id, recoverymodel.OperationStateApplying, testTime()); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		var successes atomic.Int32
		for _, next := range []recoverymodel.OperationState{recoverymodel.OperationStateValidating, recoverymodel.OperationStateRollingBack} {
			wg.Add(1)
			go func(next recoverymodel.OperationState) {
				defer wg.Done()
				<-start
				if _, err := store.Transition(id, recoverymodel.OperationStateApplying, next, testTime()); err == nil {
					successes.Add(1)
				}
			}(next)
		}
		close(start)
		wg.Wait()
		if successes.Load() != 1 {
			t.Fatalf("attempt %d had %d successful conflicting transitions", attempt, successes.Load())
		}
	}
}

func TestRestartDispositionOnlyResumesValidationOrRollback(t *testing.T) {
	cases := []struct {
		state recoverymodel.OperationState
		want  RestartDisposition
	}{
		{recoverymodel.OperationStateApplying, RestartBeginRollback},
		{recoverymodel.OperationStateValidating, RestartResumeValidation},
		{recoverymodel.OperationStateRollingBack, RestartResumeRollback},
		{recoverymodel.OperationStatePlanned, RestartNone},
		{recoverymodel.OperationStateSucceeded, RestartNone},
	}
	for _, tc := range cases {
		if got := RestartDispositionFor(tc.state); got != tc.want {
			t.Errorf("%s => %s, want %s", tc.state, got, tc.want)
		}
	}
}

func TestPrepareRestartConvertsApplyingToRollingBackDurably(t *testing.T) {
	store, err := NewSnapshotStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := persistTestManifest(store, "op-restart", recoverymodel.OperationStateApplying, testTime()); err != nil {
		t.Fatal(err)
	}
	disposition, err := store.PrepareRestart("op-restart")
	if err != nil {
		t.Fatal(err)
	}
	if disposition != RestartResumeRollback {
		t.Fatalf("disposition = %s", disposition)
	}
	loaded, err := store.Load("op-restart")
	if err != nil || loaded.State != recoverymodel.OperationStateRollingBack {
		t.Fatalf("manifest = %#v, %v", loaded, err)
	}
}

func TestTransitionRetryIsIdempotent(t *testing.T) {
	store, err := NewSnapshotStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := persistTestManifest(store, "op-idempotent", recoverymodel.OperationStateApplying, testTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition("op-idempotent", recoverymodel.OperationStateApplying, recoverymodel.OperationStateValidating, testTime().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition("op-idempotent", recoverymodel.OperationStateApplying, recoverymodel.OperationStateValidating, testTime().Add(2*time.Minute)); err != nil {
		t.Fatalf("retry rejected: %v", err)
	}
}

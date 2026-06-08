package main

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"
)

// TestWatchSignals asserts the signal→cancel wiring that unblocks the adoption
// wait. The old code never canceled ctx on a signal during WaitForAdoption, so
// the "shutdown requested during adoption wait" branch was unreachable; this
// verifies that delivering a signal on sigCh cancels the context.
func TestWatchSignals(t *testing.T) {
	tests := []struct {
		name       string
		action     func(chan os.Signal)
		wantCancel bool
	}{
		{
			name:       "SIGINT cancels context",
			action:     func(ch chan os.Signal) { ch <- syscall.SIGINT },
			wantCancel: true,
		},
		{
			name:       "SIGTERM cancels context",
			action:     func(ch chan os.Signal) { ch <- syscall.SIGTERM },
			wantCancel: true,
		},
		{
			// signal.Notify never closes the channel, but a closed channel must not
			// trigger a spurious shutdown — the watcher just returns without canceling.
			name:       "closed channel returns without canceling",
			action:     func(ch chan os.Signal) { close(ch) },
			wantCancel: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigCh := make(chan os.Signal, 1)
			done := make(chan struct{})
			go func() {
				watchSignals(sigCh, cancel)
				close(done)
			}()

			// Context must still be live before the signal arrives.
			select {
			case <-ctx.Done():
				t.Fatal("context canceled before any signal")
			default:
			}

			tt.action(sigCh)

			// watchSignals must always return after the channel receive/close.
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("watchSignals did not return")
			}

			canceled := ctx.Err() != nil
			if canceled != tt.wantCancel {
				t.Fatalf("ctx canceled = %v, want %v", canceled, tt.wantCancel)
			}
		})
	}
}

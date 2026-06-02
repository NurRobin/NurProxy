package health

import (
	"sync"
	"testing"
)

func TestState_New_startsHealthy(t *testing.T) {
	running, lastErr := New().Snapshot()
	if !running || lastErr != "" {
		t.Fatalf("New() snapshot = (%v, %q), want (true, \"\")", running, lastErr)
	}
}

func TestState_SetAndSnapshot(t *testing.T) {
	s := New()
	s.SetCaddyRunning(false)
	s.SetError("ports 80/443 in use")
	if running, lastErr := s.Snapshot(); running || lastErr != "ports 80/443 in use" {
		t.Fatalf("snapshot = (%v, %q), want (false, set)", running, lastErr)
	}

	// An empty string clears the error; Caddy can recover independently.
	s.SetError("")
	s.SetCaddyRunning(true)
	if running, lastErr := s.Snapshot(); !running || lastErr != "" {
		t.Fatalf("snapshot after clear = (%v, %q), want (true, \"\")", running, lastErr)
	}
}

// Run with -race: concurrent writers and readers must not data-race.
func TestState_concurrentAccess(t *testing.T) {
	s := New()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			s.SetCaddyRunning(n%2 == 0)
			s.SetError("e")
		}(i)
		go func() {
			defer wg.Done()
			_, _ = s.Snapshot()
		}()
	}
	wg.Wait()
}

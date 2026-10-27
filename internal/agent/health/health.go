// Package health holds the agent's self-reported operational state. It is the
// single source of truth that the agent's components write to (e.g. the Caddy
// manager when a bind fails) and that the heartbeat reads from to report status
// to the orchestrator. This is what lets the agent stay connected and explain
// *why* it's degraded — instead of dying — when, say, ports 80/443 are taken.
package health

import (
	"sync"

	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

// State is a concurrency-safe snapshot of the agent's health.
type State struct {
	mu           sync.RWMutex
	caddyRunning bool
	lastError    string
	diagnostics  []recoverymodel.Diagnostic
}

// SetDiagnostics replaces the active structured diagnostic snapshot. Snapshot
// uses its highest-severity entry for the legacy last_error field.
func (s *State) SetDiagnostics(diagnostics []recoverymodel.Diagnostic) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.diagnostics = append([]recoverymodel.Diagnostic(nil), diagnostics...)
}

// New returns a State that starts out healthy (Caddy assumed running, no error).
func New() *State {
	return &State{caddyRunning: true}
}

// SetCaddyRunning records whether the embedded Caddy is currently serving.
func (s *State) SetCaddyRunning(running bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.caddyRunning = running
}

// SetError records the most recent operational error. An empty string clears it.
func (s *State) SetError(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastError = msg
}

// Snapshot returns the current Caddy state and last error together.
func (s *State) Snapshot() (caddyRunning bool, lastError string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	lastError = s.lastError
	best := -1
	for _, diagnostic := range s.diagnostics {
		priority := severityPriority(diagnostic.Severity)
		if priority > best {
			best = priority
			lastError = diagnostic.Summary
		}
	}
	return s.caddyRunning, lastError
}

func severityPriority(severity recoverymodel.Severity) int {
	switch severity {
	case recoverymodel.SeverityCritical:
		return 3
	case recoverymodel.SeverityError:
		return 2
	case recoverymodel.SeverityWarning:
		return 1
	case recoverymodel.SeverityInfo:
		return 0
	default:
		return -1
	}
}

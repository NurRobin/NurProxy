// Package health holds the agent's self-reported operational state. It is the
// single source of truth that the agent's components write to (e.g. the Caddy
// manager when a bind fails) and that the heartbeat reads from to report status
// to the orchestrator. This is what lets the agent stay connected and explain
// *why* it's degraded — instead of dying — when, say, ports 80/443 are taken.
package health

import "sync"

// State is a concurrency-safe snapshot of the agent's health.
type State struct {
	mu           sync.RWMutex
	caddyRunning bool
	lastError    string
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
	return s.caddyRunning, s.lastError
}

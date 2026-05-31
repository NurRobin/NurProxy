// Package logbroker buffers on-demand log-tail output between an agent and the
// dashboard (§15). The dashboard opens a log view → the orchestrator starts a
// session and pushes a tail request down the agent's stream → the agent tails the
// file and POSTs LogChunks back up → the broker buffers them → the dashboard polls
// the buffer → closing the view stops the session. The agent dials out for every
// hop; the orchestrator never reads the agent inbound (invariant #2).
//
// The broker is intentionally small and in-memory: a tail exists only while a
// view is open, so there is nothing to persist, and a bounded ring per session
// keeps a noisy log from growing memory without limit. It is safe for concurrent
// use.
package logbroker

import (
	"sync"
	"time"
)

const (
	// maxBufferedLines bounds how many lines a session retains. Once full the
	// oldest lines are dropped (the dashboard shows a tail, not an archive), so a
	// firehose never grows memory unbounded.
	maxBufferedLines = 5000
	// idleTimeout is how long a session with no poll activity may live before the
	// sweeper reaps it. A dashboard that closed without a clean stop (tab crash,
	// network drop) is cleaned up so its agent-side tail is told to stop too.
	idleTimeout = 2 * time.Minute
)

// Line is one buffered log line with its monotonic sequence number, so the
// dashboard can poll incrementally ("give me everything after cursor N").
type Line struct {
	// Seq is the session-monotonic sequence of this line (1-based).
	Seq int64 `json:"seq"`
	// Text is the log line content (no trailing newline).
	Text string `json:"text"`
}

// session is one open tail's buffered state.
type session struct {
	agentID  string
	path     string
	lines    []Line
	nextSeq  int64
	done     bool
	errText  string
	lastPoll time.Time
}

// Poll is the snapshot the dashboard reads each cycle: any new lines past its
// cursor, the new cursor, and whether the tail has ended (done) or errored.
type Poll struct {
	// Lines are the buffered lines whose Seq is greater than the polled cursor.
	Lines []Line `json:"lines"`
	// Cursor is the highest Seq now delivered; the dashboard passes it back next poll.
	Cursor int64 `json:"cursor"`
	// Done reports that the agent's tail has ended (EOF) — no more lines will come.
	Done bool `json:"done"`
	// Error is a terminal tail error (path refused, file gone), empty on success.
	Error string `json:"error,omitempty"`
}

// Broker holds the live tail sessions.
type Broker struct {
	mu       sync.Mutex
	sessions map[string]*session
	now      func() time.Time // injectable clock for tests
}

// New creates an empty Broker.
func New() *Broker {
	return &Broker{
		sessions: make(map[string]*session),
		now:      time.Now,
	}
}

// withClock overrides the clock (tests only).
func (b *Broker) withClock(now func() time.Time) *Broker {
	b.now = now
	return b
}

// Start registers a new session owned by agentID tailing path. A duplicate
// sessionID resets the existing session (a reopened view reuses its ID).
func (b *Broker) Start(sessionID, agentID, path string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sessions[sessionID] = &session{
		agentID:  agentID,
		path:     path,
		nextSeq:  1,
		lastPoll: b.now(),
	}
}

// AgentFor returns the agent that owns a session, or "" if unknown. The chunk
// endpoint uses it to reject a chunk posted by an agent that does not own the
// session.
func (b *Broker) AgentFor(sessionID string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if s := b.sessions[sessionID]; s != nil {
		return s.agentID
	}
	return ""
}

// Append adds tailed lines to a session's buffer (called from the agent chunk
// endpoint). An unknown session is ignored (the view already closed). The buffer
// is a bounded ring: once over the cap the oldest lines are dropped. A terminal
// error or EOF marks the session done so the next poll tells the dashboard to
// stop. Appending to an unknown session reports false so the caller can tell the
// agent to stop a now-orphaned tail.
func (b *Broker) Append(sessionID string, lines []string, errText string, eof bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.sessions[sessionID]
	if s == nil {
		return false
	}
	for _, text := range lines {
		s.lines = append(s.lines, Line{Seq: s.nextSeq, Text: text})
		s.nextSeq++
	}
	if len(s.lines) > maxBufferedLines {
		s.lines = s.lines[len(s.lines)-maxBufferedLines:]
	}
	if errText != "" {
		s.errText = errText
		s.done = true
	}
	if eof {
		s.done = true
	}
	return true
}

// Poll returns the lines a session has buffered past cursor, advancing the
// dashboard's view. It refreshes the session's activity timestamp so an actively
// polled view is never reaped. An unknown session reports Done so a stale view
// stops polling.
func (b *Broker) Poll(sessionID string, cursor int64) Poll {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.sessions[sessionID]
	if s == nil {
		return Poll{Cursor: cursor, Done: true}
	}
	s.lastPoll = b.now()
	out := Poll{Cursor: cursor, Done: s.done, Error: s.errText}
	for _, ln := range s.lines {
		if ln.Seq > cursor {
			out.Lines = append(out.Lines, ln)
			out.Cursor = ln.Seq
		}
	}
	return out
}

// Stop removes a session (the dashboard closed the view). It returns the owning
// agent ID so the caller can push a stop event down that agent's stream; "" when
// the session was unknown.
func (b *Broker) Stop(sessionID string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.sessions[sessionID]
	if s == nil {
		return ""
	}
	delete(b.sessions, sessionID)
	return s.agentID
}

// ReapIdle removes sessions whose last poll is older than idleTimeout and returns
// each reaped session's ID and owning agent, so the caller can push a stop down
// the agent's stream (a view that vanished without a clean close should not leave
// the agent tailing forever).
func (b *Broker) ReapIdle() map[string]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	cutoff := b.now().Add(-idleTimeout)
	reaped := make(map[string]string)
	for id, s := range b.sessions {
		if s.lastPoll.Before(cutoff) {
			reaped[id] = s.agentID
			delete(b.sessions, id)
		}
	}
	return reaped
}

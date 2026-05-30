package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/agenthub"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// logReapInterval is how often the orchestrator sweeps abandoned tail sessions
// (a dashboard view that vanished without a clean stop). On reap it pushes a stop
// down the owning agent's stream so no agent is left tailing a file forever.
const logReapInterval = 30 * time.Second

// StartLogReaper runs the idle-tail sweeper until ctx is canceled. A view that
// closed uncleanly (tab crash, network drop) stops polling; its session goes idle
// and is reaped here, and the owning agent is told to stop the orphaned tail
// (§15). Best-effort: a disconnected agent simply misses the stop and its own
// stream teardown cancels the tailer instead.
func (s *Server) StartLogReaper(ctx context.Context) {
	go func() {
		t := time.NewTicker(logReapInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				for sessionID, agentID := range s.logs.ReapIdle() {
					if s.hub == nil {
						continue
					}
					data, _ := json.Marshal(proxymodel.LogTailStop{SessionID: sessionID})
					s.hub.Publish(agentID, agenthub.Event{Type: agenthub.EventLogTailStop, Data: data})
				}
			}
		}
	}()
}

// handleStartLogTail opens an on-demand log tail for the dashboard (§15). It
// validates the requested path against the agent's last-reported log paths
// (proxy_log_paths surfaced via detection), so the dashboard can only tail logs
// the agent itself advertised — and the agent re-checks the allowlist anyway
// (defense in depth). It mints a session, registers it with the broker, then
// pushes a log_tail request down the agent's existing stream. The agent dials out
// for everything: there is no inbound probe (invariant #2). A disconnected agent
// is reported so the UI can explain the tail is unavailable.
//
// POST /api/v1/agents/{id}/logs/tail   body {"path": "..."}   (user auth)
func (s *Server) handleStartLogTail(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	if s.hub == nil {
		writeError(w, http.StatusServiceUnavailable, "live streaming not enabled")
		return
	}

	var req struct {
		Path  string `json:"path"`
		Lines int    `json:"lines"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Path == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}

	agent, err := s.db.GetAgent(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if !s.pathIsKnownLog(agent.ProxyDetection, req.Path) {
		writeError(w, http.StatusForbidden, "path is not one of this agent's reported log paths")
		return
	}
	if !s.hub.Connected(id) {
		writeError(w, http.StatusConflict, "agent is not connected; cannot start a log tail")
		return
	}

	sessionID := newSessionID()
	s.logs.Start(sessionID, id, req.Path)

	data, _ := json.Marshal(proxymodel.LogTailRequest{
		SessionID: sessionID,
		Path:      req.Path,
		Lines:     req.Lines,
	})
	if !s.hub.Publish(id, agenthub.Event{Type: agenthub.EventLogTail, Data: data}) {
		s.logs.Stop(sessionID)
		writeError(w, http.StatusConflict, "agent is not connected; cannot start a log tail")
		return
	}

	s.audit(r, "agent", id, "log_tail_start", "opened log tail for "+req.Path)
	writeJSON(w, http.StatusOK, map[string]string{"session_id": sessionID})
}

// handlePollLogTail returns the lines buffered for a session past the given
// cursor (§15). The dashboard polls this while its log view is open. A poll also
// refreshes the session's activity so an actively-watched tail is never reaped.
//
// GET /api/v1/agents/{id}/logs/tail/{session}?cursor=N   (user auth)
func (s *Server) handlePollLogTail(w http.ResponseWriter, r *http.Request) {
	sessionID := pathParam(r, "session")
	cursor, _ := strconv.ParseInt(r.URL.Query().Get("cursor"), 10, 64)
	writeJSON(w, http.StatusOK, s.logs.Poll(sessionID, cursor))
}

// handleStopLogTail ends a tail session when the dashboard closes the view (§15).
// It removes the buffered session and pushes a log_tail_stop down the owning
// agent's stream so the agent stops the file tail and frees the handle.
//
// DELETE /api/v1/agents/{id}/logs/tail/{session}   (user auth)
func (s *Server) handleStopLogTail(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	sessionID := pathParam(r, "session")
	agentID := s.logs.Stop(sessionID)
	if agentID != "" && s.hub != nil {
		data, _ := json.Marshal(proxymodel.LogTailStop{SessionID: sessionID})
		s.hub.Publish(agentID, agenthub.Event{Type: agenthub.EventLogTailStop, Data: data})
		s.audit(r, "agent", id, "log_tail_stop", "closed log tail session "+sessionID)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleAgentLogChunk receives one batch of tailed log lines the agent POSTed up
// the control plane (§15). The chunk is buffered for the dashboard to poll. The
// caller must be the agent that owns the session, so one agent cannot inject into
// another's tail. A chunk for an unknown session means the view already closed:
// the orchestrator tells the agent to stop the now-orphaned tail.
//
// POST /api/v1/agents/{id}/logs/chunk   (agent auth)
func (s *Server) handleAgentLogChunk(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	if callerID, _ := r.Context().Value(ctxAgentID).(string); callerID != id {
		writeError(w, http.StatusForbidden, "agent can only post chunks for itself")
		return
	}

	var chunk proxymodel.LogChunk
	if err := readJSON(r, &chunk); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if owner := s.logs.AgentFor(chunk.SessionID); owner != "" && owner != id {
		writeError(w, http.StatusForbidden, "session belongs to a different agent")
		return
	}

	if !s.logs.Append(chunk.SessionID, chunk.Lines, chunk.Error, chunk.EOF) {
		// Unknown session: the view closed. Ask the agent to stop the orphaned tail.
		if s.hub != nil {
			data, _ := json.Marshal(proxymodel.LogTailStop{SessionID: chunk.SessionID})
			s.hub.Publish(id, agenthub.Event{Type: agenthub.EventLogTailStop, Data: data})
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "unknown_session"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// pathIsKnownLog reports whether path is among the agent's reported log paths.
// Tailing is bounded to logs the agent itself advertised (proxy_log_paths /
// detection), a server-side gate complementing the agent's own allowlist check.
func (s *Server) pathIsKnownLog(det *models.ProxyDetection, path string) bool {
	if det == nil {
		return false
	}
	for _, p := range det.LogPaths {
		if p == path {
			return true
		}
	}
	return false
}

// newSessionID mints a random opaque tail-session identifier.
func newSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is effectively impossible; fall back to a fixed prefix
		// plus the broker's uniqueness via overwrite. Log and continue.
		log.Printf("logs: rand read failed: %v", err)
		return "session-fallback"
	}
	return "tail-" + hex.EncodeToString(b[:])
}

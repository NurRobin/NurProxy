package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// This file implements the drift-review API (§11, Phase 3): list config
// artifacts (with their drift state), inspect version history, and resolve drift
// via Accept / Reject / Rollback — plus bulk accept-all / reject-all for the
// >3-artifacts case (e.g. after an OS package update). Every state-changing
// action is audited with source + actor (invariant #5), and after a Reject or
// Rollback the agent's routes are re-pushed so the accepted/rolled-back content
// is re-applied to the host (the agent always dials out; we only push down its
// open stream, invariant #2).

// GET /api/v1/artifacts — list config artifacts, optionally filtered by agent,
// domain, source, apply_state, or drifted.
func (s *Server) handleListArtifacts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := db.ConfigArtifactFilter{
		AgentID:    q.Get("agent_id"),
		Source:     q.Get("source"),
		ApplyState: q.Get("apply_state"),
	}
	if v := q.Get("domain_id"); v != "" {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			filter.DomainID = &id
		}
	}
	if v := q.Get("drifted"); v != "" {
		b := v == "true" || v == "1"
		filter.Drifted = &b
	}

	arts, err := s.db.ListConfigArtifacts(filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list artifacts")
		return
	}
	if arts == nil {
		arts = []models.ConfigArtifact{}
	}
	writeJSON(w, http.StatusOK, arts)
}

// GET /api/v1/artifacts/{id} — a single artifact with its current live state.
func (s *Server) handleGetArtifact(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	art, err := s.db.GetConfigArtifact(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "artifact not found")
		return
	}
	writeJSON(w, http.StatusOK, art)
}

// GET /api/v1/artifacts/{id}/versions — the append-only version history (newest
// first), for the dashboard's diff/rollback view.
func (s *Server) handleListArtifactVersions(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	if _, err := s.db.GetConfigArtifact(id); err != nil {
		writeError(w, http.StatusNotFound, "artifact not found")
		return
	}
	versions, err := s.db.ListConfigArtifactVersions(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list versions")
		return
	}
	if versions == nil {
		versions = []models.ConfigArtifactVersion{}
	}
	writeJSON(w, http.StatusOK, versions)
}

// POST /api/v1/artifacts/{id}/accept — resolve drift by accepting the on-disk
// content as the new live version (§11). The agent reports the drifted content in
// its checksum/heartbeat, but the heartbeat carries only the checksum; the full
// drifted content is captured on the next apply-ACK. For the built-in Caddy path
// the operator-supplied content (the reviewed on-disk text) is what we accept, so
// Accept takes the content in the request body — the exact bytes shown in the
// diff the operator approved.
func (s *Server) handleAcceptArtifact(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	art, err := s.db.GetConfigArtifact(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "artifact not found")
		return
	}

	var body struct {
		// Content is the reviewed on-disk content to accept as the new live state.
		// When empty, Accept falls back to the on-disk bytes the agent captured on
		// drift (DriftContent) — so the dashboard's one-click Accept persists the
		// operator's actual edit. If no drift content was captured (e.g. the
		// admin-API Caddy, whose route is its own live state), it falls back to the
		// already-stored content, which just re-affirms the accepted state.
		Content string `json:"content"`
	}
	_ = readJSON(r, &body)

	if body.Content == "" {
		if art.DriftContent != "" {
			body.Content = art.DriftContent
		} else {
			body.Content = art.Content
		}
	}

	ver, err := s.db.AppendConfigArtifactVersion(id, body.Content, models.ArtifactSourceManual,
		actorFromCtx(r), "accept drift")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to accept drift")
		return
	}
	s.audit(r, "config_artifact", id, "accept", fmt.Sprintf("accepted on-disk content as version %d", ver.Version))
	writeJSON(w, http.StatusOK, ver)
}

// POST /api/v1/artifacts/{id}/reject — resolve drift by reverting: re-apply the
// stored (accepted) content to the host (§11). Clears the drift flag and re-pushes
// the agent's routes so the accepted state is re-applied over the on-disk change.
func (s *Server) handleRejectArtifact(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	art, err := s.db.RejectConfigArtifactDrift(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "artifact not found")
		return
	}
	s.audit(r, "config_artifact", id, "reject", "reverted on-disk drift to accepted state")
	s.reapplyArtifact(art)
	writeJSON(w, http.StatusOK, art)
}

// POST /api/v1/artifacts/{id}/rollback — promote a prior version to live (§11)
// and re-apply it to the host. Body: {"version": N}.
func (s *Server) handleRollbackArtifact(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	var body struct {
		Version int `json:"version"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Version <= 0 {
		writeError(w, http.StatusBadRequest, "version must be a positive integer")
		return
	}

	ver, err := s.db.RollbackConfigArtifact(id, body.Version, actorFromCtx(r),
		fmt.Sprintf("rollback to version %d", body.Version))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, "config_artifact", id, "rollback", fmt.Sprintf("rolled back to version %d (new live version %d)", body.Version, ver.Version))

	if art, gErr := s.db.GetConfigArtifact(id); gErr == nil {
		s.reapplyArtifact(art)
	}
	writeJSON(w, http.StatusOK, ver)
}

// POST /api/v1/artifacts/bulk — combined accept-all / reject-all over the set of
// currently-drifted artifacts, the >3-drift bulk review (§11). Body:
// {"action": "accept"|"reject", "agent_id": "..."}. agent_id, when set, scopes
// the bulk action to one agent; otherwise every drifted artifact is resolved.
// accept-all accepts each artifact's already-stored content (the operator reviewed
// the combined diff); reject-all reverts each to its accepted state and re-pushes.
func (s *Server) handleBulkArtifacts(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action  string `json:"action"`
		AgentID string `json:"agent_id"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Action != "accept" && body.Action != "reject" {
		writeError(w, http.StatusBadRequest, "action must be 'accept' or 'reject'")
		return
	}

	drifted := true
	arts, err := s.db.ListConfigArtifacts(db.ConfigArtifactFilter{
		AgentID: body.AgentID,
		Drifted: &drifted,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list drifted artifacts")
		return
	}

	resolved := 0
	pushAgents := make(map[string]bool)
	for i := range arts {
		art := &arts[i]
		switch body.Action {
		case "accept":
			// Accept the operator's on-disk bytes (captured on drift) as a fresh
			// manual version, clearing drift. Falls back to the stored accepted
			// content when no drift bytes were captured (e.g. admin-API Caddy).
			content := art.DriftContent
			if content == "" {
				content = art.Content
			}
			if _, aErr := s.db.AppendConfigArtifactVersion(art.ID, content, models.ArtifactSourceManual, actorFromCtx(r), "bulk accept drift"); aErr != nil {
				continue
			}
			s.audit(r, "config_artifact", art.ID, "accept", "bulk accept drift")
		case "reject":
			if reverted, rErr := s.db.RejectConfigArtifactDrift(art.ID); rErr == nil {
				s.audit(r, "config_artifact", art.ID, "reject", "bulk reject drift")
				pushAgents[reverted.AgentID] = true
			} else {
				continue
			}
		}
		resolved++
	}

	// Re-apply once per affected agent for reject-all (one push converges all of
	// that agent's artifacts).
	for agentID := range pushAgents {
		s.pushAgent(agentID)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"action":   body.Action,
		"resolved": resolved,
		"total":    len(arts),
	})
}

// PUT /api/v1/agents/{id}/auto-reconcile — toggle the opt-in per-agent
// "auto-reconcile config" policy (§11). Body: {"enabled": true|false}.
func (s *Server) handleSetAutoReconcile(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	if _, err := s.db.GetAgent(id); err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.db.SetAgentAutoReconcileConfig(id, body.Enabled); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update policy")
		return
	}
	s.audit(r, "agent", id, "auto_reconcile_config", fmt.Sprintf("enabled=%t", body.Enabled))
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": body.Enabled})
}

// reapplyArtifact re-pushes the owning agent's routes so the artifact's accepted
// live content is re-applied to the host. Best-effort and a no-op when streaming
// isn't wired or the agent isn't connected (it converges on the next reconcile).
func (s *Server) reapplyArtifact(art *models.ConfigArtifact) {
	if art == nil {
		return
	}
	s.pushAgent(art.AgentID)
}

// pushAgent pushes an agent's desired routes over its live stream.
func (s *Server) pushAgent(agentID string) {
	if s.pusher == nil || agentID == "" {
		return
	}
	if err := s.pusher.PushAgentRoutes(agentID); err != nil {
		// Best-effort: the periodic reconcile converges if the push fails.
		_ = err
	}
}

// actorFromCtx returns the auth actor recorded by the middleware, defaulting to
// "unknown" so a version's actor is never blank.
func actorFromCtx(r *http.Request) string {
	if a, ok := r.Context().Value(ctxActor).(string); ok && a != "" {
		return a
	}
	return "unknown"
}

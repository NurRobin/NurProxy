package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/agenthub"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// streamKeepalive is how often the open stream emits a keepalive and refreshes
// the agent's last_seen, so a connected-but-quiet agent never drifts offline.
const streamKeepalive = 20 * time.Second

// handleAgentStream is the agent's long-lived outbound connection (Server-Sent
// Events). The agent opens it and holds it; the orchestrator pushes config down
// it the instant anything changes. Because the agent dials out, this works
// behind NAT/firewalls with no inbound reachability — and the open connection
// itself is a strong liveness signal.
//
// GET /api/v1/agents/{id}/stream  (agent auth)
func (s *Server) handleAgentStream(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	if callerID, _ := r.Context().Value(ctxAgentID).(string); callerID != id {
		writeError(w, http.StatusForbidden, "agent can only stream for itself")
		return
	}
	if s.hub == nil {
		writeError(w, http.StatusServiceUnavailable, "streaming not enabled")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ch, unsubscribe := s.hub.Subscribe(id)
	defer unsubscribe()

	// Connecting is proof of life: refresh last_seen and, if the agent had been
	// marked offline, bring it back.
	s.markAgentOnline(r, id)

	// Send the current desired routes immediately so a freshly (re)connected
	// agent converges without waiting for the next reconcile tick.
	if s.pusher != nil {
		if err := s.pusher.PushAgentRoutes(id); err != nil {
			log.Printf("stream: initial route push for agent %s failed: %v", id, err)
		}
	}

	ctx := r.Context()
	ka := time.NewTicker(streamKeepalive)
	defer ka.Stop()

	for {
		select {
		case <-ctx.Done():
			// Agent disconnected. We don't force the status offline here — the
			// agent's independent POST heartbeats (and the staleness sweeper)
			// own that, so a brief stream blip doesn't flap the agent.
			return
		case ev, open := <-ch:
			if !open {
				return
			}
			writeSSEEvent(w, ev)
			flusher.Flush()
		case <-ka.C:
			// Refresh last_seen (blank IP = keep the known value) and ping.
			if err := s.db.UpdateAgentHeartbeat(id, ""); err != nil {
				log.Printf("stream: keepalive heartbeat for agent %s failed: %v", id, err)
			}
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

// writeSSEEvent serializes one event in the Server-Sent Events wire format.
func writeSSEEvent(w http.ResponseWriter, ev agenthub.Event) {
	data := ev.Data
	if len(data) == 0 {
		data = json.RawMessage("{}")
	}
	_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, data)
}

// markAgentOnline refreshes last_seen and flips an offline agent back to adopted.
func (s *Server) markAgentOnline(r *http.Request, id string) {
	agent, err := s.db.GetAgent(id)
	if err != nil {
		return
	}
	if err := s.db.UpdateAgentHeartbeat(id, ""); err != nil {
		log.Printf("stream: failed to refresh last_seen for agent %s: %v", id, err)
	}
	if agent.Status == models.AgentStatusOffline {
		if err := s.db.UpdateAgentStatus(id, models.AgentStatusAdopted); err != nil {
			log.Printf("stream: failed to mark agent %s online: %v", id, err)
		} else {
			s.audit(r, "agent", id, "status_change", "agent came back online (stream)")
		}
	}
}

// handleAgentRoutesAck records the agent's atomic apply-ACK after an intent push
// (§3/B1). Each report carries the artifact the agent *rendered natively* plus
// its checksum; the orchestrator round-trips that rendered content into the
// central versioned store (create-or-append) so the store is authoritative
// without modeling the host, and converges each domain's status. This is how
// state converges for NAT'd agents, where the orchestrator can't read back
// inbound.
//
// POST /api/v1/agents/{id}/routes/ack  (agent auth)
func (s *Server) handleAgentRoutesAck(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	if callerID, _ := r.Context().Value(ctxAgentID).(string); callerID != id {
		writeError(w, http.StatusForbidden, "agent can only ack for itself")
		return
	}

	var req proxymodel.ApplyAck
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// An ack is also a sign of life.
	if err := s.db.UpdateAgentHeartbeat(id, ""); err != nil {
		log.Printf("ack: failed to refresh last_seen for agent %s: %v", id, err)
	}

	// Index reports by host so domain status converges, and round-trip each
	// rendered artifact into the central store keyed by its stable artifact ID.
	applied := make(map[string]bool, len(req.Reports))
	failed := make(map[string]string, len(req.Reports))
	for i := range req.Reports {
		rep := &req.Reports[i]
		if rep.Host != "" {
			if rep.Error != "" {
				failed[rep.Host] = rep.Error
			} else {
				applied[rep.Host] = true
			}
		}
		s.storeArtifactReport(r, id, rep)
	}

	domains, err := s.db.ListDomainsByAgent(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list domains")
		return
	}
	for i := range domains {
		dom := &domains[i]
		if dom.Status == models.DomainStatusDeleting {
			continue
		}
		zone, zErr := s.db.GetZone(dom.ZoneID)
		if zErr != nil {
			continue
		}
		fqdn := dom.FQDN(zone.Name)

		if msg, bad := failed[fqdn]; bad {
			if err := s.db.UpdateDomainStatus(dom.ID, models.DomainStatusError, msg); err != nil {
				log.Printf("ack: failed to set domain %d error: %v", dom.ID, err)
			}
			continue
		}
		if applied[fqdn] {
			if err := s.db.MarkDomainSynced(dom.ID); err != nil {
				log.Printf("ack: failed to mark domain %d synced: %v", dom.ID, err)
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// storeArtifactReport round-trips one agent-rendered artifact into the central
// versioned store (§3/B1). It creates the artifact on first sight (version 1) or
// appends a new version on semantic change; phantom versions from re-serialized
// content are gated out by the per-backend Equal in AppendConfigArtifactVersion.
// A failed apply records the apply_failed state with the agent's error rather
// than writing a (non-live) version. Every store write is audited with source +
// actor (invariant #5). Best-effort: store failures are logged, not fatal to the
// ACK (the agent already applied; status convergence above must still proceed).
func (s *Server) storeArtifactReport(r *http.Request, agentID string, rep *proxymodel.ArtifactReport) {
	if rep.ArtifactID == "" {
		return
	}

	// Invariant #4: the backend dropped one or more unsupported options rather
	// than failing the render. The agent logged each locally; record them in the
	// central audit log too (source agent + actor agent) so the operator can see
	// exactly what was silently dropped. This runs regardless of apply success.
	for _, w := range rep.Warnings {
		s.auditAs(r, models.AuditSourceAgent, "config_artifact", rep.ArtifactID, "option_dropped",
			fmt.Sprintf("%s (%s)", w, rep.Host))
	}

	existing, err := s.db.GetConfigArtifact(rep.ArtifactID)
	notFound := err != nil

	// A per-artifact apply failure: flag the stored artifact (if any) as
	// apply_failed; nothing to version (the rendered content never went live).
	if rep.Error != "" {
		if !notFound {
			if sErr := s.db.SetConfigArtifactApplyState(rep.ArtifactID, models.ArtifactStateApplyFailed, rep.Error); sErr != nil {
				log.Printf("ack: failed to flag artifact %s apply_failed: %v", rep.ArtifactID, sErr)
			}
		}
		s.audit(r, "config_artifact", rep.ArtifactID, "apply_failed", rep.Error)
		return
	}

	domainID := domainIDFromArtifactID(rep.ArtifactID)

	if notFound {
		art := &models.ConfigArtifact{
			ID:      rep.ArtifactID,
			AgentID: agentID,
			Backend: rep.Backend,
			Target: models.Target{
				Kind: rep.TargetKind,
				Path: rep.TargetPath,
			},
			Source:   models.ArtifactSourceGenerated,
			DomainID: domainID,
			Content:  rep.Content,
			Enabled:  rep.Enabled,
		}
		if cErr := s.db.CreateConfigArtifact(art, "agent:"+agentID, "initial apply"); cErr != nil {
			log.Printf("ack: failed to create artifact %s: %v", rep.ArtifactID, cErr)
			return
		}
		s.audit(r, "config_artifact", rep.ArtifactID, "apply", "initial apply ("+rep.Host+")")
		return
	}

	prevVersion := existing.LiveVersion
	ver, aErr := s.db.AppendConfigArtifactVersion(rep.ArtifactID, rep.Content, models.ArtifactSourceGenerated, "agent:"+agentID, "apply")
	if aErr != nil {
		log.Printf("ack: failed to append artifact %s version: %v", rep.ArtifactID, aErr)
		return
	}
	// Only audit a genuine version bump; a no-op (semantic-equal re-serialization)
	// is not a config change worth an audit line.
	if ver != nil && ver.Version != prevVersion {
		s.audit(r, "config_artifact", rep.ArtifactID, "apply", fmt.Sprintf("applied version %d (%s)", ver.Version, rep.Host))
	}
}

// domainIDFromArtifactID recovers the domain ID from a generated artifact's
// stable identity ("dom-<id>"), mirroring the reconciler's artifactIDForDomain.
// Returns nil for an artifact whose ID is not in that form (e.g. adopted files).
func domainIDFromArtifactID(artifactID string) *int64 {
	const prefix = "dom-"
	if !strings.HasPrefix(artifactID, prefix) {
		return nil
	}
	v, err := strconv.ParseInt(artifactID[len(prefix):], 10, 64)
	if err != nil {
		return nil
	}
	return &v
}

// triggerAgentPush pushes an agent's desired routes over its live stream after a
// domain change, so connected agents converge instantly instead of waiting for
// the reconcile tick. Best-effort and a no-op when streaming isn't wired up or
// the agent isn't connected.
func (s *Server) triggerAgentPush(serverID string) {
	if s.pusher == nil {
		return
	}
	srv, err := s.db.GetServer(serverID)
	if err != nil {
		return
	}
	if err := s.pusher.PushAgentRoutes(srv.AgentID); err != nil {
		log.Printf("push: failed to push routes to agent %s: %v", srv.AgentID, err)
	}
}

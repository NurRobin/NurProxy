package api

import (
	"fmt"
	"log"
	"net/http"

	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// handleAgentAdoptArtifacts ingests the config files an agent read off its host
// (existing mode, §17 "adoption reads all files") into the central versioned
// store. It is independent of the apply path: the agent reports what it can READ
// even when it lacks reload permission, so the host's config surfaces under
// Config regardless of whether NurProxy can reload the service.
//
// Each artifact upserts by its stable ID: a first sighting creates version 1; a
// re-report appends a new version only on semantic change (AppendConfigArtifactVersion
// gates phantom versions and clears drift when the host is back in agreement).
// Operator-authored files (Adopted) are stored Source: manual and never
// auto-overwritten; generated files keep Source: generated for drift tracking.
//
// POST /api/v1/agents/{id}/artifacts/adopt  (agent auth)
func (s *Server) handleAgentAdoptArtifacts(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	if callerID, _ := r.Context().Value(ctxAgentID).(string); callerID != id {
		writeError(w, http.StatusForbidden, "agent can only report for itself")
		return
	}

	var req proxymodel.AdoptedArtifactReport
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var created, updated int
	for i := range req.Artifacts {
		a := req.Artifacts[i]
		if a.ArtifactID == "" || a.TargetPath == "" {
			continue
		}
		switch s.upsertAdoptedArtifact(r, id, req.Host, &a) {
		case adoptCreated:
			created++
		case adoptUpdated:
			updated++
		}
	}

	writeJSON(w, http.StatusOK, map[string]int{
		"received": len(req.Artifacts),
		"created":  created,
		"updated":  updated,
	})
}

// adoptOutcome reports what an upsert did, so the handler can summarize + so a
// no-op (semantic-equal re-report) is distinguishable from a real change.
type adoptOutcome int

const (
	adoptNoop adoptOutcome = iota
	adoptCreated
	adoptUpdated
)

// upsertAdoptedArtifact stores one read-off-host artifact into the central store,
// creating it on first sight or appending a version on semantic change. Source
// follows the agent's Adopted flag: operator-authored → manual, generated → for
// drift. Best-effort: a store error is logged, never fatal to the batch.
func (s *Server) upsertAdoptedArtifact(r *http.Request, agentID, host string, a *proxymodel.AdoptedArtifact) adoptOutcome {
	source := models.ArtifactSourceGenerated
	if a.Adopted {
		source = models.ArtifactSourceManual
	}

	existing, err := s.db.GetConfigArtifact(a.ArtifactID)
	if err != nil || existing == nil {
		art := &models.ConfigArtifact{
			ID:      a.ArtifactID,
			AgentID: agentID,
			Backend: a.Backend,
			Target: models.Target{
				Kind: a.TargetKind,
				Path: a.TargetPath,
			},
			Source:  source,
			Content: a.Content,
			Enabled: a.Enabled,
		}
		if cErr := s.db.CreateConfigArtifact(art, "agent:"+agentID, "adopted from host"); cErr != nil {
			log.Printf("adopt: failed to create artifact %s: %v", a.ArtifactID, cErr)
			return adoptNoop
		}
		s.auditAs(r, models.AuditSourceAgent, "config_artifact", a.ArtifactID, "adopt",
			fmt.Sprintf("adopted from %s", host))
		return adoptCreated
	}

	// Ownership guard: refuse to mutate another agent's artifact even if the IDs
	// collide. Agent-scoped IDs make this unreachable in normal operation, but a
	// crafted report must never let agent-2 overwrite agent-1's stored config.
	if existing.AgentID != agentID {
		log.Printf("adopt: agent %s attempted to write artifact %s owned by agent %s; refusing", agentID, a.ArtifactID, existing.AgentID)
		return adoptNoop
	}

	// The on-host enabled state (sites-enabled present?) can change without the
	// file content changing — e.g. the operator dis/enables a vhost. That is not a
	// content version, so AppendConfigArtifactVersion (gated on semantic change)
	// won't carry it; update the flag directly so the dashboard reflects reality.
	if existing.Enabled != a.Enabled {
		if eErr := s.db.SetConfigArtifactEnabled(a.ArtifactID, a.Enabled); eErr != nil {
			log.Printf("adopt: failed to update enabled flag for %s: %v", a.ArtifactID, eErr)
		}
	}

	prevVersion := existing.LiveVersion
	ver, aErr := s.db.AppendConfigArtifactVersion(a.ArtifactID, a.Content, source, "agent:"+agentID, "adopted from host")
	if aErr != nil {
		log.Printf("adopt: failed to append artifact %s version: %v", a.ArtifactID, aErr)
		return adoptNoop
	}
	if ver != nil && ver.Version != prevVersion {
		s.auditAs(r, models.AuditSourceAgent, "config_artifact", a.ArtifactID, "adopt",
			fmt.Sprintf("re-adopted version %d from %s", ver.Version, host))
		return adoptUpdated
	}
	return adoptNoop
}

package api

import (
	"fmt"
	"net/http"

	"github.com/NurRobin/NurProxy/internal/shared/caddygen"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/nginxparse"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// This file implements the §6 "mask" config UX on top of the artifact store:
//
//   - GET  /artifacts/{id}/mask        — best-effort parse the live content into
//     the structured Route view (the toggleable form). Never destroys text: the
//     response carries `ok`, the recovered `route`, plus any `unparsed` bytes and
//     `notes` so the UI can fall back to raw where the mask is uncertain.
//   - PUT  /artifacts/{id}/content     — raw-edit an artifact. Editing a
//     `generated` artifact's text flips its source to `manual` (we can no longer
//     re-render without losing the edit). Audited; re-pushed.
//   - POST /artifacts/{id}/reset-to-model — re-render a (formerly generated)
//     artifact from its domain intent and re-attach it as `generated`, discarding
//     the manual edit. Audited; re-pushed.
//
// The mask is a view, never a lossy owner (§6): a non-OK parse leaves the raw
// text authoritative and the UI shows the form read-only/advisory.

// maskResponse is the structured-view payload for the form⇄raw toggle.
type maskResponse struct {
	// Backend is the artifact's backend, so the UI greys options the backend
	// cannot express (capability-aware UI, §8).
	Backend string `json:"backend"`
	// OK reports whether the parse fully represents the content (a lossless
	// round-trip). When false the UI keeps raw authoritative and shows the form
	// advisory-only.
	OK bool `json:"ok"`
	// Route is the recovered structured mask (best-effort when OK is false).
	Route proxymodel.Route `json:"route"`
	// Unparsed preserves verbatim every construct the parser could not map, so the
	// operator's bytes are never lost (§6).
	Unparsed []string `json:"unparsed,omitempty"`
	// Notes explains, advisory, why the parse is not clean.
	Notes []string `json:"notes,omitempty"`
}

// GET /api/v1/artifacts/{id}/mask — parse the live content into the structured
// mask (§6). Pure read; never mutates the artifact.
func (s *Server) handleArtifactMask(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	art, err := s.db.GetConfigArtifact(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "artifact not found")
		return
	}

	resp := maskResponse{Backend: art.Backend}
	switch art.Backend {
	case "nginx":
		res := nginxparse.Parse(art.Content)
		resp.OK = res.OK
		resp.Route = res.Route
		resp.Unparsed = res.Unparsed
		resp.Notes = res.Notes
	case "caddy":
		// Built-in Caddy artifacts are route JSON; a structured caddy mask parser
		// is future work (§6 "starts primitive, grows"). Surface raw-only cleanly
		// rather than pretend a parse: OK=false, no destruction.
		resp.OK = false
		resp.Notes = []string{"structured mask not yet available for the caddy backend; edit raw"}
	default:
		resp.OK = false
		resp.Notes = []string{fmt.Sprintf("no structured mask for backend %q; edit raw", art.Backend)}
	}

	writeJSON(w, http.StatusOK, resp)
}

// PUT /api/v1/artifacts/{id}/content — raw-edit the artifact. Body:
// {"content": "..."}. Editing a `generated` artifact flips it to `manual` (§6:
// we can no longer re-render without losing the edit). Records a new version and
// re-pushes the owning agent so the edit is applied to the host.
func (s *Server) handleEditArtifactContent(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	art, err := s.db.GetConfigArtifact(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "artifact not found")
		return
	}

	var body struct {
		Content string `json:"content"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// A raw edit always lands as manual: even a generated artifact, once
	// hand-edited, can no longer be re-rendered without losing the edit (§6).
	wasGenerated := art.Source == models.ArtifactSourceGenerated
	note := "raw edit"
	if wasGenerated {
		note = "raw edit (generated → manual)"
	}

	ver, err := s.db.AppendConfigArtifactVersion(id, body.Content, models.ArtifactSourceManual, actorFromCtx(r), note)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save edit")
		return
	}
	s.audit(r, "config_artifact", id, "edit", note)

	if updated, gErr := s.db.GetConfigArtifact(id); gErr == nil {
		s.reapplyArtifact(updated)
	}
	writeJSON(w, http.StatusOK, ver)
}

// POST /api/v1/artifacts/{id}/reset-to-model — re-render a (formerly generated)
// artifact from its domain intent and re-attach it as `generated`, discarding the
// manual edit (§6 "reset to model"). Only valid for artifacts linked to a domain
// (DomainID set). Records a new generated version and re-pushes.
func (s *Server) handleResetArtifactToModel(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	art, err := s.db.GetConfigArtifact(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "artifact not found")
		return
	}
	if art.DomainID == nil {
		writeError(w, http.StatusBadRequest, "artifact is not model-backed (no domain); cannot reset to model")
		return
	}

	content, err := s.renderModelContent(*art.DomainID, art.Backend)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "failed to re-render from model: "+err.Error())
		return
	}

	ver, err := s.db.AppendConfigArtifactVersion(id, content, models.ArtifactSourceGenerated, actorFromCtx(r), "reset to model")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to reset to model")
		return
	}
	s.audit(r, "config_artifact", id, "reset_to_model", fmt.Sprintf("re-rendered from domain %d (version %d)", *art.DomainID, ver.Version))

	if updated, gErr := s.db.GetConfigArtifact(id); gErr == nil {
		s.reapplyArtifact(updated)
	}
	writeJSON(w, http.StatusOK, ver)
}

// renderModelContent re-renders a domain's intent into native content for the
// given backend. For caddy it produces the route JSON the built-in path uses;
// for file backends (nginx) the agent owns native rendering (B1, §3), so the
// orchestrator re-attaches the artifact as generated and re-pushes — the agent
// re-renders on apply. Returns the caddy JSON or, for the agent-rendered case, an
// empty content the next apply-ACK fills with the agent's rendered bytes.
func (s *Server) renderModelContent(domainID int64, backend string) (string, error) {
	dom, err := s.db.GetDomain(domainID)
	if err != nil {
		return "", fmt.Errorf("domain not found")
	}
	srv, err := s.db.GetServer(dom.ServerID)
	if err != nil {
		return "", fmt.Errorf("server not found")
	}
	zone, err := s.db.GetZone(dom.ZoneID)
	if err != nil {
		return "", fmt.Errorf("zone not found")
	}

	intent := caddygen.ConfigFromDomain(*dom, dom.FQDN(zone.Name), srv.Address)

	switch backend {
	case "caddy":
		route, gErr := caddygen.GenerateRoute(intent)
		if gErr != nil {
			return "", gErr
		}
		return string(route), nil
	case "nginx":
		// The agent renders nginx natively (it owns cert/htpasswd paths, §3). The
		// orchestrator cannot produce byte-faithful nginx here; re-attaching as
		// generated + re-pushing makes the agent re-render on the next apply and
		// round-trip the artifact back. Stage the intent's host as a marker so the
		// stored version is non-empty and meaningful until the apply-ACK updates it.
		return fmt.Sprintf("# regenerated from model for %s; agent re-renders on apply\n", intent.Host), nil
	default:
		return "", fmt.Errorf("unsupported backend %q", backend)
	}
}

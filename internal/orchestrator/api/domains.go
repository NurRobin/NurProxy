package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/caddygen"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// GET /api/v1/domains — supports ?agent_id=&server_id=&status= filters.
func (s *Server) handleListDomains(w http.ResponseWriter, r *http.Request) {
	filter := db.DomainFilter{
		AgentID:  r.URL.Query().Get("agent_id"),
		ServerID: r.URL.Query().Get("server_id"),
		Status:   r.URL.Query().Get("status"),
	}

	domains, err := s.db.ListDomains(filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list domains")
		return
	}
	if domains == nil {
		domains = []models.Domain{}
	}
	writeJSON(w, http.StatusOK, domains)
}

// POST /api/v1/domains
func (s *Server) handleCreateDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Subdomain   string              `json:"subdomain"`
		ZoneID      string              `json:"zone_id"`
		ServerID    string              `json:"server_id"`
		Port        int                 `json:"port"`
		WebSocket   bool                `json:"websocket"`
		ForceHTTPS  bool                `json:"force_https"`
		SSLMode     models.SSLMode      `json:"ssl_mode"`
		ProxyConfig *models.ProxyConfig `json:"proxy_config"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Subdomain == "" || req.ZoneID == "" || req.ServerID == "" {
		writeError(w, http.StatusBadRequest, "subdomain, zone_id, and server_id are required")
		return
	}
	if req.Port <= 0 || req.Port > 65535 {
		writeError(w, http.StatusBadRequest, "port must be between 1 and 65535")
		return
	}

	// Validate zone exists
	if _, err := s.db.GetZone(req.ZoneID); err != nil {
		writeError(w, http.StatusBadRequest, "zone not found")
		return
	}

	// Validate server exists
	if _, err := s.db.GetServer(req.ServerID); err != nil {
		writeError(w, http.StatusBadRequest, "server not found")
		return
	}

	// Check subdomain uniqueness within zone
	existing, _ := s.db.ListDomains(db.DomainFilter{})
	for _, d := range existing {
		if d.Subdomain == req.Subdomain && d.ZoneID == req.ZoneID {
			writeError(w, http.StatusConflict, "subdomain already exists for this zone")
			return
		}
	}

	sslMode := req.SSLMode
	if sslMode == "" {
		sslMode = models.SSLModeAuto
	}

	dom := &models.Domain{
		Subdomain:  req.Subdomain,
		ZoneID:     req.ZoneID,
		ServerID:   req.ServerID,
		Port:       req.Port,
		WebSocket:  req.WebSocket,
		ForceHTTPS: req.ForceHTTPS,
		SSLMode:    sslMode,
		Status:     models.DomainStatusPending,
	}

	if req.ProxyConfig != nil {
		dom.ProxyConfig = *req.ProxyConfig
	}

	if err := s.db.CreateDomain(dom); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create domain")
		return
	}

	s.audit(r, "domain", strconv.FormatInt(dom.ID, 10), "create", dom.Subdomain)
	s.triggerAgentPush(dom.ServerID)

	writeJSON(w, http.StatusCreated, dom)
}

// GET /api/v1/domains/{id}
func (s *Server) handleGetDomain(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(pathParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain ID")
		return
	}

	dom, err := s.db.GetDomain(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	writeJSON(w, http.StatusOK, dom)
}

// PUT /api/v1/domains/{id}
func (s *Server) handleUpdateDomain(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(pathParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain ID")
		return
	}

	dom, err := s.db.GetDomain(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	var req struct {
		Subdomain   *string             `json:"subdomain"`
		ZoneID      *string             `json:"zone_id"`
		ServerID    *string             `json:"server_id"`
		Port        *int                `json:"port"`
		WebSocket   *bool               `json:"websocket"`
		ForceHTTPS  *bool               `json:"force_https"`
		SSLMode     *models.SSLMode     `json:"ssl_mode"`
		ProxyConfig *models.ProxyConfig `json:"proxy_config"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Subdomain != nil {
		dom.Subdomain = *req.Subdomain
	}
	if req.ZoneID != nil {
		if _, err := s.db.GetZone(*req.ZoneID); err != nil {
			writeError(w, http.StatusBadRequest, "zone not found")
			return
		}
		dom.ZoneID = *req.ZoneID
	}
	// Capture the prior server so a move can clean up the artifact on the old
	// agent (no ghost vhosts, §3).
	oldServerID := dom.ServerID
	if req.ServerID != nil {
		if _, err := s.db.GetServer(*req.ServerID); err != nil {
			writeError(w, http.StatusBadRequest, "server not found")
			return
		}
		dom.ServerID = *req.ServerID
	}
	if req.Port != nil {
		dom.Port = *req.Port
	}
	if req.WebSocket != nil {
		dom.WebSocket = *req.WebSocket
	}
	if req.ForceHTTPS != nil {
		dom.ForceHTTPS = *req.ForceHTTPS
	}
	if req.SSLMode != nil {
		dom.SSLMode = *req.SSLMode
	}
	if req.ProxyConfig != nil {
		dom.ProxyConfig = *req.ProxyConfig
	}

	// Mark as pending for reconciler to pick up
	dom.Status = models.DomainStatusPending

	if err := s.db.UpdateDomain(dom); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update domain")
		return
	}

	s.audit(r, "domain", strconv.FormatInt(dom.ID, 10), "update", dom.Subdomain)

	// Domain lifecycle: a server move (to a server on a different agent) must
	// remove the artifact on the OLD agent and (re-)render the intent on the new
	// one — no ghost vhosts (§3). The artifact row is keyed by agent_id, so we drop
	// the stale row; the old agent's next full-sync push (below) no longer lists
	// this domain, so it clears the route, and the new agent renders + reports a
	// fresh artifact in its apply-ACK.
	if req.ServerID != nil && oldServerID != dom.ServerID {
		s.handleArtifactServerMove(r, dom.ID, oldServerID, dom.ServerID)
	}

	s.triggerAgentPush(dom.ServerID)

	writeJSON(w, http.StatusOK, dom)
}

// handleArtifactServerMove cleans up a domain's config artifact after it moves
// from one server to another (§3). When the move crosses agents, it deletes the
// stale artifact row (keyed to the old agent) so no orphaned/ghost artifact
// lingers, and pushes the old agent's now-shrunk intent set so it drops the
// route on disk. The new agent re-renders the intent and round-trips a fresh
// artifact on its next apply-ACK. A move within the same agent is a no-op here
// (the artifact stays valid; the agent just re-applies it).
func (s *Server) handleArtifactServerMove(r *http.Request, domainID int64, oldServerID, newServerID string) {
	oldAgentID := s.agentIDForServer(oldServerID)
	newAgentID := s.agentIDForServer(newServerID)
	if oldAgentID == "" || oldAgentID == newAgentID {
		return // same agent (or unresolvable old server) — nothing to clean up.
	}

	artifactID := artifactIDForDomainID(domainID)
	if _, err := s.db.GetConfigArtifact(artifactID); err == nil {
		if dErr := s.db.DeleteConfigArtifact(artifactID); dErr != nil {
			log.Printf("move: failed to delete stale artifact %s: %v", artifactID, dErr)
		} else {
			s.audit(r, "config_artifact", artifactID, "remove", "domain moved to another agent")
		}
	}

	// Push the old agent so it drops the now-unmanaged route (no ghost vhost).
	s.pushAgent(oldAgentID)
}

// agentIDForServer resolves a server ID to its owning agent ID, or "" on error.
func (s *Server) agentIDForServer(serverID string) string {
	if serverID == "" {
		return ""
	}
	srv, err := s.db.GetServer(serverID)
	if err != nil {
		return ""
	}
	return srv.AgentID
}

// artifactIDForDomainID derives the stable artifact identity for a generated
// (model-backed) domain config, mirroring the reconciler's artifactIDForDomain
// and the agents_stream domainIDFromArtifactID round-trip ("dom-<id>").
func artifactIDForDomainID(domainID int64) string {
	return "dom-" + strconv.FormatInt(domainID, 10)
}

// DELETE /api/v1/domains/{id}
func (s *Server) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(pathParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain ID")
		return
	}

	// Resolve the owning server before we flip status, so we can push the new
	// (route-removed) set to the agent immediately.
	dom, _ := s.db.GetDomain(id)

	// Set status to "deleting" — reconciler handles actual cleanup
	if err := s.db.UpdateDomainStatus(id, models.DomainStatusDeleting, ""); err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	s.audit(r, "domain", strconv.FormatInt(id, 10), "delete", "")
	// A full-sync push now excludes the deleting domain, so a connected agent
	// drops the route at once; DNS record + row cleanup follow in the reconciler.
	if dom != nil {
		s.triggerAgentPush(dom.ServerID)
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "domain marked for deletion"})
}

// GET /api/v1/domains/{id}/config
func (s *Server) handleGetDomainConfig(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(pathParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain ID")
		return
	}

	dom, err := s.db.GetDomain(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	// If manual config, return the raw caddy config
	if dom.ManualConfig && !dom.ProxyConfig.RawConfig.IsZero() {
		var raw json.RawMessage
		if err := json.Unmarshal([]byte(dom.ProxyConfig.RawConfig.Content), &raw); err == nil {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"manual": true,
				"config": raw,
			})
			return
		}
	}

	// Get server for upstream address
	srv, err := s.db.GetServer(dom.ServerID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server not found")
		return
	}

	// Get zone for zone name
	zone, err := s.db.GetZone(dom.ZoneID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "zone not found")
		return
	}

	route, err := caddygen.GenerateRoute(caddygen.ConfigFromDomain(*dom, dom.FQDN(zone.Name), srv.Address))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate config: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"manual": false,
		"config": route,
	})
}

// PUT /api/v1/domains/{id}/config
func (s *Server) handleUpdateDomainConfig(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(pathParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain ID")
		return
	}

	dom, err := s.db.GetDomain(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	var req struct {
		Config json.RawMessage `json:"config"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Validate it's valid JSON
	if !json.Valid(req.Config) {
		writeError(w, http.StatusBadRequest, "invalid JSON config")
		return
	}

	dom.ManualConfig = true
	dom.ProxyConfig.RawConfig = models.RawConfig{Backend: "caddy", Content: string(req.Config)}
	dom.Status = models.DomainStatusPending

	if err := s.db.UpdateDomain(dom); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update domain config")
		return
	}

	s.audit(r, "domain", strconv.FormatInt(id, 10), "update_config", "manual config set")
	s.triggerAgentPush(dom.ServerID)

	writeJSON(w, http.StatusOK, map[string]string{"message": "manual config set"})
}

// POST /api/v1/domains/{id}/config/reset
func (s *Server) handleResetDomainConfig(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(pathParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain ID")
		return
	}

	dom, err := s.db.GetDomain(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	dom.ManualConfig = false
	dom.ProxyConfig.RawConfig = models.RawConfig{}
	dom.Status = models.DomainStatusPending

	if err := s.db.UpdateDomain(dom); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to reset domain config")
		return
	}

	s.audit(r, "domain", strconv.FormatInt(id, 10), "reset_config", "manual config cleared")
	s.triggerAgentPush(dom.ServerID)

	writeJSON(w, http.StatusOK, map[string]string{"message": "config reset to auto-generated"})
}

package api

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/auth"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// GET /api/v1/agents
func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.db.ListAgents()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list agents")
		return
	}
	if agents == nil {
		agents = []models.Agent{}
	}

	// Build response with zones included
	type agentResponse struct {
		models.Agent
		Zones []models.Zone `json:"zones"`
	}
	resp := make([]agentResponse, len(agents))
	for i, a := range agents {
		zones, err := s.db.ListAgentZones(a.ID)
		if err != nil {
			zones = []models.Zone{}
		}
		if zones == nil {
			zones = []models.Zone{}
		}
		resp[i] = agentResponse{
			Agent: a,
			Zones: zones,
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/v1/agents/register — called BY the agent during adoption.
// No auth required (agent doesn't have a token yet — it's registering one).
func (s *Server) handleRegisterAgent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID             string                 `json:"id"`
		FQDN           string                 `json:"fqdn"`
		Token          string                 `json:"token"`
		APIURL         string                 `json:"api_url"`
		PublicIP       string                 `json:"public_ip"`
		Version        string                 `json:"version"`
		ProxyDetection *models.ProxyDetection `json:"proxy_detection"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.ID == "" || req.FQDN == "" || req.Token == "" {
		writeError(w, http.StatusBadRequest, "id, fqdn, and token are required")
		return
	}

	// Check for duplicate FQDN
	if existing, err := s.db.GetAgentByFQDN(req.FQDN); err == nil && existing != nil {
		writeError(w, http.StatusConflict, "agent with this FQDN already registered")
		return
	}

	// Hash the token before storing
	tokenHash := auth.HashToken(req.Token)

	agent := &models.Agent{
		ID:        req.ID,
		Name:      req.FQDN, // default name to FQDN until adoption
		FQDN:      req.FQDN,
		APIURL:    req.APIURL,
		TokenHash: tokenHash,
		PublicIP:  req.PublicIP,
		Status:    models.AgentStatusPending,
		Version:   req.Version,
		// Assume healthy until the agent reports otherwise via heartbeat, so a
		// freshly registered agent doesn't surface a spurious "Caddy down" error.
		CaddyRunning: true,
		// Phase-0 read-only detection (§13.0/§2.1/§9), carried on the agent's
		// outbound register payload. Stored as-is; refreshed by heartbeats.
		ProxyDetection: req.ProxyDetection,
	}
	if req.ProxyDetection != nil {
		now := time.Now().UTC()
		agent.ProxyDetectedAt = &now
	}

	if err := s.db.CreateAgent(agent); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeError(w, http.StatusConflict, "agent already registered")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to register agent")
		return
	}

	s.auditAs(r, models.AuditSourceAgent, "agent", agent.ID, "register", agent.FQDN)

	writeJSON(w, http.StatusCreated, map[string]string{
		"id":     agent.ID,
		"status": string(agent.Status),
	})
}

// PUT /api/v1/agents/{id}/adopt
func (s *Server) handleAdoptAgent(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")

	agent, err := s.db.GetAgent(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	if agent.Status != models.AgentStatusPending {
		writeError(w, http.StatusBadRequest, "agent is not in pending state")
		return
	}

	var req struct {
		Name         string         `json:"name"`
		FQDN         string         `json:"fqdn"`
		ZoneIDs      []string       `json:"zone_ids"`
		DNSMode      models.DNSMode `json:"dns_mode"`
		DDNSInterval int            `json:"ddns_interval"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Name != "" {
		agent.Name = req.Name
	}
	if err := s.applyFQDNChange(agent, req.FQDN); err != nil {
		writeError(w, err.code, err.msg)
		return
	}
	if req.DNSMode != "" {
		agent.DNSMode = req.DNSMode
	}
	if req.DDNSInterval > 0 {
		agent.DDNSInterval = req.DDNSInterval
	}
	agent.Status = models.AgentStatusAdopted

	if err := s.db.UpdateAgent(agent); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to adopt agent")
		return
	}

	if len(req.ZoneIDs) > 0 {
		if err := s.db.SetAgentZones(id, req.ZoneIDs); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to set agent zones")
			return
		}
	}

	s.audit(r, "agent", id, "adopt", agent.Name)

	writeJSON(w, http.StatusOK, agent)
}

// PUT /api/v1/agents/{id}/reject
func (s *Server) handleRejectAgent(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")

	agent, err := s.db.GetAgent(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	if agent.Status != models.AgentStatusPending {
		writeError(w, http.StatusBadRequest, "agent is not in pending state")
		return
	}

	if err := s.db.DeleteAgent(id); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to reject agent")
		return
	}

	s.audit(r, "agent", id, "reject", agent.FQDN)

	writeJSON(w, http.StatusOK, map[string]string{"message": "agent rejected"})
}

// PUT /api/v1/agents/{id}
func (s *Server) handleUpdateAgent(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")

	agent, err := s.db.GetAgent(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	var req struct {
		Name         *string         `json:"name"`
		FQDN         *string         `json:"fqdn"`
		ZoneIDs      *[]string       `json:"zone_ids"`
		DNSMode      *models.DNSMode `json:"dns_mode"`
		DDNSInterval *int            `json:"ddns_interval"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Name != nil {
		agent.Name = *req.Name
	}
	if req.FQDN != nil {
		if err := s.applyFQDNChange(agent, *req.FQDN); err != nil {
			writeError(w, err.code, err.msg)
			return
		}
	}
	if req.DNSMode != nil {
		agent.DNSMode = *req.DNSMode
	}
	if req.DDNSInterval != nil {
		agent.DDNSInterval = *req.DDNSInterval
	}

	if err := s.db.UpdateAgent(agent); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update agent")
		return
	}

	if req.ZoneIDs != nil {
		if err := s.db.SetAgentZones(id, *req.ZoneIDs); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to set agent zones")
			return
		}
	}

	s.audit(r, "agent", id, "update", agent.Name)

	writeJSON(w, http.StatusOK, agent)
}

// DELETE /api/v1/agents/{id}
func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")

	if err := s.db.DeleteAgent(id); err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	s.audit(r, "agent", id, "delete", "")

	writeJSON(w, http.StatusOK, map[string]string{"message": "agent deleted"})
}

// GET /api/v1/agents/{id}/status
func (s *Server) handleAgentStatus(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")

	agent, err := s.db.GetAgent(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":                agent.ID,
		"status":            agent.Status,
		"last_seen":         agent.LastSeen,
		"public_ip":         agent.PublicIP,
		"version":           agent.Version,
		"caddy_running":     agent.CaddyRunning,
		"last_error":        agent.LastError,
		"proxy_detection":   agent.ProxyDetection,
		"proxy_detected_at": agent.ProxyDetectedAt,
	})
}

// fqdnError carries an HTTP status + message out of applyFQDNChange.
type fqdnError struct {
	code int
	msg  string
}

func (e *fqdnError) Error() string { return e.msg }

// applyFQDNChange validates and applies an FQDN (anchor hostname) override onto
// the agent in place. A blank fqdn or one equal to the current value is a no-op.
// When the anchor actually moves, it clears the stored A-record id (so the
// reconciler recreates the record at the new name) and any stale last_error.
func (s *Server) applyFQDNChange(agent *models.Agent, fqdn string) *fqdnError {
	fqdn = strings.TrimSpace(strings.ToLower(fqdn))
	if fqdn == "" || fqdn == agent.FQDN {
		return nil
	}
	if !validFQDN(fqdn) {
		return &fqdnError{http.StatusBadRequest, "invalid FQDN: must be a hostname like edge1.example.com"}
	}
	if existing, err := s.db.GetAgentByFQDN(fqdn); err == nil && existing != nil && existing.ID != agent.ID {
		return &fqdnError{http.StatusConflict, "another agent already uses this FQDN"}
	}
	agent.FQDN = fqdn
	agent.DNSRecordID = "" // anchor moved — recreate the A record at the new name
	agent.DNSError = ""    // clear any stale "FQDN outside zone" error
	return nil
}

// validFQDN reports whether s is a syntactically valid multi-label DNS hostname
// (e.g. edge1.example.com). It is deliberately permissive but rejects schemes,
// ports, whitespace, single-label names, and malformed labels.
func validFQDN(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false // require at least one dot, so it lives inside a zone
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			isLetter := c >= 'a' && c <= 'z'
			isDigit := c >= '0' && c <= '9'
			if !isLetter && !isDigit && c != '-' {
				return false
			}
		}
	}
	return true
}

// POST /api/v1/agents/{id}/heartbeat — called BY the agent.
func (s *Server) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")

	// Verify the calling agent matches the target ID
	callerID, _ := r.Context().Value(ctxAgentID).(string)
	if callerID != id {
		writeError(w, http.StatusForbidden, "agent can only heartbeat for itself")
		return
	}

	var req struct {
		PublicIP string `json:"public_ip"`
		Version  string `json:"version"`
		// CaddyRunning and LastError are the agent's self-report. CaddyRunning is
		// a pointer so an older agent that omits it doesn't get read as "down".
		CaddyRunning *bool  `json:"caddy_running"`
		LastError    string `json:"last_error"`
		// ProxyDetection is the agent's read-only Phase-0 detection, re-reported on
		// each beat (§13.0/§2.1/§9). Stored on the agent row; nil leaves it as-is.
		ProxyDetection *models.ProxyDetection `json:"proxy_detection"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Snapshot the prior state so we can detect and audit transitions.
	prev, err := s.db.GetAgent(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	caddyRunning := prev.CaddyRunning
	if req.CaddyRunning != nil {
		caddyRunning = *req.CaddyRunning
	}

	if err := s.db.UpdateAgentHealth(id, req.PublicIP, req.LastError, caddyRunning); err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	// Persist the agent's read-only proxy detection (§13.0). It's a narrow update
	// so it doesn't clobber operator-owned fields or the health self-report just
	// written above. Only update when the agent actually reported detection.
	if req.ProxyDetection != nil {
		if uerr := s.db.UpdateAgentDetection(id, req.ProxyDetection); uerr != nil {
			log.Printf("failed to update agent %s detection: %v", id, uerr)
		}
	}

	// A heartbeat is proof of life: an agent the orchestrator had marked offline
	// is back. Adoption state itself is owned by the operator, so we only flip
	// the offline<->adopted axis here, never pending->adopted.
	if prev.Status == models.AgentStatusOffline {
		if uerr := s.db.UpdateAgentStatus(id, models.AgentStatusAdopted); uerr != nil {
			log.Printf("failed to mark agent %s back online: %v", id, uerr)
		} else {
			s.audit(r, "agent", id, "status_change", "agent came back online (heartbeat)")
		}
	}

	// Audit health-state changes so operators can see, e.g., Caddy going down.
	if req.CaddyRunning != nil && prev.CaddyRunning != caddyRunning {
		s.audit(r, "agent", id, "caddy_state", fmt.Sprintf("caddy_running=%t", caddyRunning))
	}
	if prev.LastError != req.LastError && req.LastError != "" {
		s.audit(r, "agent", id, "agent_error", req.LastError)
	}

	// Re-read the fresh row (UpdateAgentHealth + the offline->adopted flip both
	// wrote to it) before any further mutation, so we don't clobber them.
	agent, err := s.db.GetAgent(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get agent status")
		return
	}

	// Update version if it changed.
	if req.Version != "" && agent.Version != req.Version {
		agent.Version = req.Version
		if uerr := s.db.UpdateAgent(agent); uerr != nil {
			log.Printf("failed to update agent version: %v", uerr)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    agent.Status,
		"last_seen": agent.LastSeen,
	})
}

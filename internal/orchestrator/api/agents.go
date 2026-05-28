package api

import (
	"net/http"
	"strings"

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
	writeJSON(w, http.StatusOK, agents)
}

// POST /api/v1/agents/register — called BY the agent during adoption.
// No auth required (agent doesn't have a token yet — it's registering one).
func (s *Server) handleRegisterAgent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       string `json:"id"`
		FQDN     string `json:"fqdn"`
		Token    string `json:"token"`
		APIURL   string `json:"api_url"`
		PublicIP string `json:"public_ip"`
		Version  string `json:"version"`
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
		PublicIP:   req.PublicIP,
		Status:    models.AgentStatusPending,
		Version:   req.Version,
	}

	if err := s.db.CreateAgent(agent); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeError(w, http.StatusConflict, "agent already registered")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to register agent")
		return
	}

	s.audit(r, "agent", agent.ID, "register", agent.FQDN)

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
		Name         string          `json:"name"`
		ProviderID   string          `json:"provider_id"`
		DNSMode      models.DNSMode  `json:"dns_mode"`
		DDNSInterval int             `json:"ddns_interval"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Name != "" {
		agent.Name = req.Name
	}
	if req.ProviderID != "" {
		if _, err := s.db.GetProvider(req.ProviderID); err != nil {
			writeError(w, http.StatusBadRequest, "provider not found")
			return
		}
		agent.ProviderID = req.ProviderID
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
		ProviderID   *string         `json:"provider_id"`
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
	if req.ProviderID != nil {
		if _, err := s.db.GetProvider(*req.ProviderID); err != nil {
			writeError(w, http.StatusBadRequest, "provider not found")
			return
		}
		agent.ProviderID = *req.ProviderID
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
		"id":        agent.ID,
		"status":    agent.Status,
		"last_seen": agent.LastSeen,
		"public_ip": agent.PublicIP,
		"version":   agent.Version,
	})
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
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.db.UpdateAgentHeartbeat(id, req.PublicIP); err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	// Update version if provided
	if req.Version != "" {
		agent, err := s.db.GetAgent(id)
		if err == nil && agent.Version != req.Version {
			agent.Version = req.Version
			s.db.UpdateAgent(agent)
		}
	}

	// Return current agent status
	agent, err := s.db.GetAgent(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get agent status")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    agent.Status,
		"last_seen": agent.LastSeen,
	})
}

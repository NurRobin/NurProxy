package api

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// GET /api/v1/agents/{id}/servers
func (s *Server) handleListServers(w http.ResponseWriter, r *http.Request) {
	agentID := pathParam(r, "id")

	// Verify agent exists
	if _, err := s.db.GetAgent(agentID); err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	servers, err := s.db.ListServersByAgent(agentID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list servers")
		return
	}
	if servers == nil {
		servers = []models.Server{}
	}
	writeJSON(w, http.StatusOK, servers)
}

// POST /api/v1/agents/{id}/servers
func (s *Server) handleCreateServer(w http.ResponseWriter, r *http.Request) {
	agentID := pathParam(r, "id")

	// Verify agent exists
	if _, err := s.db.GetAgent(agentID); err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	var req struct {
		Name    string `json:"name"`
		Address string `json:"address"`
		Notes   string `json:"notes"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Name == "" || req.Address == "" {
		writeError(w, http.StatusBadRequest, "name and address are required")
		return
	}

	srv := &models.Server{
		ID:      uuid.New().String(),
		AgentID: agentID,
		Name:    req.Name,
		Address: req.Address,
		Notes:   req.Notes,
	}

	if err := s.db.CreateServer(srv); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create server")
		return
	}

	s.audit(r, "server", srv.ID, "create", srv.Name)

	writeJSON(w, http.StatusCreated, srv)
}

// PUT /api/v1/servers/{id}
func (s *Server) handleUpdateServer(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")

	srv, err := s.db.GetServer(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}

	var req struct {
		Name    *string `json:"name"`
		Address *string `json:"address"`
		Notes   *string `json:"notes"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Name != nil {
		srv.Name = *req.Name
	}
	if req.Address != nil {
		srv.Address = *req.Address
	}
	if req.Notes != nil {
		srv.Notes = *req.Notes
	}

	if err := s.db.UpdateServer(srv); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update server")
		return
	}

	s.audit(r, "server", id, "update", srv.Name)

	writeJSON(w, http.StatusOK, srv)
}

// DELETE /api/v1/servers/{id}
func (s *Server) handleDeleteServer(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")

	// Refuse while domains still reference this server: the ON DELETE CASCADE would
	// orphan their DNS records/certs ahead of the reconciler teardown (see
	// guardChildDomains).
	if s.guardChildDomains(w, "server", db.DomainFilter{ServerID: id}) {
		return
	}

	if err := s.db.DeleteServer(id); err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}

	s.audit(r, "server", id, "delete", "")

	writeJSON(w, http.StatusOK, map[string]string{"message": "server deleted"})
}

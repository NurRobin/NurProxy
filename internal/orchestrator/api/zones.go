package api

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// GET /api/v1/zones
func (s *Server) handleListAllZones(w http.ResponseWriter, r *http.Request) {
	zones, err := s.db.ListZones()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list zones")
		return
	}
	if zones == nil {
		zones = []models.Zone{}
	}
	writeJSON(w, http.StatusOK, zones)
}

// POST /api/v1/zones
func (s *Server) handleCreateZone(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProviderID string `json:"provider_id"`
		ExternalID string `json:"external_id"`
		Name       string `json:"name"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.ProviderID == "" || req.Name == "" {
		writeError(w, http.StatusBadRequest, "provider_id and name are required")
		return
	}

	// Validate provider exists
	if _, err := s.db.GetProvider(req.ProviderID); err != nil {
		writeError(w, http.StatusBadRequest, "provider not found")
		return
	}

	z := &models.Zone{
		ID:         uuid.New().String(),
		ProviderID: req.ProviderID,
		ExternalID: req.ExternalID,
		Name:       req.Name,
	}

	if err := s.db.CreateZone(z); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create zone")
		return
	}

	s.audit(r, "zone", z.ID, "create", z.Name)

	writeJSON(w, http.StatusCreated, map[string]string{
		"id":   z.ID,
		"name": z.Name,
	})
}

// POST /api/v1/zones/batch
func (s *Server) handleCreateZonesBatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProviderID string `json:"provider_id"`
		Zones      []struct {
			ExternalID string `json:"external_id"`
			Name       string `json:"name"`
		} `json:"zones"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.ProviderID == "" || len(req.Zones) == 0 {
		writeError(w, http.StatusBadRequest, "provider_id and zones are required")
		return
	}

	// Validate provider exists
	if _, err := s.db.GetProvider(req.ProviderID); err != nil {
		writeError(w, http.StatusBadRequest, "provider not found")
		return
	}

	type zoneResp struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	var resp []zoneResp

	for _, zr := range req.Zones {
		z := &models.Zone{
			ID:         uuid.New().String(),
			ProviderID: req.ProviderID,
			ExternalID: zr.ExternalID,
			Name:       zr.Name,
		}
		if err := s.db.CreateZone(z); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to create zone: "+zr.Name)
			return
		}
		s.audit(r, "zone", z.ID, "create", z.Name)
		resp = append(resp, zoneResp{ID: z.ID, Name: z.Name})
	}

	writeJSON(w, http.StatusCreated, resp)
}

// DELETE /api/v1/zones/{id}
func (s *Server) handleDeleteZone(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")

	if err := s.db.DeleteZone(id); err != nil {
		writeError(w, http.StatusNotFound, "zone not found")
		return
	}

	s.audit(r, "zone", id, "delete", "")

	writeJSON(w, http.StatusOK, map[string]string{"message": "zone deleted"})
}

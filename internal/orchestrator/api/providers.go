package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"github.com/NurRobin/NurProxy/internal/provider"
	"github.com/NurRobin/NurProxy/internal/provider/dryrun"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// dnsProvider wraps a resolved provider in the dry-run sandbox decorator when the
// orchestrator runs in DNS sandbox mode, so provider setup (validate + list
// zones) works against the in-memory mock instead of needing live credentials
// (#93). Returns p unchanged on a normal instance.
func (s *Server) dnsProvider(p provider.Provider) provider.Provider {
	if s.dnsDryRun {
		return dryrun.Wrap(p, nil)
	}
	return p
}

// GET /api/v1/providers
func (s *Server) handleListProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := s.db.ListProviders()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list providers")
		return
	}
	if providers == nil {
		providers = []models.Provider{}
	}
	// Strip config from response (it's tagged json:"-" but just to be safe)
	type providerResponse struct {
		ID        string `json:"id"`
		Type      string `json:"type"`
		Name      string `json:"name"`
		IsDefault bool   `json:"is_default"`
		CreatedAt string `json:"created_at"`
	}
	resp := make([]providerResponse, len(providers))
	for i, p := range providers {
		resp[i] = providerResponse{
			ID:        p.ID,
			Type:      p.Type,
			Name:      p.Name,
			IsDefault: p.IsDefault,
			CreatedAt: p.CreatedAt.String(),
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/v1/providers
func (s *Server) handleCreateProvider(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type   string          `json:"type"`
		Name   string          `json:"name"`
		Config json.RawMessage `json:"config"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Type == "" || req.Name == "" {
		writeError(w, http.StatusBadRequest, "type and name are required")
		return
	}
	if len(req.Config) == 0 {
		writeError(w, http.StatusBadRequest, "config is required")
		return
	}

	// Validate config via provider
	prov, err := provider.Get(req.Type)
	if err != nil {
		writeError(w, http.StatusBadRequest, "unknown provider type: "+req.Type)
		return
	}
	prov = s.dnsProvider(prov)
	if err := prov.ValidateConfig(context.Background(), req.Config); err != nil {
		writeError(w, http.StatusBadRequest, "config validation failed: "+err.Error())
		return
	}

	p := &models.Provider{
		ID:     uuid.New().String(),
		Type:   req.Type,
		Name:   req.Name,
		Config: string(req.Config),
	}

	if err := s.db.CreateProvider(p); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create provider")
		return
	}

	s.audit(r, "provider", p.ID, "create", p.Name)

	writeJSON(w, http.StatusCreated, map[string]string{
		"id":   p.ID,
		"name": p.Name,
	})
}

// GET /api/v1/providers/{id}
func (s *Server) handleGetProvider(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	p, err := s.db.GetProvider(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "provider not found")
		return
	}
	// Strip config
	p.Config = ""
	writeJSON(w, http.StatusOK, p)
}

// PUT /api/v1/providers/{id}
func (s *Server) handleUpdateProvider(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")

	existing, err := s.db.GetProvider(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "provider not found")
		return
	}

	var req struct {
		Name   *string          `json:"name"`
		Config *json.RawMessage `json:"config"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Config != nil {
		// Validate new config
		prov, err := provider.Get(existing.Type)
		if err != nil {
			writeError(w, http.StatusBadRequest, "unknown provider type")
			return
		}
		prov = s.dnsProvider(prov)
		if err := prov.ValidateConfig(context.Background(), *req.Config); err != nil {
			writeError(w, http.StatusBadRequest, "config validation failed: "+err.Error())
			return
		}
		existing.Config = string(*req.Config)
	}

	if err := s.db.UpdateProvider(existing); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update provider")
		return
	}

	s.audit(r, "provider", id, "update", existing.Name)

	writeJSON(w, http.StatusOK, map[string]string{"message": "provider updated"})
}

// DELETE /api/v1/providers/{id}
func (s *Server) handleDeleteProvider(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")

	if err := s.db.DeleteProvider(id); err != nil {
		writeError(w, http.StatusNotFound, "provider not found")
		return
	}

	s.audit(r, "provider", id, "delete", "")

	writeJSON(w, http.StatusOK, map[string]string{"message": "provider deleted"})
}

// POST /api/v1/providers/test
func (s *Server) handleTestProvider(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type   string          `json:"type"`
		Config json.RawMessage `json:"config"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Type == "" {
		writeError(w, http.StatusBadRequest, "type is required")
		return
	}

	prov, err := provider.Get(req.Type)
	if err != nil {
		writeError(w, http.StatusBadRequest, "unknown provider type: "+req.Type)
		return
	}
	prov = s.dnsProvider(prov)

	if err := prov.ValidateConfig(context.Background(), req.Config); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"valid":   false,
			"message": err.Error(),
		})
		return
	}

	// On success, also return available zones so the frontend can offer selection
	zones, err := prov.ListZones(context.Background(), req.Config)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"valid":   true,
			"message": "Token is valid, but failed to list zones: " + err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":   true,
		"message": "Token is valid",
		"zones":   zones,
	})
}

// GET /api/v1/providers/{id}/zones
func (s *Server) handleListProviderZones(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")

	zones, err := s.db.ListZonesByProvider(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list zones")
		return
	}
	if zones == nil {
		zones = []models.Zone{}
	}

	writeJSON(w, http.StatusOK, zones)
}

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/NurRobin/NurProxy/internal/discovery"
	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/orchestrator/discoverysvc"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// discoveryTestTimeout bounds a connection test from the dashboard.
const discoveryTestTimeout = 20 * time.Second

// SetDiscovery wires the discovery service (#25). NewServer installs a
// non-dry-run service so tests and embedders always have one.
func (s *Server) SetDiscovery(svc *discoverysvc.Service) {
	s.discovery = svc
}

func (s *Server) auditor(r *http.Request) discoverysvc.Auditor {
	return func(entityType, entityID, action, details string) {
		s.audit(r, entityType, entityID, action, details)
	}
}

// discoverySourceResponse is a source as the API returns it: no config, only
// a secret-free summary of it.
type discoverySourceResponse struct {
	models.DiscoverySource
	TypeName string `json:"type_name"`
	Summary  string `json:"summary"`
	// Candidates is the number of machines in the last result; Missing the
	// number of imported servers the source no longer reports.
	Candidates int `json:"candidates"`
	Imported   int `json:"imported"`
	Missing    int `json:"missing"`
}

func (s *Server) sourceResponse(src *models.DiscoverySource) discoverySourceResponse {
	resp := discoverySourceResponse{DiscoverySource: *src, TypeName: src.Type}
	resp.Config = ""
	if d, err := s.discovery.Discoverer(src.Type); err == nil {
		resp.TypeName = d.Info().Name
		resp.Summary = d.Summary(json.RawMessage(src.Config))
	}
	if v, err := s.discovery.View(src.ID); err == nil {
		resp.Candidates = len(v.Candidates)
		resp.Missing = len(v.Missing)
		for _, c := range v.Candidates {
			if c.ServerID != "" {
				resp.Imported++
			}
		}
	}
	return resp
}

// GET /api/v1/discovery/types
func (s *Server) handleListDiscoveryTypes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, discovery.List())
}

// GET /api/v1/discovery/sources
func (s *Server) handleListDiscoverySources(w http.ResponseWriter, r *http.Request) {
	sources, err := s.db.ListDiscoverySources()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list discovery sources")
		return
	}
	out := make([]discoverySourceResponse, 0, len(sources))
	for i := range sources {
		out = append(out, s.sourceResponse(&sources[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /api/v1/discovery/sources/{id}
func (s *Server) handleGetDiscoverySource(w http.ResponseWriter, r *http.Request) {
	src, ok := s.loadDiscoverySource(w, pathParam(r, "id"))
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.sourceResponse(src))
}

func (s *Server) loadDiscoverySource(w http.ResponseWriter, id string) (*models.DiscoverySource, bool) {
	src, err := s.db.GetDiscoverySource(id)
	if errors.Is(err, db.ErrDiscoverySourceNotFound) {
		writeError(w, http.StatusNotFound, "discovery source not found")
		return nil, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load discovery source")
		return nil, false
	}
	return src, true
}

// checkSourceConfig validates config statically and, unless skipTest, checks
// that the source answers. The error text is safe to show: discoverers never
// put the secret into errors.
func (s *Server) checkSourceConfig(ctx context.Context, d discovery.Discoverer, config json.RawMessage, skipTest bool) error {
	if err := d.ValidateConfig(config); err != nil {
		return err
	}
	if skipTest {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, discoveryTestTimeout)
	defer cancel()
	return d.Test(ctx, config)
}

// POST /api/v1/discovery/sources
func (s *Server) handleCreateDiscoverySource(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type         string          `json:"type"`
		Name         string          `json:"name"`
		Config       json.RawMessage `json:"config"`
		SyncInterval int             `json:"sync_interval"`
		// SkipTest saves the source without contacting it, e.g. when it is
		// not reachable yet.
		SkipTest bool `json:"skip_test"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Type == "" || req.Name == "" {
		writeError(w, http.StatusBadRequest, "type and name are required")
		return
	}
	if len(req.Config) == 0 {
		writeError(w, http.StatusBadRequest, "config is required")
		return
	}
	if !discoverysvc.ValidSyncInterval(req.SyncInterval) {
		writeError(w, http.StatusBadRequest, "sync_interval must be 0 (manual) or between 300 and 604800 seconds")
		return
	}
	d, err := s.discovery.Discoverer(req.Type)
	if err != nil {
		writeError(w, http.StatusBadRequest, "unknown discovery type: "+req.Type)
		return
	}
	if err := s.checkSourceConfig(r.Context(), d, req.Config, req.SkipTest); err != nil {
		writeError(w, http.StatusBadRequest, "config check failed: "+err.Error())
		return
	}
	src := &models.DiscoverySource{
		ID:           uuid.New().String(),
		Type:         req.Type,
		Name:         req.Name,
		Config:       string(req.Config),
		SyncInterval: req.SyncInterval,
	}
	if err := s.db.CreateDiscoverySource(src); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create discovery source")
		return
	}
	s.audit(r, "discovery_source", src.ID, "create", src.Name+" ("+src.Type+")")
	writeJSON(w, http.StatusCreated, s.sourceResponse(src))
}

// PUT /api/v1/discovery/sources/{id}
//
// config is merged onto the stored config key by key, so a client can change
// one setting without resending the token secret.
func (s *Server) handleUpdateDiscoverySource(w http.ResponseWriter, r *http.Request) {
	src, ok := s.loadDiscoverySource(w, pathParam(r, "id"))
	if !ok {
		return
	}
	var req struct {
		Name         *string          `json:"name"`
		Config       *json.RawMessage `json:"config"`
		SyncInterval *int             `json:"sync_interval"`
		SkipTest     bool             `json:"skip_test"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			writeError(w, http.StatusBadRequest, "name must not be empty")
			return
		}
		src.Name = name
	}
	if req.SyncInterval != nil {
		if !discoverysvc.ValidSyncInterval(*req.SyncInterval) {
			writeError(w, http.StatusBadRequest, "sync_interval must be 0 (manual) or between 300 and 604800 seconds")
			return
		}
		src.SyncInterval = *req.SyncInterval
	}
	if req.Config != nil {
		d, err := s.discovery.Discoverer(src.Type)
		if err != nil {
			writeError(w, http.StatusBadRequest, "unknown discovery type: "+src.Type)
			return
		}
		merged, err := discovery.MergeConfig(json.RawMessage(src.Config), *req.Config, d.Info().SecretFields)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.checkSourceConfig(r.Context(), d, merged, req.SkipTest); err != nil {
			writeError(w, http.StatusBadRequest, "config check failed: "+err.Error())
			return
		}
		src.Config = string(merged)
	}
	if err := s.db.UpdateDiscoverySource(src); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update discovery source")
		return
	}
	s.audit(r, "discovery_source", src.ID, "update", src.Name)
	writeJSON(w, http.StatusOK, s.sourceResponse(src))
}

// DELETE /api/v1/discovery/sources/{id}
func (s *Server) handleDeleteDiscoverySource(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	if err := s.db.DeleteDiscoverySource(id); err != nil {
		if errors.Is(err, db.ErrDiscoverySourceNotFound) {
			writeError(w, http.StatusNotFound, "discovery source not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete discovery source")
		return
	}
	s.audit(r, "discovery_source", id, "delete", "")
	writeJSON(w, http.StatusOK, map[string]string{"message": "discovery source deleted"})
}

// POST /api/v1/discovery/test
//
// With source_id, config is merged onto that source's stored config, so the
// edit dialog can test without the secret.
func (s *Server) handleTestDiscoverySource(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type     string          `json:"type"`
		Config   json.RawMessage `json:"config"`
		SourceID string          `json:"source_id"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	config := req.Config
	if req.SourceID != "" {
		src, ok := s.loadDiscoverySource(w, req.SourceID)
		if !ok {
			return
		}
		req.Type = src.Type
		config = json.RawMessage(src.Config)
		if len(req.Config) > 0 {
			d, err := s.discovery.Discoverer(src.Type)
			if err != nil {
				writeError(w, http.StatusBadRequest, "unknown discovery type: "+src.Type)
				return
			}
			merged, err := discovery.MergeConfig(config, req.Config, d.Info().SecretFields)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			config = merged
		}
	}
	d, err := s.discovery.Discoverer(req.Type)
	if err != nil {
		writeError(w, http.StatusBadRequest, "unknown discovery type: "+req.Type)
		return
	}
	if err := s.checkSourceConfig(r.Context(), d, config, false); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "message": "Connection works"})
}

// POST /api/v1/discovery/sources/{id}/run
func (s *Server) handleRunDiscovery(w http.ResponseWriter, r *http.Request) {
	src, ok := s.loadDiscoverySource(w, pathParam(r, "id"))
	if !ok {
		return
	}
	view, err := s.discovery.Run(r.Context(), src.ID, s.auditor(r))
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// GET /api/v1/discovery/sources/{id}/candidates
func (s *Server) handleDiscoveryCandidates(w http.ResponseWriter, r *http.Request) {
	src, ok := s.loadDiscoverySource(w, pathParam(r, "id"))
	if !ok {
		return
	}
	view, err := s.discovery.View(src.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load discovery result")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// POST /api/v1/agents/{id}/servers/import
func (s *Server) handleImportServers(w http.ResponseWriter, r *http.Request) {
	agentID := pathParam(r, "id")
	if _, err := s.db.GetAgent(agentID); err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	var req struct {
		SourceID string                    `json:"source_id"`
		Items    []discoverysvc.ImportItem `json:"items"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.SourceID == "" {
		writeError(w, http.StatusBadRequest, "source_id is required")
		return
	}
	if _, ok := s.loadDiscoverySource(w, req.SourceID); !ok {
		return
	}
	res, err := s.discovery.Import(agentID, req.SourceID, req.Items, s.auditor(r))
	var invalid *discoverysvc.InvalidImportError
	if errors.As(err, &invalid) {
		writeError(w, http.StatusBadRequest, invalid.Msg)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to import servers")
		return
	}
	status := http.StatusOK
	if len(res.Created) > 0 {
		status = http.StatusCreated
	}
	writeJSON(w, status, res)
}

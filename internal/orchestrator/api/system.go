package api

import (
	"net/http"
	"strconv"

	"github.com/NurRobin/NurProxy/internal/shared/auth"
)

// GET /api/v1/health
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": s.version,
	})
}

// GET /api/v1/audit-log — supports ?limit=&offset= pagination.
func (s *Server) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	limit := 50
	offset := 0

	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}

	source := r.URL.Query().Get("source") // optional: ui|api|mcp|agent|system

	entries, total, err := s.db.ListAuditLogFiltered(source, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list audit log")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
		"source":  source,
	})
}

// GET /api/v1/api-key — reports whether an admin API key exists (never returns
// the key itself, only a masked preview).
func (s *Server) handleGetAPIKey(w http.ResponseWriter, r *http.Request) {
	key, err := s.db.GetSetting("admin_api_key")
	if err != nil || key == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"exists": false})
		return
	}
	masked := key
	if len(key) > 8 {
		masked = key[:4] + "…" + key[len(key)-4:]
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"exists": true, "masked": masked})
}

// POST /api/v1/api-key — generates (or regenerates) the admin API key and
// returns it once. The plaintext is only shown at creation time.
func (s *Server) handleGenerateAPIKey(w http.ResponseWriter, r *http.Request) {
	key, err := auth.GenerateAPIKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate API key")
		return
	}
	if err := s.db.SetSetting("admin_api_key", key); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save API key")
		return
	}
	s.audit(r, "system", "admin", "generate_api_key", "admin API key generated")
	writeJSON(w, http.StatusCreated, map[string]string{"api_key": key})
}

// DELETE /api/v1/api-key — revokes the admin API key.
func (s *Server) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	if err := s.db.SetSetting("admin_api_key", ""); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to revoke API key")
		return
	}
	s.audit(r, "system", "admin", "revoke_api_key", "admin API key revoked")
	writeJSON(w, http.StatusOK, map[string]string{"message": "API key revoked"})
}

// GET /api/v1/settings
func (s *Server) handleListSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.db.ListSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list settings")
		return
	}

	// Filter out sensitive settings
	filtered := make([]map[string]interface{}, 0, len(settings))
	for _, setting := range settings {
		if setting.Key == "admin_password_hash" || setting.Key == "admin_api_key" || setting.Key == sessionSecretSetting {
			continue
		}
		filtered = append(filtered, map[string]interface{}{
			"key":        setting.Key,
			"value":      setting.Value,
			"updated_at": setting.UpdatedAt,
		})
	}

	writeJSON(w, http.StatusOK, filtered)
}

// PUT /api/v1/settings/{key}
func (s *Server) handleUpdateSetting(w http.ResponseWriter, r *http.Request) {
	key := pathParam(r, "key")
	if key == "" {
		writeError(w, http.StatusBadRequest, "setting key is required")
		return
	}

	// Prevent updating sensitive settings via this endpoint
	if key == "admin_password_hash" {
		writeError(w, http.StatusForbidden, "cannot update password via settings endpoint")
		return
	}
	if key == "admin_api_key" {
		writeError(w, http.StatusForbidden, "use the /api/v1/api-key endpoint to manage the API key")
		return
	}
	if key == sessionSecretSetting {
		writeError(w, http.StatusForbidden, "the session secret is managed internally and cannot be set")
		return
	}

	var req struct {
		Value string `json:"value"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.db.SetSetting(key, req.Value); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update setting")
		return
	}

	s.audit(r, "setting", key, "update", "")

	writeJSON(w, http.StatusOK, map[string]string{
		"key":   key,
		"value": req.Value,
	})
}

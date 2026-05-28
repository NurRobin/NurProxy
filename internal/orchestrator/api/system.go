package api

import (
	"net/http"
	"strconv"
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

	entries, total, err := s.db.ListAuditLog(limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list audit log")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
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
		if setting.Key == "admin_password_hash" {
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

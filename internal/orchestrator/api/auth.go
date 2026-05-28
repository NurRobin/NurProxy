package api

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/auth"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// GET /api/v1/auth/status — returns authentication state.
func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	// Check if setup is needed
	hash, err := s.db.GetSetting("admin_password_hash")
	if err != nil || hash == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"setup_required": true,
			"authenticated":  false,
		})
		return
	}

	// Check if current request has a valid session
	authenticated := false
	if cookie, err := r.Cookie("nurproxy_session"); err == nil {
		if _, err := s.sessions.Verify(cookie.Value); err == nil {
			authenticated = true
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"setup_required": false,
		"authenticated":  authenticated,
	})
}

// POST /api/v1/auth/setup — first-time admin password setup.
// Only works when no admin_password_hash exists in settings.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	// Check if already set up
	existing, err := s.db.GetSetting("admin_password_hash")
	if err == nil && existing != "" {
		writeError(w, http.StatusConflict, "admin password already configured")
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "password is required")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	if err := s.db.SetSetting("admin_password_hash", hash); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save password")
		return
	}

	// Create session
	s.setSessionCookie(w)

	// Audit log
	if err := s.db.InsertAuditLog(&models.AuditLogEntry{
		EntityType: "system",
		EntityID:   "setup",
		Action:     "setup",
		Actor:      "admin",
		Details:    "initial admin password configured",
	}); err != nil {
		log.Printf("failed to insert audit log: %v", err)
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "setup complete"})
}

// POST /api/v1/auth/login — admin login.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "password is required")
		return
	}

	hash, err := s.db.GetSetting("admin_password_hash")
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if err := auth.CheckPassword(hash, req.Password); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	s.setSessionCookie(w)

	writeJSON(w, http.StatusOK, map[string]string{"message": "logged in"})
}

// POST /api/v1/auth/change-password — changes the admin password.
// Requires the current password and a new password of at least 8 characters.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.NewPassword == "" || req.CurrentPassword == "" {
		writeError(w, http.StatusBadRequest, "current_password and new_password are required")
		return
	}
	if len(req.NewPassword) < 8 {
		writeError(w, http.StatusBadRequest, "new password must be at least 8 characters")
		return
	}

	hash, err := s.db.GetSetting("admin_password_hash")
	if err != nil || hash == "" {
		writeError(w, http.StatusBadRequest, "admin password not configured")
		return
	}
	if err := auth.CheckPassword(hash, req.CurrentPassword); err != nil {
		writeError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}

	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	if err := s.db.SetSetting("admin_password_hash", newHash); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save password")
		return
	}

	s.audit(r, "system", "admin", "change_password", "admin password changed")
	writeJSON(w, http.StatusOK, map[string]string{"message": "password changed"})
}

// POST /api/v1/auth/logout — clears session cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "nurproxy_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

func (s *Server) setSessionCookie(w http.ResponseWriter) {
	token, _ := auth.GenerateSessionToken()
	signed := s.sessions.Sign(token)
	d := s.sessionDuration()
	http.SetCookie(w, &http.Cookie{
		Name:     "nurproxy_session",
		Value:    signed,
		Path:     "/",
		MaxAge:   int(d.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(d),
	})
}

// sessionDuration returns the configured session lifetime, read from the
// session_expiry_hours setting (default 168h = 7 days).
func (s *Server) sessionDuration() time.Duration {
	const def = 7 * 24 * time.Hour
	v, err := s.db.GetSetting("session_expiry_hours")
	if err != nil || v == "" {
		return def
	}
	hours, err := strconv.Atoi(v)
	if err != nil || hours <= 0 {
		return def
	}
	return time.Duration(hours) * time.Hour
}

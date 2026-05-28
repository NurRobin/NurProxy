package api

import (
	"log"
	"net/http"
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
	http.SetCookie(w, &http.Cookie{
		Name:     "nurproxy_session",
		Value:    signed,
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(7 * 24 * time.Hour),
	})
}

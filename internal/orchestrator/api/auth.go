package api

import (
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/auth"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// sessionVersionSetting holds a monotonically increasing server-side session
// version. Bumping it (logout / password change) invalidates every outstanding
// session cookie, because each signed token carries the version it was minted
// under and Verify rejects anything older. Stored in the settings table.
const sessionVersionSetting = "session_version"

// secureCookiesSetting gates the Secure attribute on the session cookie. When
// set to "true"/"1" Secure is forced on; "false"/"0" forces it off. When unset
// the cookie is Secure for any non-localhost request and plain for localhost, so
// HTTPS deployments behind a TLS-terminating proxy get Secure without breaking
// local http dev.
const secureCookiesSetting = "secure_cookies"

// currentSessionVersion reads the server-side session version (0 when unset).
func (s *Server) currentSessionVersion() int {
	v, err := s.db.GetSetting(sessionVersionSetting)
	if err != nil || v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// bumpSessionVersion increments the server-side session version, immediately
// invalidating every outstanding cookie. Used by logout and change-password so
// those actions take effect for live tokens rather than only nudging the
// client-side cookie.
func (s *Server) bumpSessionVersion() {
	next := s.currentSessionVersion() + 1
	if err := s.db.SetSetting(sessionVersionSetting, strconv.Itoa(next)); err != nil {
		log.Printf("failed to bump session version: %v", err)
	}
}

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
	s.setSessionCookie(w, r)

	// Audit log — bootstrap happens through the dashboard, so source is ui.
	if err := s.db.InsertAuditLog(&models.AuditLogEntry{
		EntityType: "system",
		EntityID:   "setup",
		Action:     "setup",
		Actor:      "admin",
		Source:     models.AuditSourceUI,
		Details:    "initial admin password configured",
	}); err != nil {
		log.Printf("failed to insert audit log: %v", err)
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "setup complete"})
}

// POST /api/v1/auth/login — admin login. Failed attempts are rate-limited per
// client IP to blunt online password guessing (bcrypt slows each attempt, but
// the lockout caps the total).
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if ok, retryAfter := s.loginLimiter.Allow(ip); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "too many failed login attempts; try again later")
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

	hash, err := s.db.GetSetting("admin_password_hash")
	if err != nil {
		s.loginLimiter.Fail(ip)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if err := auth.CheckPassword(hash, req.Password); err != nil {
		s.loginLimiter.Fail(ip)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	s.loginLimiter.Reset(ip)
	s.setSessionCookie(w, r)

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

	// Invalidate every outstanding session so a changed password forces re-login
	// everywhere (e.g. after a suspected credential compromise).
	s.bumpSessionVersion()

	s.audit(r, "system", "admin", "change_password", "admin password changed")
	writeJSON(w, http.StatusOK, map[string]string{"message": "password changed"})
}

// POST /api/v1/auth/logout — clears the session cookie and invalidates every
// outstanding session server-side. Clearing the cookie alone only logs out the
// calling browser; bumping the session version makes any copy of the token
// (including ones already exfiltrated) fail Verify immediately.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.bumpSessionVersion()
	http.SetCookie(w, &http.Cookie{
		Name:     "nurproxy_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.useSecureCookies(r),
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request) {
	token, _ := auth.GenerateSessionToken()
	signed := s.sessions.Sign(token)
	d := s.sessionDuration()
	http.SetCookie(w, &http.Cookie{
		Name:     "nurproxy_session",
		Value:    signed,
		Path:     "/",
		MaxAge:   int(d.Seconds()),
		HttpOnly: true,
		Secure:   s.useSecureCookies(r),
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(d),
	})
}

// useSecureCookies decides whether the session cookie carries the Secure
// attribute. An explicit secure_cookies setting wins; otherwise Secure is on for
// any non-localhost request (the production case: HTTPS terminated at a proxy)
// and off for localhost so plain-http local development keeps working.
func (s *Server) useSecureCookies(r *http.Request) bool {
	if v, err := s.db.GetSetting(secureCookiesSetting); err == nil && v != "" {
		switch v {
		case "true", "1":
			return true
		case "false", "0":
			return false
		}
	}
	return !requestIsLocalhost(r)
}

// requestIsLocalhost reports whether the request targets a loopback host, used
// to default Secure cookies off only for local development.
func requestIsLocalhost(r *http.Request) bool {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
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

package api

import (
	"context"
	"crypto/subtle"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/auth"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

type contextKey string

const (
	ctxActor   contextKey = "actor"
	ctxAgentID contextKey = "agent_id"
	ctxSource  contextKey = "source"
)

// requireAuth wraps a handler to require authentication.
// Checks: 1) session cookie, 2) Bearer token (admin API key), 3) agent token.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1) Session cookie → dashboard (UI)
		if cookie, err := r.Cookie("nurproxy_session"); err == nil {
			if _, err := s.sessions.Verify(cookie.Value); err == nil {
				ctx := context.WithValue(r.Context(), ctxActor, "admin")
				ctx = context.WithValue(ctx, ctxSource, models.AuditSourceUI)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// 2) Bearer token — admin API key → REST API
		if token := bearerToken(r); token != "" {
			apiKey, err := s.db.GetSetting("admin_api_key")
			if err == nil && apiKey != "" && subtle.ConstantTimeCompare([]byte(apiKey), []byte(token)) == 1 {
				ctx := context.WithValue(r.Context(), ctxActor, "api_key")
				ctx = context.WithValue(ctx, ctxSource, models.AuditSourceAPI)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// 3) Agent token
			agents, err := s.db.ListAgents()
			if err == nil {
				tokenHash := auth.HashToken(token)
				for _, a := range agents {
					if a.TokenHash == tokenHash {
						ctx := context.WithValue(r.Context(), ctxActor, "agent:"+a.ID)
						ctx = context.WithValue(ctx, ctxAgentID, a.ID)
						ctx = context.WithValue(ctx, ctxSource, models.AuditSourceAgent)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
				}
			}
		}

		writeError(w, http.StatusUnauthorized, "authentication required")
	}
}

// requireAgentAuth wraps a handler to require agent-specific auth.
func (s *Server) requireAgentAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "agent authentication required")
			return
		}

		agents, err := s.db.ListAgents()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list agents")
			return
		}

		tokenHash := auth.HashToken(token)
		for _, a := range agents {
			if a.TokenHash == tokenHash {
				ctx := context.WithValue(r.Context(), ctxActor, "agent:"+a.ID)
				ctx = context.WithValue(ctx, ctxAgentID, a.ID)
				ctx = context.WithValue(ctx, ctxSource, models.AuditSourceAgent)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		writeError(w, http.StatusUnauthorized, "invalid agent token")
	}
}

// corsMiddleware adds CORS headers. It allows any origin for header-based
// (Bearer API key) access but deliberately does NOT set
// Access-Control-Allow-Credentials: a wildcard origin combined with credentials
// is rejected by browsers anyway, and the dashboard is served from the same
// origin as the API, so its session cookie never needs a cross-origin grant.
// Keeping the two consistent removes the misconfiguration without losing any
// supported access path.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs requests.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, rw.statusCode, time.Since(start))
	})
}

// bearerToken extracts the token from the Authorization header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

// responseWriter wraps http.ResponseWriter to capture status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Flush delegates to the underlying writer so streaming responses (the agent
// SSE stream) keep working through the logging middleware wrapper.
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

package api

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/auth"
)

type contextKey string

const (
	ctxActor   contextKey = "actor"
	ctxAgentID contextKey = "agent_id"
)

// requireAuth wraps a handler to require authentication.
// Checks: 1) session cookie, 2) Bearer token (admin API key), 3) agent token.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1) Session cookie
		if cookie, err := r.Cookie("nurproxy_session"); err == nil {
			if _, err := s.sessions.Verify(cookie.Value); err == nil {
				ctx := context.WithValue(r.Context(), ctxActor, "admin")
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// 2) Bearer token — admin API key
		if token := bearerToken(r); token != "" {
			apiKey, err := s.db.GetSetting("admin_api_key")
			if err == nil && apiKey != "" && apiKey == token {
				ctx := context.WithValue(r.Context(), ctxActor, "api_key")
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
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		writeError(w, http.StatusUnauthorized, "invalid agent token")
	}
}

// corsMiddleware adds CORS headers.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

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

// setupCheck redirects to setup if no admin password configured.
func (s *Server) setupCheck(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, err := s.db.GetSetting("admin_password_hash")
		if err != nil {
			// No admin password set — only allow setup and health endpoints
			if r.URL.Path != "/api/v1/auth/setup" && r.URL.Path != "/api/v1/health" {
				writeJSON(w, http.StatusPreconditionRequired, map[string]string{
					"error": "initial setup required",
					"setup": "/api/v1/auth/setup",
				})
				return
			}
		}
		next.ServeHTTP(w, r)
	}
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

package api

import (
	"context"
	"log"
	"net/http"
	"net/url"
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

// requireAuth wraps an operator-only (admin) handler. It accepts EXACTLY two
// credentials: 1) a valid admin session cookie (dashboard) or 2) the admin API
// key as a Bearer token (REST API).
//
// It deliberately does NOT accept agent bearer tokens. Every route guarded by
// requireAuth is operator-only (providers, zones, domains, servers, settings,
// api-key, audit, agent management). Agent self-endpoints (register, heartbeat,
// stream, routes/ack, artifact/log/admin-op reporting) use requireAgentAuth
// instead, which scopes each agent to its own resources. Honoring an agent
// token here would let any leaked agent credential drive the whole control
// plane — a privilege escalation to full admin (H1).
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1) Session cookie → dashboard (UI)
		if cookie, err := r.Cookie("nurproxy_session"); err == nil {
			if _, err := s.sessions.Verify(cookie.Value); err == nil {
				if !cookieMutationOriginAllowed(r) {
					writeError(w, http.StatusForbidden, "cross-site cookie-authenticated mutation rejected")
					return
				}
				ctx := context.WithValue(r.Context(), ctxActor, "admin")
				ctx = context.WithValue(ctx, ctxSource, models.AuditSourceUI)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// 2) Bearer token — admin API key only → REST API. An agent token is NOT
		// a substitute here (see the doc comment above); it is rejected so a
		// leaked agent credential cannot reach admin routes.
		if token := bearerToken(r); token != "" {
			apiKey, err := s.db.GetSetting("admin_api_key")
			if err == nil && apiKey != "" {
				// The setting holds the key's SHA-256 (never the plaintext, so a
				// leaked DB cannot mint admin access); legacy pre-hashing rows hold
				// the plaintext and are upgraded in place on first use.
				if ok, legacy := auth.MatchesStoredAPIKey(apiKey, token); ok {
					if legacy {
						if err := s.db.SetSetting("admin_api_key", auth.HashToken(token)); err != nil {
							log.Printf("api-key: failed to upgrade legacy plaintext key to hash: %v", err)
						}
					}
					ctx := context.WithValue(r.Context(), ctxActor, "api_key")
					ctx = context.WithValue(ctx, ctxSource, models.AuditSourceAPI)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}
		}

		writeError(w, http.StatusUnauthorized, "authentication required")
	}
}

func cookieMutationOriginAllowed(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		if referer := r.Header.Get("Referer"); referer != "" {
			parsed, err := url.Parse(referer)
			if err != nil {
				return false
			}
			origin = parsed.Scheme + "://" + parsed.Host
		}
	}
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	expectedScheme := "http"
	if requestIsHTTPS(r) {
		expectedScheme = "https"
	}
	return strings.EqualFold(parsed.Scheme, expectedScheme) && strings.EqualFold(parsed.Host, r.Host)
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
				// Backfill the encrypted-at-rest token for rows that predate it
				// (migration 19 leaves token_enc empty): the verified plaintext is in
				// hand right now, and the reconciler's inbound fallback needs it. Once
				// per agent per process — never on the hot path after that.
				s.backfillAgentToken(a.ID, token)
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

// backfillAgentToken stores the encrypted-at-rest token for an agent whose row
// predates token_enc (empty after migration 19), using the plaintext bearer the
// agent just authenticated with. The sync.Map guard makes it a single DB
// round-trip per agent per process lifetime.
func (s *Server) backfillAgentToken(agentID, token string) {
	if _, done := s.tokenBackfilled.Load(agentID); done {
		return
	}
	stored, err := s.db.GetAgentToken(agentID)
	if err == nil && stored == "" {
		if err := s.db.SetAgentToken(agentID, token); err != nil {
			log.Printf("agent auth: failed to backfill encrypted token for %s: %v", agentID, err)
			return // retry on a later request
		}
	}
	s.tokenBackfilled.Store(agentID, true)
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

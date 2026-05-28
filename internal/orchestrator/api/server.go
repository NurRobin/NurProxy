package api

import (
	"net/http"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/auth"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// Server holds the API server state.
type Server struct {
	db       *db.DB
	version  string
	mux      *http.ServeMux
	sessions *auth.SessionManager
}

// NewServer creates a new API server and registers all routes.
func NewServer(database *db.DB, version string) *Server {
	s := &Server{
		db:       database,
		version:  version,
		mux:      http.NewServeMux(),
		sessions: auth.NewSessionManager([]byte("nurproxy-session-key-" + version)),
	}

	s.registerRoutes()
	return s
}

// Handler returns the mux wrapped with middleware.
func (s *Server) Handler() http.Handler {
	return loggingMiddleware(corsMiddleware(s.mux))
}

func (s *Server) registerRoutes() {
	// Health (no auth)
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)

	// Auth (no auth required)
	s.mux.HandleFunc("POST /api/v1/auth/setup", s.handleSetup)
	s.mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/v1/auth/logout", s.handleLogout)

	// Agent registration (no auth — agent is registering its token)
	s.mux.HandleFunc("POST /api/v1/agents/register", s.handleRegisterAgent)

	// Providers (auth required)
	s.mux.HandleFunc("GET /api/v1/providers", s.requireAuth(s.handleListProviders))
	s.mux.HandleFunc("POST /api/v1/providers", s.requireAuth(s.handleCreateProvider))
	s.mux.HandleFunc("POST /api/v1/providers/test", s.requireAuth(s.handleTestProvider))
	s.mux.HandleFunc("GET /api/v1/providers/{id}", s.requireAuth(s.handleGetProvider))
	s.mux.HandleFunc("PUT /api/v1/providers/{id}", s.requireAuth(s.handleUpdateProvider))
	s.mux.HandleFunc("DELETE /api/v1/providers/{id}", s.requireAuth(s.handleDeleteProvider))
	s.mux.HandleFunc("GET /api/v1/providers/{id}/zones", s.requireAuth(s.handleListZones))

	// Agents (auth required except heartbeat which uses agent auth)
	s.mux.HandleFunc("GET /api/v1/agents", s.requireAuth(s.handleListAgents))
	s.mux.HandleFunc("PUT /api/v1/agents/{id}", s.requireAuth(s.handleUpdateAgent))
	s.mux.HandleFunc("DELETE /api/v1/agents/{id}", s.requireAuth(s.handleDeleteAgent))
	s.mux.HandleFunc("PUT /api/v1/agents/{id}/adopt", s.requireAuth(s.handleAdoptAgent))
	s.mux.HandleFunc("PUT /api/v1/agents/{id}/reject", s.requireAuth(s.handleRejectAgent))
	s.mux.HandleFunc("GET /api/v1/agents/{id}/status", s.requireAuth(s.handleAgentStatus))
	s.mux.HandleFunc("POST /api/v1/agents/{id}/heartbeat", s.requireAgentAuth(s.handleAgentHeartbeat))

	// Servers (auth required)
	s.mux.HandleFunc("GET /api/v1/agents/{id}/servers", s.requireAuth(s.handleListServers))
	s.mux.HandleFunc("POST /api/v1/agents/{id}/servers", s.requireAuth(s.handleCreateServer))
	s.mux.HandleFunc("PUT /api/v1/servers/{id}", s.requireAuth(s.handleUpdateServer))
	s.mux.HandleFunc("DELETE /api/v1/servers/{id}", s.requireAuth(s.handleDeleteServer))

	// Domains (auth required)
	s.mux.HandleFunc("GET /api/v1/domains", s.requireAuth(s.handleListDomains))
	s.mux.HandleFunc("POST /api/v1/domains", s.requireAuth(s.handleCreateDomain))
	s.mux.HandleFunc("GET /api/v1/domains/{id}", s.requireAuth(s.handleGetDomain))
	s.mux.HandleFunc("PUT /api/v1/domains/{id}", s.requireAuth(s.handleUpdateDomain))
	s.mux.HandleFunc("DELETE /api/v1/domains/{id}", s.requireAuth(s.handleDeleteDomain))
	s.mux.HandleFunc("GET /api/v1/domains/{id}/config", s.requireAuth(s.handleGetDomainConfig))
	s.mux.HandleFunc("PUT /api/v1/domains/{id}/config", s.requireAuth(s.handleUpdateDomainConfig))
	s.mux.HandleFunc("POST /api/v1/domains/{id}/config/reset", s.requireAuth(s.handleResetDomainConfig))

	// System (auth required)
	s.mux.HandleFunc("GET /api/v1/audit-log", s.requireAuth(s.handleAuditLog))
	s.mux.HandleFunc("GET /api/v1/settings", s.requireAuth(s.handleListSettings))
	s.mux.HandleFunc("PUT /api/v1/settings/{key}", s.requireAuth(s.handleUpdateSetting))
}

// audit is a helper to insert an audit log entry.
func (s *Server) audit(r *http.Request, entityType, entityID, action, details string) {
	actor := "unknown"
	if a, ok := r.Context().Value(ctxActor).(string); ok {
		actor = a
	}
	s.db.InsertAuditLog(&models.AuditLogEntry{
		EntityType: entityType,
		EntityID:   entityID,
		Action:     action,
		Actor:      actor,
		Details:    details,
	})
}

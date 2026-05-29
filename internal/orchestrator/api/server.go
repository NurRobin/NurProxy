package api

import (
	"log"
	"net/http"

	"github.com/NurRobin/NurProxy/internal/orchestrator/agenthub"
	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/auth"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// RoutePusher computes an agent's desired routes and delivers them over its live
// stream. The reconciler implements it; API handlers call it to push config the
// instant a domain changes.
type RoutePusher interface {
	PushAgentRoutes(agentID string) error
}

// Server holds the API server state.
type Server struct {
	db       *db.DB
	version  string
	mux      *http.ServeMux
	sessions *auth.SessionManager
	hub      *agenthub.Hub
	pusher   RoutePusher
}

// SetAgentHub wires the live agent connection hub and the route pusher into the
// server, enabling the SSE stream endpoint and instant route delivery. When
// unset (e.g. in tests), the stream endpoint reports streaming unavailable and
// route changes fall back to the reconciler's periodic cycle.
func (s *Server) SetAgentHub(hub *agenthub.Hub, pusher RoutePusher) {
	s.hub = hub
	s.pusher = pusher
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
	s.mux.HandleFunc("GET /api/v1/auth/status", s.handleAuthStatus)
	s.mux.HandleFunc("POST /api/v1/auth/setup", s.handleSetup)
	s.mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/v1/auth/logout", s.handleLogout)
	s.mux.HandleFunc("POST /api/v1/auth/change-password", s.requireAuth(s.handleChangePassword))

	// Agent registration (no auth — agent is registering its token)
	s.mux.HandleFunc("POST /api/v1/agents/register", s.handleRegisterAgent)

	// Providers (auth required)
	s.mux.HandleFunc("GET /api/v1/providers", s.requireAuth(s.handleListProviders))
	s.mux.HandleFunc("POST /api/v1/providers", s.requireAuth(s.handleCreateProvider))
	s.mux.HandleFunc("POST /api/v1/providers/test", s.requireAuth(s.handleTestProvider))
	s.mux.HandleFunc("GET /api/v1/providers/{id}", s.requireAuth(s.handleGetProvider))
	s.mux.HandleFunc("PUT /api/v1/providers/{id}", s.requireAuth(s.handleUpdateProvider))
	s.mux.HandleFunc("DELETE /api/v1/providers/{id}", s.requireAuth(s.handleDeleteProvider))
	s.mux.HandleFunc("GET /api/v1/providers/{id}/zones", s.requireAuth(s.handleListProviderZones))

	// Zones (auth required)
	s.mux.HandleFunc("GET /api/v1/zones", s.requireAuth(s.handleListAllZones))
	s.mux.HandleFunc("POST /api/v1/zones", s.requireAuth(s.handleCreateZone))
	s.mux.HandleFunc("POST /api/v1/zones/batch", s.requireAuth(s.handleCreateZonesBatch))
	s.mux.HandleFunc("DELETE /api/v1/zones/{id}", s.requireAuth(s.handleDeleteZone))

	// Agents (auth required except heartbeat which uses agent auth)
	s.mux.HandleFunc("GET /api/v1/agents", s.requireAuth(s.handleListAgents))
	s.mux.HandleFunc("PUT /api/v1/agents/{id}", s.requireAuth(s.handleUpdateAgent))
	s.mux.HandleFunc("DELETE /api/v1/agents/{id}", s.requireAuth(s.handleDeleteAgent))
	s.mux.HandleFunc("PUT /api/v1/agents/{id}/adopt", s.requireAuth(s.handleAdoptAgent))
	s.mux.HandleFunc("PUT /api/v1/agents/{id}/reject", s.requireAuth(s.handleRejectAgent))
	s.mux.HandleFunc("GET /api/v1/agents/{id}/status", s.requireAuth(s.handleAgentStatus))
	s.mux.HandleFunc("POST /api/v1/agents/{id}/heartbeat", s.requireAgentAuth(s.handleAgentHeartbeat))
	// Live push channel: the agent dials out and holds this open; the
	// orchestrator pushes config down it (works behind NAT). Agent auth.
	s.mux.HandleFunc("GET /api/v1/agents/{id}/stream", s.requireAgentAuth(s.handleAgentStream))
	s.mux.HandleFunc("POST /api/v1/agents/{id}/routes/ack", s.requireAgentAuth(s.handleAgentRoutesAck))

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
	s.mux.HandleFunc("GET /api/v1/api-key", s.requireAuth(s.handleGetAPIKey))
	s.mux.HandleFunc("POST /api/v1/api-key", s.requireAuth(s.handleGenerateAPIKey))
	s.mux.HandleFunc("DELETE /api/v1/api-key", s.requireAuth(s.handleRevokeAPIKey))
}

// audit inserts an audit log entry, deriving the actor and source channel from
// the request's auth context (set by the auth middleware).
func (s *Server) audit(r *http.Request, entityType, entityID, action, details string) {
	source, _ := r.Context().Value(ctxSource).(string)
	s.auditAs(r, source, entityType, entityID, action, details)
}

// auditAs is like audit but records an explicit source. Used for endpoints that
// run without the auth middleware (e.g. agent registration), where the source
// can't be derived from context.
func (s *Server) auditAs(r *http.Request, source, entityType, entityID, action, details string) {
	actor := "unknown"
	if a, ok := r.Context().Value(ctxActor).(string); ok {
		actor = a
	}
	if err := s.db.InsertAuditLog(&models.AuditLogEntry{
		EntityType: entityType,
		EntityID:   entityID,
		Action:     action,
		Actor:      actor,
		Source:     source,
		Details:    details,
	}); err != nil {
		log.Printf("failed to insert audit log: %v", err)
	}
}

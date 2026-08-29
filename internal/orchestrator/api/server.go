package api

import (
	"context"
	"encoding/base64"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/agenthub"
	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/orchestrator/logbroker"
	"github.com/NurRobin/NurProxy/internal/orchestrator/tls"
	"github.com/NurRobin/NurProxy/internal/shared/auth"
	"github.com/NurRobin/NurProxy/internal/shared/crypto"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/ratelimit"
)

// sessionSecretSetting is the settings key under which the persistent HMAC
// secret used to sign session cookies is stored (base64 of 32 random bytes).
// It is masked from the settings API (see system.go) so it never leaves the box.
const sessionSecretSetting = "session_secret"

const (
	sessionSecretPersistAttempts = 3
	sessionSecretRetryDelay      = 50 * time.Millisecond
)

// RoutePusher computes an agent's desired routes and delivers them over its live
// stream. The reconciler implements it; API handlers call it to push config the
// instant a domain changes.
type RoutePusher interface {
	PushAgentRoutes(agentID string) error
}

// DNSTakeover forcibly aligns a domain's public DNS record with NurProxy's desired
// CNAME using the zone provider's stored credentials — the explicit admin override
// of the default "never touch a record we didn't create" stance, used to migrate an
// existing domain whose DNS predates NurProxy. The reconciler implements it.
type DNSTakeover interface {
	TakeoverDomainDNS(ctx context.Context, domID int64) error
}

// CertIssuer obtains a central TLS certificate for a host on demand (the §7
// first-issuance fast path). The TLS Renewer implements it; the domain-create
// handler kicks it asynchronously so a new central-TLS domain gets HTTPS within
// about a minute instead of waiting for the next renewal scan. Best-effort: a
// host that needs no cert is a no-op and the periodic scan is the backstop.
type CertIssuer interface {
	EnsureCertForHost(ctx context.Context, host string) error
}

// Server holds the API server state.
type Server struct {
	db       *db.DB
	version  string
	mux      *http.ServeMux
	sessions *auth.SessionManager
	hub      *agenthub.Hub
	pusher   RoutePusher
	takeover DNSTakeover
	issuer   CertIssuer
	logs     *logbroker.Broker
	// loginLimiter blunts online password guessing: too many failed logins from
	// one IP trip a temporary lockout.
	loginLimiter *ratelimit.Limiter

	// tokenBackfilled guards the once-per-agent encrypted-token backfill in
	// requireAgentAuth (see backfillAgentToken).
	tokenBackfilled sync.Map
	// recoveryMu serializes report transitions and manual repair admission so
	// two requests cannot create competing active operations from one diagnosis.
	recoveryMu sync.Mutex

	// dnsDryRun / acmeDryRun reflect sandbox mode so the health endpoint can tell
	// the dashboard to show a "dry-run — no external calls" banner (#93).
	dnsDryRun  bool
	acmeDryRun bool

	// caStatus reports the latest ACME-CA reachability observation (#91), wired
	// from the tls.CAProber. Nil (never wired, or ACME dry-run) omits the check.
	caStatus func() tls.CAStatus
}

// SetDryRun records whether the orchestrator is running in DNS/ACME sandbox mode
// so the health endpoint can surface it to the dashboard banner.
func (s *Server) SetDryRun(dns, acme bool) {
	s.dnsDryRun = dns
	s.acmeDryRun = acme
}

// SetCAStatus wires the ACME-CA reachability probe into the health endpoint
// (#91) so a CA-egress problem on the orchestrator host is visible in the
// dashboard instead of masquerading as per-domain issuance flakiness.
func (s *Server) SetCAStatus(status func() tls.CAStatus) {
	s.caStatus = status
}

// SetAgentHub wires the live agent connection hub and the route pusher into the
// server, enabling the SSE stream endpoint and instant route delivery. When
// unset (e.g. in tests), the stream endpoint reports streaming unavailable and
// route changes fall back to the reconciler's periodic cycle.
func (s *Server) SetAgentHub(hub *agenthub.Hub, pusher RoutePusher) {
	s.hub = hub
	s.pusher = pusher
}

// SetDNSTakeover wires the DNS-takeover capability (the admin override that lets
// NurProxy overwrite a conflicting foreign DNS record with the desired CNAME using
// the provider's own credentials). Optional: when unset, the takeover endpoint
// reports the capability unavailable.
func (s *Server) SetDNSTakeover(t DNSTakeover) {
	s.takeover = t
}

// SetCertIssuer wires the on-demand TLS issuer so domain creation can trigger
// first-issuance immediately. Optional: when unset, certs are issued only by the
// periodic renewal scan (the backstop).
func (s *Server) SetCertIssuer(issuer CertIssuer) {
	s.issuer = issuer
}

// NewServer creates a new API server and registers all routes.
func NewServer(database *db.DB, version string) *Server {
	s := &Server{
		db:       database,
		version:  version,
		mux:      http.NewServeMux(),
		sessions: auth.NewSessionManager(loadOrCreateSessionKey(database)),
		logs:     logbroker.New(),
		// 5 failed logins per IP within 15 min → locked out for 15 min.
		loginLimiter: ratelimit.New(5, 15*time.Minute, 15*time.Minute),
	}

	// Wire the session TTL and the server-side revocation-version provider ONCE,
	// at construction, before any handler can run. This makes token expiry and
	// revocation enforced from the very first request after a process restart.
	// Previously these were wired only lazily inside the auth handlers, so until
	// an auth handler happened to run, sm.version was nil and currentVersion()
	// returned 0 — which let a REVOKED cookie (version >= 1) pass the
	// "ver < currentVersion()" check on every protected route. Wiring here closes
	// that window. Doing it once (rather than on every auth call) also removes the
	// concurrent unsynchronized writes to sm.ttl/sm.version that raced with the
	// requireAuth Verify reads.
	s.sessions.WithTTLFunc(s.sessionDuration)
	s.sessions.WithVersion(func() int { return s.currentSessionVersion() })

	s.registerRoutes()
	return s
}

// loadOrCreateSessionKey returns the persistent HMAC key used to sign session
// cookies. It is generated once (32 cryptographically random bytes) and stored
// in the settings table so it survives restarts AND is unique per install.
// This replaces a key derived from a public constant plus the (publicly
// readable) version string, which let anyone who knew the version forge a valid
// session cookie and bypass login entirely. If the secret cannot be persisted,
// an ephemeral random key is used: still unforgeable, but sessions reset on the
// next restart.
func loadOrCreateSessionKey(database *db.DB) []byte {
	stored, getErr := database.GetSetting(sessionSecretSetting)
	if key, ok := decodeSessionKey(stored); getErr == nil && ok {
		return key
	}
	if getErr == nil && stored != "" {
		log.Printf("warning: stored session secret is malformed; regenerating (existing sessions will be invalidated)")
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		// crypto/rand is broken — unrecoverable for a security-sensitive key.
		log.Fatalf("failed to generate session secret: %v", err)
	}
	candidate := base64.StdEncoding.EncodeToString(key)
	var lastPersistErr error
	for attempt := 0; attempt < sessionSecretPersistAttempts; attempt++ {
		actual, _, err := database.CompareAndSwapSetting(sessionSecretSetting, stored, candidate)
		if err != nil {
			lastPersistErr = err
			if authoritative, readErr := database.GetSetting(sessionSecretSetting); readErr == nil {
				if persisted, ok := decodeSessionKey(authoritative); ok {
					return persisted
				}
				stored = authoritative
			}
		} else {
			if persisted, ok := decodeSessionKey(actual); ok {
				return persisted
			}
			stored = actual
		}
		if attempt+1 < sessionSecretPersistAttempts {
			time.Sleep(sessionSecretRetryDelay)
		}
	}
	if authoritative, err := database.GetSetting(sessionSecretSetting); err == nil {
		if persisted, ok := decodeSessionKey(authoritative); ok {
			return persisted
		}
	}
	if lastPersistErr != nil {
		log.Printf("warning: could not persist session secret after retries, sessions will reset on restart: %v", lastPersistErr)
		return key
	}
	log.Printf("warning: stored session secret remained malformed after atomic replacement; sessions will reset on restart")
	return key
}

func decodeSessionKey(encoded string) ([]byte, bool) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	return key, err == nil && len(key) == 32
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
	s.mux.HandleFunc("PUT /api/v1/agents/{id}/auto-reconcile", s.requireAuth(s.handleSetAutoReconcile))
	// Adoption/status poll: the agent dials out to confirm its own adoption
	// state (agent auth, scoped to itself). Not an admin route — honoring an
	// agent token here does not re-open the H1 escalation because the handler
	// rejects any id that is not the caller's own.
	s.mux.HandleFunc("GET /api/v1/agents/{id}/status", s.requireAgentAuth(s.handleAgentStatus))
	s.mux.HandleFunc("POST /api/v1/agents/{id}/heartbeat", s.requireAgentAuth(s.handleAgentHeartbeat))
	s.mux.HandleFunc("GET /api/v1/agents/{id}/diagnostics", s.requireAuth(s.handleListRecoveryDiagnostics))
	s.mux.HandleFunc("GET /api/v1/agents/{id}/repairs", s.requireAuth(s.handleListRepairs))
	s.mux.HandleFunc("POST /api/v1/agents/{id}/repairs", s.requireAuth(s.handleCreateRepair))
	s.mux.HandleFunc("POST /api/v1/agents/{id}/recovery/report", s.requireAgentAuth(s.handleRecoveryReport))
	s.mux.HandleFunc("POST /api/v1/agents/{id}/repairs/{opId}/ack", s.requireAgentAuth(s.handleRepairAck))
	s.mux.HandleFunc("PUT /api/v1/agents/{id}/safe-auto-repair", s.requireAuth(s.handleSetSafeAutoRepair))
	// Live push channel: the agent dials out and holds this open; the
	// orchestrator pushes config down it (works behind NAT). Agent auth.
	s.mux.HandleFunc("GET /api/v1/agents/{id}/stream", s.requireAgentAuth(s.handleAgentStream))
	s.mux.HandleFunc("POST /api/v1/agents/{id}/routes/ack", s.requireAgentAuth(s.handleAgentRoutesAck))
	// Adopted-config report (§17): the agent POSTs the host config it read off disk
	// (existing mode) into the central store. Agent auth, agent dials out.
	s.mux.HandleFunc("POST /api/v1/agents/{id}/artifacts/adopt", s.requireAgentAuth(s.handleAgentAdoptArtifacts))
	// On-demand log tail (§15): the agent POSTs tailed chunks up the control plane
	// (agent auth); the dashboard starts/polls/stops a tail (user auth). The tail
	// request rides the agent's existing stream — never an inbound probe.
	s.mux.HandleFunc("POST /api/v1/agents/{id}/logs/chunk", s.requireAgentAuth(s.handleAgentLogChunk))
	s.mux.HandleFunc("POST /api/v1/agents/{id}/logs/tail", s.requireAuth(s.handleStartLogTail))
	s.mux.HandleFunc("GET /api/v1/agents/{id}/logs/tail/{session}", s.requireAuth(s.handlePollLogTail))
	s.mux.HandleFunc("DELETE /api/v1/agents/{id}/logs/tail/{session}", s.requireAuth(s.handleStopLogTail))
	// Admin-change channel (§19): the dashboard prepares a pending op and gets a
	// one-time confirmation code (requireAuth); the agent claims it with its local
	// identity + the code and acks the outcome (requireAgentAuth, scoped to itself).
	s.mux.HandleFunc("POST /api/v1/agents/{id}/admin-ops", s.requireAuth(s.handlePrepareAdminOp))
	s.mux.HandleFunc("GET /api/v1/agents/{id}/admin-ops", s.requireAuth(s.handleListAdminOps))
	s.mux.HandleFunc("DELETE /api/v1/agents/{id}/admin-ops/{opId}", s.requireAuth(s.handleCancelAdminOp))
	s.mux.HandleFunc("POST /api/v1/agents/{id}/admin-ops/claim", s.requireAgentAuth(s.handleClaimAdminOp))
	s.mux.HandleFunc("POST /api/v1/agents/{id}/admin-ops/{opId}/ack", s.requireAgentAuth(s.handleAckAdminOp))

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
	s.mux.HandleFunc("POST /api/v1/domains/{id}/dns/takeover", s.requireAuth(s.handleDomainDNSTakeover))

	// Config artifacts + drift review (auth required, §11 Phase 3)
	s.mux.HandleFunc("GET /api/v1/artifacts", s.requireAuth(s.handleListArtifacts))
	s.mux.HandleFunc("POST /api/v1/artifacts/bulk", s.requireAuth(s.handleBulkArtifacts))
	s.mux.HandleFunc("GET /api/v1/artifacts/{id}", s.requireAuth(s.handleGetArtifact))
	s.mux.HandleFunc("GET /api/v1/artifacts/{id}/versions", s.requireAuth(s.handleListArtifactVersions))
	s.mux.HandleFunc("POST /api/v1/artifacts/{id}/accept", s.requireAuth(s.handleAcceptArtifact))
	s.mux.HandleFunc("POST /api/v1/artifacts/{id}/reject", s.requireAuth(s.handleRejectArtifact))
	s.mux.HandleFunc("POST /api/v1/artifacts/{id}/rollback", s.requireAuth(s.handleRollbackArtifact))
	// Config UX: the structured "mask" + raw edit + reset-to-model (§6, Phase 6)
	s.mux.HandleFunc("GET /api/v1/artifacts/{id}/mask", s.requireAuth(s.handleArtifactMask))
	s.mux.HandleFunc("PUT /api/v1/artifacts/{id}/content", s.requireAuth(s.handleEditArtifactContent))
	s.mux.HandleFunc("POST /api/v1/artifacts/{id}/reset-to-model", s.requireAuth(s.handleResetArtifactToModel))

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

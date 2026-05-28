package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/caddy"
	"github.com/NurRobin/NurProxy/internal/shared/auth"
)

// version is set at build time via ldflags.
var version = "dev"

// SetVersion allows the main package to inject the build version.
func SetVersion(v string) {
	version = v
}

// Server is the agent HTTP API server.
type Server struct {
	port        int
	caddyClient *caddy.Client
	token       string
	routes      map[string]json.RawMessage // domain -> route config
	mu          sync.RWMutex
	server      *http.Server
}

// New creates a new agent API server.
func New(port int, caddyClient *caddy.Client, token string) *Server {
	return &Server{
		port:        port,
		caddyClient: caddyClient,
		token:       token,
		routes:      make(map[string]json.RawMessage),
	}
}

// Start begins serving the agent API.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Public endpoints (no auth).
	mux.HandleFunc("/health", s.handleHealth)

	// Protected endpoints.
	mux.HandleFunc("/ip", s.authMiddleware(s.handleIP))
	mux.HandleFunc("/routes", s.authMiddleware(s.handleRoutes))
	mux.HandleFunc("/caddy/config", s.authMiddleware(s.handleCaddyConfig))

	s.server = &http.Server{
		Addr:              fmt.Sprintf(":%d", s.port),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("Agent API listening on :%d", s.port)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Agent API error: %v", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the server.
func (s *Server) Stop(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

// authMiddleware checks the Authorization header for a valid Bearer token.
func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing authorization header"})
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid authorization format"})
			return
		}

		// Accept either the plaintext token or its SHA-256 hash. The
		// orchestrator only persists the hashed token (never the plaintext),
		// so it authenticates to the agent by presenting the hash.
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token != s.token && token != auth.HashToken(s.token) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid token"})
			return
		}

		next(w, r)
	}
}

// handleHealth responds with the agent status.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": version,
	})
}

// handleIP responds with the agent's detected public IP.
func (s *Server) handleIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	ip, err := detectIP(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not detect IP"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ip": ip})
}

// handleRoutes dispatches based on HTTP method.
func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	// Check for /routes/{domain} pattern.
	path := strings.TrimPrefix(r.URL.Path, "/routes")
	if path != "" && path != "/" {
		domain := strings.TrimPrefix(path, "/")
		if r.Method == http.MethodDelete {
			s.handleDeleteRoute(w, r, domain)
			return
		}
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleListRoutes(w, r)
	case http.MethodPut:
		s.handleSyncRoutes(w, r)
	case http.MethodPost:
		s.handleAddRoute(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// handleListRoutes returns all routes.
func (s *Server) handleListRoutes(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	writeJSON(w, http.StatusOK, s.routes)
}

// routePayload is the expected shape for adding a single route.
type routePayload struct {
	Domain string          `json:"domain"`
	Route  json.RawMessage `json:"route"`
}

// handleSyncRoutes replaces all routes with the provided set.
func (s *Server) handleSyncRoutes(w http.ResponseWriter, r *http.Request) {
	var newRoutes map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&newRoutes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	ctx := r.Context()

	// Clear existing routes in Caddy.
	if err := s.caddyClient.ClearRoutes(ctx); err != nil {
		log.Printf("Warning: failed to clear Caddy routes: %v", err)
	}

	// Ensure server exists.
	if err := s.caddyClient.EnsureServer(ctx); err != nil {
		log.Printf("Warning: failed to ensure Caddy server: %v", err)
	}

	// Add all new routes.
	for domain, route := range newRoutes {
		if err := s.caddyClient.AddRoute(ctx, route); err != nil {
			log.Printf("Warning: failed to add route for %s: %v", domain, err)
		}
	}

	s.mu.Lock()
	s.routes = newRoutes
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{"status": "synced"})
}

// handleAddRoute adds or updates a single route.
func (s *Server) handleAddRoute(w http.ResponseWriter, r *http.Request) {
	var payload routePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	if payload.Domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain is required"})
		return
	}
	if payload.Route == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "route is required"})
		return
	}

	ctx := r.Context()

	// Ensure server exists.
	if err := s.caddyClient.EnsureServer(ctx); err != nil {
		log.Printf("Warning: failed to ensure Caddy server: %v", err)
	}

	// Remove old route if it exists.
	s.mu.RLock()
	_, exists := s.routes[payload.Domain]
	s.mu.RUnlock()

	if exists {
		routeID := "domain-" + slugify(payload.Domain)
		if err := s.caddyClient.RemoveRoute(ctx, routeID); err != nil {
			log.Printf("Warning: failed to remove old route for %s: %v", payload.Domain, err)
		}
	}

	// Add new route.
	if err := s.caddyClient.AddRoute(ctx, payload.Route); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to add route: " + err.Error()})
		return
	}

	s.mu.Lock()
	s.routes[payload.Domain] = payload.Route
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{"status": "added"})
}

// handleDeleteRoute removes a route by domain.
func (s *Server) handleDeleteRoute(w http.ResponseWriter, r *http.Request, domain string) {
	s.mu.RLock()
	_, exists := s.routes[domain]
	s.mu.RUnlock()

	if !exists {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "route not found"})
		return
	}

	routeID := "domain-" + slugify(domain)
	if err := s.caddyClient.RemoveRoute(r.Context(), routeID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to remove route: " + err.Error()})
		return
	}

	s.mu.Lock()
	delete(s.routes, domain)
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleCaddyConfig returns the raw Caddy config dump.
func (s *Server) handleCaddyConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	config, err := s.caddyClient.GetConfig(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get config: " + err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(config)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// slugify converts an FQDN into a safe ID string.
func slugify(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			b.WriteRune(c)
		} else {
			b.WriteRune('-')
		}
	}
	result := b.String()
	// Collapse consecutive dashes.
	for strings.Contains(result, "--") {
		result = strings.ReplaceAll(result, "--", "-")
	}
	return strings.Trim(result, "-")
}

// detectIP detects the agent's public IP using external services.
func detectIP(ctx context.Context) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}

	for _, svc := range services {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, svc, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		var buf [64]byte
		n, _ := resp.Body.Read(buf[:])
		if n > 0 {
			return strings.TrimSpace(string(buf[:n])), nil
		}
	}

	return "", fmt.Errorf("could not detect public IP")
}

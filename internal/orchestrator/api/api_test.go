package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/auth"
	"github.com/NurRobin/NurProxy/internal/shared/crypto"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

func testServer(t *testing.T) (*Server, *db.DB) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(":memory:", key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	srv := NewServer(database, "test")
	return srv, database
}

func doRequest(t *testing.T, handler http.Handler, method, path string, body interface{}, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var reqBody *bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reqBody = bytes.NewBuffer(b)
	} else {
		reqBody = &bytes.Buffer{}
	}

	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func doRequestWithAuth(t *testing.T, handler http.Handler, method, path string, body interface{}, token string) *httptest.ResponseRecorder {
	t.Helper()
	var reqBody *bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reqBody = bytes.NewBuffer(b)
	} else {
		reqBody = &bytes.Buffer{}
	}

	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// setupAdmin sets up the admin password and returns the session cookie.
func setupAdmin(t *testing.T, handler http.Handler) *http.Cookie {
	t.Helper()
	w := doRequest(t, handler, "POST", "/api/v1/auth/setup", map[string]string{
		"password": "testpassword123",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("setup failed: %d %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "nurproxy_session" {
			return c
		}
	}
	t.Fatal("no session cookie returned from setup")
	return nil
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

func TestHealth(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	w := doRequest(t, handler, "GET", "/api/v1/health", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status ok, got %s", resp["status"])
	}
	if resp["version"] != "test" {
		t.Errorf("expected version test, got %s", resp["version"])
	}
}

// ---------------------------------------------------------------------------
// Auth Setup Flow
// ---------------------------------------------------------------------------

func TestAuthSetupFlow(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	// Setup admin password
	w := doRequest(t, handler, "POST", "/api/v1/auth/setup", map[string]string{
		"password": "testpassword123",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("setup: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify session cookie was set
	var sessionCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "nurproxy_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("no session cookie set after setup")
	}

	// Setup should not work again
	w = doRequest(t, handler, "POST", "/api/v1/auth/setup", map[string]string{
		"password": "anotherpassword1",
	})
	if w.Code != http.StatusConflict {
		t.Fatalf("second setup: expected 409, got %d", w.Code)
	}

	// Login with correct password
	w = doRequest(t, handler, "POST", "/api/v1/auth/login", map[string]string{
		"password": "testpassword123",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("login: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Login with wrong password
	w = doRequest(t, handler, "POST", "/api/v1/auth/login", map[string]string{
		"password": "wrongpassword",
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong login: expected 401, got %d", w.Code)
	}

	// Use session cookie to access protected endpoint
	w = doRequest(t, handler, "GET", "/api/v1/providers", nil, sessionCookie)
	if w.Code != http.StatusOK {
		t.Fatalf("authed request: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Without auth should fail
	w = doRequest(t, handler, "GET", "/api/v1/providers", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthed request: expected 401, got %d", w.Code)
	}

	// Logout
	w = doRequest(t, handler, "POST", "/api/v1/auth/logout", nil, sessionCookie)
	if w.Code != http.StatusOK {
		t.Fatalf("logout: expected 200, got %d", w.Code)
	}
}

func TestAuthSetup_ShortPassword(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	w := doRequest(t, handler, "POST", "/api/v1/auth/setup", map[string]string{
		"password": "short",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short password, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Provider CRUD
// ---------------------------------------------------------------------------

func TestProviderCRUD(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)

	// Set up an API key for Bearer auth testing
	database.SetSetting("admin_api_key", "test-api-key-123")

	// Create provider (use Bearer token this time)
	// Note: Cloudflare ValidateConfig requires an actual API call, so we
	// use session cookie and test the DB directly for create.
	// For the test, we create directly in DB and test the API list/get/delete.
	p := &models.Provider{
		ID:       "test-prov-1",
		Type:     "cloudflare",
		Name:     "Test Provider",
		Config:   `{"api_token":"test"}`,
		ZoneID:   "zone-123",
		ZoneName: "example.com",
	}
	if err := database.CreateProvider(p); err != nil {
		t.Fatal(err)
	}

	// List providers
	w := doRequest(t, handler, "GET", "/api/v1/providers", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("list providers: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var providers []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&providers)
	if len(providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(providers))
	}

	// Get provider
	w = doRequest(t, handler, "GET", "/api/v1/providers/test-prov-1", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("get provider: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Get provider should NOT include config
	var provResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&provResp)
	if provResp["config"] != nil && provResp["config"] != "" {
		t.Error("config should not be in response")
	}

	// Get nonexistent provider
	w = doRequest(t, handler, "GET", "/api/v1/providers/nonexistent", nil, cookie)
	if w.Code != http.StatusNotFound {
		t.Fatalf("nonexistent provider: expected 404, got %d", w.Code)
	}

	// Delete provider
	w = doRequest(t, handler, "DELETE", "/api/v1/providers/test-prov-1", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("delete provider: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify deleted
	w = doRequest(t, handler, "GET", "/api/v1/providers/test-prov-1", nil, cookie)
	if w.Code != http.StatusNotFound {
		t.Fatalf("deleted provider: expected 404, got %d", w.Code)
	}

	// Test Bearer auth with API key
	w = doRequestWithAuth(t, handler, "GET", "/api/v1/providers", nil, "test-api-key-123")
	if w.Code != http.StatusOK {
		t.Fatalf("bearer auth: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Agent Registration + Adoption
// ---------------------------------------------------------------------------

func TestAgentRegistrationAndAdoption(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)

	// Create a provider for adoption
	p := &models.Provider{
		ID:       "prov-1",
		Type:     "cloudflare",
		Name:     "CF",
		Config:   `{"api_token":"test"}`,
		ZoneID:   "zone-1",
		ZoneName: "example.com",
	}
	database.CreateProvider(p)

	agentToken := "np_ag_testtoken123456789012345678901234567890123456789012345678"

	// Register agent (no auth required)
	w := doRequest(t, handler, "POST", "/api/v1/agents/register", map[string]string{
		"id":        "agent-1",
		"fqdn":      "edge1.example.com",
		"token":     agentToken,
		"api_url":   "http://edge1:8443",
		"public_ip": "1.2.3.4",
		"version":   "1.0.0",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var regResp map[string]string
	json.NewDecoder(w.Body).Decode(&regResp)
	if regResp["status"] != "pending" {
		t.Errorf("expected status pending, got %s", regResp["status"])
	}

	// List agents
	w = doRequest(t, handler, "GET", "/api/v1/agents", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("list agents: expected 200, got %d", w.Code)
	}
	var agents []models.Agent
	json.NewDecoder(w.Body).Decode(&agents)
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	if agents[0].Status != models.AgentStatusPending {
		t.Errorf("expected pending, got %s", agents[0].Status)
	}

	// Duplicate registration should fail
	w = doRequest(t, handler, "POST", "/api/v1/agents/register", map[string]string{
		"id":    "agent-1",
		"fqdn":  "edge1.example.com",
		"token": agentToken,
	})
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate register: expected 409, got %d: %s", w.Code, w.Body.String())
	}

	// Adopt agent
	w = doRequest(t, handler, "PUT", "/api/v1/agents/agent-1/adopt", map[string]interface{}{
		"name":        "Home Edge",
		"provider_id": "prov-1",
		"dns_mode":    "static",
	}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("adopt: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var adoptedAgent models.Agent
	json.NewDecoder(w.Body).Decode(&adoptedAgent)
	if adoptedAgent.Status != models.AgentStatusAdopted {
		t.Errorf("expected adopted, got %s", adoptedAgent.Status)
	}
	if adoptedAgent.Name != "Home Edge" {
		t.Errorf("expected name 'Home Edge', got %s", adoptedAgent.Name)
	}

	// Cannot adopt again
	w = doRequest(t, handler, "PUT", "/api/v1/agents/agent-1/adopt", map[string]interface{}{}, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("re-adopt: expected 400, got %d", w.Code)
	}

	// Get agent status
	w = doRequest(t, handler, "GET", "/api/v1/agents/agent-1/status", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("agent status: expected 200, got %d", w.Code)
	}

	// Heartbeat with agent token
	w = doRequestWithAuth(t, handler, "POST", "/api/v1/agents/agent-1/heartbeat",
		map[string]string{"public_ip": "5.6.7.8"}, agentToken)
	if w.Code != http.StatusOK {
		t.Fatalf("heartbeat: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify heartbeat updated IP
	agent, _ := database.GetAgent("agent-1")
	if agent.PublicIP != "5.6.7.8" {
		t.Errorf("expected public_ip 5.6.7.8, got %s", agent.PublicIP)
	}

	// Delete agent
	w = doRequest(t, handler, "DELETE", "/api/v1/agents/agent-1", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("delete agent: expected 200, got %d", w.Code)
	}
}

func TestAgentReject(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)

	p := &models.Provider{ID: "prov-1", Type: "cloudflare", Name: "CF", Config: `{"api_token":"test"}`}
	database.CreateProvider(p)

	// Register
	doRequest(t, handler, "POST", "/api/v1/agents/register", map[string]string{
		"id": "agent-2", "fqdn": "edge2.example.com", "token": "np_ag_test",
	})

	// Reject
	w := doRequest(t, handler, "PUT", "/api/v1/agents/agent-2/reject", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("reject: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Agent should be gone
	_, err := database.GetAgent("agent-2")
	if err == nil {
		t.Fatal("expected agent to be deleted after rejection")
	}
}

// ---------------------------------------------------------------------------
// Server CRUD
// ---------------------------------------------------------------------------

func TestServerCRUD(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)

	// Create provider and agent
	p := &models.Provider{ID: "prov-1", Type: "cloudflare", Name: "CF", Config: `{"api_token":"test"}`}
	database.CreateProvider(p)
	a := &models.Agent{
		ID: "agent-1", Name: "Agent", FQDN: "agent.example.com",
		ProviderID: "prov-1", DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted,
	}
	database.CreateAgent(a)

	// Create server
	w := doRequest(t, handler, "POST", "/api/v1/agents/agent-1/servers", map[string]string{
		"name":    "Backend 1",
		"address": "10.0.0.1",
		"notes":   "primary backend",
	}, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("create server: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var createdServer models.Server
	json.NewDecoder(w.Body).Decode(&createdServer)
	if createdServer.Name != "Backend 1" {
		t.Errorf("expected name 'Backend 1', got %s", createdServer.Name)
	}
	serverID := createdServer.ID

	// List servers for agent
	w = doRequest(t, handler, "GET", "/api/v1/agents/agent-1/servers", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("list servers: expected 200, got %d", w.Code)
	}
	var servers []models.Server
	json.NewDecoder(w.Body).Decode(&servers)
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}

	// Update server
	w = doRequest(t, handler, "PUT", "/api/v1/servers/"+serverID, map[string]interface{}{
		"name": "Updated Backend",
	}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("update server: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify update
	updated, _ := database.GetServer(serverID)
	if updated.Name != "Updated Backend" {
		t.Errorf("expected name 'Updated Backend', got %s", updated.Name)
	}

	// Delete server
	w = doRequest(t, handler, "DELETE", "/api/v1/servers/"+serverID, nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("delete server: expected 200, got %d", w.Code)
	}

	// Verify deleted
	_, err := database.GetServer(serverID)
	if err == nil {
		t.Fatal("expected server to be deleted")
	}
}

func TestServerCRUD_AgentNotFound(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)

	// Create server for nonexistent agent
	w := doRequest(t, handler, "POST", "/api/v1/agents/nonexistent/servers", map[string]string{
		"name": "Backend", "address": "10.0.0.1",
	}, cookie)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Domain CRUD + Filters
// ---------------------------------------------------------------------------

func TestDomainCRUD(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)

	// Set up provider, agent, server
	p := &models.Provider{ID: "prov-1", Type: "cloudflare", Name: "CF", Config: `{"api_token":"test"}`, ZoneName: "example.com"}
	database.CreateProvider(p)
	a := &models.Agent{
		ID: "agent-1", Name: "Agent", FQDN: "agent.example.com",
		ProviderID: "prov-1", DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted,
	}
	database.CreateAgent(a)
	s := &models.Server{ID: "srv-1", AgentID: "agent-1", Name: "Backend", Address: "10.0.0.1"}
	database.CreateServer(s)

	// Create domain
	w := doRequest(t, handler, "POST", "/api/v1/domains", map[string]interface{}{
		"subdomain":   "bier",
		"provider_id": "prov-1",
		"server_id":   "srv-1",
		"port":        8080,
		"websocket":   true,
	}, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("create domain: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var createdDomain models.Domain
	json.NewDecoder(w.Body).Decode(&createdDomain)
	if createdDomain.Subdomain != "bier" {
		t.Errorf("expected subdomain 'bier', got %s", createdDomain.Subdomain)
	}
	if createdDomain.Status != models.DomainStatusPending {
		t.Errorf("expected status pending, got %s", createdDomain.Status)
	}
	domainID := createdDomain.ID

	// List domains
	w = doRequest(t, handler, "GET", "/api/v1/domains", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("list domains: expected 200, got %d", w.Code)
	}
	var domains []models.Domain
	json.NewDecoder(w.Body).Decode(&domains)
	if len(domains) != 1 {
		t.Fatalf("expected 1 domain, got %d", len(domains))
	}

	// Get domain
	w = doRequest(t, handler, "GET", "/api/v1/domains/"+strconv.FormatInt(domainID, 10), nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("get domain: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Update domain
	w = doRequest(t, handler, "PUT", "/api/v1/domains/"+strconv.FormatInt(domainID, 10), map[string]interface{}{
		"port": 9090,
	}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("update domain: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	updated, _ := database.GetDomain(domainID)
	if updated.Port != 9090 {
		t.Errorf("expected port 9090, got %d", updated.Port)
	}

	// Get domain config
	w = doRequest(t, handler, "GET", "/api/v1/domains/"+strconv.FormatInt(domainID, 10)+"/config", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("get config: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Set manual config
	w = doRequest(t, handler, "PUT", "/api/v1/domains/"+strconv.FormatInt(domainID, 10)+"/config",
		map[string]interface{}{
			"config": map[string]string{"test": "value"},
		}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("set manual config: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Reset config
	w = doRequest(t, handler, "POST", "/api/v1/domains/"+strconv.FormatInt(domainID, 10)+"/config/reset", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("reset config: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	reset, _ := database.GetDomain(domainID)
	if reset.ManualConfig {
		t.Error("expected manual_config to be false after reset")
	}

	// Delete domain (soft delete)
	w = doRequest(t, handler, "DELETE", "/api/v1/domains/"+strconv.FormatInt(domainID, 10), nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("delete domain: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	deleted, _ := database.GetDomain(domainID)
	if deleted.Status != models.DomainStatusDeleting {
		t.Errorf("expected status deleting, got %s", deleted.Status)
	}
}

func TestDomainFilters(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)

	// Set up provider, agent, 2 servers, 2 domains
	p := &models.Provider{ID: "prov-1", Type: "cloudflare", Name: "CF", Config: `{"api_token":"test"}`}
	database.CreateProvider(p)
	a := &models.Agent{
		ID: "agent-1", Name: "Agent", FQDN: "agent.example.com",
		ProviderID: "prov-1", DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted,
	}
	database.CreateAgent(a)
	s1 := &models.Server{ID: "srv-1", AgentID: "agent-1", Name: "S1", Address: "10.0.0.1"}
	s2 := &models.Server{ID: "srv-2", AgentID: "agent-1", Name: "S2", Address: "10.0.0.2"}
	database.CreateServer(s1)
	database.CreateServer(s2)

	d1 := &models.Domain{Subdomain: "app", ProviderID: "prov-1", ServerID: "srv-1", Port: 80, SSLMode: models.SSLModeAuto, Status: models.DomainStatusActive}
	d2 := &models.Domain{Subdomain: "api", ProviderID: "prov-1", ServerID: "srv-2", Port: 3000, SSLMode: models.SSLModeAuto, Status: models.DomainStatusPending}
	database.CreateDomain(d1)
	database.CreateDomain(d2)

	// Filter by server_id
	w := doRequest(t, handler, "GET", "/api/v1/domains?server_id=srv-1", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var byServer []models.Domain
	json.NewDecoder(w.Body).Decode(&byServer)
	if len(byServer) != 1 || byServer[0].Subdomain != "app" {
		t.Errorf("filter by server: expected app, got %v", byServer)
	}

	// Filter by status
	w = doRequest(t, handler, "GET", "/api/v1/domains?status=pending", nil, cookie)
	var byStatus []models.Domain
	json.NewDecoder(w.Body).Decode(&byStatus)
	if len(byStatus) != 1 || byStatus[0].Subdomain != "api" {
		t.Errorf("filter by status: expected api, got %v", byStatus)
	}

	// Filter by agent_id
	w = doRequest(t, handler, "GET", "/api/v1/domains?agent_id=agent-1", nil, cookie)
	var byAgent []models.Domain
	json.NewDecoder(w.Body).Decode(&byAgent)
	if len(byAgent) != 2 {
		t.Errorf("filter by agent: expected 2, got %d", len(byAgent))
	}
}

func TestDomainCreate_Validation(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)

	// Missing required fields
	w := doRequest(t, handler, "POST", "/api/v1/domains", map[string]interface{}{
		"subdomain": "test",
	}, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	// Invalid port
	w = doRequest(t, handler, "POST", "/api/v1/domains", map[string]interface{}{
		"subdomain": "test", "provider_id": "prov-1", "server_id": "srv-1", "port": 0,
	}, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid port, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Audit Log
// ---------------------------------------------------------------------------

func TestAuditLog(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)

	// Insert some audit entries
	for i := 0; i < 5; i++ {
		database.InsertAuditLog(&models.AuditLogEntry{
			EntityType: "test", EntityID: "t-1", Action: "test", Actor: "admin",
		})
	}

	// List audit log
	w := doRequest(t, handler, "GET", "/api/v1/audit-log", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	total, _ := resp["total"].(float64)
	// At least 5 + the setup audit entry
	if total < 5 {
		t.Errorf("expected at least 5 entries, got %.0f", total)
	}

	// Pagination
	w = doRequest(t, handler, "GET", "/api/v1/audit-log?limit=2&offset=0", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	json.NewDecoder(w.Body).Decode(&resp)
	entries, ok := resp["entries"].([]interface{})
	if !ok {
		t.Fatal("expected entries array")
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries with limit 2, got %d", len(entries))
	}
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

func TestSettings(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)

	// List settings
	w := doRequest(t, handler, "GET", "/api/v1/settings", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("list settings: expected 200, got %d", w.Code)
	}

	var settings []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&settings)
	if len(settings) < 2 {
		t.Fatalf("expected at least 2 settings, got %d", len(settings))
	}

	// Sensitive settings should be filtered
	for _, s := range settings {
		if s["key"] == "admin_password_hash" {
			t.Error("admin_password_hash should not be in settings list")
		}
	}

	// Update setting
	w = doRequest(t, handler, "PUT", "/api/v1/settings/mcp_enabled", map[string]string{
		"value": "true",
	}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("update setting: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify update
	w = doRequest(t, handler, "GET", "/api/v1/settings", nil, cookie)
	json.NewDecoder(w.Body).Decode(&settings)
	found := false
	for _, s := range settings {
		if s["key"] == "mcp_enabled" && s["value"] == "true" {
			found = true
		}
	}
	if !found {
		t.Error("mcp_enabled not updated to true")
	}

	// Cannot update admin_password_hash via settings
	w = doRequest(t, handler, "PUT", "/api/v1/settings/admin_password_hash", map[string]string{
		"value": "hacked",
	}, cookie)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for password hash update, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Agent Auth (Bearer token)
// ---------------------------------------------------------------------------

func TestAgentAuth(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()

	p := &models.Provider{ID: "prov-1", Type: "cloudflare", Name: "CF", Config: `{"api_token":"test"}`}
	database.CreateProvider(p)

	token := "np_ag_someagenttoken123456789"
	tokenHash := auth.HashToken(token)

	a := &models.Agent{
		ID: "agent-1", Name: "Agent", FQDN: "agent.example.com", TokenHash: tokenHash,
		ProviderID: "prov-1", DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted,
	}
	database.CreateAgent(a)

	// Agent auth should work for heartbeat
	w := doRequestWithAuth(t, handler, "POST", "/api/v1/agents/agent-1/heartbeat",
		map[string]string{"public_ip": "1.2.3.4"}, token)
	if w.Code != http.StatusOK {
		t.Fatalf("agent heartbeat: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Agent token should also work as general auth
	w = doRequestWithAuth(t, handler, "GET", "/api/v1/agents", nil, token)
	if w.Code != http.StatusOK {
		t.Fatalf("agent list via agent token: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Invalid token should fail
	w = doRequestWithAuth(t, handler, "POST", "/api/v1/agents/agent-1/heartbeat",
		map[string]string{"public_ip": "1.2.3.4"}, "invalid-token")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token: expected 401, got %d", w.Code)
	}

	// Agent can't heartbeat for another agent
	database.CreateAgent(&models.Agent{
		ID: "agent-2", Name: "Agent 2", FQDN: "agent2.example.com", TokenHash: "other",
		ProviderID: "prov-1", DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted,
	})
	w = doRequestWithAuth(t, handler, "POST", "/api/v1/agents/agent-2/heartbeat",
		map[string]string{"public_ip": "1.2.3.4"}, token)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-agent heartbeat: expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

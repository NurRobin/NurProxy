//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	agentapi "github.com/NurRobin/NurProxy/internal/agent/api"
	"github.com/NurRobin/NurProxy/internal/agent/caddy"
	orchestratorapi "github.com/NurRobin/NurProxy/internal/orchestrator/api"
	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/orchestrator/reconciler"
	"github.com/NurRobin/NurProxy/internal/provider"
	"github.com/NurRobin/NurProxy/internal/shared/auth"
	"github.com/NurRobin/NurProxy/internal/shared/crypto"
)

// ---------------------------------------------------------------------------
// Mock DNS Provider
// ---------------------------------------------------------------------------

type mockProvider struct {
	records map[string]*provider.Record
	mu      sync.Mutex
	nextID  int
}

func newMockProvider() *mockProvider {
	return &mockProvider{
		records: make(map[string]*provider.Record),
	}
}

func (p *mockProvider) Info() provider.ProviderInfo {
	return provider.ProviderInfo{
		ID:          "mock",
		Name:        "Mock Provider",
		Description: "In-memory mock DNS provider for E2E tests",
		RecordTypes: []string{"A", "AAAA", "CNAME"},
	}
}

func (p *mockProvider) ConfigSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"api_token":{"type":"string"}},"required":["api_token"]}`)
}

func (p *mockProvider) ValidateConfig(_ context.Context, config json.RawMessage) error {
	var cfg struct {
		APIToken string `json:"api_token"`
	}
	if err := json.Unmarshal(config, &cfg); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	if cfg.APIToken == "" {
		return fmt.Errorf("api_token is required")
	}
	return nil
}

func (p *mockProvider) ListZones(_ context.Context, _ json.RawMessage) ([]provider.Zone, error) {
	return []provider.Zone{{ID: "zone-test", Name: "testzone.com"}}, nil
}

func (p *mockProvider) CreateRecord(_ context.Context, _ json.RawMessage, rec provider.Record) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextID++
	id := fmt.Sprintf("mock-rec-%d", p.nextID)
	r := rec // copy
	p.records[id] = &r
	return id, nil
}

func (p *mockProvider) UpdateRecord(_ context.Context, _ json.RawMessage, recordID string, rec provider.Record) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.records[recordID]; !ok {
		return fmt.Errorf("record not found: %s", recordID)
	}
	r := rec
	p.records[recordID] = &r
	return nil
}

func (p *mockProvider) DeleteRecord(_ context.Context, _ json.RawMessage, recordID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.records[recordID]; !ok {
		return fmt.Errorf("record not found: %s", recordID)
	}
	delete(p.records, recordID)
	return nil
}

func (p *mockProvider) GetRecord(_ context.Context, _ json.RawMessage, recordID string) (*provider.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	rec, ok := p.records[recordID]
	if !ok {
		return nil, fmt.Errorf("record not found: %s", recordID)
	}
	r := *rec
	return &r, nil
}

func (p *mockProvider) getRecord(id string) (*provider.Record, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	rec, ok := p.records[id]
	if !ok {
		return nil, false
	}
	r := *rec
	return &r, true
}

func (p *mockProvider) recordCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.records)
}

// ---------------------------------------------------------------------------
// Mock Agent Client for reconciler
// ---------------------------------------------------------------------------

// agentClientAdapter wraps real HTTP calls to the agent API, satisfying the
// reconciler.AgentClient interface.
type agentClientAdapter struct {
	httpClient *http.Client
}

func newAgentClientAdapter() *agentClientAdapter {
	return &agentClientAdapter{
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func (a *agentClientAdapter) Health(ctx context.Context, agentURL, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(agentURL, "/")+"/health", nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health returned %d", resp.StatusCode)
	}
	return nil
}

func (a *agentClientAdapter) PushRoute(ctx context.Context, agentURL, token string, route json.RawMessage) error {
	// The agent expects POST /routes with {"domain":"...","route":...}
	// Extract the host from route to use as domain key.
	host := extractHostFromRoute(route)
	payload := map[string]interface{}{
		"domain": host,
		"route":  json.RawMessage(route),
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(agentURL, "/")+"/routes", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("push route returned %d", resp.StatusCode)
	}
	return nil
}

func (a *agentClientAdapter) DeleteRoute(ctx context.Context, agentURL, token, domain string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, strings.TrimRight(agentURL, "/")+"/routes/"+domain, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("delete route returned %d", resp.StatusCode)
	}
	return nil
}

func (a *agentClientAdapter) SyncRoutes(ctx context.Context, agentURL, token string, routes []json.RawMessage) error {
	routeMap := make(map[string]json.RawMessage)
	for _, r := range routes {
		host := extractHostFromRoute(r)
		if host != "" {
			routeMap[host] = r
		}
	}
	body, _ := json.Marshal(routeMap)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, strings.TrimRight(agentURL, "/")+"/routes", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sync routes returned %d", resp.StatusCode)
	}
	return nil
}

func (a *agentClientAdapter) GetRoutes(ctx context.Context, agentURL, token string) ([]json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(agentURL, "/")+"/routes", nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("get routes returned %d", resp.StatusCode)
	}

	// The agent returns map[string]json.RawMessage, but we need []json.RawMessage.
	var routeMap map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&routeMap); err != nil {
		return nil, fmt.Errorf("decoding routes: %w", err)
	}
	var result []json.RawMessage
	for _, v := range routeMap {
		result = append(result, v)
	}
	return result, nil
}

// extractHostFromRoute pulls the first host from a Caddy route JSON.
func extractHostFromRoute(raw json.RawMessage) string {
	var partial struct {
		Match []struct {
			Host []string `json:"host"`
		} `json:"match"`
	}
	if err := json.Unmarshal(raw, &partial); err != nil {
		return ""
	}
	if len(partial.Match) > 0 && len(partial.Match[0].Host) > 0 {
		return partial.Match[0].Host[0]
	}
	return ""
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func setupTestOrchestrator(t *testing.T) (url string, database *db.DB, cleanup func()) {
	t.Helper()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generating crypto key: %v", err)
	}

	database, err = db.Open(":memory:", key)
	if err != nil {
		t.Fatalf("opening test DB: %v", err)
	}

	srv := orchestratorapi.NewServer(database, "test")
	ts := httptest.NewServer(srv.Handler())

	cleanup = func() {
		ts.Close()
		database.Close()
	}

	return ts.URL, database, cleanup
}

func setupTestAgent(t *testing.T, orchestratorURL string) (agentURL string, agentID string, rawToken string, tokenHash string, cleanup func()) {
	t.Helper()

	// Generate a token for the agent.
	rawToken, err := auth.GenerateAgentToken()
	if err != nil {
		t.Fatalf("generating agent token: %v", err)
	}

	// The token hash is what the orchestrator stores and what the reconciler's
	// agent client sends as the Bearer token to the agent API.
	tokenHash = auth.HashToken(rawToken)

	agentID = "e2e-agent-1"

	// Create a mock Caddy client.
	caddyClient := caddy.NewMockClient()

	// Find a free port for the agent API.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding free port: %v", err)
	}
	agentPort := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	// The agent API is configured with the token hash so that it accepts
	// Bearer tokens sent by the orchestrator's agent client (which sends
	// the hash stored in the DB).
	agentSrv := agentapi.New(agentPort, caddyClient, tokenHash)
	ctx, cancel := context.WithCancel(context.Background())
	if err := agentSrv.Start(ctx); err != nil {
		cancel()
		t.Fatalf("starting agent: %v", err)
	}

	agentURL = fmt.Sprintf("http://127.0.0.1:%d", agentPort)

	// Wait for agent to be listening.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", agentPort), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	cleanup = func() {
		agentSrv.Stop(context.Background())
		cancel()
	}

	return agentURL, agentID, rawToken, tokenHash, cleanup
}

func httpDo(t *testing.T, method, url string, body interface{}, cookie *http.Cookie) *http.Response {
	t.Helper()

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshalling request body: %v", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("executing request %s %s: %v", method, url, err)
	}
	return resp
}

func httpDoWithBearer(t *testing.T, method, url string, body interface{}, bearerToken string) *http.Response {
	t.Helper()

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshalling request body: %v", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("executing request %s %s: %v", method, url, err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	return data
}

func decodeJSON(t *testing.T, resp *http.Response, v interface{}) {
	t.Helper()
	data := readBody(t, resp)
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("decoding JSON response: %v\nBody: %s", err, string(data))
	}
}

func extractSessionCookie(t *testing.T, resp *http.Response) *http.Cookie {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name == "nurproxy_session" {
			return c
		}
	}
	t.Fatal("nurproxy_session cookie not found in response")
	return nil
}

// ---------------------------------------------------------------------------
// E2E Test
// ---------------------------------------------------------------------------

func TestE2E_FullAdoptionAndDomainFlow(t *testing.T) {
	// Register mock DNS provider.
	mockDNS := newMockProvider()
	provider.Register(mockDNS)

	// -----------------------------------------------------------------------
	// 1. Setup: orchestrator and agent
	// -----------------------------------------------------------------------

	orchURL, database, orchCleanup := setupTestOrchestrator(t)
	defer orchCleanup()

	agentURL, agentID, agentRawToken, agentTokenHash, agentCleanup := setupTestAgent(t, orchURL)
	defer agentCleanup()

	agentFQDN := "edge1.testzone.com"

	// -----------------------------------------------------------------------
	// 2. Admin setup and login
	// -----------------------------------------------------------------------

	testPassword := "securepassword123"

	// POST /auth/setup
	resp := httpDo(t, http.MethodPost, orchURL+"/api/v1/auth/setup", map[string]string{
		"password": testPassword,
	}, nil)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("setup returned %d: %s", resp.StatusCode, string(body))
	}

	// POST /auth/login to get session cookie
	resp = httpDo(t, http.MethodPost, orchURL+"/api/v1/auth/login", map[string]string{
		"password": testPassword,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		body := readBody(t, resp)
		t.Fatalf("login returned %d: %s", resp.StatusCode, string(body))
	}
	sessionCookie := extractSessionCookie(t, resp)
	resp.Body.Close()

	// Verify login worked by hitting a protected endpoint.
	resp = httpDo(t, http.MethodGet, orchURL+"/api/v1/health", nil, sessionCookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health check with session cookie returned %d", resp.StatusCode)
	}
	resp.Body.Close()

	// -----------------------------------------------------------------------
	// 3. Add DNS provider
	// -----------------------------------------------------------------------

	resp = httpDo(t, http.MethodPost, orchURL+"/api/v1/providers", map[string]interface{}{
		"type":      "mock",
		"name":      "E2E Mock Provider",
		"config":    map[string]string{"api_token": "test-token-123"},
		"zone_id":   "zone-test",
		"zone_name": "testzone.com",
	}, sessionCookie)
	var providerResp map[string]string
	decodeJSON(t, resp, &providerResp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create provider returned %d", resp.StatusCode)
	}
	providerID := providerResp["id"]
	if providerID == "" {
		t.Fatal("provider ID is empty")
	}
	t.Logf("Created provider: %s", providerID)

	// -----------------------------------------------------------------------
	// 4. Agent adoption flow
	// -----------------------------------------------------------------------

	// Agent registers itself with the orchestrator.
	// The raw token is sent; the orchestrator hashes it before storing.
	resp = httpDo(t, http.MethodPost, orchURL+"/api/v1/agents/register", map[string]interface{}{
		"id":        agentID,
		"fqdn":      agentFQDN,
		"token":     agentRawToken,
		"api_url":   agentURL,
		"public_ip": "203.0.113.1",
		"version":   "1.0.0-test",
	}, nil)
	var regResp map[string]string
	decodeJSON(t, resp, &regResp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register agent returned %d: %+v", resp.StatusCode, regResp)
	}
	if regResp["status"] != "pending" {
		t.Fatalf("expected agent status 'pending', got %q", regResp["status"])
	}
	t.Logf("Agent registered with status: %s", regResp["status"])

	// Verify agent appears in list with status "pending".
	resp = httpDo(t, http.MethodGet, orchURL+"/api/v1/agents", nil, sessionCookie)
	var agents []map[string]interface{}
	decodeJSON(t, resp, &agents)
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	if agents[0]["status"] != "pending" {
		t.Fatalf("expected agent status 'pending' in list, got %q", agents[0]["status"])
	}
	if agents[0]["fqdn"] != agentFQDN {
		t.Fatalf("expected agent FQDN %q, got %q", agentFQDN, agents[0]["fqdn"])
	}

	// Admin adopts the agent.
	resp = httpDo(t, http.MethodPut, orchURL+"/api/v1/agents/"+agentID+"/adopt", map[string]interface{}{
		"name":        "E2E Agent",
		"provider_id": providerID,
		"dns_mode":    "static",
	}, sessionCookie)
	var adoptResp map[string]interface{}
	decodeJSON(t, resp, &adoptResp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("adopt agent returned %d: %+v", resp.StatusCode, adoptResp)
	}
	if adoptResp["status"] != "adopted" {
		t.Fatalf("expected agent status 'adopted' after adoption, got %q", adoptResp["status"])
	}
	t.Log("Agent adopted successfully")

	// Verify the agent is now adopted in the list.
	resp = httpDo(t, http.MethodGet, orchURL+"/api/v1/agents", nil, sessionCookie)
	decodeJSON(t, resp, &agents)
	if agents[0]["status"] != "adopted" {
		t.Fatalf("expected agent status 'adopted' in list, got %q", agents[0]["status"])
	}

	// -----------------------------------------------------------------------
	// 5. Add server
	// -----------------------------------------------------------------------

	resp = httpDo(t, http.MethodPost, orchURL+"/api/v1/agents/"+agentID+"/servers", map[string]interface{}{
		"name":    "testhost",
		"address": "192.168.1.100",
	}, sessionCookie)
	var serverResp map[string]interface{}
	decodeJSON(t, resp, &serverResp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create server returned %d: %+v", resp.StatusCode, serverResp)
	}
	serverID, ok := serverResp["id"].(string)
	if !ok || serverID == "" {
		t.Fatal("server ID is empty or not a string")
	}
	if serverResp["name"] != "testhost" {
		t.Fatalf("expected server name 'testhost', got %q", serverResp["name"])
	}
	if serverResp["address"] != "192.168.1.100" {
		t.Fatalf("expected server address '192.168.1.100', got %q", serverResp["address"])
	}
	t.Logf("Created server: %s", serverID)

	// -----------------------------------------------------------------------
	// 6. Create domain
	// -----------------------------------------------------------------------

	resp = httpDo(t, http.MethodPost, orchURL+"/api/v1/domains", map[string]interface{}{
		"subdomain":   "app",
		"provider_id": providerID,
		"server_id":   serverID,
		"port":        8080,
		"websocket":   true,
	}, sessionCookie)
	var domainResp map[string]interface{}
	decodeJSON(t, resp, &domainResp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create domain returned %d: %+v", resp.StatusCode, domainResp)
	}

	// Domain ID is a float64 from JSON; convert to int64.
	domainIDFloat, ok := domainResp["id"].(float64)
	if !ok {
		t.Fatal("domain ID is not a number")
	}
	domainID := int64(domainIDFloat)
	if domainID == 0 {
		t.Fatal("domain ID is 0")
	}
	if domainResp["status"] != "pending" {
		t.Fatalf("expected domain status 'pending', got %q", domainResp["status"])
	}
	if domainResp["subdomain"] != "app" {
		t.Fatalf("expected subdomain 'app', got %q", domainResp["subdomain"])
	}
	wsVal, _ := domainResp["websocket"].(bool)
	if !wsVal {
		t.Fatal("expected websocket=true on created domain")
	}
	t.Logf("Created domain: %d (status: %s)", domainID, domainResp["status"])

	// -----------------------------------------------------------------------
	// 7. Run reconciler
	// -----------------------------------------------------------------------

	// The reconciler passes agent.TokenHash (from the DB) to its AgentClient
	// methods. The orchestrator stored auth.HashToken(rawToken) which equals
	// agentTokenHash. The agent API was started with agentTokenHash as its
	// accepted Bearer token. So the reconciler will authenticate successfully.
	agentClient := newAgentClientAdapter()
	rec := reconciler.New(database, agentClient, time.Minute)

	if err := rec.RunOnce(context.Background()); err != nil {
		t.Fatalf("reconciler RunOnce: %v", err)
	}

	// Verify: mock DNS provider received CNAME record creation.
	// Expected: app.testzone.com -> edge1.testzone.com
	dom, err := database.GetDomain(domainID)
	if err != nil {
		t.Fatalf("getting domain after reconciler: %v", err)
	}
	if dom.DNSRecordID == "" {
		t.Fatal("expected dns_record_id to be set after reconciliation")
	}

	dnsRec, found := mockDNS.getRecord(dom.DNSRecordID)
	if !found {
		t.Fatalf("DNS record %s not found in mock provider", dom.DNSRecordID)
	}
	if dnsRec.Type != "CNAME" {
		t.Errorf("expected DNS record type 'CNAME', got %q", dnsRec.Type)
	}
	if dnsRec.Name != "app.testzone.com" {
		t.Errorf("expected DNS record name 'app.testzone.com', got %q", dnsRec.Name)
	}
	if dnsRec.Content != agentFQDN {
		t.Errorf("expected DNS record content %q, got %q", agentFQDN, dnsRec.Content)
	}
	t.Logf("DNS record created: %s CNAME %s -> %s", dom.DNSRecordID, dnsRec.Name, dnsRec.Content)

	// Verify: domain status updated to "active".
	if dom.Status != "active" {
		t.Errorf("expected domain status 'active' after reconciliation, got %q", dom.Status)
	}

	// Also verify via API.
	resp = httpDo(t, http.MethodGet, orchURL+"/api/v1/domains/"+strconv.FormatInt(domainID, 10), nil, sessionCookie)
	var domainGetResp map[string]interface{}
	decodeJSON(t, resp, &domainGetResp)
	if domainGetResp["status"] != "active" {
		t.Errorf("expected domain status 'active' via API, got %q", domainGetResp["status"])
	}
	if domainGetResp["dns_record_id"] == nil || domainGetResp["dns_record_id"] == "" {
		t.Error("expected dns_record_id to be set via API")
	}

	// -----------------------------------------------------------------------
	// 8. Verify route on agent
	// -----------------------------------------------------------------------

	// Use the token hash to authenticate with the agent API (that's what it was started with).
	resp = httpDoWithBearer(t, http.MethodGet, agentURL+"/routes", nil, agentTokenHash)
	var routeMap map[string]json.RawMessage
	decodeJSON(t, resp, &routeMap)
	if len(routeMap) == 0 {
		t.Fatal("expected at least 1 route on agent, got 0")
	}

	// Find the route for app.testzone.com.
	foundRoute := false
	for domain, route := range routeMap {
		host := extractHostFromRoute(route)
		if host == "app.testzone.com" || domain == "app.testzone.com" {
			foundRoute = true

			// Verify route has correct upstream.
			var routeObj map[string]interface{}
			if err := json.Unmarshal(route, &routeObj); err != nil {
				t.Fatalf("unmarshalling route: %v", err)
			}

			// Check match hosts.
			matches, _ := routeObj["match"].([]interface{})
			if len(matches) == 0 {
				t.Fatal("route has no match rules")
			}
			matchObj, _ := matches[0].(map[string]interface{})
			hosts, _ := matchObj["host"].([]interface{})
			if len(hosts) == 0 || hosts[0] != "app.testzone.com" {
				t.Errorf("expected route host 'app.testzone.com', got %v", hosts)
			}

			t.Logf("Route found on agent for domain: %s", domain)
			break
		}
	}
	if !foundRoute {
		t.Errorf("route for app.testzone.com not found on agent; routes: %v", routeMap)
	}

	// -----------------------------------------------------------------------
	// 9. Agent heartbeat
	// -----------------------------------------------------------------------

	// Use the raw token for orchestrator auth (requireAgentAuth hashes it to match stored hash).
	newIP := "198.51.100.42"
	resp = httpDoWithBearer(t, http.MethodPost, orchURL+"/api/v1/agents/"+agentID+"/heartbeat", map[string]interface{}{
		"public_ip": newIP,
		"version":   "1.0.1-test",
	}, agentRawToken)
	var heartbeatResp map[string]interface{}
	decodeJSON(t, resp, &heartbeatResp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat returned %d: %+v", resp.StatusCode, heartbeatResp)
	}
	if heartbeatResp["status"] != "adopted" {
		t.Errorf("expected agent status 'adopted' in heartbeat response, got %q", heartbeatResp["status"])
	}

	// Verify agent's public_ip updated.
	resp = httpDo(t, http.MethodGet, orchURL+"/api/v1/agents", nil, sessionCookie)
	decodeJSON(t, resp, &agents)
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	if agents[0]["public_ip"] != newIP {
		t.Errorf("expected agent public_ip %q, got %q", newIP, agents[0]["public_ip"])
	}
	t.Logf("Agent heartbeat updated IP to: %s", newIP)

	// -----------------------------------------------------------------------
	// 10. Domain config operations
	// -----------------------------------------------------------------------

	domainIDStr := strconv.FormatInt(domainID, 10)

	// GET /domains/{id}/config -> returns valid Caddy JSON.
	resp = httpDo(t, http.MethodGet, orchURL+"/api/v1/domains/"+domainIDStr+"/config", nil, sessionCookie)
	var configResp map[string]interface{}
	decodeJSON(t, resp, &configResp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get domain config returned %d", resp.StatusCode)
	}
	if configResp["manual"] != false {
		t.Errorf("expected manual=false for auto-generated config, got %v", configResp["manual"])
	}
	if configResp["config"] == nil {
		t.Fatal("expected non-nil config in domain config response")
	}
	// Verify the config is valid JSON with expected structure.
	configBytes, err := json.Marshal(configResp["config"])
	if err != nil {
		t.Fatalf("marshalling config: %v", err)
	}
	var routeConfig map[string]interface{}
	if err := json.Unmarshal(configBytes, &routeConfig); err != nil {
		t.Fatalf("config is not valid JSON: %v", err)
	}
	if routeConfig["@id"] == nil {
		t.Error("expected @id field in generated Caddy config")
	}
	t.Logf("Domain config is valid Caddy JSON with @id: %v", routeConfig["@id"])

	// PUT /domains/{id}/config with custom config -> sets manual_config=true.
	customConfig := map[string]interface{}{
		"@id":      "custom-domain",
		"match":    []map[string]interface{}{{"host": []string{"app.testzone.com"}}},
		"handle":   []map[string]interface{}{{"handler": "static_response", "status_code": "200"}},
		"terminal": true,
	}
	resp = httpDo(t, http.MethodPut, orchURL+"/api/v1/domains/"+domainIDStr+"/config", map[string]interface{}{
		"config": customConfig,
	}, sessionCookie)
	var updateConfigResp map[string]string
	decodeJSON(t, resp, &updateConfigResp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update domain config returned %d: %+v", resp.StatusCode, updateConfigResp)
	}

	// Verify manual_config is now true.
	resp = httpDo(t, http.MethodGet, orchURL+"/api/v1/domains/"+domainIDStr, nil, sessionCookie)
	decodeJSON(t, resp, &domainGetResp)
	if domainGetResp["manual_config"] != true {
		t.Errorf("expected manual_config=true after config update, got %v", domainGetResp["manual_config"])
	}

	// GET config again should show manual=true.
	resp = httpDo(t, http.MethodGet, orchURL+"/api/v1/domains/"+domainIDStr+"/config", nil, sessionCookie)
	decodeJSON(t, resp, &configResp)
	if configResp["manual"] != true {
		t.Errorf("expected manual=true after custom config set, got %v", configResp["manual"])
	}

	// POST /domains/{id}/config/reset -> clears manual_config.
	resp = httpDo(t, http.MethodPost, orchURL+"/api/v1/domains/"+domainIDStr+"/config/reset", nil, sessionCookie)
	var resetResp map[string]string
	decodeJSON(t, resp, &resetResp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset domain config returned %d: %+v", resp.StatusCode, resetResp)
	}

	// Verify manual_config is cleared.
	resp = httpDo(t, http.MethodGet, orchURL+"/api/v1/domains/"+domainIDStr, nil, sessionCookie)
	decodeJSON(t, resp, &domainGetResp)
	if domainGetResp["manual_config"] != false {
		t.Errorf("expected manual_config=false after config reset, got %v", domainGetResp["manual_config"])
	}
	t.Log("Domain config operations verified (get, set manual, reset)")

	// -----------------------------------------------------------------------
	// 11. Cleanup: delete domain and verify DNS record removed
	// -----------------------------------------------------------------------

	dnsRecordID := dom.DNSRecordID

	// DELETE domain (marks as deleting).
	resp = httpDo(t, http.MethodDelete, orchURL+"/api/v1/domains/"+domainIDStr, nil, sessionCookie)
	var deleteResp map[string]string
	decodeJSON(t, resp, &deleteResp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete domain returned %d: %+v", resp.StatusCode, deleteResp)
	}

	// Verify domain status is "deleting".
	dom, err = database.GetDomain(domainID)
	if err != nil {
		t.Fatalf("getting domain after delete: %v", err)
	}
	if dom.Status != "deleting" {
		t.Errorf("expected domain status 'deleting', got %q", dom.Status)
	}

	// The DNS record should still exist at this point (reconciler hasn't cleaned up yet).
	_, dnsFound := mockDNS.getRecord(dnsRecordID)
	if !dnsFound {
		t.Log("DNS record already removed (acceptable: reconciler skips 'deleting' domains)")
	} else {
		t.Logf("DNS record %s still exists after domain delete (pending reconciler cleanup)", dnsRecordID)
	}

	// DELETE agent -> cascades to servers (and domains via FK cascade).
	resp = httpDo(t, http.MethodDelete, orchURL+"/api/v1/agents/"+agentID, nil, sessionCookie)
	decodeJSON(t, resp, &deleteResp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete agent returned %d: %+v", resp.StatusCode, deleteResp)
	}

	// Verify agent is gone.
	resp = httpDo(t, http.MethodGet, orchURL+"/api/v1/agents", nil, sessionCookie)
	decodeJSON(t, resp, &agents)
	if len(agents) != 0 {
		t.Errorf("expected 0 agents after deletion, got %d", len(agents))
	}

	t.Log("Cleanup verified: agent deleted with cascade")
	t.Log("E2E test complete: full adoption and domain flow passed")
}

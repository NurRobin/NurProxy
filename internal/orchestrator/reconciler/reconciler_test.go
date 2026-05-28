package reconciler

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/provider"
	"github.com/NurRobin/NurProxy/internal/shared/crypto"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// ---------------------------------------------------------------------------
// Mock Agent Client
// ---------------------------------------------------------------------------

type mockAgentClient struct {
	mu         sync.Mutex
	routes     map[string][]json.RawMessage // agentURL -> routes
	healthy    map[string]bool              // agentURL -> reachable
	pushCalls  int
	pushErrors map[string]error // fqdn -> error
}

func newMockAgentClient() *mockAgentClient {
	return &mockAgentClient{
		routes:     make(map[string][]json.RawMessage),
		healthy:    make(map[string]bool),
		pushErrors: make(map[string]error),
	}
}

func (m *mockAgentClient) Health(_ context.Context, agentURL, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if h, ok := m.healthy[agentURL]; ok && h {
		return nil
	}
	return fmt.Errorf("agent %s is unreachable", agentURL)
}

func (m *mockAgentClient) PushRoute(_ context.Context, agentURL, _ string, route json.RawMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pushCalls++

	fqdn := extractHostFromRoute(route)
	if err, ok := m.pushErrors[fqdn]; ok {
		return err
	}

	// Replace existing route with same host or append.
	existing := m.routes[agentURL]
	found := false
	for i, r := range existing {
		if extractHostFromRoute(r) == fqdn {
			existing[i] = route
			found = true
			break
		}
	}
	if !found {
		existing = append(existing, route)
	}
	m.routes[agentURL] = existing
	return nil
}

func (m *mockAgentClient) DeleteRoute(_ context.Context, agentURL, _, domain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var filtered []json.RawMessage
	for _, r := range m.routes[agentURL] {
		if extractHostFromRoute(r) != domain {
			filtered = append(filtered, r)
		}
	}
	m.routes[agentURL] = filtered
	return nil
}

func (m *mockAgentClient) SyncRoutes(_ context.Context, agentURL, _ string, routes []json.RawMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes[agentURL] = routes
	return nil
}

func (m *mockAgentClient) GetRoutes(_ context.Context, agentURL, _ string) ([]json.RawMessage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.routes[agentURL], nil
}

func (m *mockAgentClient) setHealthy(agentURL string, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthy[agentURL] = ok
}

func (m *mockAgentClient) setRoutes(agentURL string, routes []json.RawMessage) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes[agentURL] = routes
}

func (m *mockAgentClient) getRoutes(agentURL string) []json.RawMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.routes[agentURL]
}

func (m *mockAgentClient) getPushCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pushCalls
}

// ---------------------------------------------------------------------------
// Mock DNS Provider
// ---------------------------------------------------------------------------

type mockDNSProvider struct {
	mu      sync.Mutex
	records map[string]provider.Record // recordID -> record
	nextID  int
}

func newMockDNSProvider() *mockDNSProvider {
	return &mockDNSProvider{
		records: make(map[string]provider.Record),
	}
}

func (p *mockDNSProvider) Info() provider.ProviderInfo {
	return provider.ProviderInfo{
		ID:          "mock",
		Name:        "Mock Provider",
		Description: "In-memory mock for testing",
		RecordTypes: []string{"A", "AAAA", "CNAME"},
	}
}

func (p *mockDNSProvider) ConfigSchema() json.RawMessage {
	return json.RawMessage(`{}`)
}

func (p *mockDNSProvider) ValidateConfig(_ context.Context, _ json.RawMessage) error {
	return nil
}

func (p *mockDNSProvider) ListZones(_ context.Context, _ json.RawMessage) ([]provider.Zone, error) {
	return []provider.Zone{{ID: "zone-1", Name: "example.com"}}, nil
}

func (p *mockDNSProvider) CreateRecord(_ context.Context, _ json.RawMessage, rec provider.Record) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextID++
	id := fmt.Sprintf("rec-%d", p.nextID)
	p.records[id] = rec
	return id, nil
}

func (p *mockDNSProvider) UpdateRecord(_ context.Context, _ json.RawMessage, recordID string, rec provider.Record) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.records[recordID]; !ok {
		return fmt.Errorf("record not found: %s", recordID)
	}
	p.records[recordID] = rec
	return nil
}

func (p *mockDNSProvider) DeleteRecord(_ context.Context, _ json.RawMessage, recordID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.records, recordID)
	return nil
}

func (p *mockDNSProvider) GetRecord(_ context.Context, _ json.RawMessage, recordID string) (*provider.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	rec, ok := p.records[recordID]
	if !ok {
		return nil, fmt.Errorf("record not found: %s", recordID)
	}
	return &rec, nil
}

func (p *mockDNSProvider) getRecord(id string) (provider.Record, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.records[id]
	return r, ok
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func testDB(t *testing.T) *db.DB {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(":memory:", key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// setupScenario creates a provider, zone, agent, server, and domain for testing.
// It returns all entities for further assertions. The agent is marked adopted
// and the domain has status pending.
func setupScenario(t *testing.T, d *db.DB) (prov *models.Provider, zone *models.Zone, agent *models.Agent, srv *models.Server, dom *models.Domain) {
	t.Helper()

	prov = &models.Provider{
		ID:     "prov-1",
		Type:   "mock",
		Name:   "Mock CF",
		Config: `{"api_token":"secret"}`,
	}
	if err := d.CreateProvider(prov); err != nil {
		t.Fatalf("CreateProvider: %v", err)
	}

	zone = &models.Zone{
		ID:         "zone-1",
		ProviderID: prov.ID,
		ExternalID: "ext-zone-1",
		Name:       "example.com",
	}
	if err := d.CreateZone(zone); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}

	agent = &models.Agent{
		ID:        "agent-1",
		Name:      "Agent One",
		FQDN:      "agent1.example.com",
		APIURL:    "https://agent1.example.com:8443",
		TokenHash: "token-hash-1",
		DNSMode:   models.DNSModeStatic,
		Status:    models.AgentStatusAdopted,
	}
	if err := d.CreateAgent(agent); err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	srv = &models.Server{
		ID:      "srv-1",
		AgentID: agent.ID,
		Name:    "Backend",
		Address: "10.0.0.1",
	}
	if err := d.CreateServer(srv); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	dom = &models.Domain{
		Subdomain: "app",
		ZoneID:    zone.ID,
		ServerID:  srv.ID,
		Port:      8080,
		SSLMode:   models.SSLModeAuto,
		Status:    models.DomainStatusPending,
	}
	if err := d.CreateDomain(dom); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}

	return
}

// registerMockProvider registers the mock provider in the global registry.
// It returns a cleanup function that should be deferred.
func registerMockProvider(t *testing.T) *mockDNSProvider {
	t.Helper()
	mp := newMockDNSProvider()
	provider.Register(mp)
	return mp
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestReconcileRoutes_PushMissing(t *testing.T) {
	d := testDB(t)
	_, _, agent, _, dom := setupScenario(t, d)

	mc := newMockAgentClient()
	mc.setHealthy(agent.APIURL, true)
	// Agent has no routes initially.

	r := New(d, mc, time.Minute)

	if err := r.reconcileRoutes(context.Background(), agent); err != nil {
		t.Fatalf("reconcileRoutes: %v", err)
	}

	// The route should have been pushed.
	routes := mc.getRoutes(agent.APIURL)
	if len(routes) != 1 {
		t.Fatalf("expected 1 route on agent, got %d", len(routes))
	}

	// The host should be app.example.com.
	host := extractHostFromRoute(routes[0])
	if host != "app.example.com" {
		t.Errorf("expected host app.example.com, got %s", host)
	}

	// Domain status should be active.
	got, err := d.GetDomain(dom.ID)
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	if got.Status != models.DomainStatusActive {
		t.Errorf("expected domain status %q, got %q", models.DomainStatusActive, got.Status)
	}

	// Audit log should have a push entry.
	entries, total, err := d.ListAuditLog(10, 0)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	if total == 0 {
		t.Fatal("expected at least one audit log entry")
	}
	found := false
	for _, e := range entries {
		if e.Action == "route_pushed" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected audit entry with action route_pushed")
	}
}

func TestReconcileRoutes_IgnoreUnmanaged(t *testing.T) {
	d := testDB(t)
	_, _, agent, _, _ := setupScenario(t, d)

	mc := newMockAgentClient()
	mc.setHealthy(agent.APIURL, true)

	// Put an unmanaged route on the agent.
	unmanagedRoute := json.RawMessage(`{"@id":"unknown","match":[{"host":["rogue.example.com"]}],"terminal":true}`)
	mc.setRoutes(agent.APIURL, []json.RawMessage{unmanagedRoute})

	r := New(d, mc, time.Minute)

	if err := r.reconcileRoutes(context.Background(), agent); err != nil {
		t.Fatalf("reconcileRoutes: %v", err)
	}

	// The unmanaged route should still be there (not deleted).
	routes := mc.getRoutes(agent.APIURL)
	hasRogue := false
	for _, rt := range routes {
		if extractHostFromRoute(rt) == "rogue.example.com" {
			hasRogue = true
			break
		}
	}
	if !hasRogue {
		t.Error("unmanaged route was deleted — it should have been left intact")
	}

	// Should have an audit log warning about the unmanaged route.
	entries, _, err := d.ListAuditLog(10, 0)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "unmanaged_route" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected audit entry with action unmanaged_route")
	}
}

func TestReconcileRoutes_FixDrift(t *testing.T) {
	d := testDB(t)
	_, _, agent, _, dom := setupScenario(t, d)

	mc := newMockAgentClient()
	mc.setHealthy(agent.APIURL, true)

	// Put a stale/wrong route on the agent for the same host.
	staleRoute := json.RawMessage(`{"@id":"domain-app-example-com","match":[{"host":["app.example.com"]}],"handle":[{"handler":"subroute"}],"terminal":true}`)
	mc.setRoutes(agent.APIURL, []json.RawMessage{staleRoute})

	r := New(d, mc, time.Minute)

	if err := r.reconcileRoutes(context.Background(), agent); err != nil {
		t.Fatalf("reconcileRoutes: %v", err)
	}

	// The route should have been corrected (push called).
	if mc.getPushCalls() != 1 {
		t.Errorf("expected 1 push call, got %d", mc.getPushCalls())
	}

	// Domain should be active.
	got, _ := d.GetDomain(dom.ID)
	if got.Status != models.DomainStatusActive {
		t.Errorf("expected status %q, got %q", models.DomainStatusActive, got.Status)
	}

	// Audit log should record drift fix.
	entries, _, _ := d.ListAuditLog(10, 0)
	found := false
	for _, e := range entries {
		if e.Action == "drift_fixed" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected audit entry with action drift_fixed")
	}
}

func TestReconcileRoutes_RespectManualConfig(t *testing.T) {
	d := testDB(t)
	_, _, agent, _, dom := setupScenario(t, d)

	// Set manual config on the domain.
	dom.ManualConfig = true
	if err := d.UpdateDomain(dom); err != nil {
		t.Fatalf("UpdateDomain: %v", err)
	}

	mc := newMockAgentClient()
	mc.setHealthy(agent.APIURL, true)

	// Put a "wrong" route on the agent.
	wrongRoute := json.RawMessage(`{"@id":"domain-app-example-com","match":[{"host":["app.example.com"]}],"handle":[{"handler":"custom"}],"terminal":true}`)
	mc.setRoutes(agent.APIURL, []json.RawMessage{wrongRoute})

	r := New(d, mc, time.Minute)

	if err := r.reconcileRoutes(context.Background(), agent); err != nil {
		t.Fatalf("reconcileRoutes: %v", err)
	}

	// Push should NOT have been called — manual config is respected.
	if mc.getPushCalls() != 0 {
		t.Errorf("expected 0 push calls (manual config), got %d", mc.getPushCalls())
	}

	// The "wrong" route should still be on the agent unchanged.
	routes := mc.getRoutes(agent.APIURL)
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	host := extractHostFromRoute(routes[0])
	if host != "app.example.com" {
		t.Errorf("route host changed unexpectedly to %s", host)
	}

	// Should have a drift_detected audit entry.
	entries, _, _ := d.ListAuditLog(10, 0)
	found := false
	for _, e := range entries {
		if e.Action == "drift_detected" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected audit entry with action drift_detected for manual config")
	}
}

func TestReconcileDNS_CreateMissingRecord(t *testing.T) {
	d := testDB(t)
	mp := registerMockProvider(t)
	_, _, _, _, dom := setupScenario(t, d)

	mc := newMockAgentClient()
	r := New(d, mc, time.Minute)

	if err := r.reconcileDNS(context.Background()); err != nil {
		t.Fatalf("reconcileDNS: %v", err)
	}

	// Domain should now have a dns_record_id.
	got, err := d.GetDomain(dom.ID)
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	if got.DNSRecordID == "" {
		t.Fatal("expected dns_record_id to be set after DNS reconciliation")
	}

	// The mock provider should have the record.
	rec, ok := mp.getRecord(got.DNSRecordID)
	if !ok {
		t.Fatalf("record %s not found in mock provider", got.DNSRecordID)
	}
	if rec.Type != "CNAME" {
		t.Errorf("record type: got %q, want CNAME", rec.Type)
	}
	if rec.Content != "agent1.example.com" {
		t.Errorf("record content: got %q, want agent1.example.com", rec.Content)
	}
	if rec.Name != "app.example.com" {
		t.Errorf("record name: got %q, want app.example.com", rec.Name)
	}
}

func TestReconcileDNS_FixDrift(t *testing.T) {
	d := testDB(t)
	mp := registerMockProvider(t)
	_, _, _, _, dom := setupScenario(t, d)

	// Pre-create a DNS record pointing to the wrong target.
	mp.mu.Lock()
	mp.nextID++
	recordID := fmt.Sprintf("rec-%d", mp.nextID)
	mp.records[recordID] = provider.Record{
		Type:    "CNAME",
		Name:    "app.example.com",
		Content: "old-agent.example.com", // Wrong target.
	}
	mp.mu.Unlock()

	// Store the record ID on the domain.
	if err := d.UpdateDomainDNSRecord(dom.ID, recordID); err != nil {
		t.Fatalf("UpdateDomainDNSRecord: %v", err)
	}

	mc := newMockAgentClient()
	r := New(d, mc, time.Minute)

	if err := r.reconcileDNS(context.Background()); err != nil {
		t.Fatalf("reconcileDNS: %v", err)
	}

	// The record should now point to the correct target.
	rec, ok := mp.getRecord(recordID)
	if !ok {
		t.Fatalf("record %s not found after reconciliation", recordID)
	}
	if rec.Content != "agent1.example.com" {
		t.Errorf("record content: got %q, want agent1.example.com", rec.Content)
	}

	// Audit log should reflect the update.
	entries, _, _ := d.ListAuditLog(10, 0)
	found := false
	for _, e := range entries {
		if e.Action == "dns_updated" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected audit entry with action dns_updated")
	}
}

func TestReconcileDeletions_RemovesRecordRouteAndRow(t *testing.T) {
	d := testDB(t)
	mp := registerMockProvider(t)
	_, _, agent, _, dom := setupScenario(t, d)

	// Give the domain an existing DNS record and a route on the agent.
	recID, err := mp.CreateRecord(context.Background(), nil, provider.Record{
		Type: "CNAME", Name: "app.example.com", Content: "agent1.example.com",
	})
	if err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}
	if err := d.UpdateDomainDNSRecord(dom.ID, recID); err != nil {
		t.Fatalf("UpdateDomainDNSRecord: %v", err)
	}
	if err := d.UpdateDomainStatus(dom.ID, models.DomainStatusDeleting, ""); err != nil {
		t.Fatalf("UpdateDomainStatus: %v", err)
	}

	mc := newMockAgentClient()
	mc.setHealthy(agent.APIURL, true)
	mc.setRoutes(agent.APIURL, []json.RawMessage{
		json.RawMessage(`{"@id":"domain-app-example-com","match":[{"host":["app.example.com"]}],"terminal":true}`),
	})

	r := New(d, mc, time.Minute)
	if err := r.reconcileDeletions(context.Background()); err != nil {
		t.Fatalf("reconcileDeletions: %v", err)
	}

	// DNS record gone.
	if _, ok := mp.getRecord(recID); ok {
		t.Error("expected DNS record to be deleted")
	}
	// Route gone from agent.
	if len(mc.getRoutes(agent.APIURL)) != 0 {
		t.Errorf("expected route removed, got %d routes", len(mc.getRoutes(agent.APIURL)))
	}
	// Domain row gone.
	if _, err := d.GetDomain(dom.ID); err == nil {
		t.Error("expected domain row to be deleted")
	}
	// Audit trail recorded the deletion.
	entries, _, _ := d.ListAuditLog(20, 0)
	found := false
	for _, e := range entries {
		if e.Action == "deleted" && e.EntityType == "domain" {
			found = true
		}
	}
	if !found {
		t.Error("expected audit entry with action deleted")
	}
}

func TestReconcileAgentDNS_CreateAndDDNSUpdate(t *testing.T) {
	d := testDB(t)
	mp := registerMockProvider(t)
	_, zone, agent, _, _ := setupScenario(t, d)

	// Put the agent in DDNS mode, give it a public IP and an assigned zone.
	agent.DNSMode = models.DNSModeDDNS
	agent.PublicIP = "203.0.113.10"
	if err := d.UpdateAgent(agent); err != nil {
		t.Fatalf("UpdateAgent: %v", err)
	}
	if err := d.AddAgentZone(agent.ID, zone.ID); err != nil {
		t.Fatalf("AddAgentZone: %v", err)
	}

	mc := newMockAgentClient()
	r := New(d, mc, time.Minute)

	// First cycle: create the A record.
	if err := r.reconcileAgentDNS(context.Background()); err != nil {
		t.Fatalf("reconcileAgentDNS: %v", err)
	}
	got, _ := d.GetAgent(agent.ID)
	if got.DNSRecordID == "" {
		t.Fatal("expected agent to have an A record id")
	}
	rec, ok := mp.getRecord(got.DNSRecordID)
	if !ok || rec.Type != "A" || rec.Content != "203.0.113.10" || rec.Name != "agent1.example.com" {
		t.Fatalf("unexpected A record: %+v (ok=%v)", rec, ok)
	}

	// IP changes — a DDNS cycle should update the record.
	got.PublicIP = "203.0.113.99"
	if err := d.UpdateAgent(got); err != nil {
		t.Fatalf("UpdateAgent: %v", err)
	}
	if err := r.reconcileAgentDNS(context.Background()); err != nil {
		t.Fatalf("reconcileAgentDNS (update): %v", err)
	}
	rec, _ = mp.getRecord(got.DNSRecordID)
	if rec.Content != "203.0.113.99" {
		t.Errorf("DDNS did not update record: got %q, want 203.0.113.99", rec.Content)
	}

	entries, _, _ := d.ListAuditLog(20, 0)
	found := false
	for _, e := range entries {
		if e.Action == "ddns_updated" {
			found = true
		}
	}
	if !found {
		t.Error("expected ddns_updated audit entry")
	}
}

func TestReconcileAgentDNS_StaticModeNoUpdate(t *testing.T) {
	d := testDB(t)
	mp := registerMockProvider(t)
	_, zone, agent, _, _ := setupScenario(t, d)

	agent.DNSMode = models.DNSModeStatic
	agent.PublicIP = "203.0.113.10"
	if err := d.UpdateAgent(agent); err != nil {
		t.Fatalf("UpdateAgent: %v", err)
	}
	if err := d.AddAgentZone(agent.ID, zone.ID); err != nil {
		t.Fatalf("AddAgentZone: %v", err)
	}

	mc := newMockAgentClient()
	r := New(d, mc, time.Minute)

	if err := r.reconcileAgentDNS(context.Background()); err != nil {
		t.Fatalf("reconcileAgentDNS: %v", err)
	}
	got, _ := d.GetAgent(agent.ID)
	recID := got.DNSRecordID
	if recID == "" {
		t.Fatal("expected A record created in static mode too")
	}

	// IP changes, but static mode must NOT auto-update.
	got.PublicIP = "203.0.113.99"
	if err := d.UpdateAgent(got); err != nil {
		t.Fatalf("UpdateAgent: %v", err)
	}
	if err := r.reconcileAgentDNS(context.Background()); err != nil {
		t.Fatalf("reconcileAgentDNS (2): %v", err)
	}
	rec, _ := mp.getRecord(recID)
	if rec.Content != "203.0.113.10" {
		t.Errorf("static mode should not auto-update: got %q, want 203.0.113.10", rec.Content)
	}
}

func TestMatchZoneForFQDN(t *testing.T) {
	zones := []models.Zone{
		{ID: "z1", Name: "example.com"},
		{ID: "z2", Name: "sub.example.com"},
	}
	if z := matchZoneForFQDN("host.sub.example.com", zones); z == nil || z.ID != "z2" {
		t.Errorf("expected longest-suffix match z2, got %+v", z)
	}
	if z := matchZoneForFQDN("host.example.com", zones); z == nil || z.ID != "z1" {
		t.Errorf("expected z1, got %+v", z)
	}
	if z := matchZoneForFQDN("agent.other.org", zones); z != nil {
		t.Errorf("expected no match, got %+v", z)
	}
}

func TestReconcileAgents_MarkOffline(t *testing.T) {
	d := testDB(t)
	_, _, agent, _, _ := setupScenario(t, d)

	mc := newMockAgentClient()
	// Agent is NOT healthy.
	mc.setHealthy(agent.APIURL, false)

	r := New(d, mc, time.Minute)

	if err := r.reconcileAgents(context.Background()); err != nil {
		t.Fatalf("reconcileAgents: %v", err)
	}

	// Agent should now be offline.
	got, err := d.GetAgent(agent.ID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if got.Status != models.AgentStatusOffline {
		t.Errorf("expected agent status %q, got %q", models.AgentStatusOffline, got.Status)
	}

	// Audit log should reflect the status change.
	entries, _, _ := d.ListAuditLog(10, 0)
	found := false
	for _, e := range entries {
		if e.Action == "status_change" && e.EntityID == agent.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected audit entry with action status_change for offline agent")
	}
}

func TestReconcileAgents_ComeBackOnline(t *testing.T) {
	d := testDB(t)
	_, _, agent, _, _ := setupScenario(t, d)

	// Mark agent as offline first.
	if err := d.UpdateAgentStatus(agent.ID, models.AgentStatusOffline); err != nil {
		t.Fatalf("UpdateAgentStatus: %v", err)
	}

	mc := newMockAgentClient()
	mc.setHealthy(agent.APIURL, true)

	r := New(d, mc, time.Minute)

	if err := r.reconcileAgents(context.Background()); err != nil {
		t.Fatalf("reconcileAgents: %v", err)
	}

	// Agent should be adopted again.
	got, err := d.GetAgent(agent.ID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if got.Status != models.AgentStatusAdopted {
		t.Errorf("expected agent status %q, got %q", models.AgentStatusAdopted, got.Status)
	}
}

func TestRunOnce_FullCycle(t *testing.T) {
	d := testDB(t)
	mp := registerMockProvider(t)
	_, _, agent, _, dom := setupScenario(t, d)

	mc := newMockAgentClient()
	mc.setHealthy(agent.APIURL, true)

	r := New(d, mc, time.Minute)

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	// Route should be pushed.
	routes := mc.getRoutes(agent.APIURL)
	if len(routes) != 1 {
		t.Fatalf("expected 1 route on agent, got %d", len(routes))
	}
	host := extractHostFromRoute(routes[0])
	if host != "app.example.com" {
		t.Errorf("expected host app.example.com, got %s", host)
	}

	// DNS record should be created.
	got, err := d.GetDomain(dom.ID)
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	if got.DNSRecordID == "" {
		t.Fatal("expected dns_record_id to be set")
	}
	if got.Status != models.DomainStatusActive {
		t.Errorf("expected domain status %q, got %q", models.DomainStatusActive, got.Status)
	}

	// Verify the DNS record content.
	rec, ok := mp.getRecord(got.DNSRecordID)
	if !ok {
		t.Fatalf("DNS record not found in mock provider")
	}
	if rec.Content != "agent1.example.com" {
		t.Errorf("DNS content: got %q, want agent1.example.com", rec.Content)
	}

	// Agent should still be adopted.
	gotAgent, err := d.GetAgent(agent.ID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if gotAgent.Status != models.AgentStatusAdopted {
		t.Errorf("expected agent status %q, got %q", models.AgentStatusAdopted, gotAgent.Status)
	}

	// Running a second cycle should be idempotent (no extra pushes).
	pushBefore := mc.getPushCalls()
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce (second): %v", err)
	}
	pushAfter := mc.getPushCalls()
	if pushAfter != pushBefore {
		t.Errorf("second RunOnce caused %d additional push(es), expected 0", pushAfter-pushBefore)
	}
}

func TestStartStop(t *testing.T) {
	d := testDB(t)
	_ = registerMockProvider(t)
	// No entities needed — just testing the lifecycle.

	mc := newMockAgentClient()
	r := New(d, mc, 50*time.Millisecond)

	if r.Running() {
		t.Fatal("reconciler should not be running before Start")
	}

	ctx := context.Background()
	r.Start(ctx)

	if !r.Running() {
		t.Fatal("reconciler should be running after Start")
	}

	// Let it tick a couple of times.
	time.Sleep(200 * time.Millisecond)

	r.Stop()

	if r.Running() {
		t.Fatal("reconciler should not be running after Stop")
	}

	// Starting again should work.
	r.Start(ctx)
	if !r.Running() {
		t.Fatal("reconciler should be running after second Start")
	}
	r.Stop()
}

func TestExtractHostFromRoute(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "standard route",
			raw:  `{"@id":"test","match":[{"host":["app.example.com"]}],"terminal":true}`,
			want: "app.example.com",
		},
		{
			name: "no match",
			raw:  `{"@id":"test","terminal":true}`,
			want: "",
		},
		{
			name: "empty host",
			raw:  `{"@id":"test","match":[{"host":[]}],"terminal":true}`,
			want: "",
		},
		{
			name: "invalid json",
			raw:  `not json`,
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHostFromRoute(json.RawMessage(tt.raw))
			if got != tt.want {
				t.Errorf("extractHostFromRoute = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRoutesMatch(t *testing.T) {
	a := json.RawMessage(`{"a":1,"b":2}`)
	b := json.RawMessage(`{"b":2,"a":1}`)
	c := json.RawMessage(`{"a":1,"b":3}`)

	if !routesMatch(a, b) {
		t.Error("expected a and b to match (key order differs)")
	}
	if routesMatch(a, c) {
		t.Error("expected a and c to NOT match")
	}
}

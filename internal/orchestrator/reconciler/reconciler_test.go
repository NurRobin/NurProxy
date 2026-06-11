package reconciler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/orchestrator/tls"
	"github.com/NurRobin/NurProxy/internal/provider"
	"github.com/NurRobin/NurProxy/internal/shared/crypto"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// ---------------------------------------------------------------------------
// Mock Agent Client
// ---------------------------------------------------------------------------

type mockAgentClient struct {
	mu               sync.Mutex
	routes           map[string][]json.RawMessage // agentURL -> routes
	healthy          map[string]bool              // agentURL -> reachable
	pushCalls        int
	deleteRouteCalls int              // inbound DeleteRoute invocations (must stay 0 for stream-connected agents)
	pushErrors       map[string]error // fqdn -> error
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
	m.deleteRouteCalls++
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
// Mock Route Hub
// ---------------------------------------------------------------------------

type mockHub struct {
	mu        sync.Mutex
	connected map[string]bool
	published map[string][][]proxymodel.RouteIntent
	sets      map[string][]proxymodel.IntentSet
}

func newMockHub() *mockHub {
	return &mockHub{
		connected: make(map[string]bool),
		published: make(map[string][][]proxymodel.RouteIntent),
		sets:      make(map[string][]proxymodel.IntentSet),
	}
}

func (m *mockHub) Connected(agentID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connected[agentID]
}

func (m *mockHub) PublishIntents(agentID string, intents []proxymodel.RouteIntent) bool {
	return m.PublishIntentSet(agentID, proxymodel.IntentSet{Intents: intents})
}

func (m *mockHub) PublishIntentSet(agentID string, set proxymodel.IntentSet) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.published[agentID] = append(m.published[agentID], set.Intents)
	m.sets[agentID] = append(m.sets[agentID], set)
	return m.connected[agentID]
}

func (m *mockHub) lastSet(agentID string) (proxymodel.IntentSet, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sets := m.sets[agentID]
	if len(sets) == 0 {
		return proxymodel.IntentSet{}, false
	}
	return sets[len(sets)-1], true
}

func (m *mockHub) setConnected(agentID string, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected[agentID] = ok
}

func (m *mockHub) lastPublished(agentID string) []proxymodel.RouteIntent {
	m.mu.Lock()
	defer m.mu.Unlock()
	batches := m.published[agentID]
	if len(batches) == 0 {
		return nil
	}
	return batches[len(batches)-1]
}

// ---------------------------------------------------------------------------
// Mock DNS Provider
// ---------------------------------------------------------------------------

type mockDNSProvider struct {
	mu      sync.Mutex
	records map[string]provider.Record // recordID -> record
	nextID  int
	// deleteErr, when set, is returned by DeleteRecord instead of deleting — used
	// to simulate provider failures (transient errors, ErrRecordNotFound).
	deleteErr error
	// getErr, when set, is returned by GetRecord instead of the stored record —
	// used to simulate a transient read failure vs. a genuine ErrRecordNotFound.
	getErr error
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
	if p.deleteErr != nil {
		return p.deleteErr
	}
	delete(p.records, recordID)
	return nil
}

func (p *mockDNSProvider) GetRecord(_ context.Context, _ json.RawMessage, recordID string) (*provider.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.getErr != nil {
		return nil, p.getErr
	}
	rec, ok := p.records[recordID]
	if !ok {
		return nil, fmt.Errorf("record not found: %s", recordID)
	}
	return &rec, nil
}

func (p *mockDNSProvider) ListRecords(_ context.Context, _ json.RawMessage, name, recordType string) ([]provider.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []provider.Record
	for id, rec := range p.records {
		if name != "" && !strings.EqualFold(rec.Name, name) {
			continue
		}
		if recordType != "" && !strings.EqualFold(rec.Type, recordType) {
			continue
		}
		rec.ID = id
		out = append(out, rec)
	}
	return out, nil
}

// seedRecord injects a pre-existing record (simulating one created by a prior run
// or the operator), returning its ID — used by the check-before-create tests.
func (p *mockDNSProvider) seedRecord(rec provider.Record) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextID++
	id := fmt.Sprintf("seed-%d", p.nextID)
	p.records[id] = rec
	return id
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

	// A freshly-heartbeating, live agent: last_seen is recent so staleness-based
	// liveness keeps it adopted.
	seen := time.Now().UTC()
	agent = &models.Agent{
		ID:        "agent-1",
		Name:      "Agent One",
		FQDN:      "agent1.example.com",
		APIURL:    "https://agent1.example.com:8443",
		TokenHash: "token-hash-1",
		DNSMode:   models.DNSModeStatic,
		Status:    models.AgentStatusAdopted,
		LastSeen:  &seen,
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
	// A cert exists for the host, so a successful apply marks the domain active
	// (a central-TLS domain WITHOUT a cert would correctly be "degraded", §78).
	if err := d.UpsertCertificate(&models.Certificate{ID: "cert-app", Host: "app.example.com", Names: []string{"app.example.com"}, CertPEM: "C", KeyPEM: "K"}); err != nil {
		t.Fatalf("UpsertCertificate: %v", err)
	}

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

func TestReconcileRoutes_HubPushSkipsInbound(t *testing.T) {
	d := testDB(t)
	_, _, agent, _, _ := setupScenario(t, d)

	mc := newMockAgentClient()
	hub := newMockHub()
	hub.setConnected(agent.ID, true)

	r := New(d, mc, time.Minute)
	r.SetHub(hub)

	if err := r.reconcileRoutes(context.Background(), agent); err != nil {
		t.Fatalf("reconcileRoutes: %v", err)
	}

	// Routes should be delivered over the stream, NOT via the inbound client.
	pushed := hub.lastPublished(agent.ID)
	if len(pushed) != 1 {
		t.Fatalf("expected 1 intent published to hub, got %d", len(pushed))
	}
	if host := pushed[0].Route.Host; host != "app.example.com" {
		t.Errorf("published intent host = %q, want app.example.com", host)
	}
	if pushed[0].ArtifactID == "" {
		t.Error("published intent should carry a stable artifact id")
	}
	if mc.getPushCalls() != 0 {
		t.Errorf("inbound push should not be used for a connected agent, got %d calls", mc.getPushCalls())
	}
}

// TestBuildDesiredRoutes_SkipsDriftedArtifact verifies drift = review, not
// bulldoze (§11, invariant #3): a domain whose artifact is in an unresolved
// drifted state is NOT pushed, so the reconciler never overwrites the operator's
// on-disk change while it awaits review. Enabling the opt-in per-agent
// auto-reconcile policy restores the push (hands-off auto-correction).
func TestBuildDesiredRoutes_SkipsDriftedArtifact(t *testing.T) {
	d := testDB(t)
	_, _, agent, _, dom := setupScenario(t, d)

	// Create the domain's artifact and flag it drifted.
	artifactID := artifactIDForDomain(dom.ID)
	art := &models.ConfigArtifact{
		ID:      artifactID,
		AgentID: agent.ID,
		Backend: "caddy",
		Target:  models.Target{Kind: models.TargetKindCaddyRoute, Path: "caddy:route:" + artifactID},
		Source:  models.ArtifactSourceGenerated,
		Content: `{"handle":[]}`,
	}
	if err := d.CreateConfigArtifact(art, "tester", "seed"); err != nil {
		t.Fatalf("CreateConfigArtifact: %v", err)
	}
	if err := d.MarkConfigArtifactDrifted(artifactID); err != nil {
		t.Fatalf("MarkConfigArtifactDrifted: %v", err)
	}

	r := New(d, newMockAgentClient(), time.Minute)

	desired, keep, err := r.buildDesiredRoutes(agent)
	if err != nil {
		t.Fatalf("buildDesiredRoutes: %v", err)
	}
	if len(desired) != 0 {
		t.Errorf("drifted artifact should be skipped, got %d desired routes", len(desired))
	}
	// But the drifted file must be RETAINED (keep), so the agent's prune does not
	// mistake it for a deleted domain's orphan (invariant #3).
	if len(keep) != 1 {
		t.Errorf("drifted artifact path should be in keep, got %d keep paths", len(keep))
	}

	// With auto-reconcile enabled, the domain is pushed again (and not in keep-extra).
	if err := d.SetAgentAutoReconcileConfig(agent.ID, true); err != nil {
		t.Fatalf("SetAgentAutoReconcileConfig: %v", err)
	}
	agent.AutoReconcileConfig = true
	desired, keep, err = r.buildDesiredRoutes(agent)
	if err != nil {
		t.Fatalf("buildDesiredRoutes (auto): %v", err)
	}
	if len(desired) != 1 {
		t.Errorf("auto-reconcile should push the artifact, got %d desired routes", len(desired))
	}
	if len(keep) != 0 {
		t.Errorf("auto-reconcile pushes the artifact, so keep-extra should be empty, got %d", len(keep))
	}
}

func TestPushAgentRoutes(t *testing.T) {
	d := testDB(t)
	_, _, agent, _, _ := setupScenario(t, d)

	hub := newMockHub()
	hub.setConnected(agent.ID, true)

	r := New(d, newMockAgentClient(), time.Minute)
	r.SetHub(hub)

	if err := r.PushAgentRoutes(agent.ID); err != nil {
		t.Fatalf("PushAgentRoutes: %v", err)
	}
	pushed := hub.lastPublished(agent.ID)
	if len(pushed) != 1 {
		t.Fatalf("expected 1 route pushed, got %d", len(pushed))
	}

	// Disconnected agent: no-op, no error.
	hub.setConnected(agent.ID, false)
	hub.published[agent.ID] = nil
	if err := r.PushAgentRoutes(agent.ID); err != nil {
		t.Fatalf("PushAgentRoutes (disconnected): %v", err)
	}
	if hub.lastPublished(agent.ID) != nil {
		t.Error("expected no publish to a disconnected agent")
	}
}

// TestPushAgentRoutes_includesCertsForPreflight verifies the push carries the
// agent's cert bundles alongside the intents (§5/§7), so the agent installs them
// before applying the referencing config (preflight ordering). The decrypted key
// must ride the bundle (re-encrypted at rest on the agent).
func TestPushAgentRoutes_includesCertsForPreflight(t *testing.T) {
	d := testDB(t)
	_, _, agent, _, _ := setupScenario(t, d)

	if err := d.UpsertCertificate(&models.Certificate{
		ID:      "cert-1",
		Host:    "app.example.com",
		Names:   []string{"app.example.com"},
		CertPEM: "LEAFCHAIN",
		KeyPEM:  "PRIVATEKEY",
	}); err != nil {
		t.Fatalf("UpsertCertificate: %v", err)
	}

	hub := newMockHub()
	hub.setConnected(agent.ID, true)

	r := New(d, newMockAgentClient(), time.Minute)
	r.SetHub(hub)

	if err := r.PushAgentRoutes(agent.ID); err != nil {
		t.Fatalf("PushAgentRoutes: %v", err)
	}

	set, ok := hub.lastSet(agent.ID)
	if !ok {
		t.Fatal("expected an intent set to be published")
	}
	if len(set.Intents) != 1 {
		t.Fatalf("expected 1 intent, got %d", len(set.Intents))
	}
	if len(set.Certs) != 1 {
		t.Fatalf("expected 1 cert bundle in the push, got %d", len(set.Certs))
	}
	cb := set.Certs[0]
	if cb.Host != "app.example.com" {
		t.Errorf("cert host = %q, want app.example.com", cb.Host)
	}
	if cb.CertPEM != "LEAFCHAIN" || cb.KeyPEM != "PRIVATEKEY" {
		t.Errorf("cert bundle = %+v, want decrypted leaf+key", cb)
	}
}

// TestPushAgentRoutes_noCert_omitsBundles verifies that without a stored cert the
// push carries no cert material (the host falls back to self-ACME, §7) and never
// fails the push.
func TestPushAgentRoutes_noCert_omitsBundles(t *testing.T) {
	d := testDB(t)
	_, _, agent, _, _ := setupScenario(t, d)

	hub := newMockHub()
	hub.setConnected(agent.ID, true)

	r := New(d, newMockAgentClient(), time.Minute)
	r.SetHub(hub)

	if err := r.PushAgentRoutes(agent.ID); err != nil {
		t.Fatalf("PushAgentRoutes: %v", err)
	}
	set, ok := hub.lastSet(agent.ID)
	if !ok {
		t.Fatal("expected an intent set to be published")
	}
	if len(set.Certs) != 0 {
		t.Errorf("expected no cert bundles, got %d", len(set.Certs))
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
	// A cert exists for the host, so the drift-fix marks the domain active. The
	// drift-fix path now goes through MarkDomainApplied (not MarkDomainSynced), so
	// it honors the §78 degraded check — a central-TLS domain WITHOUT a cert would
	// correctly be "degraded" instead of a bare "active".
	if err := d.UpsertCertificate(&models.Certificate{ID: "cert-app", Host: "app.example.com", Names: []string{"app.example.com"}, CertPEM: "C", KeyPEM: "K"}); err != nil {
		t.Fatalf("UpsertCertificate: %v", err)
	}

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

// The drift-fix path routes through MarkDomainApplied, so a central-TLS domain
// with NO issued certificate is marked "degraded" (served over plaintext), not a
// bare "active". Under the old MarkDomainSynced this §78 check was bypassed and
// the domain wrongly showed "active".
func TestReconcileRoutes_FixDriftDegradedWhenNoCert(t *testing.T) {
	d := testDB(t)
	_, _, agent, _, dom := setupScenario(t, d) // SSLModeAuto -> central TLS, no cert seeded

	mc := newMockAgentClient()
	mc.setHealthy(agent.APIURL, true)
	staleRoute := json.RawMessage(`{"@id":"domain-app-example-com","match":[{"host":["app.example.com"]}],"handle":[{"handler":"subroute"}],"terminal":true}`)
	mc.setRoutes(agent.APIURL, []json.RawMessage{staleRoute})

	r := New(d, mc, time.Minute)
	if err := r.reconcileRoutes(context.Background(), agent); err != nil {
		t.Fatalf("reconcileRoutes: %v", err)
	}

	got, _ := d.GetDomain(dom.ID)
	if got.Status != models.DomainStatusDegraded {
		t.Errorf("expected status %q (no cert, §78), got %q", models.DomainStatusDegraded, got.Status)
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
	if err := d.UpdateDomainDNSRecord(dom.ID, recordID, true); err != nil {
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

// A transient GetRecord failure (network/auth/rate-limit — NOT ErrRecordNotFound)
// for a NurProxy-managed CNAME must preserve the stored record id and the
// dns_managed=true flag, NOT re-resolve by name and adopt the record as
// managed=false (which would flip it to "adopted" and defeat teardown, #66/§79).
// A genuine ErrRecordNotFound, by contrast, IS treated as a real miss and the
// record is re-resolved/re-created.
func TestReconcileDNS_TransientGetRecordPreservesManaged(t *testing.T) {
	tests := []struct {
		name        string
		getErr      error
		wantManaged bool
		wantSameID  bool
	}{
		{
			name:        "transient error preserves managed and id",
			getErr:      errors.New("dial tcp: i/o timeout"),
			wantManaged: true,
			wantSameID:  true,
		},
		{
			name:        "record-not-found re-resolves and adopts",
			getErr:      provider.ErrRecordNotFound,
			wantManaged: false, // re-resolved by name, the live record is adopted
			wantSameID:  true,  // same record id (re-found by name)
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := testDB(t)
			mp := registerMockProvider(t)
			_, _, _, _, dom := setupScenario(t, d)

			// Seed a correct, NurProxy-created CNAME and record it as managed=true.
			recordID := mp.seedRecord(provider.Record{
				Type:    "CNAME",
				Name:    "app.example.com",
				Content: "agent1.example.com",
			})
			if err := d.UpdateDomainDNSRecord(dom.ID, recordID, true); err != nil {
				t.Fatalf("UpdateDomainDNSRecord: %v", err)
			}

			// GetRecord fails this cycle; ListRecords (used by the re-resolve path)
			// still returns the live record, so a wrongful re-resolve WOULD adopt it
			// as managed=false — the regression we guard against.
			mp.getErr = tc.getErr

			r := New(d, newMockAgentClient(), time.Minute)
			if err := r.reconcileDNS(context.Background()); err != nil {
				t.Fatalf("reconcileDNS: %v", err)
			}

			got, err := d.GetDomain(dom.ID)
			if err != nil {
				t.Fatalf("GetDomain: %v", err)
			}
			if got.DNSManaged != tc.wantManaged {
				t.Errorf("dns_managed = %v, want %v", got.DNSManaged, tc.wantManaged)
			}
			if tc.wantSameID && got.DNSRecordID != recordID {
				t.Errorf("dns_record_id = %q, want preserved %q", got.DNSRecordID, recordID)
			}
		})
	}
}

// reconcileAgentDNS must only adopt an existing A/AAAA whose content already
// matches the agent IP. A same-type record with a DIFFERENT IP is one NurProxy
// did not create; it must raise an explicit conflict (dns_error + audit) rather
// than UpdateRecord-ing over a record it doesn't own.
func TestReconcileAgentDNS_AddressContentMismatchConflict(t *testing.T) {
	tests := []struct {
		name       string
		recordType string
		seedIP     string
		agentIP    string
		ip6        bool
	}{
		{name: "A mismatch", recordType: "A", seedIP: "198.51.100.5", agentIP: "203.0.113.10"},
		{name: "AAAA mismatch", recordType: "AAAA", seedIP: "2001:db8::5", agentIP: "2001:db8::10", ip6: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := testDB(t)
			mp := registerMockProvider(t)
			_, zone, agent, _, _ := setupScenario(t, d)

			agent.DNSMode = models.DNSModeDDNS
			if tc.ip6 {
				agent.PublicIP = "203.0.113.10" // A is fine; only AAAA conflicts
				agent.PublicIP6 = tc.agentIP
			} else {
				agent.PublicIP = tc.agentIP
			}
			if err := d.UpdateAgent(agent); err != nil {
				t.Fatalf("UpdateAgent: %v", err)
			}
			if err := d.AddAgentZone(agent.ID, zone.ID); err != nil {
				t.Fatalf("AddAgentZone: %v", err)
			}

			// An operator-owned record of the same type, different IP, sits at the
			// anchor FQDN. NurProxy has no stored id for it (record id "").
			conflictID := mp.seedRecord(provider.Record{
				Type:    tc.recordType,
				Name:    agent.FQDN,
				Content: tc.seedIP,
			})

			r := New(d, newMockAgentClient(), time.Minute)
			if err := r.reconcileAgentDNS(context.Background()); err != nil {
				t.Fatalf("reconcileAgentDNS: %v", err)
			}

			// The pre-existing record must be left UNTOUCHED (no overwrite).
			rec, ok := mp.getRecord(conflictID)
			if !ok {
				t.Fatalf("seeded record %s disappeared", conflictID)
			}
			if rec.Content != tc.seedIP {
				t.Errorf("seeded record was overwritten: content = %q, want %q (NurProxy must not touch a record it didn't create)", rec.Content, tc.seedIP)
			}

			// The agent must carry a DNS conflict error and NOT have adopted the
			// foreign record's id for this family.
			got, _ := d.GetAgent(agent.ID)
			if got.DNSError == "" {
				t.Error("expected a dns_error conflict to be set on the agent")
			}
			gotID := got.DNSRecordID
			if tc.ip6 {
				gotID = got.DNSRecordID6
			}
			if gotID == conflictID {
				t.Errorf("agent adopted the foreign %s record id %q — it must not own a record it didn't create", tc.recordType, conflictID)
			}

			entries, _, _ := d.ListAuditLog(20, 0)
			wantAction := strings.ToLower(tc.recordType) + "_record_conflict"
			found := false
			for _, e := range entries {
				if e.Action == wantAction {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected audit entry with action %q", wantAction)
			}
		})
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
	if err := d.UpdateDomainDNSRecord(dom.ID, recID, true); err != nil {
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
	// The agent is stream-connected: route removal must ride the dial-out stream
	// (a re-push of the now-smaller desired set the agent prunes against), never an
	// inbound DeleteRoute call (invariant #2, §3 no ghost vhost).
	hub := newMockHub()
	hub.setConnected(agent.ID, true)
	r.SetHub(hub)
	if err := r.reconcileDeletions(context.Background()); err != nil {
		t.Fatalf("reconcileDeletions: %v", err)
	}

	// DNS record gone.
	if _, ok := mp.getRecord(recID); ok {
		t.Error("expected DNS record to be deleted")
	}
	// Route removal rides the stream, not the inbound API.
	if mc.deleteRouteCalls != 0 {
		t.Errorf("expected no inbound DeleteRoute calls (dial-out only), got %d", mc.deleteRouteCalls)
	}
	// The agent's desired set was re-pushed and is now empty (its only domain was
	// deleted), so the agent prunes the orphaned on-disk vhost.
	if set, ok := hub.lastSet(agent.ID); !ok {
		t.Error("expected a re-push of the desired set over the stream after delete")
	} else if len(set.Intents) != 0 {
		t.Errorf("expected empty desired set after the only domain was deleted, got %d intents", len(set.Intents))
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

// A record already absent at the provider (ErrRecordNotFound) must NOT wedge the
// teardown: deletion is idempotent, so the domain row is still removed.
func TestReconcileDeletions_recordAlreadyGone_completesTeardown(t *testing.T) {
	d := testDB(t)
	mp := registerMockProvider(t)
	_, _, _, _, dom := setupScenario(t, d)

	if err := d.UpdateDomainDNSRecord(dom.ID, "rec-gone", true); err != nil {
		t.Fatalf("UpdateDomainDNSRecord: %v", err)
	}
	if err := d.UpdateDomainStatus(dom.ID, models.DomainStatusDeleting, ""); err != nil {
		t.Fatalf("UpdateDomainStatus: %v", err)
	}
	mp.deleteErr = provider.ErrRecordNotFound

	r := New(d, newMockAgentClient(), time.Minute)
	if err := r.reconcileDeletions(context.Background()); err != nil {
		t.Fatalf("reconcileDeletions: %v", err)
	}
	if _, err := d.GetDomain(dom.ID); err == nil {
		t.Error("domain should be torn down even when the DNS record was already gone")
	}
}

// A transient (non-not-found) delete error must keep the domain for retry rather
// than tearing it down — otherwise a real record could be orphaned.
func TestReconcileDeletions_transientError_keepsDomainForRetry(t *testing.T) {
	d := testDB(t)
	mp := registerMockProvider(t)
	_, _, _, _, dom := setupScenario(t, d)

	if err := d.UpdateDomainDNSRecord(dom.ID, "rec-x", true); err != nil {
		t.Fatalf("UpdateDomainDNSRecord: %v", err)
	}
	if err := d.UpdateDomainStatus(dom.ID, models.DomainStatusDeleting, ""); err != nil {
		t.Fatalf("UpdateDomainStatus: %v", err)
	}
	mp.deleteErr = errors.New("cloudflare API error: [1001] dns resolution timed out")

	r := New(d, newMockAgentClient(), time.Minute)
	if err := r.reconcileDeletions(context.Background()); err != nil {
		t.Fatalf("reconcileDeletions: %v", err)
	}
	got, err := d.GetDomain(dom.ID)
	if err != nil {
		t.Fatal("domain must survive a transient DNS-delete error for retry")
	}
	if got.Status != models.DomainStatusDeleting {
		t.Errorf("status = %q, want still deleting", got.Status)
	}
	if got.DNSRecordID != "rec-x" {
		t.Errorf("DNS record id should be retained for retry, got %q", got.DNSRecordID)
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

// An agent reporting a public IPv6 gets an AAAA record alongside its A record,
// each tracked by its own provider record ID. DDNS then updates each family
// independently.
func TestReconcileAgentDNS_CreatesAAAAForIPv6(t *testing.T) {
	d := testDB(t)
	mp := registerMockProvider(t)
	_, zone, agent, _, _ := setupScenario(t, d)

	agent.DNSMode = models.DNSModeDDNS
	agent.PublicIP = "203.0.113.10"
	agent.PublicIP6 = "2001:db8::10"
	if err := d.UpdateAgent(agent); err != nil {
		t.Fatalf("UpdateAgent: %v", err)
	}
	if err := d.AddAgentZone(agent.ID, zone.ID); err != nil {
		t.Fatalf("AddAgentZone: %v", err)
	}

	r := New(d, newMockAgentClient(), time.Minute)
	if err := r.reconcileAgentDNS(context.Background()); err != nil {
		t.Fatalf("reconcileAgentDNS: %v", err)
	}

	got, _ := d.GetAgent(agent.ID)
	if got.DNSRecordID == "" || got.DNSRecordID6 == "" {
		t.Fatalf("expected both A and AAAA record ids, got A=%q AAAA=%q", got.DNSRecordID, got.DNSRecordID6)
	}
	if got.DNSRecordID == got.DNSRecordID6 {
		t.Fatal("A and AAAA must be distinct records")
	}

	a4, _ := mp.getRecord(got.DNSRecordID)
	if a4.Type != "A" || a4.Content != "203.0.113.10" {
		t.Errorf("A record: %+v", a4)
	}
	a6, ok := mp.getRecord(got.DNSRecordID6)
	if !ok || a6.Type != "AAAA" || a6.Content != "2001:db8::10" || a6.Name != "agent1.example.com" {
		t.Fatalf("AAAA record: %+v (ok=%v)", a6, ok)
	}

	// A v6 change updates only the AAAA record.
	got.PublicIP6 = "2001:db8::99"
	if err := d.UpdateAgent(got); err != nil {
		t.Fatalf("UpdateAgent: %v", err)
	}
	if err := r.reconcileAgentDNS(context.Background()); err != nil {
		t.Fatalf("reconcileAgentDNS (v6 update): %v", err)
	}
	a6, _ = mp.getRecord(got.DNSRecordID6)
	if a6.Content != "2001:db8::99" {
		t.Errorf("DDNS did not update AAAA: got %q, want 2001:db8::99", a6.Content)
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

	// Agent's last heartbeat is long ago — well past the offline timeout.
	stale := time.Now().UTC().Add(-10 * time.Minute)
	agent.LastSeen = &stale
	if err := d.UpdateAgent(agent); err != nil {
		t.Fatalf("UpdateAgent: %v", err)
	}

	mc := newMockAgentClient()
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

	// Mark agent as offline, but its last heartbeat is fresh (setupScenario set
	// it just now) — so a reconcile cycle should bring it back online.
	if err := d.UpdateAgentStatus(agent.ID, models.AgentStatusOffline); err != nil {
		t.Fatalf("UpdateAgentStatus: %v", err)
	}

	mc := newMockAgentClient()
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
	// Cert present so the fully-synced domain ends "active" (no cert => "degraded", §78).
	if err := d.UpsertCertificate(&models.Certificate{ID: "cert-app", Host: "app.example.com", Names: []string{"app.example.com"}, CertPEM: "C", KeyPEM: "K"}); err != nil {
		t.Fatalf("UpsertCertificate: %v", err)
	}

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

// TestCertRenewalStore_firstIssuesCentralDomains verifies the scan now returns a
// first-issuance target for a central-TLS domain that has no certificate yet, and
// stops returning it once a cert exists (the renewal path then owns expiry).
func TestCertRenewalStore_firstIssuesCentralDomains(t *testing.T) {
	registerMockProvider(t)
	d := testDB(t)
	_, _, _, _, _ = setupScenario(t, d) // domain app.example.com, SSLMode auto -> central

	store := NewCertRenewalStore(d)

	targets, err := store.DueForRenewal(context.Background(), tls.DefaultRenewWindow)
	if err != nil {
		t.Fatalf("DueForRenewal: %v", err)
	}
	if len(targets) != 1 || targets[0].Host != "app.example.com" {
		t.Fatalf("expected one first-issue target for app.example.com, got %+v", targets)
	}
	if targets[0].Provider == nil {
		t.Error("first-issue target must carry a resolved DNS provider")
	}
	// The target must be flagged FirstIssue so the per-host lock in renewOne
	// re-checks for a concurrently-issued cert instead of double-driving ACME.
	if !targets[0].FirstIssue {
		t.Error("first-issuance target must carry FirstIssue=true so renewOne re-checks under the lock")
	}

	// TargetForHost resolves the same host on demand.
	one, err := store.TargetForHost(context.Background(), "app.example.com")
	if err != nil {
		t.Fatalf("TargetForHost: %v", err)
	}
	if one == nil || one.Host != "app.example.com" {
		t.Fatalf("TargetForHost returned %+v, want app.example.com", one)
	}

	// Once a cert exists, the host drops out of first-issuance and TargetForHost.
	if err := d.UpsertCertificate(&models.Certificate{
		ID: "app.example.com", Host: "app.example.com",
		Names: []string{"app.example.com"}, CertPEM: "C", KeyPEM: "K",
		ExpiresAt: time.Now().UTC().Add(90 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("UpsertCertificate: %v", err)
	}
	targets, err = store.DueForRenewal(context.Background(), tls.DefaultRenewWindow)
	if err != nil {
		t.Fatalf("DueForRenewal after cert: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("a domain with a valid cert should not be first-issued, got %+v", targets)
	}
	if one, _ := store.TargetForHost(context.Background(), "app.example.com"); one != nil {
		t.Errorf("TargetForHost should be nil once a cert exists, got %+v", one)
	}
}

// TestReconcileDNS_adoptsIdenticalExistingRecord verifies the check-before-create
// path: when a CNAME identical to the one NurProxy would create already exists
// (e.g. left over from a prior run), the reconciler adopts its ID instead of
// blind-creating a duplicate (which the provider would reject as "already exists").
func TestReconcileDNS_adoptsIdenticalExistingRecord(t *testing.T) {
	mp := registerMockProvider(t)
	d := testDB(t)
	_, _, agent, _, dom := setupScenario(t, d)

	// Seed the exact record NurProxy would create: CNAME app.example.com -> agentFQDN.
	seedID := mp.seedRecord(provider.Record{Type: "CNAME", Name: "app.example.com", Content: agent.FQDN})

	r := New(d, newMockAgentClient(), time.Minute)
	if err := r.reconcileDNS(context.Background()); err != nil {
		t.Fatalf("reconcileDNS: %v", err)
	}

	got, _ := d.GetDomain(dom.ID)
	if got.DNSRecordID != seedID {
		t.Errorf("expected the existing record %q to be adopted, got DNSRecordID=%q", seedID, got.DNSRecordID)
	}
	// No duplicate created.
	recs, _ := mp.ListRecords(context.Background(), nil, "app.example.com", "")
	if len(recs) != 1 {
		t.Errorf("expected exactly 1 record (adopted, no duplicate), got %d", len(recs))
	}
}

// TestReconcileDNS_conflictOnDifferentExistingRecord verifies that a pre-existing
// record that does NOT match the desired one yields an explicit conflict error
// (current vs desired) and is never overwritten.
func TestReconcileDNS_conflictOnDifferentExistingRecord(t *testing.T) {
	mp := registerMockProvider(t)
	d := testDB(t)
	_, _, _, _, dom := setupScenario(t, d)

	// Seed a DIFFERENT record on the same name: an A record to some other host.
	mp.seedRecord(provider.Record{Type: "A", Name: "app.example.com", Content: "203.0.113.99"})

	r := New(d, newMockAgentClient(), time.Minute)
	if err := r.reconcileDNS(context.Background()); err != nil {
		t.Fatalf("reconcileDNS: %v", err)
	}

	got, _ := d.GetDomain(dom.ID)
	if got.Status != models.DomainStatusError {
		t.Errorf("expected Error status on conflict, got %q", got.Status)
	}
	if got.DNSRecordID != "" {
		t.Errorf("conflict must not adopt/create a record, got DNSRecordID=%q", got.DNSRecordID)
	}
	if !strings.Contains(got.ErrorMsg, "already exists") || !strings.Contains(got.ErrorMsg, "203.0.113.99") {
		t.Errorf("conflict error should state current vs desired, got %q", got.ErrorMsg)
	}
}

// TestReconcileDeletions_KeepsAdoptedRecord proves the #79 fix: when a domain's
// DNS record was ADOPTED (managed=false) rather than created by NurProxy,
// teardown must NOT delete it (that record predates NurProxy and is the
// operator's), yet the domain row must still be removed (no stranding in
// "deleting").
func TestReconcileDeletions_KeepsAdoptedRecord(t *testing.T) {
	d := testDB(t)
	mp := registerMockProvider(t)
	_, _, agent, _, dom := setupScenario(t, d)

	recID, err := mp.CreateRecord(context.Background(), nil, provider.Record{
		Type: "CNAME", Name: "app.example.com", Content: "agent1.example.com",
	})
	if err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}
	// Adopted, not created by NurProxy.
	if err := d.UpdateDomainDNSRecord(dom.ID, recID, false); err != nil {
		t.Fatalf("UpdateDomainDNSRecord: %v", err)
	}
	if err := d.UpdateDomainStatus(dom.ID, models.DomainStatusDeleting, ""); err != nil {
		t.Fatalf("UpdateDomainStatus: %v", err)
	}

	mc := newMockAgentClient()
	mc.setHealthy(agent.APIURL, true)
	r := New(d, mc, time.Minute)
	hub := newMockHub()
	hub.setConnected(agent.ID, true)
	r.SetHub(hub)
	if err := r.reconcileDeletions(context.Background()); err != nil {
		t.Fatalf("reconcileDeletions: %v", err)
	}

	// The adopted DNS record MUST survive.
	if _, ok := mp.getRecord(recID); !ok {
		t.Error("adopted DNS record was deleted; teardown must only delete records NurProxy created (#79)")
	}
	// The domain row is still removed — no stranding in "deleting".
	if _, err := d.GetDomain(dom.ID); err == nil {
		t.Error("expected domain row to be removed even though the adopted record was kept")
	}
}

package db

import (
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/crypto"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// testDB creates a fresh in-memory database for each test.
func testDB(t *testing.T) *DB {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	d, err := Open(":memory:", key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// ---------------------------------------------------------------------------
// Migration
// ---------------------------------------------------------------------------

func TestMigration_TablesExist(t *testing.T) {
	d := testDB(t)

	tables := []string{
		"providers", "agents", "servers", "domains",
		"notifiers", "audit_log", "settings", "schema_version",
	}
	for _, tbl := range tables {
		var name string
		err := d.sql.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", tbl,
		).Scan(&name)
		if err != nil {
			t.Errorf("expected table %q to exist: %v", tbl, err)
		}
	}
}

func TestMigration_Idempotent(t *testing.T) {
	d := testDB(t)
	// Running migrate again should be a no-op.
	if err := d.migrate(); err != nil {
		t.Fatalf("second migrate failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Providers
// ---------------------------------------------------------------------------

func createTestProvider(t *testing.T, d *DB) *models.Provider {
	t.Helper()
	p := &models.Provider{
		ID:       "prov-1",
		Type:     "cloudflare",
		Name:     "My CF",
		Config:   `{"api_token":"secret123"}`,
		ZoneID:   "zone-abc",
		ZoneName: "example.com",
	}
	if err := d.CreateProvider(p); err != nil {
		t.Fatalf("CreateProvider: %v", err)
	}
	return p
}

func TestProvider_CreateAndGet(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)

	got, err := d.GetProvider(p.ID)
	if err != nil {
		t.Fatalf("GetProvider: %v", err)
	}
	if got.Name != p.Name {
		t.Errorf("Name: got %q, want %q", got.Name, p.Name)
	}
	if got.Config != p.Config {
		t.Errorf("Config not decrypted correctly: got %q, want %q", got.Config, p.Config)
	}
	if got.ZoneID != p.ZoneID {
		t.Errorf("ZoneID: got %q, want %q", got.ZoneID, p.ZoneID)
	}
}

func TestProvider_ConfigEncryption(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)

	// Read the raw stored value — it must NOT be the plaintext.
	var raw string
	err := d.sql.QueryRow("SELECT config FROM providers WHERE id = ?", p.ID).Scan(&raw)
	if err != nil {
		t.Fatal(err)
	}
	if raw == p.Config {
		t.Fatal("config stored in plaintext, expected encrypted")
	}
}

func TestProvider_List(t *testing.T) {
	d := testDB(t)
	createTestProvider(t, d)

	p2 := &models.Provider{
		ID:     "prov-2",
		Type:   "cloudflare",
		Name:   "Second",
		Config: `{"api_token":"other"}`,
	}
	if err := d.CreateProvider(p2); err != nil {
		t.Fatal(err)
	}

	list, err := d.ListProviders()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(list))
	}
}

func TestProvider_Update(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)

	p.Name = "Updated"
	p.Config = `{"api_token":"newsecret"}`
	if err := d.UpdateProvider(p); err != nil {
		t.Fatal(err)
	}

	got, err := d.GetProvider(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Updated" {
		t.Errorf("Name: got %q, want %q", got.Name, "Updated")
	}
	if got.Config != p.Config {
		t.Errorf("Config: got %q, want %q", got.Config, p.Config)
	}
}

func TestProvider_Delete(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)

	if err := d.DeleteProvider(p.ID); err != nil {
		t.Fatal(err)
	}

	_, err := d.GetProvider(p.ID)
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestProvider_SetDefault(t *testing.T) {
	d := testDB(t)
	p1 := createTestProvider(t, d)

	p2 := &models.Provider{
		ID: "prov-2", Type: "cloudflare", Name: "Two", Config: "{}",
	}
	if err := d.CreateProvider(p2); err != nil {
		t.Fatal(err)
	}

	if err := d.SetDefaultProvider(p1.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := d.GetProvider(p1.ID)
	if !got.IsDefault {
		t.Error("expected prov-1 to be default")
	}

	// Switch default to p2.
	if err := d.SetDefaultProvider(p2.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = d.GetProvider(p1.ID)
	if got.IsDefault {
		t.Error("expected prov-1 to no longer be default")
	}
	got2, _ := d.GetProvider(p2.ID)
	if !got2.IsDefault {
		t.Error("expected prov-2 to be default")
	}
}

func TestProvider_GetNotFound(t *testing.T) {
	d := testDB(t)
	_, err := d.GetProvider("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent provider")
	}
}

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------

func createTestAgent(t *testing.T, d *DB, providerID string) *models.Agent {
	t.Helper()
	a := &models.Agent{
		ID:           "agent-1",
		Name:         "Agent One",
		FQDN:         "agent1.example.com",
		APIURL:       "https://agent1.example.com:8443",
		TokenHash:    "hash123",
		ProviderID:   providerID,
		DNSMode:      models.DNSModeStatic,
		DDNSInterval: 300,
		Status:       models.AgentStatusPending,
		Version:      "1.0.0",
	}
	if err := d.CreateAgent(a); err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	return a
}

func TestAgent_CreateAndGet(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	a := createTestAgent(t, d, p.ID)

	got, err := d.GetAgent(a.ID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if got.Name != a.Name {
		t.Errorf("Name: got %q, want %q", got.Name, a.Name)
	}
	if got.FQDN != a.FQDN {
		t.Errorf("FQDN: got %q, want %q", got.FQDN, a.FQDN)
	}
	if got.Status != models.AgentStatusPending {
		t.Errorf("Status: got %q, want %q", got.Status, models.AgentStatusPending)
	}
}

func TestAgent_GetByFQDN(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	a := createTestAgent(t, d, p.ID)

	got, err := d.GetAgentByFQDN(a.FQDN)
	if err != nil {
		t.Fatalf("GetAgentByFQDN: %v", err)
	}
	if got.ID != a.ID {
		t.Errorf("ID: got %q, want %q", got.ID, a.ID)
	}
}

func TestAgent_List(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	createTestAgent(t, d, p.ID)

	a2 := &models.Agent{
		ID: "agent-2", Name: "Agent Two", FQDN: "agent2.example.com",
		ProviderID: p.ID, DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted,
	}
	if err := d.CreateAgent(a2); err != nil {
		t.Fatal(err)
	}

	list, err := d.ListAgents()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(list))
	}
}

func TestAgent_Update(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	a := createTestAgent(t, d, p.ID)

	a.Name = "Updated Agent"
	a.Version = "2.0.0"
	if err := d.UpdateAgent(a); err != nil {
		t.Fatal(err)
	}

	got, _ := d.GetAgent(a.ID)
	if got.Name != "Updated Agent" {
		t.Errorf("Name: got %q, want %q", got.Name, "Updated Agent")
	}
	if got.Version != "2.0.0" {
		t.Errorf("Version: got %q, want %q", got.Version, "2.0.0")
	}
}

func TestAgent_Delete_CascadesToServers(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	a := createTestAgent(t, d, p.ID)

	s := &models.Server{
		ID: "srv-1", AgentID: a.ID, Name: "Server 1", Address: "10.0.0.1",
	}
	if err := d.CreateServer(s); err != nil {
		t.Fatal(err)
	}

	// Delete agent — server should be cascade-deleted.
	if err := d.DeleteAgent(a.ID); err != nil {
		t.Fatal(err)
	}

	_, err := d.GetServer(s.ID)
	if err == nil {
		t.Fatal("expected server to be deleted via cascade")
	}
}

func TestAgent_UpdateStatus(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	a := createTestAgent(t, d, p.ID)

	if err := d.UpdateAgentStatus(a.ID, models.AgentStatusAdopted); err != nil {
		t.Fatal(err)
	}

	got, _ := d.GetAgent(a.ID)
	if got.Status != models.AgentStatusAdopted {
		t.Errorf("Status: got %q, want %q", got.Status, models.AgentStatusAdopted)
	}
}

func TestAgent_Heartbeat(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	a := createTestAgent(t, d, p.ID)

	if err := d.UpdateAgentHeartbeat(a.ID, "1.2.3.4"); err != nil {
		t.Fatal(err)
	}

	got, _ := d.GetAgent(a.ID)
	if got.PublicIP != "1.2.3.4" {
		t.Errorf("PublicIP: got %q, want %q", got.PublicIP, "1.2.3.4")
	}
	if got.LastSeen == nil {
		t.Error("LastSeen should be set after heartbeat")
	}
}

func TestAgent_ListPending(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	createTestAgent(t, d, p.ID) // status = pending

	a2 := &models.Agent{
		ID: "agent-2", Name: "Adopted", FQDN: "a2.example.com",
		ProviderID: p.ID, DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted,
	}
	if err := d.CreateAgent(a2); err != nil {
		t.Fatal(err)
	}

	pending, err := d.ListPendingAgents()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending agent, got %d", len(pending))
	}
	if pending[0].ID != "agent-1" {
		t.Errorf("expected agent-1, got %s", pending[0].ID)
	}
}

// ---------------------------------------------------------------------------
// Servers
// ---------------------------------------------------------------------------

func createTestServer(t *testing.T, d *DB, agentID string) *models.Server {
	t.Helper()
	s := &models.Server{
		ID: "srv-1", AgentID: agentID, Name: "Backend 1", Address: "10.0.0.1:8080", Notes: "primary",
	}
	if err := d.CreateServer(s); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	return s
}

func TestServer_CreateAndGet(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	a := createTestAgent(t, d, p.ID)
	s := createTestServer(t, d, a.ID)

	got, err := d.GetServer(s.ID)
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	if got.Address != s.Address {
		t.Errorf("Address: got %q, want %q", got.Address, s.Address)
	}
	if got.Notes != "primary" {
		t.Errorf("Notes: got %q, want %q", got.Notes, "primary")
	}
}

func TestServer_ListByAgent(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	a := createTestAgent(t, d, p.ID)
	createTestServer(t, d, a.ID)

	s2 := &models.Server{
		ID: "srv-2", AgentID: a.ID, Name: "Backend 2", Address: "10.0.0.2:8080",
	}
	if err := d.CreateServer(s2); err != nil {
		t.Fatal(err)
	}

	list, err := d.ListServersByAgent(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(list))
	}
}

func TestServer_Update(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	a := createTestAgent(t, d, p.ID)
	s := createTestServer(t, d, a.ID)

	s.Name = "Updated"
	s.Address = "10.0.0.99:9090"
	if err := d.UpdateServer(s); err != nil {
		t.Fatal(err)
	}

	got, _ := d.GetServer(s.ID)
	if got.Name != "Updated" {
		t.Errorf("Name: got %q, want %q", got.Name, "Updated")
	}
}

func TestServer_Delete(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	a := createTestAgent(t, d, p.ID)
	s := createTestServer(t, d, a.ID)

	if err := d.DeleteServer(s.ID); err != nil {
		t.Fatal(err)
	}

	_, err := d.GetServer(s.ID)
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

// ---------------------------------------------------------------------------
// Domains
// ---------------------------------------------------------------------------

func createTestDomain(t *testing.T, d *DB, providerID, serverID string) *models.Domain {
	t.Helper()
	dom := &models.Domain{
		Subdomain:  "app",
		ProviderID: providerID,
		ServerID:   serverID,
		Port:       8080,
		ProxyConfig: models.ProxyConfig{
			WebSocket:  true,
			ForceHTTPS: true,
		},
		WebSocket:  true,
		ForceHTTPS: true,
		SSLMode:    models.SSLModeAuto,
		Status:     models.DomainStatusPending,
	}
	if err := d.CreateDomain(dom); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	return dom
}

func TestDomain_CreateAndGet(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	a := createTestAgent(t, d, p.ID)
	s := createTestServer(t, d, a.ID)
	dom := createTestDomain(t, d, p.ID, s.ID)

	if dom.ID == 0 {
		t.Fatal("expected domain ID to be assigned")
	}

	got, err := d.GetDomain(dom.ID)
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	if got.Subdomain != "app" {
		t.Errorf("Subdomain: got %q, want %q", got.Subdomain, "app")
	}
	if got.Port != 8080 {
		t.Errorf("Port: got %d, want %d", got.Port, 8080)
	}
	if !got.ProxyConfig.WebSocket {
		t.Error("expected ProxyConfig.WebSocket to be true")
	}
	if !got.WebSocket {
		t.Error("expected WebSocket to be true")
	}
	if got.SSLMode != models.SSLModeAuto {
		t.Errorf("SSLMode: got %q, want %q", got.SSLMode, models.SSLModeAuto)
	}
}

func TestDomain_ListWithFilters(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	a := createTestAgent(t, d, p.ID)
	s := createTestServer(t, d, a.ID)
	createTestDomain(t, d, p.ID, s.ID)

	// Create a second domain on a different server.
	s2 := &models.Server{ID: "srv-2", AgentID: a.ID, Name: "S2", Address: "10.0.0.2"}
	if err := d.CreateServer(s2); err != nil {
		t.Fatal(err)
	}
	dom2 := &models.Domain{
		Subdomain: "api", ProviderID: p.ID, ServerID: s2.ID,
		Port: 3000, SSLMode: models.SSLModeAuto, Status: models.DomainStatusActive,
	}
	if err := d.CreateDomain(dom2); err != nil {
		t.Fatal(err)
	}

	// No filter.
	all, err := d.ListDomains(DomainFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(all))
	}

	// Filter by server.
	byServer, err := d.ListDomains(DomainFilter{ServerID: s2.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(byServer) != 1 || byServer[0].Subdomain != "api" {
		t.Errorf("filter by server: got %+v", byServer)
	}

	// Filter by status.
	byStatus, err := d.ListDomains(DomainFilter{Status: string(models.DomainStatusActive)})
	if err != nil {
		t.Fatal(err)
	}
	if len(byStatus) != 1 || byStatus[0].Subdomain != "api" {
		t.Errorf("filter by status: got %+v", byStatus)
	}

	// Filter by agent (via join through servers).
	byAgent, err := d.ListDomains(DomainFilter{AgentID: a.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(byAgent) != 2 {
		t.Errorf("filter by agent: expected 2, got %d", len(byAgent))
	}
}

func TestDomain_Update(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	a := createTestAgent(t, d, p.ID)
	s := createTestServer(t, d, a.ID)
	dom := createTestDomain(t, d, p.ID, s.ID)

	dom.Port = 9090
	dom.Status = models.DomainStatusActive
	if err := d.UpdateDomain(dom); err != nil {
		t.Fatal(err)
	}

	got, _ := d.GetDomain(dom.ID)
	if got.Port != 9090 {
		t.Errorf("Port: got %d, want 9090", got.Port)
	}
}

func TestDomain_Delete(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	a := createTestAgent(t, d, p.ID)
	s := createTestServer(t, d, a.ID)
	dom := createTestDomain(t, d, p.ID, s.ID)

	if err := d.DeleteDomain(dom.ID); err != nil {
		t.Fatal(err)
	}

	_, err := d.GetDomain(dom.ID)
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestDomain_UpdateStatus(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	a := createTestAgent(t, d, p.ID)
	s := createTestServer(t, d, a.ID)
	dom := createTestDomain(t, d, p.ID, s.ID)

	if err := d.UpdateDomainStatus(dom.ID, models.DomainStatusError, "dns failed"); err != nil {
		t.Fatal(err)
	}

	got, _ := d.GetDomain(dom.ID)
	if got.Status != models.DomainStatusError {
		t.Errorf("Status: got %q, want %q", got.Status, models.DomainStatusError)
	}
	if got.ErrorMsg != "dns failed" {
		t.Errorf("ErrorMsg: got %q, want %q", got.ErrorMsg, "dns failed")
	}
}

func TestDomain_UpdateDNSRecord(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	a := createTestAgent(t, d, p.ID)
	s := createTestServer(t, d, a.ID)
	dom := createTestDomain(t, d, p.ID, s.ID)

	if err := d.UpdateDomainDNSRecord(dom.ID, "rec-xyz"); err != nil {
		t.Fatal(err)
	}

	got, _ := d.GetDomain(dom.ID)
	if got.DNSRecordID != "rec-xyz" {
		t.Errorf("DNSRecordID: got %q, want %q", got.DNSRecordID, "rec-xyz")
	}
}

func TestDomain_ListByAgent(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	a := createTestAgent(t, d, p.ID)
	s := createTestServer(t, d, a.ID)
	createTestDomain(t, d, p.ID, s.ID)

	// Agent with no domains.
	a2 := &models.Agent{
		ID: "agent-2", Name: "No Domains", FQDN: "a2.example.com",
		ProviderID: p.ID, DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted,
	}
	if err := d.CreateAgent(a2); err != nil {
		t.Fatal(err)
	}

	doms, err := d.ListDomainsByAgent(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(doms) != 1 {
		t.Fatalf("expected 1 domain for agent-1, got %d", len(doms))
	}

	empty, err := d.ListDomainsByAgent(a2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Errorf("expected 0 domains for agent-2, got %d", len(empty))
	}
}

// ---------------------------------------------------------------------------
// Audit Log
// ---------------------------------------------------------------------------

func TestAudit_InsertAndList(t *testing.T) {
	d := testDB(t)

	for i := 0; i < 5; i++ {
		entry := &models.AuditLogEntry{
			EntityType: "provider",
			EntityID:   "prov-1",
			Action:     "create",
			Actor:      "admin",
			Details:    "created provider",
		}
		if err := d.InsertAuditLog(entry); err != nil {
			t.Fatal(err)
		}
		if entry.ID == 0 {
			t.Error("expected audit log ID to be assigned")
		}
	}

	// Page 1 (limit 3).
	entries, total, err := d.ListAuditLog(3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 {
		t.Errorf("total: got %d, want 5", total)
	}
	if len(entries) != 3 {
		t.Errorf("entries: got %d, want 3", len(entries))
	}

	// Page 2.
	entries2, total2, err := d.ListAuditLog(3, 3)
	if err != nil {
		t.Fatal(err)
	}
	if total2 != 5 {
		t.Errorf("total2: got %d, want 5", total2)
	}
	if len(entries2) != 2 {
		t.Errorf("entries2: got %d, want 2", len(entries2))
	}
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

func TestSettings_DefaultsSeeded(t *testing.T) {
	d := testDB(t)

	val, err := d.GetSetting("mcp_enabled")
	if err != nil {
		t.Fatal(err)
	}
	if val != "false" {
		t.Errorf("mcp_enabled: got %q, want %q", val, "false")
	}

	val, err = d.GetSetting("reconciler_interval")
	if err != nil {
		t.Fatal(err)
	}
	if val != "60" {
		t.Errorf("reconciler_interval: got %q, want %q", val, "60")
	}
}

func TestSettings_SetAndGet(t *testing.T) {
	d := testDB(t)

	if err := d.SetSetting("mcp_enabled", "true"); err != nil {
		t.Fatal(err)
	}

	val, err := d.GetSetting("mcp_enabled")
	if err != nil {
		t.Fatal(err)
	}
	if val != "true" {
		t.Errorf("mcp_enabled: got %q, want %q", val, "true")
	}
}

func TestSettings_SetNew(t *testing.T) {
	d := testDB(t)

	if err := d.SetSetting("new_key", "new_value"); err != nil {
		t.Fatal(err)
	}

	val, err := d.GetSetting("new_key")
	if err != nil {
		t.Fatal(err)
	}
	if val != "new_value" {
		t.Errorf("new_key: got %q, want %q", val, "new_value")
	}
}

func TestSettings_List(t *testing.T) {
	d := testDB(t)

	list, err := d.ListSettings()
	if err != nil {
		t.Fatal(err)
	}
	// At minimum the 2 seeded settings.
	if len(list) < 2 {
		t.Fatalf("expected at least 2 settings, got %d", len(list))
	}

	keys := map[string]bool{}
	for _, s := range list {
		keys[s.Key] = true
	}
	if !keys["mcp_enabled"] {
		t.Error("missing mcp_enabled setting")
	}
	if !keys["reconciler_interval"] {
		t.Error("missing reconciler_interval setting")
	}
}

func TestSettings_GetNotFound(t *testing.T) {
	d := testDB(t)
	_, err := d.GetSetting("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent setting")
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestAgent_LastSeenNilRoundtrip(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	a := createTestAgent(t, d, p.ID) // LastSeen is nil

	got, err := d.GetAgent(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastSeen != nil {
		t.Errorf("expected LastSeen to be nil, got %v", got.LastSeen)
	}
}

func TestDomain_ProxyConfigRoundtrip(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	a := createTestAgent(t, d, p.ID)
	s := createTestServer(t, d, a.ID)

	dom := &models.Domain{
		Subdomain:  "complex",
		ProviderID: p.ID,
		ServerID:   s.ID,
		Port:       443,
		ProxyConfig: models.ProxyConfig{
			WebSocket:             true,
			ForceHTTPS:            true,
			MaxBodySize:           "50M",
			CustomRequestHeaders:  map[string]string{"X-Custom": "val"},
			CustomResponseHeaders: map[string]string{"X-Frame-Options": "DENY"},
			UpstreamScheme:        "https",
			TimeoutRead:           30,
			TimeoutWrite:          30,
			RateLimit:             100.0,
			IPAllowlist:           []string{"10.0.0.0/8"},
		},
		SSLMode: models.SSLModeAuto,
		Status:  models.DomainStatusPending,
	}
	if err := d.CreateDomain(dom); err != nil {
		t.Fatal(err)
	}

	got, err := d.GetDomain(dom.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProxyConfig.MaxBodySize != "50M" {
		t.Errorf("MaxBodySize: got %q, want %q", got.ProxyConfig.MaxBodySize, "50M")
	}
	if got.ProxyConfig.CustomRequestHeaders["X-Custom"] != "val" {
		t.Error("CustomRequestHeaders not preserved")
	}
	if got.ProxyConfig.RateLimit != 100.0 {
		t.Errorf("RateLimit: got %f, want 100.0", got.ProxyConfig.RateLimit)
	}
	if len(got.ProxyConfig.IPAllowlist) != 1 || got.ProxyConfig.IPAllowlist[0] != "10.0.0.0/8" {
		t.Errorf("IPAllowlist: got %v", got.ProxyConfig.IPAllowlist)
	}
}

func TestDomain_LastSyncedRoundtrip(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	a := createTestAgent(t, d, p.ID)
	s := createTestServer(t, d, a.ID)

	now := time.Now().UTC().Truncate(time.Second)
	dom := &models.Domain{
		Subdomain:  "synced",
		ProviderID: p.ID,
		ServerID:   s.ID,
		Port:       80,
		SSLMode:    models.SSLModeOff,
		Status:     models.DomainStatusActive,
		LastSynced: &now,
	}
	if err := d.CreateDomain(dom); err != nil {
		t.Fatal(err)
	}

	got, err := d.GetDomain(dom.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastSynced == nil {
		t.Fatal("expected LastSynced to be set")
	}
}

package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/crypto"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

const testKey = "test-api-key"

func testHandler(t *testing.T) (*Handler, *db.DB) {
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
	return New(database, "test"), database
}

// enable turns MCP on and sets the admin API key.
func enable(t *testing.T, d *db.DB) {
	t.Helper()
	if err := d.SetSetting("mcp_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if err := d.SetSetting("admin_api_key", testKey); err != nil {
		t.Fatal(err)
	}
}

// rpc sends a JSON-RPC request and returns the HTTP recorder + decoded response.
func rpc(t *testing.T, h *Handler, token, method string, params any) (*httptest.ResponseRecorder, rpcResponse) {
	t.Helper()
	body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method}
	if params != nil {
		body["params"] = params
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(b))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	var resp rpcResponse
	if w.Code == http.StatusOK {
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
	}
	return w, resp
}

// callTool issues a tools/call and decodes the JSON text content into out.
// It returns whether the tool reported isError.
func callTool(t *testing.T, h *Handler, name string, args any, out any) bool {
	t.Helper()
	_, resp := rpc(t, h, testKey, "tools/call", map[string]any{"name": name, "arguments": args})
	if resp.Error != nil {
		t.Fatalf("tools/call %s rpc error: %+v", name, resp.Error)
	}
	res, _ := resp.Result.(map[string]any)
	isErr, _ := res["isError"].(bool)
	content, _ := res["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("tools/call %s returned no content", name)
	}
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	if out != nil && !isErr {
		if err := json.Unmarshal([]byte(text), out); err != nil {
			t.Fatalf("decoding %s result %q: %v", name, text, err)
		}
	}
	if isErr {
		t.Logf("tool %s isError: %s", name, text)
	}
	return isErr
}

func TestDisabledReturns404(t *testing.T) {
	h, _ := testHandler(t)
	// mcp_enabled not set.
	w, _ := rpc(t, h, testKey, "tools/list", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("disabled MCP should 404, got %d", w.Code)
	}
}

func TestUnauthorized(t *testing.T) {
	h, d := testHandler(t)
	enable(t, d)

	if w, _ := rpc(t, h, "", "tools/list", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("missing token should 401, got %d", w.Code)
	}
	if w, _ := rpc(t, h, "wrong-key", "tools/list", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong token should 401, got %d", w.Code)
	}
}

func TestInitialize(t *testing.T) {
	h, d := testHandler(t)
	enable(t, d)
	_, resp := rpc(t, h, testKey, "initialize", map[string]any{})
	if resp.Error != nil {
		t.Fatalf("initialize error: %+v", resp.Error)
	}
	res, _ := resp.Result.(map[string]any)
	if res["protocolVersion"] != protocolVersion {
		t.Errorf("protocolVersion = %v, want %s", res["protocolVersion"], protocolVersion)
	}
}

func TestToolsList(t *testing.T) {
	h, d := testHandler(t)
	enable(t, d)
	_, resp := rpc(t, h, testKey, "tools/list", nil)
	if resp.Error != nil {
		t.Fatalf("tools/list error: %+v", resp.Error)
	}
	res, _ := resp.Result.(map[string]any)
	list, _ := res["tools"].([]any)
	want := map[string]bool{
		"create_domain": true, "delete_domain": true, "update_domain": true,
		"list_domains": true, "list_agents": true, "list_servers": true,
		"get_agent_status": true,
	}
	if len(list) != len(want) {
		t.Errorf("expected %d tools, got %d", len(want), len(list))
	}
	for _, item := range list {
		m, _ := item.(map[string]any)
		delete(want, m["name"].(string))
	}
	if len(want) != 0 {
		t.Errorf("missing tools: %v", want)
	}
}

func TestUnknownTool(t *testing.T) {
	h, d := testHandler(t)
	enable(t, d)
	_, resp := rpc(t, h, testKey, "tools/call", map[string]any{"name": "nope", "arguments": map[string]any{}})
	if resp.Error == nil || resp.Error.Code != invalidParams {
		t.Errorf("unknown tool should be invalidParams, got %+v", resp.Error)
	}
}

// seed creates a provider/zone/agent/server and returns ids for domain tests.
func seed(t *testing.T, d *db.DB) (zoneID, serverID, agentID string) {
	t.Helper()
	if err := d.CreateProvider(&models.Provider{ID: "prov-1", Type: "mock", Name: "P", Config: "{}"}); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateZone(&models.Zone{ID: "zone-1", ProviderID: "prov-1", Name: "example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateAgent(&models.Agent{ID: "agent-1", Name: "A", FQDN: "edge1.example.com", Status: models.AgentStatusAdopted}); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateServer(&models.Server{ID: "srv-1", AgentID: "agent-1", Name: "B", Address: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	return "zone-1", "srv-1", "agent-1"
}

func TestCreateListUpdateDeleteDomain(t *testing.T) {
	h, d := testHandler(t)
	enable(t, d)
	zoneID, serverID, agentID := seed(t, d)

	// create_domain
	var created models.Domain
	if isErr := callTool(t, h, "create_domain", map[string]any{
		"subdomain": "app", "zone_id": zoneID, "server_id": serverID, "port": 8080,
	}, &created); isErr {
		t.Fatal("create_domain returned isError")
	}
	if created.ID == 0 || created.Subdomain != "app" {
		t.Fatalf("unexpected created domain: %+v", created)
	}

	// The mutation must be recorded in the audit log as source "mcp".
	entries, _, err := d.ListAuditLogFiltered(models.AuditSourceMCP, 10, 0)
	if err != nil {
		t.Fatalf("ListAuditLogFiltered: %v", err)
	}
	foundCreate := false
	for _, e := range entries {
		if e.Source != models.AuditSourceMCP {
			t.Errorf("filtered audit entry source = %q, want mcp", e.Source)
		}
		if e.Action == "create" && e.EntityType == "domain" {
			foundCreate = true
		}
	}
	if !foundCreate {
		t.Error("expected an mcp-sourced 'create domain' audit entry")
	}

	// duplicate should be a tool error
	if isErr := callTool(t, h, "create_domain", map[string]any{
		"subdomain": "app", "zone_id": zoneID, "server_id": serverID, "port": 8080,
	}, nil); !isErr {
		t.Error("duplicate subdomain should report isError")
	}

	// bad port should be a tool error
	if isErr := callTool(t, h, "create_domain", map[string]any{
		"subdomain": "bad", "zone_id": zoneID, "server_id": serverID, "port": 0,
	}, nil); !isErr {
		t.Error("invalid port should report isError")
	}

	// list_domains by agent
	var domains []models.Domain
	callTool(t, h, "list_domains", map[string]any{"agent_id": agentID}, &domains)
	if len(domains) != 1 {
		t.Fatalf("expected 1 domain, got %d", len(domains))
	}

	// update_domain
	var updated models.Domain
	callTool(t, h, "update_domain", map[string]any{"id": created.ID, "port": 9090}, &updated)
	if updated.Port != 9090 {
		t.Errorf("update_domain port = %d, want 9090", updated.Port)
	}

	// delete_domain
	var del map[string]any
	if isErr := callTool(t, h, "delete_domain", map[string]any{"id": created.ID}, &del); isErr {
		t.Fatal("delete_domain returned isError")
	}
	got, err := d.GetDomain(created.ID)
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	if got.Status != models.DomainStatusDeleting {
		t.Errorf("domain status = %q, want deleting", got.Status)
	}
}

func TestAgentAndServerTools(t *testing.T) {
	h, d := testHandler(t)
	enable(t, d)
	_, _, agentID := seed(t, d)

	var agents []models.Agent
	callTool(t, h, "list_agents", map[string]any{}, &agents)
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	if agents[0].TokenHash != "" {
		t.Error("list_agents must not leak token hash")
	}

	var status map[string]any
	callTool(t, h, "get_agent_status", map[string]any{"agent_id": agentID}, &status)
	if status["status"] != string(models.AgentStatusAdopted) {
		t.Errorf("get_agent_status status = %v", status["status"])
	}

	var servers []models.Server
	callTool(t, h, "list_servers", map[string]any{"agent_id": agentID}, &servers)
	if len(servers) != 1 {
		t.Errorf("expected 1 server, got %d", len(servers))
	}

	// missing agent → tool error
	if isErr := callTool(t, h, "get_agent_status", map[string]any{"agent_id": "ghost"}, nil); !isErr {
		t.Error("get_agent_status for unknown agent should report isError")
	}
}

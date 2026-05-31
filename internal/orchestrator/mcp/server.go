// Package mcp implements an opt-in Model Context Protocol server so AI tools can
// drive NurProxy (manage domains, inspect agents/servers) over a single
// JSON-RPC 2.0 HTTP endpoint.
//
// It is disabled by default: the handler 404s unless the `mcp_enabled` setting
// is "true". When enabled it authenticates every request with the admin API key
// (Bearer token) — the same key managed via the settings API — so it never
// relies on a browser session.
package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// protocolVersion is the MCP revision this server speaks.
const protocolVersion = "2024-11-05"

// Handler serves MCP over HTTP. Mount it at /mcp (and /mcp/).
type Handler struct {
	db      *db.DB
	version string
}

// New creates an MCP handler backed by the given database.
func New(database *db.DB, version string) *Handler {
	return &Handler{db: database, version: version}
}

// enabled reports whether the operator turned MCP on.
func (h *Handler) enabled() bool {
	v, err := h.db.GetSetting("mcp_enabled")
	return err == nil && v == "true"
}

// authorized checks the request's Bearer token against the admin API key. MCP is
// unusable until an admin API key has been generated.
func (h *Handler) authorized(r *http.Request) bool {
	key, err := h.db.GetSetting("admin_api_key")
	if err != nil || key == "" {
		return false
	}
	authz := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(authz, prefix) {
		return false
	}
	return strings.TrimSpace(authz[len(prefix):]) == key
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Disabled → behave as if the endpoint doesn't exist.
	if !h.enabled() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorized(r) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, nil, parseError, "failed to read request body")
		return
	}

	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, nil, parseError, "invalid JSON")
		return
	}
	h.dispatch(w, &req)
}

// dispatch routes a single JSON-RPC request to its handler.
func (h *Handler) dispatch(w http.ResponseWriter, req *rpcRequest) {
	// Notifications (e.g. notifications/initialized) carry no id and expect no
	// response — just acknowledge at the HTTP layer.
	if strings.HasPrefix(req.Method, "notifications/") {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	switch req.Method {
	case "initialize":
		writeResult(w, req.ID, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "nurproxy", "version": h.version},
		})
	case "ping":
		writeResult(w, req.ID, map[string]any{})
	case "tools/list":
		writeResult(w, req.ID, map[string]any{"tools": toolList()})
	case "tools/call":
		h.handleToolCall(w, req)
	default:
		writeError(w, req.ID, methodNotFound, "unknown method: "+req.Method)
	}
}

// handleToolCall validates the requested tool and arguments, runs it, and wraps
// the result (or error) in MCP tool-result content.
func (h *Handler) handleToolCall(w http.ResponseWriter, req *rpcRequest) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeError(w, req.ID, invalidParams, "invalid params")
		return
	}

	tool, ok := tools[params.Name]
	if !ok {
		writeError(w, req.ID, invalidParams, "unknown tool: "+params.Name)
		return
	}

	result, err := tool.run(h.db, params.Arguments)
	if err != nil {
		// Tool-level failures are reported as a tool result with isError=true
		// (per MCP), not a JSON-RPC protocol error.
		writeResult(w, req.ID, toolError(err.Error()))
		return
	}
	writeResult(w, req.ID, toolText(result))
}

// ---------------------------------------------------------------------------
// Tool registry
// ---------------------------------------------------------------------------

type tool struct {
	name        string
	description string
	inputSchema string // JSON Schema literal
	run         func(d *db.DB, args json.RawMessage) (any, error)
}

var tools = func() map[string]tool {
	m := make(map[string]tool)
	for _, t := range []tool{
		{
			name:        "list_agents",
			description: "List all registered agents with their status and health.",
			inputSchema: `{"type":"object","properties":{},"additionalProperties":false}`,
			run:         toolListAgents,
		},
		{
			name:        "get_agent_status",
			description: "Get the status and health of a single agent by id.",
			inputSchema: `{"type":"object","properties":{"agent_id":{"type":"string"}},"required":["agent_id"],"additionalProperties":false}`,
			run:         toolGetAgentStatus,
		},
		{
			name:        "list_servers",
			description: "List backend servers, optionally filtered to one agent.",
			inputSchema: `{"type":"object","properties":{"agent_id":{"type":"string"}},"additionalProperties":false}`,
			run:         toolListServers,
		},
		{
			name:        "list_domains",
			description: "List proxied domains, optionally filtered by agent_id or status.",
			inputSchema: `{"type":"object","properties":{"agent_id":{"type":"string"},"status":{"type":"string"}},"additionalProperties":false}`,
			run:         toolListDomains,
		},
		{
			name:        "create_domain",
			description: "Create a proxied domain (subdomain in a zone, pointing at a server+port).",
			inputSchema: `{"type":"object","properties":{"subdomain":{"type":"string"},"zone_id":{"type":"string"},"server_id":{"type":"string"},"port":{"type":"integer"},"websocket":{"type":"boolean"},"force_https":{"type":"boolean"},"ssl_mode":{"type":"string","enum":["auto","manual","off"]}},"required":["subdomain","zone_id","server_id","port"],"additionalProperties":false}`,
			run:         toolCreateDomain,
		},
		{
			name:        "update_domain",
			description: "Update fields of an existing domain by id. Re-queues it for reconciliation.",
			inputSchema: `{"type":"object","properties":{"id":{"type":"integer"},"server_id":{"type":"string"},"port":{"type":"integer"},"websocket":{"type":"boolean"},"force_https":{"type":"boolean"},"ssl_mode":{"type":"string","enum":["auto","manual","off"]}},"required":["id"],"additionalProperties":false}`,
			run:         toolUpdateDomain,
		},
		{
			name:        "delete_domain",
			description: "Delete a domain by id (marks it for teardown of its DNS record and route).",
			inputSchema: `{"type":"object","properties":{"id":{"type":"integer"}},"required":["id"],"additionalProperties":false}`,
			run:         toolDeleteDomain,
		},
	} {
		m[t.name] = t
	}
	return m
}()

// toolList renders the registry as MCP tool descriptors (sorted for stability).
func toolList() []map[string]any {
	names := make([]string, 0, len(tools))
	for n := range tools {
		names = append(names, n)
	}
	sortStrings(names)
	out := make([]map[string]any, 0, len(tools))
	for _, n := range names {
		t := tools[n]
		out = append(out, map[string]any{
			"name":        t.name,
			"description": t.description,
			"inputSchema": json.RawMessage(t.inputSchema),
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

func toolListAgents(d *db.DB, _ json.RawMessage) (any, error) {
	agents, err := d.ListAgents()
	if err != nil {
		return nil, err
	}
	if agents == nil {
		agents = []models.Agent{}
	}
	return agents, nil
}

func toolGetAgentStatus(d *db.DB, args json.RawMessage) (any, error) {
	var in struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if in.AgentID == "" {
		return nil, fmt.Errorf("agent_id is required")
	}
	a, err := d.GetAgent(in.AgentID)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"id":            a.ID,
		"name":          a.Name,
		"fqdn":          a.FQDN,
		"status":        a.Status,
		"public_ip":     a.PublicIP,
		"version":       a.Version,
		"caddy_running": a.CaddyRunning,
		"last_error":    a.LastError,
		"dns_error":     a.DNSError,
		"last_seen":     a.LastSeen,
	}, nil
}

func toolListServers(d *db.DB, args json.RawMessage) (any, error) {
	var in struct {
		AgentID string `json:"agent_id"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &in); err != nil {
			return nil, fmt.Errorf("invalid arguments: %w", err)
		}
	}
	if in.AgentID != "" {
		return nonNilServers(d.ListServersByAgent(in.AgentID))
	}
	// Aggregate across all agents.
	agents, err := d.ListAgents()
	if err != nil {
		return nil, err
	}
	all := []models.Server{}
	for i := range agents {
		servers, err := d.ListServersByAgent(agents[i].ID)
		if err != nil {
			return nil, err
		}
		all = append(all, servers...)
	}
	return all, nil
}

func toolListDomains(d *db.DB, args json.RawMessage) (any, error) {
	var in struct {
		AgentID string `json:"agent_id"`
		Status  string `json:"status"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &in); err != nil {
			return nil, fmt.Errorf("invalid arguments: %w", err)
		}
	}
	domains, err := d.ListDomains(db.DomainFilter{AgentID: in.AgentID, Status: in.Status})
	if err != nil {
		return nil, err
	}
	if domains == nil {
		domains = []models.Domain{}
	}
	return domains, nil
}

func toolCreateDomain(d *db.DB, args json.RawMessage) (any, error) {
	var in struct {
		Subdomain  string `json:"subdomain"`
		ZoneID     string `json:"zone_id"`
		ServerID   string `json:"server_id"`
		Port       int    `json:"port"`
		WebSocket  bool   `json:"websocket"`
		ForceHTTPS bool   `json:"force_https"`
		SSLMode    string `json:"ssl_mode"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if in.Subdomain == "" || in.ZoneID == "" || in.ServerID == "" {
		return nil, fmt.Errorf("subdomain, zone_id, and server_id are required")
	}
	if in.Port <= 0 || in.Port > 65535 {
		return nil, fmt.Errorf("port must be between 1 and 65535")
	}
	if _, err := d.GetZone(in.ZoneID); err != nil {
		return nil, fmt.Errorf("zone not found")
	}
	if _, err := d.GetServer(in.ServerID); err != nil {
		return nil, fmt.Errorf("server not found")
	}
	existing, _ := d.ListDomains(db.DomainFilter{})
	for i := range existing {
		if existing[i].Subdomain == in.Subdomain && existing[i].ZoneID == in.ZoneID {
			return nil, fmt.Errorf("subdomain already exists for this zone")
		}
	}
	sslMode := models.SSLMode(in.SSLMode)
	if sslMode == "" {
		sslMode = models.SSLModeAuto
	}
	dom := &models.Domain{
		Subdomain:  in.Subdomain,
		ZoneID:     in.ZoneID,
		ServerID:   in.ServerID,
		Port:       in.Port,
		WebSocket:  in.WebSocket,
		ForceHTTPS: in.ForceHTTPS,
		SSLMode:    sslMode,
		Status:     models.DomainStatusPending,
	}
	if err := d.CreateDomain(dom); err != nil {
		return nil, err
	}
	auditMCP(d, "domain", fmt.Sprintf("%d", dom.ID), "create", dom.Subdomain)
	return dom, nil
}

func toolUpdateDomain(d *db.DB, args json.RawMessage) (any, error) {
	var in struct {
		ID         int64   `json:"id"`
		ServerID   *string `json:"server_id"`
		Port       *int    `json:"port"`
		WebSocket  *bool   `json:"websocket"`
		ForceHTTPS *bool   `json:"force_https"`
		SSLMode    *string `json:"ssl_mode"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if in.ID == 0 {
		return nil, fmt.Errorf("id is required")
	}
	dom, err := d.GetDomain(in.ID)
	if err != nil {
		return nil, fmt.Errorf("domain not found")
	}
	if in.ServerID != nil {
		if _, err := d.GetServer(*in.ServerID); err != nil {
			return nil, fmt.Errorf("server not found")
		}
		dom.ServerID = *in.ServerID
	}
	if in.Port != nil {
		if *in.Port <= 0 || *in.Port > 65535 {
			return nil, fmt.Errorf("port must be between 1 and 65535")
		}
		dom.Port = *in.Port
	}
	if in.WebSocket != nil {
		dom.WebSocket = *in.WebSocket
	}
	if in.ForceHTTPS != nil {
		dom.ForceHTTPS = *in.ForceHTTPS
	}
	if in.SSLMode != nil {
		dom.SSLMode = models.SSLMode(*in.SSLMode)
	}
	dom.Status = models.DomainStatusPending // re-queue for reconciliation
	if err := d.UpdateDomain(dom); err != nil {
		return nil, err
	}
	auditMCP(d, "domain", fmt.Sprintf("%d", dom.ID), "update", dom.Subdomain)
	return dom, nil
}

func toolDeleteDomain(d *db.DB, args json.RawMessage) (any, error) {
	var in struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if in.ID == 0 {
		return nil, fmt.Errorf("id is required")
	}
	if err := d.UpdateDomainStatus(in.ID, models.DomainStatusDeleting, ""); err != nil {
		return nil, fmt.Errorf("domain not found")
	}
	auditMCP(d, "domain", fmt.Sprintf("%d", in.ID), "delete", "")
	return map[string]any{"id": in.ID, "status": "deleting"}, nil
}

// auditMCP records a mutation made through the MCP channel.
func auditMCP(d *db.DB, entityType, entityID, action, details string) {
	_ = d.InsertAuditLog(&models.AuditLogEntry{
		EntityType: entityType,
		EntityID:   entityID,
		Action:     action,
		Actor:      "mcp",
		Source:     models.AuditSourceMCP,
		Details:    details,
	})
}

func nonNilServers(s []models.Server, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	if s == nil {
		return []models.Server{}, nil
	}
	return s, nil
}

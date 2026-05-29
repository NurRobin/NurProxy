package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

func TestAuditSource_UIAndFilter(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)

	// A session-authenticated action that writes an audit entry.
	if w := doRequest(t, h, "POST", "/api/v1/api-key", nil, cookie); w.Code != http.StatusCreated {
		t.Fatalf("generate api key: %d %s", w.Code, w.Body.String())
	}

	type auditResp struct {
		Entries []models.AuditLogEntry `json:"entries"`
		Total   int                    `json:"total"`
	}

	// Filtered to source=ui: must contain the action, all entries source "ui".
	w := doRequest(t, h, "GET", "/api/v1/audit-log?source=ui", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("audit-log?source=ui: %d", w.Code)
	}
	var ui auditResp
	if err := json.Unmarshal(w.Body.Bytes(), &ui); err != nil {
		t.Fatal(err)
	}
	if len(ui.Entries) == 0 {
		t.Fatal("expected at least one ui-sourced audit entry")
	}
	foundKey := false
	for _, e := range ui.Entries {
		if e.Source != models.AuditSourceUI {
			t.Errorf("entry source = %q, want ui", e.Source)
		}
		if e.Action == "generate_api_key" {
			foundKey = true
		}
	}
	if !foundKey {
		t.Error("expected the generate_api_key action under source=ui")
	}

	// Filtered to source=mcp: nothing happened over MCP here.
	w = doRequest(t, h, "GET", "/api/v1/audit-log?source=mcp", nil, cookie)
	var mcp auditResp
	_ = json.Unmarshal(w.Body.Bytes(), &mcp)
	if mcp.Total != 0 || len(mcp.Entries) != 0 {
		t.Errorf("expected no mcp-sourced entries, got total=%d len=%d", mcp.Total, len(mcp.Entries))
	}
}

func TestAuditSource_AgentRegister(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)

	// Agent registration is a no-auth endpoint that records source "agent".
	body := map[string]string{"id": "a1", "fqdn": "edge1.example.com", "token": "tok"}
	if w := doRequestWithAuth(t, h, "POST", "/api/v1/agents/register", body, ""); w.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}

	w := doRequest(t, h, "GET", "/api/v1/audit-log?source=agent", nil, cookie)
	var resp struct {
		Entries []models.AuditLogEntry `json:"entries"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	found := false
	for _, e := range resp.Entries {
		if e.Action == "register" && e.Source == models.AuditSourceAgent {
			found = true
		}
	}
	if !found {
		t.Error("expected an agent-sourced register entry")
	}
}

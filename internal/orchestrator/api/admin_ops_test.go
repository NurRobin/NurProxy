package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/auth"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// prepareAdminOp drives the dashboard prepare endpoint and returns the decoded
// {id, code, expires_at} response, failing on a non-201.
func prepareAdminOp(t *testing.T, h http.Handler, cookie *http.Cookie, agentID string, body interface{}) map[string]interface{} {
	t.Helper()
	w := doRequest(t, h, "POST", "/api/v1/agents/"+agentID+"/admin-ops", body, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("prepare admin op: expected 201, got %d %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode prepare response: %v", err)
	}
	return resp
}

func setProxyModeBody() map[string]interface{} {
	return map[string]interface{}{
		"op_type": models.AdminOpSetProxyMode,
		"payload": models.SetProxyModePayload{
			ProxyMode:      "existing",
			ProxyType:      "nginx",
			ProxyConfigDir: "/etc/nginx/conf.d",
		},
	}
}

func TestAdminOp_PrepareReturnsCodeAndPersistsButListHidesCode(t *testing.T) {
	srv, database := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)
	makeAgent(t, database, "agent-1", "edge1.example.com", models.AgentStatusAdopted, nil)

	resp := prepareAdminOp(t, h, cookie, "agent-1", setProxyModeBody())

	code, _ := resp["code"].(string)
	if code == "" {
		t.Fatal("prepare did not return a plaintext code")
	}
	opID, _ := resp["id"].(string)
	if opID == "" {
		t.Fatal("prepare did not return an op id")
	}
	if resp["expires_at"] == nil {
		t.Fatal("prepare did not return expires_at")
	}

	// The op is persisted with a hash of the code, never the plaintext.
	stored, err := database.GetAdminOp(t.Context(), opID)
	if err != nil {
		t.Fatalf("GetAdminOp: %v", err)
	}
	if stored.CodeHash == "" || stored.CodeHash == code {
		t.Fatalf("stored op should hold a hash, not the plaintext code: %q", stored.CodeHash)
	}
	if stored.Status != models.AdminOpPending {
		t.Fatalf("expected pending, got %s", stored.Status)
	}

	// The list endpoint must never leak the code or code_hash.
	w := doRequest(t, h, "GET", "/api/v1/agents/agent-1/admin-ops", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d %s", w.Code, w.Body.String())
	}
	raw := w.Body.String()
	if strings.Contains(raw, code) {
		t.Fatalf("list leaked the plaintext code: %s", raw)
	}
	if strings.Contains(raw, "code_hash") || strings.Contains(raw, stored.CodeHash) {
		t.Fatalf("list leaked the code hash: %s", raw)
	}

	var listResp struct {
		Ops []adminOpView `json:"ops"`
	}
	if err := json.Unmarshal([]byte(raw), &listResp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listResp.Ops) != 1 {
		t.Fatalf("expected 1 pending op, got %d", len(listResp.Ops))
	}
	if listResp.Ops[0].ID != opID || listResp.Ops[0].Status != models.AdminOpPending {
		t.Fatalf("unexpected listed op: %+v", listResp.Ops[0])
	}

	// Audit: prepare wrote a source=ui actor=admin entry.
	e := findAudit(t, database, "agent", "agent-1", "admin_op.prepare")
	if e.Source != models.AuditSourceUI || e.Actor != "admin" {
		t.Fatalf("prepare audit: got source=%s actor=%s", e.Source, e.Actor)
	}
}

func TestAdminOp_PrepareUnknownOpType(t *testing.T) {
	srv, database := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)
	makeAgent(t, database, "agent-1", "edge1.example.com", models.AgentStatusAdopted, nil)

	w := doRequest(t, h, "POST", "/api/v1/agents/agent-1/admin-ops",
		map[string]interface{}{"op_type": "rotate_token", "payload": map[string]string{}}, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown op_type, got %d %s", w.Code, w.Body.String())
	}
}

func TestAdminOp_PrepareUnknownAgent(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)

	w := doRequest(t, h, "POST", "/api/v1/agents/ghost/admin-ops", setProxyModeBody(), cookie)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown agent, got %d %s", w.Code, w.Body.String())
	}
}

func TestAdminOp_ClaimWithRightCodeReturnsPayloadAndApplies(t *testing.T) {
	srv, database := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)
	token := makeAgent(t, database, "agent-1", "edge1.example.com", models.AgentStatusAdopted, nil)

	prep := prepareAdminOp(t, h, cookie, "agent-1", setProxyModeBody())
	code := prep["code"].(string)
	opID := prep["id"].(string)

	w := doRequestWithAuth(t, h, "POST", "/api/v1/agents/agent-1/admin-ops/claim",
		map[string]string{"code": code}, token)
	if w.Code != http.StatusOK {
		t.Fatalf("claim: expected 200, got %d %s", w.Code, w.Body.String())
	}

	var claim struct {
		ID      string                     `json:"id"`
		OpType  string                     `json:"op_type"`
		Payload models.SetProxyModePayload `json:"payload"`
	}
	if err := json.NewDecoder(w.Body).Decode(&claim); err != nil {
		t.Fatalf("decode claim: %v", err)
	}
	if claim.ID != opID || claim.OpType != models.AdminOpSetProxyMode {
		t.Fatalf("unexpected claim: %+v", claim)
	}
	if claim.Payload.ProxyMode != "existing" || claim.Payload.ProxyType != "nginx" {
		t.Fatalf("payload not round-tripped: %+v", claim.Payload)
	}

	// It flipped to applied and is now single-use.
	stored, err := database.GetAdminOp(t.Context(), opID)
	if err != nil {
		t.Fatalf("GetAdminOp: %v", err)
	}
	if stored.Status != models.AdminOpApplied {
		t.Fatalf("expected applied, got %s", stored.Status)
	}

	// Second claim with the same code now fails (single-use).
	w2 := doRequestWithAuth(t, h, "POST", "/api/v1/agents/agent-1/admin-ops/claim",
		map[string]string{"code": code}, token)
	if w2.Code != http.StatusNotFound {
		t.Fatalf("re-claim: expected 404, got %d %s", w2.Code, w2.Body.String())
	}

	// Audit: claim wrote a source=agent actor=agent:agent-1 entry.
	e := findAudit(t, database, "agent", "agent-1", "admin_op.claim")
	if e.Source != models.AuditSourceAgent || e.Actor != "agent:agent-1" {
		t.Fatalf("claim audit: got source=%s actor=%s", e.Source, e.Actor)
	}
}

func TestAdminOp_ClaimWrongCode(t *testing.T) {
	srv, database := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)
	token := makeAgent(t, database, "agent-1", "edge1.example.com", models.AgentStatusAdopted, nil)
	prepareAdminOp(t, h, cookie, "agent-1", setProxyModeBody())

	w := doRequestWithAuth(t, h, "POST", "/api/v1/agents/agent-1/admin-ops/claim",
		map[string]string{"code": "WRNG-CODE"}, token)
	if w.Code != http.StatusNotFound {
		t.Fatalf("wrong-code claim: expected 404, got %d %s", w.Code, w.Body.String())
	}
}

func TestAdminOp_ClaimByDifferentAgentFails(t *testing.T) {
	srv, database := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)
	makeAgent(t, database, "agent-1", "edge1.example.com", models.AgentStatusAdopted, nil)
	// A second agent with its own token (makeAgent uses a fixed token string, so
	// register agent-2 directly to get a distinct token).
	const otherToken = "other-agent-token"
	if err := database.CreateAgent(&models.Agent{
		ID:        "agent-2",
		Name:      "edge2.example.com",
		FQDN:      "edge2.example.com",
		TokenHash: auth.HashToken(otherToken),
		Status:    models.AgentStatusAdopted,
		DNSMode:   models.DNSModeStatic,
	}); err != nil {
		t.Fatalf("CreateAgent agent-2: %v", err)
	}

	prep := prepareAdminOp(t, h, cookie, "agent-1", setProxyModeBody())
	code := prep["code"].(string)

	// agent-2 authenticates but targets agent-1's path → 403 (scoped to self).
	w := doRequestWithAuth(t, h, "POST", "/api/v1/agents/agent-1/admin-ops/claim",
		map[string]string{"code": code}, otherToken)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-agent path claim: expected 403, got %d %s", w.Code, w.Body.String())
	}

	// agent-2 claiming on its own path with agent-1's code → 404 (code is scoped
	// to the agent it was minted for; no match for agent-2).
	w2 := doRequestWithAuth(t, h, "POST", "/api/v1/agents/agent-2/admin-ops/claim",
		map[string]string{"code": code}, otherToken)
	if w2.Code != http.StatusNotFound {
		t.Fatalf("other-agent same-code claim: expected 404, got %d %s", w2.Code, w2.Body.String())
	}
}

func TestAdminOp_Cancel(t *testing.T) {
	srv, database := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)
	makeAgent(t, database, "agent-1", "edge1.example.com", models.AgentStatusAdopted, nil)

	prep := prepareAdminOp(t, h, cookie, "agent-1", setProxyModeBody())
	opID := prep["id"].(string)

	w := doRequest(t, h, "DELETE", "/api/v1/agents/agent-1/admin-ops/"+opID, nil, cookie)
	if w.Code != http.StatusNoContent {
		t.Fatalf("cancel: expected 204, got %d %s", w.Code, w.Body.String())
	}

	stored, err := database.GetAdminOp(t.Context(), opID)
	if err != nil {
		t.Fatalf("GetAdminOp: %v", err)
	}
	if stored.Status != models.AdminOpCanceled {
		t.Fatalf("expected canceled, got %s", stored.Status)
	}

	// Canceling an op that doesn't belong to the agent → 404.
	makeAgent(t, database, "agent-3", "edge3.example.com", models.AgentStatusAdopted, nil)
	w2 := doRequest(t, h, "DELETE", "/api/v1/agents/agent-3/admin-ops/"+opID, nil, cookie)
	if w2.Code != http.StatusNotFound {
		t.Fatalf("cancel wrong-agent: expected 404, got %d %s", w2.Code, w2.Body.String())
	}
}

func TestAdminOp_Ack(t *testing.T) {
	srv, database := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)
	token := makeAgent(t, database, "agent-1", "edge1.example.com", models.AgentStatusAdopted, nil)

	prep := prepareAdminOp(t, h, cookie, "agent-1", setProxyModeBody())
	opID := prep["id"].(string)
	code := prep["code"].(string)

	// Claim first so the op is applied, then ack the outcome.
	if w := doRequestWithAuth(t, h, "POST", "/api/v1/agents/agent-1/admin-ops/claim",
		map[string]string{"code": code}, token); w.Code != http.StatusOK {
		t.Fatalf("claim: %d %s", w.Code, w.Body.String())
	}

	w := doRequestWithAuth(t, h, "POST", "/api/v1/agents/agent-1/admin-ops/"+opID+"/ack",
		map[string]interface{}{"ok": true, "result": "switched to nginx; reload ok"}, token)
	if w.Code != http.StatusOK {
		t.Fatalf("ack: expected 200, got %d %s", w.Code, w.Body.String())
	}

	stored, err := database.GetAdminOp(t.Context(), opID)
	if err != nil {
		t.Fatalf("GetAdminOp: %v", err)
	}
	if stored.Result != "switched to nginx; reload ok" {
		t.Fatalf("result not recorded: %q", stored.Result)
	}

	e := findAudit(t, database, "agent", "agent-1", "admin_op.ack")
	if e.Source != models.AuditSourceAgent || !strings.Contains(e.Details, "ok=true") {
		t.Fatalf("ack audit: source=%s details=%q", e.Source, e.Details)
	}
}

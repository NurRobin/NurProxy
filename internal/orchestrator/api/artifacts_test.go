package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// seedArtifact inserts an agent + a generated caddy-route artifact for the
// drift-review API tests.
func seedArtifact(t *testing.T, srv *Server, agentID, artifactID, content string) *models.ConfigArtifact {
	t.Helper()
	if _, err := srv.db.GetAgent(agentID); err != nil {
		a := &models.Agent{ID: agentID, Name: agentID, FQDN: agentID + ".example.com", Status: models.AgentStatusAdopted}
		if cErr := srv.db.CreateAgent(a); cErr != nil {
			t.Fatalf("CreateAgent: %v", cErr)
		}
	}
	art := &models.ConfigArtifact{
		ID:      artifactID,
		AgentID: agentID,
		Backend: "caddy",
		Target:  models.Target{Kind: models.TargetKindCaddyRoute, Path: "caddy:route:" + artifactID},
		Source:  models.ArtifactSourceGenerated,
		Content: content,
	}
	if err := srv.db.CreateConfigArtifact(art, "tester", "seed"); err != nil {
		t.Fatalf("CreateConfigArtifact: %v", err)
	}
	return art
}

func TestArtifacts_ListAndGet(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)
	seedArtifact(t, srv, "agent-1", "dom-1", `{"handle":[]}`)

	w := doRequest(t, h, "GET", "/api/v1/artifacts", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var list []models.ConfigArtifact
	if err := json.NewDecoder(w.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "dom-1" {
		t.Fatalf("unexpected list: %+v", list)
	}

	w = doRequest(t, h, "GET", "/api/v1/artifacts/dom-1", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("get: %d", w.Code)
	}
}

func TestArtifacts_ListDriftedFilter(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)
	seedArtifact(t, srv, "agent-1", "dom-1", `{"handle":[]}`)
	seedArtifact(t, srv, "agent-1", "dom-2", `{"handle":[]}`)
	if err := srv.db.MarkConfigArtifactDrifted("dom-2"); err != nil {
		t.Fatal(err)
	}

	w := doRequest(t, h, "GET", "/api/v1/artifacts?drifted=true", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("list drifted: %d", w.Code)
	}
	var list []models.ConfigArtifact
	json.NewDecoder(w.Body).Decode(&list)
	if len(list) != 1 || list[0].ID != "dom-2" {
		t.Fatalf("drifted filter: %+v", list)
	}
}

func TestArtifacts_Accept_promotesOnDiskContent(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)
	seedArtifact(t, srv, "agent-1", "dom-1", `{"handle":[]}`)
	if err := srv.db.MarkConfigArtifactDrifted("dom-1"); err != nil {
		t.Fatal(err)
	}

	w := doRequest(t, h, "POST", "/api/v1/artifacts/dom-1/accept",
		map[string]string{"content": `{"handle":["edited"]}`}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("accept: %d %s", w.Code, w.Body.String())
	}
	got, _ := srv.db.GetConfigArtifact("dom-1")
	if got.Drifted || got.ApplyState != models.ArtifactStateLive {
		t.Errorf("accept did not clear drift: %+v", got)
	}
	if got.Content != `{"handle":["edited"]}` || got.LiveVersion != 2 {
		t.Errorf("accept did not promote content: %+v", got)
	}
}

func TestArtifacts_Reject_clearsDriftKeepsAccepted(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)
	seedArtifact(t, srv, "agent-1", "dom-1", `{"handle":[]}`)
	if err := srv.db.MarkConfigArtifactDrifted("dom-1"); err != nil {
		t.Fatal(err)
	}

	w := doRequest(t, h, "POST", "/api/v1/artifacts/dom-1/reject", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("reject: %d %s", w.Code, w.Body.String())
	}
	got, _ := srv.db.GetConfigArtifact("dom-1")
	if got.Drifted || got.ApplyState != models.ArtifactStateLive {
		t.Errorf("reject did not clear drift: %+v", got)
	}
	if got.Content != `{"handle":[]}` || got.LiveVersion != 1 {
		t.Errorf("reject changed accepted content/version: %+v", got)
	}
}

func TestArtifacts_Rollback(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)
	seedArtifact(t, srv, "agent-1", "dom-1", `{"handle":[]}`)
	if _, err := srv.db.AppendConfigArtifactVersion("dom-1", `{"handle":["v2"]}`, models.ArtifactSourceManual, "op", "edit"); err != nil {
		t.Fatal(err)
	}

	w := doRequest(t, h, "POST", "/api/v1/artifacts/dom-1/rollback", map[string]int{"version": 1}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("rollback: %d %s", w.Code, w.Body.String())
	}
	got, _ := srv.db.GetConfigArtifact("dom-1")
	if got.Content != `{"handle":[]}` || got.LiveVersion != 3 {
		t.Errorf("rollback result: %+v", got)
	}
}

func TestArtifacts_Rollback_badBody(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)
	seedArtifact(t, srv, "agent-1", "dom-1", `{"handle":[]}`)

	w := doRequest(t, h, "POST", "/api/v1/artifacts/dom-1/rollback", map[string]int{"version": 0}, cookie)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for version 0, got %d", w.Code)
	}
}

func TestArtifacts_BulkReject(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)
	for _, id := range []string{"dom-1", "dom-2", "dom-3", "dom-4"} {
		seedArtifact(t, srv, "agent-1", id, `{"handle":[]}`)
		if err := srv.db.MarkConfigArtifactDrifted(id); err != nil {
			t.Fatal(err)
		}
	}

	w := doRequest(t, h, "POST", "/api/v1/artifacts/bulk",
		map[string]string{"action": "reject", "agent_id": "agent-1"}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("bulk: %d %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["resolved"].(float64) != 4 {
		t.Errorf("expected 4 resolved, got %v", resp["resolved"])
	}
	drifted := true
	remaining, _ := srv.db.ListConfigArtifacts(db.ConfigArtifactFilter{Drifted: &drifted})
	if len(remaining) != 0 {
		t.Errorf("expected 0 drifted after bulk reject, got %d", len(remaining))
	}
}

func TestArtifacts_BulkBadAction(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)
	w := doRequest(t, h, "POST", "/api/v1/artifacts/bulk", map[string]string{"action": "nuke"}, cookie)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad action, got %d", w.Code)
	}
}

func TestArtifacts_AutoReconcileToggle(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)
	seedArtifact(t, srv, "agent-1", "dom-1", `{"handle":[]}`) // creates agent-1

	w := doRequest(t, h, "PUT", "/api/v1/agents/agent-1/auto-reconcile", map[string]bool{"enabled": true}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("toggle: %d %s", w.Code, w.Body.String())
	}
	got, _ := srv.db.GetAgent("agent-1")
	if !got.AutoReconcileConfig {
		t.Error("auto-reconcile not enabled")
	}
}

// TestHeartbeat_ChecksumFlagsAndClearsDrift exercises the heartbeat half of
// drift detection end-to-end through the HTTP handler (§11): a divergent reported
// checksum flags the artifact drifted; a matching one clears it.
func TestHeartbeat_ChecksumFlagsAndClearsDrift(t *testing.T) {
	srv, database := testServer(t)
	h := srv.Handler()
	_ = setupAdmin(t, h)

	agentToken := "np_ag_testtoken123456789012345678901234567890123456789012345678"
	w := doRequest(t, h, "POST", "/api/v1/agents/register", map[string]string{
		"id":    "agent-1",
		"fqdn":  "edge1.example.com",
		"token": agentToken,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}

	art := seedArtifact(t, srv, "agent-1", "dom-1", `{"handle":[]}`)

	// Divergent checksum -> drift.
	w = doRequestWithAuth(t, h, "POST", "/api/v1/agents/agent-1/heartbeat", map[string]any{
		"public_ip":          "1.2.3.4",
		"artifact_checksums": []map[string]string{{"artifact_id": "dom-1", "checksum": "deadbeef"}},
	}, agentToken)
	if w.Code != http.StatusOK {
		t.Fatalf("heartbeat (drift): %d %s", w.Code, w.Body.String())
	}
	got, _ := database.GetConfigArtifact("dom-1")
	if !got.Drifted || got.ApplyState != models.ArtifactStateDrifted {
		t.Fatalf("heartbeat did not flag drift: %+v", got)
	}

	// Matching checksum -> drift cleared.
	w = doRequestWithAuth(t, h, "POST", "/api/v1/agents/agent-1/heartbeat", map[string]any{
		"artifact_checksums": []map[string]string{{"artifact_id": "dom-1", "checksum": art.Checksum}},
	}, agentToken)
	if w.Code != http.StatusOK {
		t.Fatalf("heartbeat (clear): %d %s", w.Code, w.Body.String())
	}
	got, _ = database.GetConfigArtifact("dom-1")
	if got.Drifted || got.ApplyState != models.ArtifactStateLive {
		t.Errorf("heartbeat did not clear drift: %+v", got)
	}
}

func TestArtifacts_RequireAuth(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	w := doRequest(t, h, "GET", "/api/v1/artifacts", nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", w.Code)
	}
}

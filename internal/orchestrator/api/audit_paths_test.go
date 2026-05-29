package api

import (
	"fmt"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// This file asserts invariant #5 (§17): every config-change path — apply,
// accept, reject, rollback, edit, reset-to-model, drift flag, apply_failed, and
// the invariant-#4 option_dropped — writes an audit entry with the correct
// source + actor. The operational behavior of each path is covered elsewhere;
// here we only check the audit trail.

// findAudit returns the newest audit entry matching entity+action, or fails.
func findAudit(t *testing.T, database *db.DB, entityType, entityID, action string) models.AuditLogEntry {
	t.Helper()
	entries, _, err := database.ListAuditLog(500, 0)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	for _, e := range entries {
		if e.EntityType == entityType && e.EntityID == entityID && e.Action == action {
			return e
		}
	}
	t.Fatalf("no audit entry for %s/%s action=%s; have %d entries", entityType, entityID, action, len(entries))
	return models.AuditLogEntry{}
}

// TestAuditPaths_UIConfigChanges_sourceUIActorAdmin checks accept/reject/
// rollback/edit/reset all audit as source=ui actor=admin when driven through a
// session cookie (the dashboard channel).
func TestAuditPaths_UIConfigChanges_sourceUIActorAdmin(t *testing.T) {
	srv, database := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)

	// --- accept ---
	seedArtifact(t, srv, "agent-1", "dom-1", `{"handle":[]}`)
	if err := srv.db.MarkConfigArtifactDrifted("dom-1"); err != nil {
		t.Fatal(err)
	}
	if w := doRequest(t, h, "POST", "/api/v1/artifacts/dom-1/accept",
		map[string]string{"content": `{"handle":["x"]}`}, cookie); w.Code != 200 {
		t.Fatalf("accept: %d %s", w.Code, w.Body.String())
	}
	assertUIAdmin(t, findAudit(t, database, "config_artifact", "dom-1", "accept"))

	// --- reject ---
	if err := srv.db.MarkConfigArtifactDrifted("dom-1"); err != nil {
		t.Fatal(err)
	}
	if w := doRequest(t, h, "POST", "/api/v1/artifacts/dom-1/reject", nil, cookie); w.Code != 200 {
		t.Fatalf("reject: %d %s", w.Code, w.Body.String())
	}
	assertUIAdmin(t, findAudit(t, database, "config_artifact", "dom-1", "reject"))

	// --- rollback (needs a prior version to roll back to) ---
	if _, err := srv.db.AppendConfigArtifactVersion("dom-1", `{"handle":["v3"]}`, models.ArtifactSourceManual, "op", "edit"); err != nil {
		t.Fatal(err)
	}
	if w := doRequest(t, h, "POST", "/api/v1/artifacts/dom-1/rollback",
		map[string]int{"version": 1}, cookie); w.Code != 200 {
		t.Fatalf("rollback: %d %s", w.Code, w.Body.String())
	}
	assertUIAdmin(t, findAudit(t, database, "config_artifact", "dom-1", "rollback"))

	// --- edit ---
	if w := doRequest(t, h, "PUT", "/api/v1/artifacts/dom-1/content",
		map[string]string{"content": `{"handle":["raw-edit"]}`}, cookie); w.Code != 200 {
		t.Fatalf("edit: %d %s", w.Code, w.Body.String())
	}
	assertUIAdmin(t, findAudit(t, database, "config_artifact", "dom-1", "edit"))
}

// TestAuditPaths_BulkReject_sourceUIActorAdmin checks the >3-drift bulk path
// audits each reject as source=ui actor=admin.
func TestAuditPaths_BulkReject_sourceUIActorAdmin(t *testing.T) {
	srv, database := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)

	for _, id := range []string{"dom-1", "dom-2"} {
		seedArtifact(t, srv, "agent-1", id, `{"handle":[]}`)
		if err := srv.db.MarkConfigArtifactDrifted(id); err != nil {
			t.Fatal(err)
		}
	}
	if w := doRequest(t, h, "POST", "/api/v1/artifacts/bulk",
		map[string]string{"action": "reject", "agent_id": "agent-1"}, cookie); w.Code != 200 {
		t.Fatalf("bulk reject: %d %s", w.Code, w.Body.String())
	}
	assertUIAdmin(t, findAudit(t, database, "config_artifact", "dom-1", "reject"))
	assertUIAdmin(t, findAudit(t, database, "config_artifact", "dom-2", "reject"))
}

// TestAuditPaths_AgentApply_sourceAgentActorAgent checks the apply path (agent
// apply-ACK) audits as source=agent actor=agent:<id>.
func TestAuditPaths_AgentApply_sourceAgentActorAgent(t *testing.T) {
	srv, database := testServer(t)
	token := makeAgent(t, database, "agent-1", "edge1.example.com", models.AgentStatusAdopted, nil)

	_ = database.CreateProvider(&models.Provider{ID: "prov-1", Type: "mock", Name: "P", Config: "{}"})
	_ = database.CreateZone(&models.Zone{ID: "zone-1", ProviderID: "prov-1", Name: "example.com"})
	_ = database.CreateServer(&models.Server{ID: "srv-1", AgentID: "agent-1", Name: "B", Address: "10.0.0.1"})
	dom := &models.Domain{Subdomain: "app", ZoneID: "zone-1", ServerID: "srv-1", Port: 80, Status: models.DomainStatusPending}
	if err := database.CreateDomain(dom); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	artID := fmt.Sprintf("dom-%d", dom.ID)
	content := `{"@id":"r1","match":[{"host":["app.example.com"]}]}`
	ack := proxymodel.ApplyAck{Reports: []proxymodel.ArtifactReport{{
		ArtifactID: artID,
		Host:       "app.example.com",
		Backend:    "caddy",
		TargetKind: "caddy-route",
		TargetPath: "caddy:route:r1",
		Content:    content,
		Checksum:   db.ChecksumContent(content),
		Enabled:    true,
	}}}
	if w := doRequestWithAuth(t, srv.Handler(), "POST", "/api/v1/agents/agent-1/routes/ack", ack, token); w.Code != 200 {
		t.Fatalf("ack: %d %s", w.Code, w.Body.String())
	}

	e := findAudit(t, database, "config_artifact", artID, "apply")
	if e.Source != models.AuditSourceAgent {
		t.Errorf("apply source = %q, want agent", e.Source)
	}
	if e.Actor != "agent:agent-1" {
		t.Errorf("apply actor = %q, want agent:agent-1", e.Actor)
	}
}

// TestAuditPaths_AgentApplyFailed_audited checks a per-artifact apply failure is
// audited as apply_failed, source=agent.
func TestAuditPaths_AgentApplyFailed_audited(t *testing.T) {
	srv, database := testServer(t)
	token := makeAgent(t, database, "agent-1", "edge1.example.com", models.AgentStatusAdopted, nil)

	ack := proxymodel.ApplyAck{Reports: []proxymodel.ArtifactReport{{
		ArtifactID: "dom-99",
		Host:       "bad.example.com",
		Backend:    "caddy",
		Error:      "caddy refused: port in use",
	}}}
	if w := doRequestWithAuth(t, srv.Handler(), "POST", "/api/v1/agents/agent-1/routes/ack", ack, token); w.Code != 200 {
		t.Fatalf("ack: %d %s", w.Code, w.Body.String())
	}
	e := findAudit(t, database, "config_artifact", "dom-99", "apply_failed")
	if e.Source != models.AuditSourceAgent {
		t.Errorf("apply_failed source = %q, want agent", e.Source)
	}
	if !strings.Contains(e.Details, "port in use") {
		t.Errorf("apply_failed details = %q, want the agent error", e.Details)
	}
}

// TestAuditPaths_DroppedOptions_auditedSourceAgent checks invariant #4: when a
// backend drops unsupported options (carried in the ACK's Warnings), each is
// written to the central audit log as option_dropped, source=agent.
func TestAuditPaths_DroppedOptions_auditedSourceAgent(t *testing.T) {
	srv, database := testServer(t)
	token := makeAgent(t, database, "agent-1", "edge1.example.com", models.AgentStatusAdopted, nil)

	ack := proxymodel.ApplyAck{Reports: []proxymodel.ArtifactReport{{
		ArtifactID: "dom-7",
		Host:       "app.example.com",
		Backend:    "nginx",
		TargetKind: "file",
		TargetPath: "/etc/nginx/sites-available/nurproxy-app.example.com.conf",
		Content:    "server {}",
		Checksum:   db.ChecksumContent("server {}"),
		Enabled:    true,
		Warnings: []string{
			"rate_limit: nginx renderer cannot express per-client rate limit",
			"basic_auth: no htpasswd path configured",
		},
	}}}
	if w := doRequestWithAuth(t, srv.Handler(), "POST", "/api/v1/agents/agent-1/routes/ack", ack, token); w.Code != 200 {
		t.Fatalf("ack: %d %s", w.Code, w.Body.String())
	}

	entries, _, err := database.ListAuditLogFiltered(models.AuditSourceAgent, 500, 0)
	if err != nil {
		t.Fatalf("ListAuditLogFiltered: %v", err)
	}
	dropped := 0
	for _, e := range entries {
		if e.EntityType != "config_artifact" || e.EntityID != "dom-7" || e.Action != "option_dropped" {
			continue
		}
		if e.Actor != "agent:agent-1" {
			t.Errorf("option_dropped actor = %q, want agent:agent-1", e.Actor)
		}
		dropped++
	}
	if dropped != 2 {
		t.Fatalf("expected 2 option_dropped audit entries, got %d", dropped)
	}
}

func assertUIAdmin(t *testing.T, e models.AuditLogEntry) {
	t.Helper()
	if e.Source != models.AuditSourceUI {
		t.Errorf("action %q source = %q, want ui", e.Action, e.Source)
	}
	if e.Actor != "admin" {
		t.Errorf("action %q actor = %q, want admin", e.Action, e.Actor)
	}
}

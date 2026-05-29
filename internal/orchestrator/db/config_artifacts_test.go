package db

import (
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// createTestAgentRow inserts a minimal agent so artifacts have a valid
// agent_id foreign key. It uses the raw SQL path to stay independent of the
// agent repository's API.
func createTestAgentRow(t *testing.T, d *DB, id string) {
	t.Helper()
	_, err := d.sql.Exec(`
		INSERT INTO agents (id, name, fqdn, status)
		VALUES (?, ?, ?, 'adopted')`, id, id, id+".example.com")
	if err != nil {
		t.Fatalf("inserting agent: %v", err)
	}
}

func createTestArtifact(t *testing.T, d *DB, id, agentID string) *models.ConfigArtifact {
	t.Helper()
	art := &models.ConfigArtifact{
		ID:      id,
		AgentID: agentID,
		Backend: "caddy",
		Target: models.Target{
			Kind: models.TargetKindCaddyRoute,
			Path: "caddy:route:" + id,
		},
		Source:     models.ArtifactSourceGenerated,
		Content:    `{"handle":[]}`,
		Enabled:    true,
		ApplyState: models.ArtifactStateLive,
	}
	if err := d.CreateConfigArtifact(art, "tester", "initial apply"); err != nil {
		t.Fatalf("CreateConfigArtifact: %v", err)
	}
	return art
}

func TestConfigArtifact_CreateAndGet_writesVersionOne(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")
	art := createTestArtifact(t, d, "art-1", "agent-1")

	if art.LiveVersion != 1 {
		t.Errorf("LiveVersion = %d, want 1", art.LiveVersion)
	}
	if art.Checksum == "" {
		t.Error("checksum was not computed")
	}
	if art.Checksum != ChecksumContent(art.Content) {
		t.Error("checksum does not match content")
	}

	got, err := d.GetConfigArtifact("art-1")
	if err != nil {
		t.Fatalf("GetConfigArtifact: %v", err)
	}
	if got.AgentID != "agent-1" || got.Backend != "caddy" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if got.Target.Kind != models.TargetKindCaddyRoute || got.Target.Path != "caddy:route:art-1" {
		t.Errorf("target mismatch: %+v", got.Target)
	}
	if !got.Enabled || got.Drifted {
		t.Errorf("flags mismatch: enabled=%v drifted=%v", got.Enabled, got.Drifted)
	}

	versions, err := d.ListConfigArtifactVersions("art-1")
	if err != nil {
		t.Fatalf("ListConfigArtifactVersions: %v", err)
	}
	if len(versions) != 1 {
		t.Fatalf("got %d versions, want 1", len(versions))
	}
	if versions[0].Version != 1 || versions[0].Actor != "tester" {
		t.Errorf("version 1 mismatch: %+v", versions[0])
	}
}

func TestConfigArtifact_CreateWithoutID_returnsError(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")
	art := &models.ConfigArtifact{AgentID: "agent-1", Backend: "caddy"}
	if err := d.CreateConfigArtifact(art, "tester", ""); err == nil {
		t.Fatal("expected error for empty id")
	}
}

func TestConfigArtifact_GetMissing_returnsError(t *testing.T) {
	d := testDB(t)
	if _, err := d.GetConfigArtifact("nope"); err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestConfigArtifact_AppendVersion_promotesLiveState(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")
	createTestArtifact(t, d, "art-1", "agent-1")

	v, err := d.AppendConfigArtifactVersion("art-1", `{"handle":["v2"]}`,
		models.ArtifactSourceManual, "operator", "accepted drift")
	if err != nil {
		t.Fatalf("AppendConfigArtifactVersion: %v", err)
	}
	if v.Version != 2 {
		t.Errorf("new version = %d, want 2", v.Version)
	}

	got, err := d.GetConfigArtifact("art-1")
	if err != nil {
		t.Fatalf("GetConfigArtifact: %v", err)
	}
	if got.LiveVersion != 2 {
		t.Errorf("LiveVersion = %d, want 2", got.LiveVersion)
	}
	if got.Content != `{"handle":["v2"]}` {
		t.Errorf("content not promoted: %q", got.Content)
	}
	if got.Source != models.ArtifactSourceManual {
		t.Errorf("source = %q, want manual", got.Source)
	}
	if got.Checksum != ChecksumContent(`{"handle":["v2"]}`) {
		t.Error("checksum not updated to new content")
	}

	versions, err := d.ListConfigArtifactVersions("art-1")
	if err != nil {
		t.Fatalf("ListConfigArtifactVersions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("got %d versions, want 2 (append-only)", len(versions))
	}
	// Newest first.
	if versions[0].Version != 2 || versions[1].Version != 1 {
		t.Errorf("version ordering: %d, %d", versions[0].Version, versions[1].Version)
	}
}

func TestConfigArtifact_AppendVersionInheritsSource_whenEmpty(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")
	createTestArtifact(t, d, "art-1", "agent-1")

	v, err := d.AppendConfigArtifactVersion("art-1", `{"new":true}`, "", "tester", "re-render")
	if err != nil {
		t.Fatalf("AppendConfigArtifactVersion: %v", err)
	}
	if v.Source != models.ArtifactSourceGenerated {
		t.Errorf("source = %q, want inherited generated", v.Source)
	}
}

func TestConfigArtifact_AppendVersionMissing_returnsError(t *testing.T) {
	d := testDB(t)
	if _, err := d.AppendConfigArtifactVersion("nope", "x", "", "a", "b"); err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestConfigArtifact_MarkDrifted_thenAcceptClearsDrift(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")
	createTestArtifact(t, d, "art-1", "agent-1")

	if err := d.MarkConfigArtifactDrifted("art-1"); err != nil {
		t.Fatalf("MarkConfigArtifactDrifted: %v", err)
	}
	got, err := d.GetConfigArtifact("art-1")
	if err != nil {
		t.Fatalf("GetConfigArtifact: %v", err)
	}
	if !got.Drifted || got.ApplyState != models.ArtifactStateDrifted {
		t.Errorf("expected drifted state, got drifted=%v state=%q", got.Drifted, got.ApplyState)
	}
	// Stored content must be preserved (accepted state intact for review).
	if got.Content != `{"handle":[]}` {
		t.Errorf("content changed on drift: %q", got.Content)
	}

	// Accept: a new version with the on-disk content resolves the drift.
	if _, err := d.AppendConfigArtifactVersion("art-1", `{"drifted":true}`,
		models.ArtifactSourceManual, "operator", "accept"); err != nil {
		t.Fatalf("append on accept: %v", err)
	}
	got, err = d.GetConfigArtifact("art-1")
	if err != nil {
		t.Fatalf("GetConfigArtifact: %v", err)
	}
	if got.Drifted || got.ApplyState != models.ArtifactStateLive {
		t.Errorf("accept did not clear drift: drifted=%v state=%q", got.Drifted, got.ApplyState)
	}
}

func TestConfigArtifact_SetApplyState_failedAndDrifted(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")
	createTestArtifact(t, d, "art-1", "agent-1")

	if err := d.SetConfigArtifactApplyState("art-1", models.ArtifactStateApplyFailed, "nginx -t failed"); err != nil {
		t.Fatalf("SetConfigArtifactApplyState: %v", err)
	}
	got, _ := d.GetConfigArtifact("art-1")
	if got.ApplyState != models.ArtifactStateApplyFailed || got.LastError != "nginx -t failed" {
		t.Errorf("apply_failed not set: %+v", got)
	}
	if got.Drifted {
		t.Error("apply_failed should not set drifted")
	}

	if err := d.SetConfigArtifactApplyState("art-1", models.ArtifactStateDrifted, ""); err != nil {
		t.Fatalf("SetConfigArtifactApplyState drifted: %v", err)
	}
	got, _ = d.GetConfigArtifact("art-1")
	if !got.Drifted {
		t.Error("drifted state should set drifted flag")
	}
}

func TestConfigArtifact_List_filters(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")
	createTestAgentRow(t, d, "agent-2")

	a := createTestArtifact(t, d, "art-1", "agent-1")
	_ = a
	createTestArtifact(t, d, "art-2", "agent-1")
	createTestArtifact(t, d, "art-3", "agent-2")
	if err := d.MarkConfigArtifactDrifted("art-2"); err != nil {
		t.Fatal(err)
	}

	byAgent, err := d.ListConfigArtifacts(ConfigArtifactFilter{AgentID: "agent-1"})
	if err != nil {
		t.Fatalf("ListConfigArtifacts: %v", err)
	}
	if len(byAgent) != 2 {
		t.Errorf("agent-1 artifacts = %d, want 2", len(byAgent))
	}

	drifted := true
	driftedArts, err := d.ListConfigArtifacts(ConfigArtifactFilter{Drifted: &drifted})
	if err != nil {
		t.Fatalf("ListConfigArtifacts drifted: %v", err)
	}
	if len(driftedArts) != 1 || driftedArts[0].ID != "art-2" {
		t.Errorf("drifted filter = %+v, want only art-2", driftedArts)
	}

	gen, err := d.ListConfigArtifacts(ConfigArtifactFilter{Source: models.ArtifactSourceGenerated})
	if err != nil {
		t.Fatalf("ListConfigArtifacts source: %v", err)
	}
	if len(gen) != 3 {
		t.Errorf("generated artifacts = %d, want 3", len(gen))
	}
}

func TestConfigArtifact_ListByDomain(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")

	if _, err := d.sql.Exec(`INSERT INTO providers (id, type, name, config) VALUES ('p1','cloudflare','p','{}')`); err != nil {
		t.Fatalf("inserting provider: %v", err)
	}
	if _, err := d.sql.Exec(`INSERT INTO zones (id, provider_id, name) VALUES ('z1','p1','example.com')`); err != nil {
		t.Fatalf("inserting zone: %v", err)
	}
	if _, err := d.sql.Exec(`INSERT INTO servers (id, agent_id, name, address) VALUES ('s1','agent-1','s','1.2.3.4')`); err != nil {
		t.Fatalf("inserting server: %v", err)
	}
	res, err := d.sql.Exec(`
		INSERT INTO domains (subdomain, zone_id, server_id, port)
		VALUES ('app', 'z1', 's1', 80)`)
	if err != nil {
		t.Fatalf("inserting domain: %v", err)
	}
	domainID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	art := &models.ConfigArtifact{
		ID:       "art-dom",
		AgentID:  "agent-1",
		Backend:  "nginx",
		Target:   models.Target{Kind: models.TargetKindFile, Path: "/etc/nginx/sites-available/x.conf"},
		Source:   models.ArtifactSourceGenerated,
		DomainID: &domainID,
		Content:  "server {}",
	}
	if err := d.CreateConfigArtifact(art, "tester", "x"); err != nil {
		t.Fatalf("CreateConfigArtifact: %v", err)
	}

	got, err := d.ListConfigArtifacts(ConfigArtifactFilter{DomainID: &domainID})
	if err != nil {
		t.Fatalf("ListConfigArtifacts: %v", err)
	}
	if len(got) != 1 || got[0].DomainID == nil || *got[0].DomainID != domainID {
		t.Errorf("domain filter result: %+v", got)
	}
}

func TestConfigArtifact_GetVersion(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")
	createTestArtifact(t, d, "art-1", "agent-1")
	if _, err := d.AppendConfigArtifactVersion("art-1", "v2content", "", "t", ""); err != nil {
		t.Fatal(err)
	}

	v1, err := d.GetConfigArtifactVersion("art-1", 1)
	if err != nil {
		t.Fatalf("GetConfigArtifactVersion 1: %v", err)
	}
	if v1.Content != `{"handle":[]}` {
		t.Errorf("v1 content: %q", v1.Content)
	}
	v2, err := d.GetConfigArtifactVersion("art-1", 2)
	if err != nil {
		t.Fatalf("GetConfigArtifactVersion 2: %v", err)
	}
	if v2.Content != "v2content" {
		t.Errorf("v2 content: %q", v2.Content)
	}
	if _, err := d.GetConfigArtifactVersion("art-1", 99); err == nil {
		t.Error("expected not-found for missing version")
	}
}

func TestConfigArtifact_SetEnabled(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")
	createTestArtifact(t, d, "art-1", "agent-1")

	if err := d.SetConfigArtifactEnabled("art-1", false); err != nil {
		t.Fatalf("SetConfigArtifactEnabled: %v", err)
	}
	got, _ := d.GetConfigArtifact("art-1")
	if got.Enabled {
		t.Error("expected enabled=false")
	}
}

func TestConfigArtifact_Delete_cascadesVersions(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")
	createTestArtifact(t, d, "art-1", "agent-1")
	if _, err := d.AppendConfigArtifactVersion("art-1", "v2", "", "t", ""); err != nil {
		t.Fatal(err)
	}

	if err := d.DeleteConfigArtifact("art-1"); err != nil {
		t.Fatalf("DeleteConfigArtifact: %v", err)
	}
	if _, err := d.GetConfigArtifact("art-1"); err == nil {
		t.Error("artifact should be gone")
	}

	var count int
	if err := d.sql.QueryRow(
		"SELECT COUNT(*) FROM config_artifact_versions WHERE artifact_id = ?", "art-1",
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("versions not cascaded: %d remain", count)
	}
}

func TestConfigArtifact_DeleteMissing_returnsError(t *testing.T) {
	d := testDB(t)
	if err := d.DeleteConfigArtifact("nope"); err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestConfigArtifact_UniqueTarget_rejectsDuplicate(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")
	createTestArtifact(t, d, "art-1", "agent-1")

	dup := &models.ConfigArtifact{
		ID:      "art-2",
		AgentID: "agent-1",
		Backend: "caddy",
		Target:  models.Target{Kind: models.TargetKindCaddyRoute, Path: "caddy:route:art-1"},
		Content: "x",
	}
	if err := d.CreateConfigArtifact(dup, "tester", ""); err == nil {
		t.Fatal("expected unique-constraint violation for duplicate target")
	}
}

package mcp

import (
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

func TestDomainFailoverTools(t *testing.T) {
	h, d := testHandler(t)
	enable(t, d)
	zoneID, serverID, _ := seed(t, d)
	now := time.Now().UTC()
	if err := d.CreateAgent(&models.Agent{ID: "agent-2", Name: "B", FQDN: "edge2.example.com", Status: models.AgentStatusAdopted, LastSeen: &now}); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateServer(&models.Server{ID: "srv-2", AgentID: "agent-2", Name: "B", Address: "10.0.0.2"}); err != nil {
		t.Fatal(err)
	}
	var created models.Domain
	if isErr := callTool(t, h, "create_domain", map[string]any{
		"subdomain": "app", "zone_id": zoneID, "server_id": serverID, "port": 8080,
	}, &created); isErr {
		t.Fatal("create_domain returned isError")
	}

	// agent-2 does not serve the zone yet.
	if isErr := callTool(t, h, "set_domain_backups", map[string]any{"id": created.ID, "server_ids": []string{"srv-2"}}, nil); !isErr {
		t.Fatal("backup outside the zone was accepted")
	}
	if err := d.AddAgentZone("agent-2", zoneID); err != nil {
		t.Fatal(err)
	}
	var status models.DomainFailoverStatus
	if isErr := callTool(t, h, "set_domain_backups", map[string]any{"id": created.ID, "server_ids": []string{"srv-2"}}, &status); isErr {
		t.Fatal("set_domain_backups returned isError")
	}
	if len(status.Candidates) != 2 || status.ActiveServerID != serverID || !status.Candidates[1].Healthy {
		t.Fatalf("status = %+v", status)
	}
	if isErr := callTool(t, h, "get_domain_failover", map[string]any{"id": created.ID}, &status); isErr || len(status.Candidates) != 2 {
		t.Fatalf("get_domain_failover = %+v (isError %v)", status, isErr)
	}

	// Moving the primary onto the backup's agent is refused.
	if isErr := callTool(t, h, "update_domain", map[string]any{"id": created.ID, "server_id": "srv-2"}, nil); !isErr {
		t.Fatal("primary moved onto the backup agent")
	}

	var listed []models.Domain
	if isErr := callTool(t, h, "list_domains", map[string]any{}, &listed); isErr || len(listed) != 1 || len(listed[0].BackupServerIDs) != 1 {
		t.Fatalf("list_domains = %+v", listed)
	}
}

package mcp

import (
	"fmt"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// The MCP update_domain tool must handle a cross-agent server change like the
// REST API does: tombstone the old host on the old agent (#148).
func TestUpdateDomainMoveTombstonesOldAgent(t *testing.T) {
	h, d := testHandler(t)
	enable(t, d)
	zoneID, serverID, _ := seed(t, d)
	for _, agent := range []*models.Agent{
		{ID: "agent-nginx", Name: "N", FQDN: "edge2.example.com", Status: models.AgentStatusAdopted, ProxyMode: "existing", ProxyDetection: &models.ProxyDetection{Installed: true, Kind: "nginx"}},
	} {
		if err := d.CreateAgent(agent); err != nil {
			t.Fatal(err)
		}
		if err := d.UpdateAgentHealth(agent.ID, "", "", "", false, "existing"); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.CreateServer(&models.Server{ID: "srv-nginx", AgentID: "agent-nginx", Name: "N", Address: "10.0.0.9"}); err != nil {
		t.Fatal(err)
	}

	var created models.Domain
	if isErr := callTool(t, h, "create_domain", map[string]any{
		"subdomain": "app", "zone_id": zoneID, "server_id": "srv-nginx", "port": 8080,
	}, &created); isErr {
		t.Fatal("create_domain returned isError")
	}
	var moved models.Domain
	if isErr := callTool(t, h, "update_domain", map[string]any{"id": created.ID, "server_id": serverID}, &moved); isErr {
		t.Fatal("update_domain returned isError")
	}
	deletions, err := d.ListManagedRouteTombstones("agent-nginx")
	want := helperprotocol.ManagedDeletion{ResourceID: fmt.Sprintf("dom-%d", created.ID), Host: "app.example.com", Backend: "nginx"}
	if err != nil || len(deletions) != 1 || deletions[0] != want {
		t.Fatalf("old agent tombstones = %#v, err=%v, want %#v", deletions, err, want)
	}
}

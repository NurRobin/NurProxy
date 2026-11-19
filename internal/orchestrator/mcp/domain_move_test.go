package mcp

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
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

// update_domain renames like the REST API (#151): the old vhost on the same
// nginx agent gets a tombstone of its own, the old DNS record is queued for
// cleanup, and the old certificate is dropped.
func TestUpdateDomainRenameCleansUp(t *testing.T) {
	h, d := testHandler(t)
	enable(t, d)
	zoneID, _, _ := seed(t, d)
	if err := d.CreateAgent(&models.Agent{ID: "agent-nginx", Name: "N", FQDN: "edge2.example.com", Status: models.AgentStatusAdopted, ProxyMode: "existing", ProxyDetection: &models.ProxyDetection{Installed: true, Kind: "nginx"}}); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateAgentHealth("agent-nginx", "", "", "", false, "existing"); err != nil {
		t.Fatal(err)
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
	if err := d.UpdateDomainDNSRecord(created.ID, "rec-old", true); err != nil {
		t.Fatal(err)
	}
	if err := d.UpsertCertificate(&models.Certificate{ID: "cert-old", Host: "app.example.com", Names: []string{"app.example.com"}, CertPEM: "LEAF", KeyPEM: "KEY"}); err != nil {
		t.Fatal(err)
	}

	var renamed models.Domain
	if isErr := callTool(t, h, "update_domain", map[string]any{"id": created.ID, "subdomain": "web", "port": 9090}, &renamed); isErr {
		t.Fatal("update_domain returned isError")
	}
	if renamed.Subdomain != "web" || renamed.Port != 9090 || renamed.DNSRecordID != "" {
		t.Fatalf("renamed domain = %+v", renamed)
	}
	deletions, err := d.ListManagedRouteTombstones("agent-nginx")
	if err != nil || len(deletions) != 1 || deletions[0].Host != "app.example.com" ||
		!strings.HasPrefix(deletions[0].ResourceID, fmt.Sprintf("dom-%d-was-", created.ID)) {
		t.Fatalf("tombstones = %#v, err=%v", deletions, err)
	}
	if queued, err := d.ListDomainDNSCleanups(); err != nil || len(queued) != 1 || queued[0].RecordID != "rec-old" || !queued[0].Owned {
		t.Fatalf("queued cleanups = %+v, err=%v", queued, err)
	}
	if _, err := d.GetCertificate("app.example.com"); !errors.Is(err, db.ErrCertNotFound) {
		t.Fatalf("old certificate still stored (err=%v)", err)
	}
}

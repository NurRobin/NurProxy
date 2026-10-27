package api

import (
	"fmt"
	"net/http"
	"strconv"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// seedMoveTargets adds a second server on agent-1 and a server on a second
// nginx agent, so a domain from seedDomainTopology can move within and across
// agents.
func seedMoveTargets(t *testing.T, srv *Server) {
	t.Helper()
	database := srv.db
	if err := database.CreateServer(&models.Server{ID: "srv-1b", AgentID: "agent-1", Name: "Same agent", Address: "10.0.0.3"}); err != nil {
		t.Fatal(err)
	}
	other := &models.Agent{
		ID: "agent-2", Name: "Other", FQDN: "other.example.com",
		DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted,
		ProxyMode:      "existing",
		ProxyDetection: &models.ProxyDetection{Installed: true, Kind: "nginx"},
	}
	if err := database.CreateAgent(other); err != nil {
		t.Fatal(err)
	}
	if err := database.UpdateAgentHealth("agent-2", "", "", "", false, "existing"); err != nil {
		t.Fatal(err)
	}
	if err := database.CreateServer(&models.Server{ID: "srv-2", AgentID: "agent-2", Name: "Other agent", Address: "10.0.0.2"}); err != nil {
		t.Fatal(err)
	}
}

// Regression for #148: moving a domain (also a manual_config raw nginx one) to a
// server on another agent must leave a route tombstone on the old agent, so its
// next signed apply removes the vhost in the same transaction that prunes the
// certificate. A move within one agent must not produce one.
func TestUpdateDomainServerMoveTombstones(t *testing.T) {
	cases := []struct {
		name       string
		manual     bool
		moves      []string // server IDs, applied in order
		wantAgent1 bool     // tombstone for the domain expected on agent-1
		wantAgent2 bool     // tombstone for the domain expected on agent-2
	}{
		{name: "move to another agent", moves: []string{"srv-2"}, wantAgent1: true},
		{name: "manual config move to another agent", manual: true, moves: []string{"srv-2"}, wantAgent1: true},
		{name: "move within the same agent", moves: []string{"srv-1b"}},
		{name: "move away and back again", moves: []string{"srv-2", "srv-1"}, wantAgent2: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, database := testServer(t)
			handler := srv.Handler()
			cookie := setupAdmin(t, handler)
			domainID, fqdn := seedDomainTopology(t, srv, cookie)
			seedMoveTargets(t, srv)
			if tc.manual {
				dom, err := database.GetDomain(domainID)
				if err != nil {
					t.Fatal(err)
				}
				dom.ManualConfig = true
				dom.ProxyConfig.RawConfig = models.RawConfig{Backend: "nginx", Content: "server { listen 80; server_name " + fqdn + "; }"}
				if err := database.UpdateDomain(dom); err != nil {
					t.Fatal(err)
				}
			}
			for _, serverID := range tc.moves {
				w := doRequest(t, handler, http.MethodPut, "/api/v1/domains/"+strconv.FormatInt(domainID, 10),
					map[string]any{"server_id": serverID}, cookie)
				if w.Code != http.StatusOK {
					t.Fatalf("move to %s: %d: %s", serverID, w.Code, w.Body.String())
				}
			}
			want := helperprotocol.ManagedDeletion{ResourceID: fmt.Sprintf("dom-%d", domainID), Host: fqdn, Backend: "nginx"}
			for agentID, expected := range map[string]bool{"agent-1": tc.wantAgent1, "agent-2": tc.wantAgent2} {
				deletions, err := database.ListManagedRouteTombstones(agentID)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, deletion := range deletions {
					if deletion.ResourceID == want.ResourceID {
						if deletion != want {
							t.Fatalf("%s tombstone = %#v, want %#v", agentID, deletion, want)
						}
						found = true
					}
				}
				if found != expected {
					t.Fatalf("%s tombstone present = %v, want %v (all: %#v)", agentID, found, expected, deletions)
				}
			}
		})
	}
}

package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// Queued agent anchor deletions show up in /health as counts only; the
// provider error text must not reach the unauthenticated endpoint.
func TestHealth_agentDNSCleanup(t *testing.T) {
	tests := []struct {
		name     string
		queue    bool
		fail     bool
		wantSub  string
		wantNone bool
	}{
		{name: "nothing queued", wantNone: true},
		{name: "queued", queue: true, wantSub: "ok (1 old agent DNS record(s) queued"},
		{name: "failing", queue: true, fail: true, wantSub: "1 failing"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, database := testServer(t)
			if tc.queue {
				a := &models.Agent{ID: "a1", Name: "edge1", FQDN: "edge1.example.com", DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted}
				if err := database.CreateAgent(a); err != nil {
					t.Fatal(err)
				}
				if _, err := database.SetAgentAnchorRecord(a.ID, a.FQDN, "A", "rec-1", "", true); err != nil {
					t.Fatal(err)
				}
				if err := database.DeleteAgent(a.ID); err != nil {
					t.Fatal(err)
				}
			}
			if tc.fail {
				q, _ := database.ListAgentAnchorCleanups()
				if err := database.RecordAgentAnchorCleanupFailure(q[0].ID, "secret provider detail"); err != nil {
					t.Fatal(err)
				}
			}

			w := doRequest(t, srv.Handler(), "GET", "/api/v1/health", nil)
			var body struct {
				Checks map[string]string `json:"checks"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			got, ok := body.Checks["agent_dns_cleanup"]
			if tc.wantNone {
				if ok {
					t.Errorf("unexpected agent_dns_cleanup check %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.wantSub) {
				t.Errorf("agent_dns_cleanup = %q, want it to contain %q", got, tc.wantSub)
			}
			if strings.Contains(w.Body.String(), "secret provider detail") {
				t.Error("health leaked the provider error text")
			}
		})
	}
}

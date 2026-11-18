package reconciler

import (
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// TestBuildDesiredRoutes_pathRoutes checks that a domain's path routes reach
// the pushed intent with their servers' addresses, and that a route the
// agent cannot serve (server gone or on another agent, backend without path
// routes) holds the domain back with the reason instead of pushing it
// without that path.
func TestBuildDesiredRoutes_pathRoutes(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T, r *Reconciler, agent *models.Agent)
		server  string
		wantErr string
	}{
		{name: "pushed with address", server: "srv-api"},
		{name: "server on another agent", server: "srv-far", wantErr: "another agent"},
		{name: "server gone", server: "srv-gone", wantErr: "not found"},
		{
			name:   "backend without path routes",
			server: "srv-api",
			setup: func(t *testing.T, r *Reconciler, agent *models.Agent) {
				agent.ProxyCapabilities = &models.ProxyCapabilities{ReverseProxy: true}
			},
			wantErr: "cannot render path routes",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := testDB(t)
			_, _, agent, _, dom := setupScenario(t, d)
			if err := d.CreateServer(&models.Server{ID: "srv-api", AgentID: agent.ID, Name: "API", Address: "192.168.178.210:8080"}); err != nil {
				t.Fatal(err)
			}
			if err := d.CreateAgent(&models.Agent{ID: "agent-2", Name: "Other", FQDN: "other.example.com", DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted}); err != nil {
				t.Fatal(err)
			}
			if err := d.CreateServer(&models.Server{ID: "srv-far", AgentID: "agent-2", Name: "Far", Address: "10.9.9.9"}); err != nil {
				t.Fatal(err)
			}
			dom.ProxyConfig.Routes = []models.PathRoute{{Match: "exact", Path: "/api/world", ServerID: tt.server}}
			if err := d.UpdateDomain(dom); err != nil {
				t.Fatal(err)
			}
			r := New(d, newMockAgentClient(), time.Minute)
			if tt.setup != nil {
				tt.setup(t, r, agent)
			}
			desired, _, err := r.buildDesiredRoutes(agent)
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantErr == "" {
				route, ok := desired["app.example.com"]
				if !ok {
					t.Fatalf("domain not pushed: %+v", desired)
				}
				want := []proxymodel.PathRoute{{Match: proxymodel.PathMatchExact, Path: "/api/world", Upstream: proxymodel.Upstream{Addr: "192.168.178.210", Port: 8080}}}
				if len(route.intent.PathRoutes) != 1 || route.intent.PathRoutes[0] != want[0] {
					t.Fatalf("path routes = %+v, want %+v", route.intent.PathRoutes, want)
				}
				return
			}
			if len(desired) != 0 {
				t.Fatalf("domain pushed without its path route: %+v", desired)
			}
			stored, err := d.GetDomain(dom.ID)
			if err != nil {
				t.Fatal(err)
			}
			if stored.Status != models.DomainStatusError || !strings.Contains(stored.ErrorMsg, tt.wantErr) {
				t.Fatalf("domain status = %q, error = %q, want error mentioning %q", stored.Status, stored.ErrorMsg, tt.wantErr)
			}
		})
	}
}

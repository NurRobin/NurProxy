package api

import (
	"net/http"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/auth"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// TestAgentStatus_Auth pins the auth contract of GET /api/v1/agents/{id}/status,
// which the agent's adoption loop polls with its own bearer token. Round-2 H1
// hardening removed agent-token acceptance from requireAuth, so this route moved
// to requireAgentAuth (scoped to self). Regression guard: the agent's self-poll
// must succeed (otherwise adoption never converges), while admin creds and other
// agents' tokens must not reach it.
func TestAgentStatus_Auth(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)

	selfToken := makeAgent(t, database, "agent-1", "edge1.example.com", models.AgentStatusAdopted, nil)

	// A second agent with a distinct token (makeAgent uses a fixed token string,
	// so create agent-2 directly to get a different credential).
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

	tests := []struct {
		name     string
		token    string // bearer agent token; empty means use the admin cookie
		useAdmin bool
		want     int
	}{
		{
			name:  "agent self token succeeds",
			token: selfToken,
			want:  http.StatusOK,
		},
		{
			name:  "other agent token forbidden (scoped to self)",
			token: otherToken,
			want:  http.StatusForbidden,
		},
		{
			name:     "admin cookie rejected (not an admin route)",
			useAdmin: true,
			want:     http.StatusUnauthorized,
		},
		{
			name:  "no credentials rejected",
			token: "",
			want:  http.StatusUnauthorized,
		},
		{
			name:  "unknown agent token rejected",
			token: "np_ag_bogus_token_value",
			want:  http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var code int
			if tt.useAdmin {
				code = doRequest(t, handler, "GET", "/api/v1/agents/agent-1/status", nil, cookie).Code
			} else {
				code = doRequestWithAuth(t, handler, "GET", "/api/v1/agents/agent-1/status", nil, tt.token).Code
			}
			if code != tt.want {
				t.Fatalf("status auth: expected %d, got %d", tt.want, code)
			}
		})
	}
}

package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/agenthub"
	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/auth"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// stubPusher publishes a fixed intent set whenever the handler asks to push,
// standing in for the reconciler in stream tests.
type stubPusher struct {
	hub     *agenthub.Hub
	intents []proxymodel.RouteIntent
}

func (p *stubPusher) PushAgentRoutes(agentID string) error {
	p.hub.PublishIntents(agentID, p.intents)
	return nil
}

// makeAgent inserts an agent with a known plaintext token and returns the token.
func makeAgent(t *testing.T, database interface {
	CreateAgent(*models.Agent) error
}, id, fqdn string, status models.AgentStatus, lastSeen *time.Time) string {
	t.Helper()
	const token = "agent-secret-token"
	a := &models.Agent{
		ID:        id,
		Name:      fqdn,
		FQDN:      fqdn,
		TokenHash: auth.HashToken(token),
		Status:    status,
		DNSMode:   models.DNSModeStatic,
		LastSeen:  lastSeen,
	}
	if err := database.CreateAgent(a); err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	return token
}

func TestAgentStream_DeliversRoutesAndMarksOnline(t *testing.T) {
	srv, database := testServer(t)

	// An offline agent with a stale heartbeat — connecting should bring it back.
	stale := time.Now().UTC().Add(-time.Hour)
	token := makeAgent(t, database, "agent-1", "edge1.example.com", models.AgentStatusOffline, &stale)

	hub := agenthub.New()
	intents := []proxymodel.RouteIntent{{
		ArtifactID: "dom-1",
		Backend:    "caddy",
		Route: proxymodel.Route{
			Host:     "app.example.com",
			Upstream: proxymodel.Upstream{Addr: "10.0.0.1", Port: 8080},
		},
	}}
	srv.SetAgentHub(hub, &stubPusher{hub: hub, intents: intents})

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/agents/agent-1/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("stream request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream status = %d", resp.StatusCode)
	}

	// Read until we see the routes event's data line.
	gotRoutes := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		var sawRoutesEvent bool
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "event:") && strings.Contains(line, agenthub.EventRoutes) {
				sawRoutesEvent = true
			}
			if sawRoutesEvent && strings.HasPrefix(line, "data:") {
				gotRoutes <- strings.TrimSpace(line[len("data:"):])
				return
			}
		}
	}()

	select {
	case data := <-gotRoutes:
		var got proxymodel.IntentSet
		if err := json.Unmarshal([]byte(data), &got); err != nil {
			t.Fatalf("intent data not valid JSON: %v (%q)", err, data)
		}
		if len(got.Intents) != 1 {
			t.Errorf("expected 1 intent, got %d", len(got.Intents))
		}
		if got.Intents[0].Route.Host != "app.example.com" {
			t.Errorf("intent host = %q, want app.example.com", got.Intents[0].Route.Host)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for routes event")
	}

	// Connecting should have flipped the agent back online and refreshed last_seen.
	// Give the handler a moment to run markAgentOnline.
	deadline := time.Now().Add(time.Second)
	for {
		a, err := database.GetAgent("agent-1")
		if err != nil {
			t.Fatalf("GetAgent: %v", err)
		}
		if a.Status == models.AgentStatusAdopted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent not marked online after stream connect, status=%q", a.Status)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAgentRoutesAck_UpdatesDomainStatus(t *testing.T) {
	srv, database := testServer(t)
	token := makeAgent(t, database, "agent-1", "edge1.example.com", models.AgentStatusAdopted, nil)
	srv.SetAgentHub(agenthub.New(), nil)

	// Minimal provider/zone/server/domain so the ack can resolve the FQDN.
	if err := database.CreateProvider(&models.Provider{ID: "prov-1", Type: "mock", Name: "P", Config: "{}"}); err != nil {
		t.Fatalf("CreateProvider: %v", err)
	}
	if err := database.CreateZone(&models.Zone{ID: "zone-1", ProviderID: "prov-1", Name: "example.com"}); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}
	if err := database.CreateServer(&models.Server{ID: "srv-1", AgentID: "agent-1", Name: "B", Address: "10.0.0.1"}); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	dom := &models.Domain{Subdomain: "app", ZoneID: "zone-1", ServerID: "srv-1", Port: 80, Status: models.DomainStatusPending}
	if err := database.CreateDomain(dom); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	// A cert exists for the host so the applied domain ends "active"; without one a
	// central-TLS domain would be "degraded" (served plaintext), per §78.
	if err := database.UpsertCertificate(&models.Certificate{ID: "cert-app", Host: "app.example.com", Names: []string{"app.example.com"}, CertPEM: "C", KeyPEM: "K"}); err != nil {
		t.Fatalf("UpsertCertificate: %v", err)
	}

	artifactID := fmt.Sprintf("dom-%d", dom.ID)
	content := `{"@id":"r1","match":[{"host":["app.example.com"]}]}`
	ack := proxymodel.ApplyAck{Reports: []proxymodel.ArtifactReport{{
		ArtifactID: artifactID,
		Host:       "app.example.com",
		Backend:    "caddy",
		TargetKind: "caddy-route",
		TargetPath: "caddy:route:r1",
		Content:    content,
		Checksum:   db.ChecksumContent(content),
		Enabled:    true,
	}}}
	w := doRequestWithAuth(t, srv.Handler(), "POST", "/api/v1/agents/agent-1/routes/ack", ack, token)
	if w.Code != http.StatusOK {
		t.Fatalf("ack status = %d: %s", w.Code, w.Body.String())
	}

	got, err := database.GetDomain(dom.ID)
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	if got.Status != models.DomainStatusActive {
		t.Errorf("domain status = %q, want active", got.Status)
	}
	if got.LastSynced == nil {
		t.Error("expected last_synced to be set after ack")
	}

	// The agent-rendered artifact should have been round-tripped into the store
	// as version 1 (B1, §3).
	art, err := database.GetConfigArtifact(artifactID)
	if err != nil {
		t.Fatalf("artifact not stored from ack: %v", err)
	}
	if art.Content != content {
		t.Errorf("stored content = %q, want %q", art.Content, content)
	}
	if art.LiveVersion != 1 {
		t.Errorf("live version = %d, want 1", art.LiveVersion)
	}
	if art.Target.Kind != "caddy-route" {
		t.Errorf("target kind = %q, want caddy-route", art.Target.Kind)
	}
	if art.DomainID == nil || *art.DomainID != dom.ID {
		t.Errorf("artifact domain id = %v, want %d", art.DomainID, dom.ID)
	}

	// A re-apply of byte-identical content must NOT spawn a phantom version.
	w2 := doRequestWithAuth(t, srv.Handler(), "POST", "/api/v1/agents/agent-1/routes/ack", ack, token)
	if w2.Code != http.StatusOK {
		t.Fatalf("second ack status = %d", w2.Code)
	}
	art2, err := database.GetConfigArtifact(artifactID)
	if err != nil {
		t.Fatalf("GetConfigArtifact: %v", err)
	}
	if art2.LiveVersion != 1 {
		t.Errorf("live version after identical re-apply = %d, want 1 (no phantom version)", art2.LiveVersion)
	}
}

func TestAgentRoutesAck_RecordsError(t *testing.T) {
	srv, database := testServer(t)
	token := makeAgent(t, database, "agent-1", "edge1.example.com", models.AgentStatusAdopted, nil)
	srv.SetAgentHub(agenthub.New(), nil)

	_ = database.CreateProvider(&models.Provider{ID: "prov-1", Type: "mock", Name: "P", Config: "{}"})
	_ = database.CreateZone(&models.Zone{ID: "zone-1", ProviderID: "prov-1", Name: "example.com"})
	_ = database.CreateServer(&models.Server{ID: "srv-1", AgentID: "agent-1", Name: "B", Address: "10.0.0.1"})
	dom := &models.Domain{Subdomain: "app", ZoneID: "zone-1", ServerID: "srv-1", Port: 80, Status: models.DomainStatusPending}
	if err := database.CreateDomain(dom); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}

	ack := proxymodel.ApplyAck{Reports: []proxymodel.ArtifactReport{{
		ArtifactID: fmt.Sprintf("dom-%d", dom.ID),
		Host:       "app.example.com",
		Backend:    "caddy",
		Error:      "caddy refused: port in use",
	}}}
	w := doRequestWithAuth(t, srv.Handler(), "POST", "/api/v1/agents/agent-1/routes/ack", ack, token)
	if w.Code != http.StatusOK {
		t.Fatalf("ack status = %d", w.Code)
	}

	got, err := database.GetDomain(dom.ID)
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	if got.Status != models.DomainStatusError {
		t.Errorf("domain status = %q, want error", got.Status)
	}
	if !strings.Contains(got.ErrorMsg, "port in use") {
		t.Errorf("expected error message recorded, got %q", got.ErrorMsg)
	}
}

func TestAgentStream_RejectsWrongAgent(t *testing.T) {
	srv, database := testServer(t)
	token := makeAgent(t, database, "agent-1", "edge1.example.com", models.AgentStatusAdopted, nil)
	srv.SetAgentHub(agenthub.New(), nil)

	// Authenticated as agent-1 but requesting agent-2's stream.
	w := doRequestWithAuth(t, srv.Handler(), "GET", "/api/v1/agents/agent-2/stream", nil, token)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for cross-agent stream, got %d", w.Code)
	}
}

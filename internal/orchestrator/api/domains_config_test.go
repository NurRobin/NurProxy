package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// seedDomainTopology creates provider, zone, agent (existing-mode nginx), server
// and one domain, returning the domain ID and its FQDN.
func seedDomainTopology(t *testing.T, srv *Server, cookie *http.Cookie) (int64, string) {
	t.Helper()
	database := srv.db
	p := &models.Provider{ID: "prov-1", Type: "cloudflare", Name: "CF", Config: `{"api_token":"test"}`}
	if err := database.CreateProvider(p); err != nil {
		t.Fatal(err)
	}
	z := &models.Zone{ID: "zone-1", ProviderID: "prov-1", ExternalID: "ext-1", Name: "example.com"}
	if err := database.CreateZone(z); err != nil {
		t.Fatal(err)
	}
	a := &models.Agent{
		ID: "agent-1", Name: "Agent", FQDN: "agent.example.com",
		DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted,
		ProxyMode:      "existing",
		ProxyDetection: &models.ProxyDetection{Installed: true, Kind: "nginx"},
	}
	if err := database.CreateAgent(a); err != nil {
		t.Fatal(err)
	}
	// proxy_mode is owned by the heartbeat (CreateAgent defaults it to built-in),
	// so set it explicitly to model an agent running in existing mode.
	if err := database.UpdateAgentHealth("agent-1", "", "", "", false, "existing"); err != nil {
		t.Fatal(err)
	}
	s := &models.Server{ID: "srv-1", AgentID: "agent-1", Name: "Backend", Address: "10.0.0.1"}
	if err := database.CreateServer(s); err != nil {
		t.Fatal(err)
	}

	w := doRequest(t, srv.Handler(), "POST", "/api/v1/domains", map[string]interface{}{
		"subdomain": "health",
		"zone_id":   "zone-1",
		"server_id": "srv-1",
		"port":      8080,
	}, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("create domain: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var dom models.Domain
	if err := json.NewDecoder(w.Body).Decode(&dom); err != nil {
		t.Fatal(err)
	}
	return dom.ID, "health.example.com"
}

// Without an applied artifact the config editor falls back to a fresh preview
// render. Its placeholder cert paths must match the agent's real cert-store
// convention (<data-dir>/certs/<host>.crt + .key.plain) — the old placeholders
// pointed at /var/lib/nurproxy/certs/<host>.key, which does not exist on any
// agent, and saving them as a manual config broke nginx -t.
func TestDomainConfigPreviewUsesAgentCertStorePaths(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)
	domainID, fqdn := seedDomainTopology(t, srv, cookie)

	w := doRequest(t, handler, "GET", "/api/v1/domains/"+strconv.FormatInt(domainID, 10)+"/config", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("get config: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Manual  bool   `json:"manual"`
		Backend string `json:"backend"`
		Applied bool   `json:"applied"`
		Config  string `json:"config"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Manual {
		t.Error("expected manual=false for generated preview")
	}
	if resp.Applied {
		t.Error("expected applied=false when no artifact exists")
	}
	if resp.Backend != "nginx" {
		t.Fatalf("expected backend nginx, got %q", resp.Backend)
	}
	wantCert := "/var/lib/nurproxy-agent/certs/" + fqdn + ".crt"
	wantKey := "/var/lib/nurproxy-agent/certs/" + fqdn + ".key.plain"
	if !strings.Contains(resp.Config, wantCert) {
		t.Errorf("preview missing cert path %s:\n%s", wantCert, resp.Config)
	}
	if !strings.Contains(resp.Config, wantKey) {
		t.Errorf("preview missing key path %s:\n%s", wantKey, resp.Config)
	}
	if strings.Contains(resp.Config, "/var/lib/nurproxy/certs/") {
		t.Errorf("preview still renders the orchestrator cert dir:\n%s", resp.Config)
	}
}

// Once the agent has round-tripped its applied config into the artifact store,
// the config editor must serve those bytes — the real on-disk vhost with the
// agent's actual cert paths — instead of re-rendering a guessed preview.
func TestDomainConfigPrefersAppliedArtifact(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)
	domainID, fqdn := seedDomainTopology(t, srv, cookie)

	applied := "# applied by agent\nserver {\n  server_name " + fqdn + ";\n  ssl_certificate /custom/certs/" + fqdn + ".crt;\n}\n"
	art := &models.ConfigArtifact{
		ID:      "dom-" + strconv.FormatInt(domainID, 10),
		AgentID: "agent-1",
		Backend: "nginx",
		Target:  models.Target{Kind: models.TargetKindFile, Path: "/etc/nginx/sites-available/" + fqdn + ".conf"},
		Source:  models.ArtifactSourceGenerated,
		DomainID: func() *int64 {
			id := domainID
			return &id
		}(),
		Content: applied,
	}
	if err := database.CreateConfigArtifact(art, "test", "applied via apply-ACK"); err != nil {
		t.Fatal(err)
	}

	w := doRequest(t, handler, "GET", "/api/v1/domains/"+strconv.FormatInt(domainID, 10)+"/config", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("get config: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Manual  bool   `json:"manual"`
		Backend string `json:"backend"`
		Applied bool   `json:"applied"`
		Config  string `json:"config"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Manual {
		t.Error("expected manual=false")
	}
	if !resp.Applied {
		t.Error("expected applied=true when an artifact exists")
	}
	if resp.Backend != "nginx" {
		t.Errorf("expected backend nginx, got %q", resp.Backend)
	}
	if resp.Config != applied {
		t.Errorf("expected the applied artifact content verbatim, got:\n%s", resp.Config)
	}

	// A manual override still wins over the artifact.
	w = doRequest(t, handler, "PUT", "/api/v1/domains/"+strconv.FormatInt(domainID, 10)+"/config",
		map[string]interface{}{"config": "# manual override"}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("set manual config: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	w = doRequest(t, handler, "GET", "/api/v1/domains/"+strconv.FormatInt(domainID, 10)+"/config", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("get manual config: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var manualResp struct {
		Manual bool   `json:"manual"`
		Config string `json:"config"`
	}
	if err := json.NewDecoder(w.Body).Decode(&manualResp); err != nil {
		t.Fatal(err)
	}
	if !manualResp.Manual {
		t.Error("expected manual=true after manual override")
	}
	if manualResp.Config != "# manual override" {
		t.Errorf("expected the manual content, got %q", manualResp.Config)
	}
}

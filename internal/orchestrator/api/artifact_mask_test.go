package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// seedNginxArtifact inserts an agent + a manual nginx file artifact for the
// mask / edit / reset tests.
func seedNginxArtifact(t *testing.T, srv *Server, agentID, artifactID, content string) *models.ConfigArtifact {
	t.Helper()
	if _, err := srv.db.GetAgent(agentID); err != nil {
		a := &models.Agent{ID: agentID, Name: agentID, FQDN: agentID + ".example.com", Status: models.AgentStatusAdopted}
		if cErr := srv.db.CreateAgent(a); cErr != nil {
			t.Fatalf("CreateAgent: %v", cErr)
		}
	}
	art := &models.ConfigArtifact{
		ID:      artifactID,
		AgentID: agentID,
		Backend: "nginx",
		Target:  models.Target{Kind: models.TargetKindFile, Path: "/etc/nginx/sites-available/" + artifactID + ".conf"},
		Source:  models.ArtifactSourceManual,
		Content: content,
	}
	if err := srv.db.CreateConfigArtifact(art, "tester", "seed"); err != nil {
		t.Fatalf("CreateConfigArtifact: %v", err)
	}
	return art
}

// TestArtifactMask_cleanNginx_returnsStructuredRoute parses a clean nginx vhost
// into the structured mask and asserts OK + recovered fields.
func TestArtifactMask_cleanNginx_returnsStructuredRoute(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)
	content := `server {
    listen 80;
    server_name app.example.com;
    location / {
        proxy_pass http://10.0.0.4:8080;
        proxy_set_header Host $host;
    }
}`
	seedNginxArtifact(t, srv, "agent-1", "art-1", content)

	w := doRequest(t, h, "GET", "/api/v1/artifacts/art-1/mask", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("mask: %d %s", w.Code, w.Body.String())
	}
	var resp maskResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK {
		t.Fatalf("expected OK mask; notes=%v unparsed=%v", resp.Notes, resp.Unparsed)
	}
	if resp.Route.Host != "app.example.com" || resp.Route.Upstream.Port != 8080 {
		t.Errorf("recovered route = %+v", resp.Route)
	}
}

// TestArtifactMask_unparseableNginx_preservesRawNotOK asserts the mask never
// destroys text: an unknown directive comes back in Unparsed with OK=false.
func TestArtifactMask_unparseableNginx_preservesRawNotOK(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)
	content := `server {
    listen 80;
    server_name x.example.com;
    gzip on;
    location / { proxy_pass http://10.0.0.1:80; }
}`
	seedNginxArtifact(t, srv, "agent-1", "art-2", content)

	w := doRequest(t, h, "GET", "/api/v1/artifacts/art-2/mask", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("mask: %d", w.Code)
	}
	var resp maskResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.OK {
		t.Error("expected OK=false for unparseable content")
	}
	found := false
	for _, u := range resp.Unparsed {
		if u == "gzip on" {
			found = true
		}
	}
	if !found {
		t.Errorf("unparseable text not preserved: %v", resp.Unparsed)
	}
}

// TestArtifactMask_caddyBackend_rawOnly asserts the caddy backend returns a
// raw-only mask (no structured caddy parser yet) without erroring.
func TestArtifactMask_caddyBackend_rawOnly(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)
	seedArtifact(t, srv, "agent-1", "dom-1", `{"handle":[]}`)

	w := doRequest(t, h, "GET", "/api/v1/artifacts/dom-1/mask", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("mask: %d", w.Code)
	}
	var resp maskResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.OK {
		t.Error("expected caddy mask to be raw-only (OK=false)")
	}
	if resp.Backend != "caddy" {
		t.Errorf("backend = %q", resp.Backend)
	}
}

// TestEditArtifactContent_generatedFlipsToManual asserts a raw edit of a
// generated artifact flips its source to manual and records a new version.
func TestEditArtifactContent_generatedFlipsToManual(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)
	seedArtifact(t, srv, "agent-1", "dom-1", `{"handle":[]}`)

	w := doRequest(t, h, "PUT", "/api/v1/artifacts/dom-1/content",
		map[string]string{"content": `{"handle":["edited"]}`}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("edit: %d %s", w.Code, w.Body.String())
	}

	art, err := srv.db.GetConfigArtifact("dom-1")
	if err != nil {
		t.Fatal(err)
	}
	if art.Source != models.ArtifactSourceManual {
		t.Errorf("source = %q, want manual after raw edit", art.Source)
	}
	if art.Content != `{"handle":["edited"]}` {
		t.Errorf("content not updated: %q", art.Content)
	}
}

// TestResetArtifactToModel_requiresDomain asserts reset-to-model refuses an
// artifact with no backing domain.
func TestResetArtifactToModel_requiresDomain(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	cookie := setupAdmin(t, h)
	seedNginxArtifact(t, srv, "agent-1", "art-1", "server {}")

	w := doRequest(t, h, "POST", "/api/v1/artifacts/art-1/reset-to-model", nil, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-model-backed artifact, got %d", w.Code)
	}
}

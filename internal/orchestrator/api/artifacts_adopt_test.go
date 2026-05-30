package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

func TestAgentAdoptArtifacts_createsThenUpserts(t *testing.T) {
	srv, database := testServer(t)
	token := makeAgent(t, database, "agent-1", "durox.example.com", models.AgentStatusAdopted, nil)

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	post := func(t *testing.T, report proxymodel.AdoptedArtifactReport) map[string]int {
		t.Helper()
		body, _ := json.Marshal(report)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/agents/agent-1/artifacts/adopt", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var out map[string]int
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	id := proxymodel.AdoptedArtifactID("nginx", "/etc/nginx/sites-available/default")
	report := proxymodel.AdoptedArtifactReport{
		Host: "durox.example.com",
		Artifacts: []proxymodel.AdoptedArtifact{{
			ArtifactID: id,
			Backend:    "nginx",
			TargetKind: "file",
			TargetPath: "/etc/nginx/sites-available/default",
			Content:    "server { listen 80; }",
			Checksum:   "abc",
			Enabled:    true,
			Adopted:    true,
		}},
	}

	// First report creates version 1.
	if out := post(t, report); out["created"] != 1 {
		t.Fatalf("first report: created = %d, want 1 (%+v)", out["created"], out)
	}
	art, err := database.GetConfigArtifact(id)
	if err != nil {
		t.Fatalf("GetConfigArtifact: %v", err)
	}
	if art.Source != models.ArtifactSourceManual {
		t.Errorf("adopted file should be Source manual, got %q", art.Source)
	}
	if art.Content != "server { listen 80; }" || art.Backend != "nginx" {
		t.Errorf("stored content/backend wrong: %+v", art)
	}
	if art.LiveVersion != 1 {
		t.Errorf("live version = %d, want 1", art.LiveVersion)
	}

	// Re-reporting identical content is a no-op (no phantom version).
	if out := post(t, report); out["created"] != 0 || out["updated"] != 0 {
		t.Fatalf("identical re-report should be a no-op, got %+v", out)
	}
	art, _ = database.GetConfigArtifact(id)
	if art.LiveVersion != 1 {
		t.Errorf("no-op re-report bumped version to %d", art.LiveVersion)
	}

	// A semantic change appends version 2.
	report.Artifacts[0].Content = "server { listen 8080; }"
	if out := post(t, report); out["updated"] != 1 {
		t.Fatalf("changed report: updated = %d, want 1 (%+v)", out["updated"], out)
	}
	art, _ = database.GetConfigArtifact(id)
	if art.LiveVersion != 2 {
		t.Errorf("changed re-report: live version = %d, want 2", art.LiveVersion)
	}
}

func TestAgentAdoptArtifacts_rejectsOtherAgent(t *testing.T) {
	srv, database := testServer(t)
	token := makeAgent(t, database, "agent-1", "a.example.com", models.AgentStatusAdopted, nil)
	makeAgent(t, database, "agent-2", "b.example.com", models.AgentStatusAdopted, nil)

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	body, _ := json.Marshal(proxymodel.AdoptedArtifactReport{Host: "b.example.com"})
	// agent-1's token reporting for agent-2 must be forbidden.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/agents/agent-2/artifacts/adopt", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-agent report status = %d, want 403", resp.StatusCode)
	}
}

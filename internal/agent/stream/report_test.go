package stream

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

func TestReportAdopted(t *testing.T) {
	var gotPath, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &Client{orchestratorURL: srv.URL, agentID: "agent-1", token: "tok", http: srv.Client()}

	// An empty set is a no-op: no request is sent.
	if err := c.ReportAdopted(context.Background(), "durox.example.com", "nginx", nil); err != nil {
		t.Fatalf("empty ReportAdopted should be a no-op, got %v", err)
	}
	if gotPath != "" {
		t.Fatalf("empty set should send nothing, but hit %q", gotPath)
	}

	arts := []proxy.Artifact{
		{
			Target:  proxy.Target{Kind: proxy.TargetKindFile, Path: "/etc/nginx/sites-available/default"},
			Content: "server {}",
			Enabled: true,
			Adopted: true,
		},
	}
	if err := c.ReportAdopted(context.Background(), "durox.example.com", "nginx", arts); err != nil {
		t.Fatalf("ReportAdopted: %v", err)
	}

	if gotPath != "/api/v1/agents/agent-1/artifacts/adopt" {
		t.Errorf("path = %q, want /api/v1/agents/agent-1/artifacts/adopt", gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("auth = %q, want Bearer tok", gotAuth)
	}

	var body proxymodel.AdoptedArtifactReport
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
		t.Fatalf("body is not the expected JSON: %v\n%s", err, gotBody)
	}
	if body.Host != "durox.example.com" {
		t.Errorf("host = %q, want durox.example.com", body.Host)
	}
	if len(body.Artifacts) != 1 {
		t.Fatalf("want 1 artifact, got %d", len(body.Artifacts))
	}
	a := body.Artifacts[0]
	if a.TargetPath != "/etc/nginx/sites-available/default" || a.TargetKind != "file" {
		t.Errorf("path/kind mapped wrong: %+v", a)
	}
	if a.Content != "server {}" || !a.Adopted || !a.Enabled {
		t.Errorf("content/adopted/enabled mismatch: %+v", a)
	}
	if a.Backend != "nginx" {
		t.Errorf("backend = %q, want nginx", a.Backend)
	}
	// ID must be stable + derived from agent+backend+path (no slashes/dots left raw).
	want := proxymodel.AdoptedArtifactID("agent-1", "nginx", "/etc/nginx/sites-available/default")
	if a.ArtifactID != want {
		t.Errorf("artifact id = %q, want %q", a.ArtifactID, want)
	}
	if a.Checksum == "" {
		t.Error("checksum should be computed by the agent")
	}
}

func TestReportAdopted_serverError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := &Client{orchestratorURL: srv.URL, agentID: "a", token: "t", http: srv.Client()}
	err := c.ReportAdopted(context.Background(), "h", "nginx", []proxy.Artifact{
		{Target: proxy.Target{Kind: proxy.TargetKindFile, Path: "/x"}, Content: "y"},
	})
	if err == nil {
		t.Fatal("a 500 response should surface an error the caller can log")
	}
}

func TestAdoptedArtifactID_stableAndTokenized(t *testing.T) {
	a := proxymodel.AdoptedArtifactID("agent-1", "nginx", "/etc/nginx/sites-available/default")
	b := proxymodel.AdoptedArtifactID("agent-1", "nginx", "/etc/nginx/sites-available/default")
	if a != b {
		t.Fatalf("AdoptedArtifactID not deterministic: %q vs %q", a, b)
	}
	for _, c := range []byte(a) {
		if c == '/' || c == ' ' {
			t.Fatalf("id should not contain raw path separators: %q", a)
		}
	}
	if a[:6] != "adopt-" {
		t.Errorf("id should carry the adopt- prefix: %q", a)
	}
}

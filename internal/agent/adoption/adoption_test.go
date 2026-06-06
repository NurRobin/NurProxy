package adoption

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// New must generate a token + agent id on first run and then REUSE the persisted
// values on subsequent runs (so an agent keeps its identity across restarts).
func TestManager_New_generatesAndPersistsIdentity(t *testing.T) {
	dir := t.TempDir()

	m1, err := New("http://orch:8080", "edge1.example.com", dir, 8780)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if m1.Token() == "" || m1.AgentID() == "" {
		t.Fatal("expected a generated token and agent id")
	}

	// Both must be persisted to disk...
	for _, name := range []string{"token", "agent-id"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("expected %s to be written: %v", name, err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("%s mode = %v, want 0600 (identity is sensitive)", name, info.Mode().Perm())
		}
	}

	// ...and reused by a second Manager over the same data dir.
	m2, err := New("http://orch:8080", "edge1.example.com", dir, 8780)
	if err != nil {
		t.Fatalf("New (reload): %v", err)
	}
	if m2.Token() != m1.Token() {
		t.Error("token not persisted: second New generated a different token")
	}
	if m2.AgentID() != m1.AgentID() {
		t.Error("agent id not persisted: second New generated a different id")
	}
}

// checkStatus is the core of WaitForAdoption: it reads the agent's status from
// the orchestrator and returns it, erroring on a non-200.
func TestManager_checkStatus(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte(`{"status":"adopted"}`))
	}))
	defer server.Close()

	m, err := New(server.URL, "edge1.example.com", t.TempDir(), 8780)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	status, err := m.checkStatus(context.Background(), server.URL+"/api/v1/agents/x/status")
	if err != nil {
		t.Fatalf("checkStatus: %v", err)
	}
	if status != "adopted" {
		t.Errorf("status = %q, want adopted", status)
	}
	if gotAuth != "Bearer "+m.Token() {
		t.Errorf("checkStatus must authenticate with the agent token, got %q", gotAuth)
	}
}

func TestManager_checkStatus_non200_errors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	m, err := New(server.URL, "edge1.example.com", t.TempDir(), 8780)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := m.checkStatus(context.Background(), server.URL+"/x"); err == nil {
		t.Fatal("expected an error on a non-200 status response")
	}
}

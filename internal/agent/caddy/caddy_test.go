package caddy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMockClientEnsureServer(t *testing.T) {
	c := NewMockClient()
	ctx := context.Background()

	if err := c.EnsureServer(ctx); err != nil {
		t.Fatalf("EnsureServer failed: %v", err)
	}

	// Calling again should be idempotent.
	if err := c.EnsureServer(ctx); err != nil {
		t.Fatalf("EnsureServer (second call) failed: %v", err)
	}
}

func TestMockClientAddAndListRoutes(t *testing.T) {
	c := NewMockClient()
	ctx := context.Background()

	route := json.RawMessage(`{"@id":"domain-test-example-com","match":[{"host":["test.example.com"]}]}`)

	if err := c.AddRoute(ctx, route); err != nil {
		t.Fatalf("AddRoute failed: %v", err)
	}

	routes, err := c.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("ListRoutes failed: %v", err)
	}

	if len(routes) != 1 {
		t.Errorf("route count = %d, want 1", len(routes))
	}
}

func TestMockClientRemoveRoute(t *testing.T) {
	c := NewMockClient()
	ctx := context.Background()

	route := json.RawMessage(`{"@id":"domain-test-example-com","match":[{"host":["test.example.com"]}]}`)

	if err := c.AddRoute(ctx, route); err != nil {
		t.Fatalf("AddRoute failed: %v", err)
	}

	if err := c.RemoveRoute(ctx, "domain-test-example-com"); err != nil {
		t.Fatalf("RemoveRoute failed: %v", err)
	}

	routes, err := c.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("ListRoutes failed: %v", err)
	}

	if len(routes) != 0 {
		t.Errorf("route count = %d, want 0 after removal", len(routes))
	}
}

func TestMockClientGetConfig(t *testing.T) {
	c := NewMockClient()
	ctx := context.Background()

	config, err := c.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}

	if len(config) == 0 {
		t.Error("config should not be empty")
	}
}

func TestMockClientClearRoutes(t *testing.T) {
	c := NewMockClient()
	ctx := context.Background()

	route1 := json.RawMessage(`{"@id":"domain-a-com"}`)
	route2 := json.RawMessage(`{"@id":"domain-b-com"}`)
	if err := c.AddRoute(ctx, route1); err != nil {
		t.Fatalf("AddRoute route1 failed: %v", err)
	}
	if err := c.AddRoute(ctx, route2); err != nil {
		t.Fatalf("AddRoute route2 failed: %v", err)
	}

	if err := c.ClearRoutes(ctx); err != nil {
		t.Fatalf("ClearRoutes failed: %v", err)
	}

	routes, err := c.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("ListRoutes failed: %v", err)
	}
	if len(routes) != 0 {
		t.Errorf("route count = %d, want 0 after clear", len(routes))
	}
}

func TestClientEnsureServer(t *testing.T) {
	// Mock Caddy Admin API server.
	serverCreated := false
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/apps/http/servers/srv0":
			if serverCreated {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"listen":[":443",":80"]}`))
			} else {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error":"not found"}`))
			}
		case r.Method == http.MethodPost && r.URL.Path == "/config/apps/http/servers/srv0":
			serverCreated = true
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mock.Close()

	c := &Client{
		baseURL: mock.URL,
		http:    mock.Client(),
	}

	ctx := context.Background()
	if err := c.EnsureServer(ctx); err != nil {
		t.Fatalf("EnsureServer failed: %v", err)
	}

	if !serverCreated {
		t.Error("server should have been created")
	}

	// Second call should succeed without creating again.
	if err := c.EnsureServer(ctx); err != nil {
		t.Fatalf("EnsureServer (second call) failed: %v", err)
	}
}

func TestClientAddRoute(t *testing.T) {
	var received []byte
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/config/apps/http/servers/srv0/routes" {
			buf := make([]byte, 4096)
			n, _ := r.Body.Read(buf)
			received = buf[:n]
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mock.Close()

	c := &Client{
		baseURL: mock.URL,
		http:    mock.Client(),
	}

	route := json.RawMessage(`{"@id":"test-route"}`)
	ctx := context.Background()
	if err := c.AddRoute(ctx, route); err != nil {
		t.Fatalf("AddRoute failed: %v", err)
	}

	if string(received) != `{"@id":"test-route"}` {
		t.Errorf("received = %q, want %q", string(received), `{"@id":"test-route"}`)
	}
}

func TestClientRemoveRoute(t *testing.T) {
	deletedID := ""
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && len(r.URL.Path) > 4 && r.URL.Path[:4] == "/id/" {
			deletedID = r.URL.Path[4:]
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mock.Close()

	c := &Client{
		baseURL: mock.URL,
		http:    mock.Client(),
	}

	ctx := context.Background()
	if err := c.RemoveRoute(ctx, "my-route-id"); err != nil {
		t.Fatalf("RemoveRoute failed: %v", err)
	}

	if deletedID != "my-route-id" {
		t.Errorf("deletedID = %q, want %q", deletedID, "my-route-id")
	}
}

func TestClientListRoutes(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/config/apps/http/servers/srv0/routes" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[{"@id":"route1"},{"@id":"route2"}]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mock.Close()

	c := &Client{
		baseURL: mock.URL,
		http:    mock.Client(),
	}

	ctx := context.Background()
	routes, err := c.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("ListRoutes failed: %v", err)
	}

	if len(routes) != 2 {
		t.Errorf("route count = %d, want 2", len(routes))
	}
}

func TestClientGetConfig(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/config/" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"admin":{"listen":"localhost:2019"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mock.Close()

	c := &Client{
		baseURL: mock.URL,
		http:    mock.Client(),
	}

	ctx := context.Background()
	config, err := c.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(config, &parsed); err != nil {
		t.Fatalf("parsing config: %v", err)
	}

	if parsed["admin"] == nil {
		t.Error("expected admin key in config")
	}
}

func TestClientErrorResponse(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer mock.Close()

	c := &Client{
		baseURL: mock.URL,
		http:    mock.Client(),
	}

	ctx := context.Background()
	_, err := c.GetConfig(ctx)
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
}

func TestNewProcess(t *testing.T) {
	p := NewProcess(2019)
	if p == nil {
		t.Fatal("NewProcess returned nil")
	}
	if p.adminPort != 2019 {
		t.Errorf("adminPort = %d, want 2019", p.adminPort)
	}
	if p.Running() {
		t.Error("new process should not be running")
	}
}

func TestProcessMockMode(t *testing.T) {
	p := NewProcess(2019)
	ctx := context.Background()

	// In test env, caddy binary likely not available, so it should go mock.
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !p.Running() {
		t.Error("process should be running after Start")
	}

	if err := p.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	if p.Running() {
		t.Error("process should not be running after Stop")
	}
}

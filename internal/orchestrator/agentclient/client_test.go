package agentclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealth_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("expected /health, got %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected Bearer test-token, got %s", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewWithHTTPClient(srv.Client())
	if err := c.Health(context.Background(), srv.URL, "test-token"); err != nil {
		t.Fatalf("Health: %v", err)
	}
}

func TestHealth_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewWithHTTPClient(srv.Client())
	if err := c.Health(context.Background(), srv.URL, "token"); err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestPushRoute(t *testing.T) {
	var payload struct {
		Domain string          `json:"domain"`
		Route  json.RawMessage `json:"route"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Single-route add maps to the agent's POST /routes handler.
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/routes" {
			t.Errorf("expected /routes, got %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewWithHTTPClient(srv.Client())
	route := json.RawMessage(`{"match":[{"host":["app.example.com"]}],"handle":[]}`)
	if err := c.PushRoute(context.Background(), srv.URL, "token", route); err != nil {
		t.Fatalf("PushRoute: %v", err)
	}

	// The client must send {domain, route} with the domain extracted from the host.
	if payload.Domain != "app.example.com" {
		t.Errorf("expected domain app.example.com, got %q", payload.Domain)
	}
	if len(payload.Route) == 0 {
		t.Fatal("expected route to be sent")
	}
}

func TestPushRoute_NoHost(t *testing.T) {
	c := New()
	// A route without a host match cannot be keyed by domain.
	err := c.PushRoute(context.Background(), "http://example", "token", json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("expected error for route without host")
	}
}

func TestDeleteRoute(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		if r.URL.Path != "/routes/example.com" {
			t.Errorf("expected /routes/example.com, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewWithHTTPClient(srv.Client())
	if err := c.DeleteRoute(context.Background(), srv.URL, "token", "example.com"); err != nil {
		t.Fatalf("DeleteRoute: %v", err)
	}
}

func TestSyncRoutes(t *testing.T) {
	var received map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Full sync maps to the agent's PUT /routes (domain -> route map).
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		if r.URL.Path != "/routes" {
			t.Errorf("expected /routes, got %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewWithHTTPClient(srv.Client())
	routes := []json.RawMessage{
		json.RawMessage(`{"match":[{"host":["a.example.com"]}]}`),
		json.RawMessage(`{"match":[{"host":["b.example.com"]}]}`),
	}
	if err := c.SyncRoutes(context.Background(), srv.URL, "token", routes); err != nil {
		t.Fatalf("SyncRoutes: %v", err)
	}

	if len(received) != 2 || received["a.example.com"] == nil || received["b.example.com"] == nil {
		t.Fatalf("expected routes keyed by domain, got %v", received)
	}
}

func TestGetRoutes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/routes" {
			t.Errorf("expected /routes, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		// The agent returns a map of domain -> route.
		w.Write([]byte(`{"a.example.com":{"test":"route1"},"b.example.com":{"test":"route2"}}`))
	}))
	defer srv.Close()

	c := NewWithHTTPClient(srv.Client())
	routes, err := c.GetRoutes(context.Background(), srv.URL, "token")
	if err != nil {
		t.Fatalf("GetRoutes: %v", err)
	}

	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(routes))
	}
}

func TestPushRoute_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	c := NewWithHTTPClient(srv.Client())
	err := c.PushRoute(context.Background(), srv.URL, "token", json.RawMessage(`{"match":[{"host":["x.example.com"]}]}`))
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestTrailingSlash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("expected /health, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewWithHTTPClient(srv.Client())
	// URL with trailing slash
	if err := c.Health(context.Background(), srv.URL+"/", "token"); err != nil {
		t.Fatalf("Health with trailing slash: %v", err)
	}
}

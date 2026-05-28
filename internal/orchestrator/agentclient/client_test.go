package agentclient

import (
	"context"
	"encoding/json"
	"io"
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
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		if r.URL.Path != "/routes" {
			t.Errorf("expected /routes, got %s", r.URL.Path)
		}
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewWithHTTPClient(srv.Client())
	route := json.RawMessage(`{"test":"route"}`)
	if err := c.PushRoute(context.Background(), srv.URL, "token", route); err != nil {
		t.Fatalf("PushRoute: %v", err)
	}

	if len(receivedBody) == 0 {
		t.Fatal("expected body to be sent")
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
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/routes/sync" {
			t.Errorf("expected /routes/sync, got %s", r.URL.Path)
		}
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewWithHTTPClient(srv.Client())
	routes := []json.RawMessage{
		json.RawMessage(`{"test":"route1"}`),
		json.RawMessage(`{"test":"route2"}`),
	}
	if err := c.SyncRoutes(context.Background(), srv.URL, "token", routes); err != nil {
		t.Fatalf("SyncRoutes: %v", err)
	}

	if len(receivedBody) == 0 {
		t.Fatal("expected body to be sent")
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
		w.Write([]byte(`[{"test":"route1"},{"test":"route2"}]`))
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
	err := c.PushRoute(context.Background(), srv.URL, "token", json.RawMessage(`{}`))
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

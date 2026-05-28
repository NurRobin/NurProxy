package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/caddy"
)

const testToken = "np_ag_testtoken1234567890"

func newTestServer() *Server {
	client := caddy.NewMockClient()
	return New(0, client, testToken)
}

func TestHandleHealth(t *testing.T) {
	s := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	s.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %q, want %q", body["status"], "ok")
	}
	if body["version"] == "" {
		t.Error("version should not be empty")
	}
}

func TestHandleHealthMethodNotAllowed(t *testing.T) {
	s := newTestServer()

	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	w := httptest.NewRecorder()

	s.handleHealth(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestAuthMiddlewareValidToken(t *testing.T) {
	s := newTestServer()

	called := false
	handler := s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()

	handler(w, req)

	if !called {
		t.Error("handler was not called with valid token")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestAuthMiddlewareMissingToken(t *testing.T) {
	s := newTestServer()

	called := false
	handler := s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if called {
		t.Error("handler should not be called without token")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestAuthMiddlewareInvalidToken(t *testing.T) {
	s := newTestServer()

	called := false
	handler := s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()

	handler(w, req)

	if called {
		t.Error("handler should not be called with invalid token")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestAuthMiddlewareBadFormat(t *testing.T) {
	s := newTestServer()

	called := false
	handler := s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()

	handler(w, req)

	if called {
		t.Error("handler should not be called with bad auth format")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestHandleListRoutesEmpty(t *testing.T) {
	s := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/routes", nil)
	w := httptest.NewRecorder()

	s.handleListRoutes(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]json.RawMessage
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("expected empty routes, got %d", len(body))
	}
}

func TestHandleAddRoute(t *testing.T) {
	s := newTestServer()

	route := json.RawMessage(`{"@id":"domain-test-example-com","match":[{"host":["test.example.com"]}]}`)
	payload := routePayload{
		Domain: "test.example.com",
		Route:  route,
	}
	data, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/routes", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleAddRoute(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	// Verify route was stored.
	s.mu.RLock()
	_, exists := s.routes["test.example.com"]
	s.mu.RUnlock()
	if !exists {
		t.Error("route was not stored")
	}
}

func TestHandleAddRouteMissingDomain(t *testing.T) {
	s := newTestServer()

	payload := routePayload{
		Domain: "",
		Route:  json.RawMessage(`{}`),
	}
	data, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/routes", bytes.NewReader(data))
	w := httptest.NewRecorder()

	s.handleAddRoute(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleAddRouteMissingRoute(t *testing.T) {
	s := newTestServer()

	payload := `{"domain":"test.example.com"}`

	req := httptest.NewRequest(http.MethodPost, "/routes", bytes.NewReader([]byte(payload)))
	w := httptest.NewRecorder()

	s.handleAddRoute(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleSyncRoutes(t *testing.T) {
	s := newTestServer()

	// Pre-populate a route.
	s.mu.Lock()
	s.routes["old.example.com"] = json.RawMessage(`{"@id":"domain-old-example-com"}`)
	s.mu.Unlock()

	newRoutes := map[string]json.RawMessage{
		"new1.example.com": json.RawMessage(`{"@id":"domain-new1-example-com"}`),
		"new2.example.com": json.RawMessage(`{"@id":"domain-new2-example-com"}`),
	}
	data, _ := json.Marshal(newRoutes)

	req := httptest.NewRequest(http.MethodPut, "/routes", bytes.NewReader(data))
	w := httptest.NewRecorder()

	s.handleSyncRoutes(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	s.mu.RLock()
	if len(s.routes) != 2 {
		t.Errorf("routes count = %d, want 2", len(s.routes))
	}
	if _, exists := s.routes["old.example.com"]; exists {
		t.Error("old route should have been removed")
	}
	s.mu.RUnlock()
}

func TestHandleDeleteRoute(t *testing.T) {
	s := newTestServer()

	// Add a route first.
	s.mu.Lock()
	s.routes["test.example.com"] = json.RawMessage(`{"@id":"domain-test-example-com"}`)
	s.mu.Unlock()

	req := httptest.NewRequest(http.MethodDelete, "/routes/test.example.com", nil)
	w := httptest.NewRecorder()

	s.handleDeleteRoute(w, req, "test.example.com")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	s.mu.RLock()
	if _, exists := s.routes["test.example.com"]; exists {
		t.Error("route should have been deleted")
	}
	s.mu.RUnlock()
}

func TestHandleDeleteRouteNotFound(t *testing.T) {
	s := newTestServer()

	req := httptest.NewRequest(http.MethodDelete, "/routes/nonexistent.example.com", nil)
	w := httptest.NewRecorder()

	s.handleDeleteRoute(w, req, "nonexistent.example.com")

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestHandleCaddyConfig(t *testing.T) {
	s := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/caddy/config", nil)
	w := httptest.NewRecorder()

	s.handleCaddyConfig(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
}

func TestHandleRoutesDispatch(t *testing.T) {
	s := newTestServer()

	// GET /routes should dispatch to list.
	req := httptest.NewRequest(http.MethodGet, "/routes", nil)
	w := httptest.NewRecorder()
	s.handleRoutes(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET /routes status = %d, want %d", w.Code, http.StatusOK)
	}

	// PATCH /routes should be method not allowed.
	req = httptest.NewRequest(http.MethodPatch, "/routes", nil)
	w = httptest.NewRecorder()
	s.handleRoutes(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("PATCH /routes status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestSlugify(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"test.example.com", "test-example-com"},
		{"MY.APP.io", "my-app-io"},
		{"a--b", "a-b"},
		{"-leading-", "leading"},
	}

	for _, tt := range tests {
		got := slugify(tt.input)
		if got != tt.want {
			t.Errorf("slugify(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestHandleSyncRoutesInvalidJSON(t *testing.T) {
	s := newTestServer()

	req := httptest.NewRequest(http.MethodPut, "/routes", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()

	s.handleSyncRoutes(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleAddRouteInvalidJSON(t *testing.T) {
	s := newTestServer()

	req := httptest.NewRequest(http.MethodPost, "/routes", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()

	s.handleAddRoute(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleRoutesDeleteDispatch(t *testing.T) {
	s := newTestServer()

	// Add a route first.
	s.mu.Lock()
	s.routes["test.example.com"] = json.RawMessage(`{"@id":"domain-test-example-com"}`)
	s.mu.Unlock()

	// DELETE /routes/test.example.com should dispatch to delete.
	req := httptest.NewRequest(http.MethodDelete, "/routes/test.example.com", nil)
	w := httptest.NewRecorder()
	s.handleRoutes(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("DELETE /routes/test.example.com status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandleRoutesSubpathMethodNotAllowed(t *testing.T) {
	s := newTestServer()

	// POST /routes/test.example.com should be method not allowed.
	req := httptest.NewRequest(http.MethodPost, "/routes/test.example.com", nil)
	w := httptest.NewRecorder()
	s.handleRoutes(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /routes/test.example.com status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

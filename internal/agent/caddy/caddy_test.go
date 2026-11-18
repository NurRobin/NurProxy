package caddy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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
	// Mock Caddy Admin API server. It emulates the real admin API's path
	// semantics: GET 404s on a missing path, and the admin API does NOT create
	// intermediate parents — so a fresh instance (only admin configured) has no
	// apps/http/servers, and EnsureServer must build the structure top-down.
	var appsExists, httpExists, srv0Exists, srv0HasRoutes bool
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exists := func(b bool) {
			if b {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{}`))
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/apps/http/servers/srv0":
			if !srv0Exists {
				w.WriteHeader(http.StatusNotFound)
			} else if srv0HasRoutes {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"listen":[":443",":80"],"routes":[]}`))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"listen":[":443",":80"]}`))
			}
		case r.Method == http.MethodGet && r.URL.Path == "/config/apps/http":
			exists(httpExists)
		case r.Method == http.MethodGet && r.URL.Path == "/config/apps":
			exists(appsExists)
		// PUT creates the value at a path whose immediate parent already exists.
		case r.Method == http.MethodPut && r.URL.Path == "/config/apps":
			appsExists, httpExists, srv0Exists, srv0HasRoutes = true, true, true, true
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPut && r.URL.Path == "/config/apps/http":
			if !appsExists {
				w.WriteHeader(http.StatusInternalServerError) // no parent
				return
			}
			httpExists, srv0Exists, srv0HasRoutes = true, true, true
			w.WriteHeader(http.StatusOK)
		case (r.Method == http.MethodPut || r.Method == http.MethodPost) && r.URL.Path == "/config/apps/http/servers/srv0":
			if !httpExists {
				w.WriteHeader(http.StatusInternalServerError) // no parent
				return
			}
			srv0Exists, srv0HasRoutes = true, true
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPut && r.URL.Path == "/config/apps/http/servers/srv0/routes":
			if !srv0Exists {
				w.WriteHeader(http.StatusInternalServerError) // no parent
				return
			}
			srv0HasRoutes = true
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

	if !srv0Exists {
		t.Error("server should have been created")
	}
	if !srv0HasRoutes {
		t.Error("created server must have a routes array")
	}

	// Second call should succeed without creating again.
	if err := c.EnsureServer(ctx); err != nil {
		t.Fatalf("EnsureServer (second call) failed: %v", err)
	}
}

func TestClientEnsureServer_listen(t *testing.T) {
	tests := []struct {
		name            string
		host            string
		httpPort        int
		httpsPort       int
		wantListen      []string
		wantHTTPPort    any
		wantHTTPSPortIn bool
	}{
		{name: "defaults", wantListen: []string{":443", ":80"}},
		{name: "explicit defaults", httpPort: 80, httpsPort: 443, wantListen: []string{":443", ":80"}},
		{name: "unprivileged loopback", host: "127.0.0.1", httpPort: 18080, httpsPort: 18443,
			wantListen: []string{"127.0.0.1:18443", "127.0.0.1:18080"}, wantHTTPPort: float64(18080), wantHTTPSPortIn: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var created map[string]any
			mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPut && r.URL.Path == "/config/apps" {
					var body struct {
						HTTP map[string]any `json:"http"`
					}
					_ = json.NewDecoder(r.Body).Decode(&body)
					created = body.HTTP
					w.WriteHeader(http.StatusOK)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer mock.Close()

			c := (&Client{baseURL: mock.URL, http: mock.Client()}).WithListen(tt.host, tt.httpPort, tt.httpsPort)
			if err := c.EnsureServer(context.Background()); err != nil {
				t.Fatalf("EnsureServer: %v", err)
			}
			srv0 := created["servers"].(map[string]any)["srv0"].(map[string]any)
			got, _ := json.Marshal(srv0["listen"])
			want, _ := json.Marshal(tt.wantListen)
			if string(got) != string(want) {
				t.Errorf("listen = %s, want %s", got, want)
			}
			if created["http_port"] != tt.wantHTTPPort {
				t.Errorf("http_port = %v, want %v", created["http_port"], tt.wantHTTPPort)
			}
			if _, ok := created["https_port"]; ok != tt.wantHTTPSPortIn {
				t.Errorf("https_port present = %v, want %v", ok, tt.wantHTTPSPortIn)
			}
		})
	}
}

// The admin API's PUT answers 409 when a key already exists, so a second TLS
// apply on a running Caddy must replace the values (PATCH) instead of failing.
// Otherwise every push after the first fails and new hosts' certs never load.
func TestClientApplyTLS_reapplyReplacesExistingKeys(t *testing.T) {
	config := map[string]string{}
	var tlsApp bool
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/apps/tls":
			if !tlsApp {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && r.URL.Path == "/config/apps":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodPut && r.URL.Path == "/config/apps/tls":
			tlsApp = true
			config["/config/apps/tls/certificates"] = string(body)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPut:
			if _, ok := config[r.URL.Path]; ok {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"key already exists"}`))
				return
			}
			config[r.URL.Path] = string(body)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPatch:
			if _, ok := config[r.URL.Path]; !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			config[r.URL.Path] = string(body)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mock.Close()

	c := &Client{baseURL: mock.URL, http: mock.Client()}
	ctx := context.Background()
	first := json.RawMessage(`[{"certificate":"/a.crt","key":"/a.key"}]`)
	second := json.RawMessage(`[{"certificate":"/a.crt","key":"/a.key"},{"certificate":"/b.crt","key":"/b.key"}]`)
	auto := json.RawMessage(`{"disable":true}`)
	policies := json.RawMessage(`[{}]`)
	if err := c.ApplyTLS(ctx, first, auto, policies); err != nil {
		t.Fatalf("first ApplyTLS: %v", err)
	}
	if err := c.ApplyTLS(ctx, second, auto, policies); err != nil {
		t.Fatalf("second ApplyTLS: %v", err)
	}
	var certs struct {
		LoadFiles []map[string]string `json:"load_files"`
	}
	if err := json.Unmarshal([]byte(config["/config/apps/tls/certificates"]), &certs); err != nil {
		t.Fatalf("certificates: %v", err)
	}
	if len(certs.LoadFiles) != 2 {
		t.Errorf("load_files after re-apply = %v, want both certs", certs.LoadFiles)
	}
}

func TestClientSetKey_otherErrorsAreReturned(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			t.Errorf("PATCH sent after a non-conflict error")
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer mock.Close()
	c := &Client{baseURL: mock.URL, http: mock.Client()}
	err := c.setKey(context.Background(), "/config/x", []byte(`{}`))
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("setKey error = %v, want the 400", err)
	}
}

// A srv0 that already exists WITHOUT a routes array (e.g. created by the TLS
// strategy apply, which PUTs only automatic_https) must be repaired by
// EnsureServer: it seeds an empty routes array so the subsequent AddRoute POST
// appends to a list instead of writing an object Caddy rejects as a RouteList
// (regression for issue #106).
func TestClientEnsureServer_seedsRoutesOnExistingServerWithoutRoutes(t *testing.T) {
	srv0HasRoutes := false
	seeded := false
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/apps/http/servers/srv0":
			w.WriteHeader(http.StatusOK)
			if srv0HasRoutes {
				w.Write([]byte(`{"automatic_https":{"disable":true},"routes":[]}`))
			} else {
				w.Write([]byte(`{"automatic_https":{"disable":true}}`))
			}
		case r.Method == http.MethodPut && r.URL.Path == "/config/apps/http/servers/srv0/routes":
			srv0HasRoutes = true
			seeded = true
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mock.Close()

	c := &Client{baseURL: mock.URL, http: mock.Client()}
	if err := c.EnsureServer(context.Background()); err != nil {
		t.Fatalf("EnsureServer failed: %v", err)
	}
	if !seeded {
		t.Error("EnsureServer must seed a routes array on an existing srv0 that lacks one")
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

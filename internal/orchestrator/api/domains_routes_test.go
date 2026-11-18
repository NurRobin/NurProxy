package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// seedRouteServers adds a second server on the domain's agent and one on
// another agent.
func seedRouteServers(t *testing.T, srv *Server) {
	t.Helper()
	database := srv.db
	if err := database.CreateServer(&models.Server{ID: "srv-api", AgentID: "agent-1", Name: "API", Address: "192.168.178.210"}); err != nil {
		t.Fatal(err)
	}
	if err := database.CreateAgent(&models.Agent{ID: "agent-2", Name: "Other", FQDN: "other.example.com", DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted}); err != nil {
		t.Fatal(err)
	}
	if err := database.CreateServer(&models.Server{ID: "srv-far", AgentID: "agent-2", Name: "Far", Address: "10.9.9.9"}); err != nil {
		t.Fatal(err)
	}
}

func routesBody(routes ...map[string]any) map[string]any {
	list := make([]any, len(routes))
	for i, r := range routes {
		list[i] = r
	}
	return map[string]any{"proxy_config": map[string]any{"routes": list}}
}

// TestDomainRoutesValidation covers path routes on update: shape checks,
// the same-agent rule, unknown servers and the capability check.
func TestDomainRoutesValidation(t *testing.T) {
	exact := map[string]any{"match": "exact", "path": "/api/world", "server_id": "srv-api", "port": 80}
	prefix := map[string]any{"match": "prefix", "path": "/media", "server_id": "srv-1", "port": 9000, "strip_prefix": true}
	with := func(base map[string]any, k string, v any) map[string]any {
		out := map[string]any{}
		for key, val := range base {
			out[key] = val
		}
		out[k] = v
		return out
	}
	tests := []struct {
		name     string
		caps     *models.ProxyCapabilities
		body     map[string]any
		wantCode int
		wantErr  string
	}{
		{name: "exact and prefix", body: routesBody(exact, prefix), wantCode: http.StatusOK},
		{name: "server on another agent", body: routesBody(with(exact, "server_id", "srv-far")), wantCode: http.StatusBadRequest, wantErr: "another agent"},
		{name: "unknown server", body: routesBody(with(exact, "server_id", "nope")), wantCode: http.StatusBadRequest, wantErr: "not found"},
		{name: "missing match", body: routesBody(with(exact, "match", "")), wantCode: http.StatusBadRequest, wantErr: "match"},
		{name: "regex match", body: routesBody(with(exact, "match", "regex")), wantCode: http.StatusBadRequest, wantErr: "match"},
		{name: "path injection", body: routesBody(with(exact, "path", "/x { return 200; }")), wantCode: http.StatusBadRequest, wantErr: "path"},
		{name: "wildcard path", body: routesBody(with(prefix, "path", "/media/*")), wantCode: http.StatusBadRequest, wantErr: "path"},
		{name: "relative path", body: routesBody(with(prefix, "path", "media")), wantCode: http.StatusBadRequest, wantErr: "path"},
		{name: "prefix root", body: routesBody(with(prefix, "path", "/")), wantCode: http.StatusBadRequest, wantErr: "default upstream"},
		{name: "prefix trailing slash", body: routesBody(with(prefix, "path", "/media/")), wantCode: http.StatusBadRequest, wantErr: "trailing slash"},
		{name: "dot segment", body: routesBody(with(prefix, "path", "/a/../b")), wantCode: http.StatusBadRequest, wantErr: "segments"},
		{name: "strip on exact", body: routesBody(with(exact, "strip_prefix", true)), wantCode: http.StatusBadRequest, wantErr: "strip prefix"},
		{name: "port zero", body: routesBody(with(exact, "port", 0)), wantCode: http.StatusBadRequest, wantErr: "port"},
		{name: "bad scheme", body: routesBody(with(exact, "upstream_scheme", "ftp")), wantCode: http.StatusBadRequest, wantErr: "scheme"},
		{name: "duplicate", body: routesBody(exact, exact), wantCode: http.StatusBadRequest, wantErr: "twice"},
		{name: "backend without path routes", caps: &models.ProxyCapabilities{ReverseProxy: true, AccessLog: true}, body: routesBody(exact), wantCode: http.StatusBadRequest, wantErr: "cannot render path routes"},
		{name: "backend with path routes", caps: &models.ProxyCapabilities{ReverseProxy: true, PathRoutes: true}, body: routesBody(exact), wantCode: http.StatusOK},
		{name: "clear routes", body: map[string]any{"proxy_config": map[string]any{"routes": nil}}, wantCode: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, database := testServer(t)
			handler := srv.Handler()
			cookie := setupAdmin(t, handler)
			domainID, _ := seedDomainTopology(t, srv, cookie)
			seedRouteServers(t, srv)
			if tt.caps != nil {
				if err := database.UpdateAgentCapabilities("agent-1", tt.caps); err != nil {
					t.Fatal(err)
				}
			}
			w := doRequest(t, handler, http.MethodPut, "/api/v1/domains/"+strconv.FormatInt(domainID, 10), tt.body, cookie)
			if w.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d: %s", w.Code, tt.wantCode, w.Body.String())
			}
			if tt.wantErr != "" && !strings.Contains(w.Body.String(), tt.wantErr) {
				t.Fatalf("error %q does not mention %q", w.Body.String(), tt.wantErr)
			}
		})
	}
}

// TestDomainRoutesCreateAndPreview creates a domain with path routes and
// checks that they are stored and rendered into the nginx preview, and that
// moving the domain to another agent's server is refused while its routes
// point at servers of the old agent.
func TestDomainRoutesCreateAndPreview(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)
	seedDomainTopology(t, srv, cookie)
	seedRouteServers(t, srv)

	w := doRequest(t, handler, http.MethodPost, "/api/v1/domains", map[string]any{
		"subdomain": "christmas", "zone_id": "zone-1", "server_id": "srv-api", "port": 2412,
		"proxy_config": map[string]any{"routes": []any{
			map[string]any{"match": "exact", "path": "/api/world", "server_id": "srv-api", "port": 80},
		}},
	}, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var dom models.Domain
	if err := json.NewDecoder(w.Body).Decode(&dom); err != nil {
		t.Fatal(err)
	}
	stored, err := database.GetDomain(dom.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.ProxyConfig.Routes) != 1 || stored.ProxyConfig.Routes[0].Path != "/api/world" {
		t.Fatalf("stored routes = %+v", stored.ProxyConfig.Routes)
	}

	server, err := database.GetServer(stored.ServerID)
	if err != nil {
		t.Fatal(err)
	}
	_, cfg, err := srv.renderDomainPreview(stored, server, "christmas.example.com")
	if err != nil {
		t.Fatal(err)
	}
	text, _ := cfg.(string)
	if !strings.Contains(text, "location = /api/world {\n        proxy_pass http://192.168.178.210:80;") || !strings.Contains(text, "proxy_pass http://192.168.178.210:2412;") {
		t.Fatalf("nginx preview lacks the path route:\n%s", text)
	}

	path := "/api/v1/domains/" + strconv.FormatInt(dom.ID, 10)
	if w := doRequest(t, handler, http.MethodPut, path, map[string]any{"server_id": "srv-far"}, cookie); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "another agent") {
		t.Fatalf("move with routes on the old agent: %d %s", w.Code, w.Body.String())
	}
}

// TestDeleteServer_refusedWhilePathRoutesUseIt checks that a server used by
// another domain's path route cannot be deleted, not even with cascade, and
// can be once the route is gone.
func TestDeleteServer_refusedWhilePathRoutesUseIt(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)
	domainID, _ := seedDomainTopology(t, srv, cookie)
	seedRouteServers(t, srv)
	path := "/api/v1/domains/" + strconv.FormatInt(domainID, 10)
	if w := doRequest(t, handler, http.MethodPut, path, routesBody(map[string]any{"match": "prefix", "path": "/api", "server_id": "srv-api", "port": 80}), cookie); w.Code != http.StatusOK {
		t.Fatalf("add route: %d %s", w.Code, w.Body.String())
	}

	for _, target := range []string{"/api/v1/servers/srv-api", "/api/v1/servers/srv-api?cascade=true"} {
		w := doRequest(t, handler, http.MethodDelete, target, nil, cookie)
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "path routes") || !strings.Contains(w.Body.String(), `"health"`) {
			t.Fatalf("DELETE %s: %d %s, want 409 naming the domain", target, w.Code, w.Body.String())
		}
	}

	if w := doRequest(t, handler, http.MethodPut, path, map[string]any{"proxy_config": map[string]any{"routes": []any{}}}, cookie); w.Code != http.StatusOK {
		t.Fatalf("clear routes: %d %s", w.Code, w.Body.String())
	}
	if w := doRequest(t, handler, http.MethodDelete, "/api/v1/servers/srv-api", nil, cookie); w.Code != http.StatusOK {
		t.Fatalf("DELETE after removing the route: %d %s", w.Code, w.Body.String())
	}
}

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

const routesTestDomain = `{"id":7,"subdomain":"app","proxy_config":{"websocket":true,"routes":[
	{"match":"exact","path":"/api/world","server_id":"s2","port":80},
	{"match":"prefix","path":"/media","server_id":"s3","port":9000}]}}`

// TestDomainRouteCommands checks that route add/remove read the stored
// routes and write back the edited list as proxy_config.routes, leaving the
// other proxy_config keys out of the request.
func TestDomainRouteCommands(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []models.PathRoute
	}{
		{
			name: "add exact https websocket",
			args: []string{"add", "7", "--path", "/ws", "--server", "s4", "--port", "8443", "--match", "exact", "--scheme", "https", "--websocket"},
			want: []models.PathRoute{
				{Match: "exact", Path: "/api/world", ServerID: "s2", Port: 80},
				{Match: "prefix", Path: "/media", ServerID: "s3", Port: 9000},
				{Match: "exact", Path: "/ws", ServerID: "s4", Port: 8443, UpstreamScheme: "https", WebSocket: true},
			},
		},
		{
			name: "add prefix by default",
			args: []string{"add", "7", "--path", "/static", "--server", "s3", "--port", "80", "--strip-prefix"},
			want: []models.PathRoute{
				{Match: "exact", Path: "/api/world", ServerID: "s2", Port: 80},
				{Match: "prefix", Path: "/media", ServerID: "s3", Port: 9000},
				{Match: "prefix", Path: "/static", ServerID: "s3", Port: 80, StripPrefix: true},
			},
		},
		{
			name: "remove",
			args: []string{"remove", "7", "--path", "/api/world"},
			want: []models.PathRoute{{Match: "prefix", Path: "/media", ServerID: "s3", Port: 9000}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, reqs := newTestServer(t, func(w http.ResponseWriter, r *http.Request, rec *capturedReq) {
				_, _ = io.WriteString(w, routesTestDomain)
			})
			cmdDomainRoute(append(tt.args, "--url", srv.URL, "--key", "k"))
			if len(*reqs) != 2 || (*reqs)[0].method != http.MethodGet || (*reqs)[1].method != http.MethodPut || (*reqs)[1].path != "/api/v1/domains/7" {
				t.Fatalf("requests = %+v, want GET then PUT /api/v1/domains/7", *reqs)
			}
			var body struct {
				ProxyConfig map[string]json.RawMessage `json:"proxy_config"`
			}
			if err := json.Unmarshal([]byte((*reqs)[1].body), &body); err != nil {
				t.Fatal(err)
			}
			if len(body.ProxyConfig) != 1 {
				t.Fatalf("proxy_config keys = %v, want only routes", body.ProxyConfig)
			}
			var got []models.PathRoute
			if err := json.Unmarshal(body.ProxyConfig["routes"], &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("routes = %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestRemovePathRoute(t *testing.T) {
	both := []models.PathRoute{{Match: "prefix", Path: "/a"}, {Match: "exact", Path: "/a"}}
	if _, err := removePathRoute(both, "", "/a"); err == nil {
		t.Fatal("ambiguous removal without --match was accepted")
	}
	got, err := removePathRoute(both, "exact", "/a")
	if err != nil || len(got) != 1 || got[0].Match != "prefix" {
		t.Fatalf("remove exact = %+v, %v", got, err)
	}
	if _, err := removePathRoute(both, "", "/b"); err == nil {
		t.Fatal("removing a missing route was accepted")
	}
	if _, err := addPathRoute(both, models.PathRoute{Match: "exact", Path: "/a"}); err == nil {
		t.Fatal("duplicate route was accepted")
	}
}

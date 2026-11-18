package nginxparse

import (
	"reflect"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/nginxgen"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// TestParse_pathRoutes_roundTrip renders path routes with nginxgen and reads
// them back: the mask is clean and recovers the routes, most specific first.
func TestParse_pathRoutes_roundTrip(t *testing.T) {
	for name, mutate := range map[string]func(*proxymodel.Route){
		"plain":                func(*proxymodel.Route) {},
		"shared headers":       func(r *proxymodel.Route) { r.RequestHeaders = map[string]string{"X-Team": "edge"} },
		"shared timeouts":      func(r *proxymodel.Route) { r.Timeouts = proxymodel.Timeouts{Read: 60, Write: 30} },
		"default strip prefix": func(r *proxymodel.Route) { r.Path.StripPrefix = "/app" },
	} {
		t.Run(name, func(t *testing.T) {
			route := proxymodel.Route{
				Host:       "app.example.com",
				Upstream:   proxymodel.Upstream{Addr: "10.0.0.4", Port: 8080},
				TLS:        proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
				PathRoutes: policyTestPathRoutes(),
			}
			mutate(&route)
			out, err := nginxgen.Render(nginxgen.Input{Route: route})
			if err != nil {
				t.Fatal(err)
			}
			res := Parse(out.Server)
			if !res.OK {
				t.Fatalf("expected a clean parse; notes=%v unparsed=%v\n%s", res.Notes, res.Unparsed, out.Server)
			}
			want := proxymodel.SortedPathRoutes(route.PathRoutes)
			if !reflect.DeepEqual(proxymodel.SortedPathRoutes(res.Route.PathRoutes), want) {
				t.Fatalf("path routes = %+v\nwant %+v", res.Route.PathRoutes, want)
			}
		})
	}
}

// TestParse_pathRoutes_importsHandWrittenVhost reads the vhost from issue #89:
// the exact location becomes a path route and nothing is left behind.
func TestParse_pathRoutes_importsHandWrittenVhost(t *testing.T) {
	content := `server {
    listen 80;
    server_name christmas.example.com;
    location = /api/world { proxy_pass http://192.168.178.210:80; }
    location /           { proxy_pass http://192.168.178.210:2412; }
}`
	res := Parse(content)
	if !res.OK {
		t.Fatalf("expected a clean parse; notes=%v unparsed=%v", res.Notes, res.Unparsed)
	}
	want := []proxymodel.PathRoute{{Match: proxymodel.PathMatchExact, Path: "/api/world", Upstream: proxymodel.Upstream{Addr: "192.168.178.210", Port: 80}}}
	if !reflect.DeepEqual(res.Route.PathRoutes, want) {
		t.Fatalf("path routes = %+v, want %+v", res.Route.PathRoutes, want)
	}
	if res.Route.Upstream.Port != 2412 {
		t.Fatalf("default upstream = %+v", res.Route.Upstream)
	}
}

// TestParse_pathRoutes_warnsAboutWhatIsNotCarriedOver checks that a location
// the mask cannot represent exactly is never dropped silently: the parse is
// not clean, the block stays in Unparsed or the difference is named in Notes.
func TestParse_pathRoutes_warnsAboutWhatIsNotCarriedOver(t *testing.T) {
	const root = "    location / { proxy_pass http://10.0.0.4:8080; }\n"
	tests := []struct {
		name       string
		location   string
		note       string
		unparsed   bool
		wantRoutes []proxymodel.PathRoute
	}{
		{
			name:     "regex location",
			location: "    location ~ ^/api/(v1|v2)/ { proxy_pass http://10.0.0.5:80; }\n",
			note:     "regex and ^~ locations are not supported",
			unparsed: true,
		},
		{
			name:     "prefix priority location",
			location: "    location ^~ /static/ { proxy_pass http://10.0.0.5:80; }\n",
			note:     "not carried over",
			unparsed: true,
		},
		{
			name:     "location serving files",
			location: "    location /static/ { root /srv/www; }\n",
			note:     "not carried over",
			unparsed: true,
		},
		{
			name:     "own request header",
			location: "    location = /x { proxy_pass http://10.0.0.5:80; proxy_set_header X-Own 1; }\n",
			note:     "sets its own",
			unparsed: true,
			wantRoutes: []proxymodel.PathRoute{{
				Match: proxymodel.PathMatchExact, Path: "/x", Upstream: proxymodel.Upstream{Addr: "10.0.0.5", Port: 80},
			}},
		},
		{
			name:     "prefix without trailing slash",
			location: "    location /api { proxy_pass http://10.0.0.5:80; }\n",
			note:     "segment boundary",
			wantRoutes: []proxymodel.PathRoute{{
				Match: proxymodel.PathMatchPrefix, Path: "/api", Upstream: proxymodel.Upstream{Addr: "10.0.0.5", Port: 80},
			}},
		},
		{
			name:     "prefix without exact companion",
			location: "    location /api/ { proxy_pass http://10.0.0.5:80; }\n",
			note:     "redirect",
			wantRoutes: []proxymodel.PathRoute{{
				Match: proxymodel.PathMatchPrefix, Path: "/api", Upstream: proxymodel.Upstream{Addr: "10.0.0.5", Port: 80},
			}},
		},
		{
			name:     "nested if",
			location: "    if ($host = x) { return 404; }\n",
			note:     "not carried over",
			unparsed: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := "server {\n    listen 80;\n    server_name app.example.com;\n" + tt.location + root + "}\n"
			res := Parse(content)
			if res.OK {
				t.Fatalf("parse reported clean for a location it cannot carry over:\n%s", content)
			}
			if !strings.Contains(strings.Join(res.Notes, "\n"), tt.note) {
				t.Fatalf("notes %q do not mention %q", res.Notes, tt.note)
			}
			if tt.unparsed && !strings.Contains(strings.Join(res.Unparsed, "\n"), strings.TrimSpace(tt.location)) {
				t.Fatalf("location missing from unparsed %q", res.Unparsed)
			}
			if !reflect.DeepEqual(res.Route.PathRoutes, tt.wantRoutes) {
				t.Fatalf("path routes = %+v, want %+v", res.Route.PathRoutes, tt.wantRoutes)
			}
		})
	}
}

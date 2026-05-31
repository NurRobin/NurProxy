package nginxdiscover

import (
	"reflect"
	"testing"
)

func TestDiscover_directProxyPass(t *testing.T) {
	cfg := `
server {
    listen 443 ssl;
    server_name app.example.com www.example.com;
    location / {
        proxy_pass http://192.168.1.10:8080/;
    }
}`
	got := Discover(cfg)
	if len(got) != 1 {
		t.Fatalf("want 1 upstream, got %d: %+v", len(got), got)
	}
	u := got[0]
	if u.Scheme != "http" || u.Host != "192.168.1.10" || u.Port != 8080 {
		t.Errorf("bad upstream: %+v", u)
	}
	if !reflect.DeepEqual(u.ServerNames, []string{"app.example.com", "www.example.com"}) {
		t.Errorf("server names = %v", u.ServerNames)
	}
}

func TestDiscover_namedUpstreamResolved(t *testing.T) {
	cfg := `
upstream backend {
    server 10.0.0.1:3000;
    server 10.0.0.2:3000;
}
server {
    server_name api.example.com;
    location / { proxy_pass http://backend; }
}`
	got := Discover(cfg)
	if len(got) != 2 {
		t.Fatalf("named upstream should expand to 2 members, got %d: %+v", len(got), got)
	}
	for _, u := range got {
		if u.Port != 3000 || u.Scheme != "http" {
			t.Errorf("member not resolved with scheme/port: %+v", u)
		}
		if len(u.ServerNames) != 1 || u.ServerNames[0] != "api.example.com" {
			t.Errorf("member should carry the vhost name: %+v", u)
		}
	}
}

func TestDiscover_multipleServersAndDedup(t *testing.T) {
	cfg := `
server { server_name a.com; location / { proxy_pass http://10.0.0.5:80; } }
server { server_name b.com; location / { proxy_pass http://10.0.0.5:80; } }
server { server_name c.com; location / { proxy_pass https://10.0.0.9:443; } }`
	got := Discover(cfg)
	if len(got) != 2 {
		t.Fatalf("want 2 distinct upstreams (one shared), got %d: %+v", len(got), got)
	}
	// 10.0.0.5:80 is referenced by a.com and b.com — names merged.
	var shared *Upstream
	for i := range got {
		if got[i].Addr() == "10.0.0.5:80" {
			shared = &got[i]
		}
	}
	if shared == nil {
		t.Fatalf("missing shared upstream: %+v", got)
	}
	if !reflect.DeepEqual(shared.ServerNames, []string{"a.com", "b.com"}) {
		t.Errorf("shared upstream should merge both vhost names, got %v", shared.ServerNames)
	}
}

func TestDiscover_skipsVariablesAndSchemeless(t *testing.T) {
	cfg := `
server {
    server_name x.com;
    location /a { proxy_pass $upstream; }
    location /b { proxy_pass http://$backend; }
    location /c { fastcgi_pass unix:/run/php.sock; }
    location /d { proxy_pass http://10.1.2.3:9000; }
}`
	got := Discover(cfg)
	if len(got) != 1 || got[0].Addr() != "10.1.2.3:9000" {
		t.Fatalf("should keep only the concrete target, got %+v", got)
	}
}

func TestDiscover_ignoresCommentsAndWildcardNames(t *testing.T) {
	cfg := `
server {
    # proxy_pass http://commented-out:1234;
    server_name _ *.wild.com real.com;
    location / { proxy_pass http://10.0.0.1:8000; }
}`
	got := Discover(cfg)
	if len(got) != 1 {
		t.Fatalf("comment must be ignored, got %+v", got)
	}
	if !reflect.DeepEqual(got[0].ServerNames, []string{"real.com"}) {
		t.Errorf("wildcard/underscore names should be dropped, got %v", got[0].ServerNames)
	}
}

func TestDiscover_pathAndTrailingStripped(t *testing.T) {
	got := Discover(`server { server_name p.com; location / { proxy_pass http://10.0.0.7:8080/app/; } }`)
	if len(got) != 1 || got[0].Host != "10.0.0.7" || got[0].Port != 8080 {
		t.Fatalf("trailing path should be stripped, got %+v", got)
	}
}

func TestDiscover_hostOnlyNoPort(t *testing.T) {
	got := Discover(`server { server_name h.com; location / { proxy_pass http://backend.internal; } }`)
	if len(got) != 1 || got[0].Host != "backend.internal" || got[0].Port != 0 {
		t.Fatalf("host-only target mishandled: %+v", got)
	}
	if got[0].Addr() != "backend.internal" {
		t.Errorf("Addr() for port-less host = %q", got[0].Addr())
	}
}

func TestDiscover_empty(t *testing.T) {
	if got := Discover(""); len(got) != 0 {
		t.Errorf("empty config should yield nothing, got %+v", got)
	}
	if got := Discover("worker_processes auto;\nevents { worker_connections 1024; }\n"); len(got) != 0 {
		t.Errorf("config with no proxy_pass should yield nothing, got %+v", got)
	}
}

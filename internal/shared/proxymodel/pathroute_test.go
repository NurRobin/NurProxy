package proxymodel

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestPathRoute_Validate(t *testing.T) {
	ok := PathRoute{Match: PathMatchPrefix, Path: "/api", Upstream: Upstream{Addr: "10.0.0.5", Port: 80}}
	tests := []struct {
		name    string
		mutate  func(*PathRoute)
		wantErr string
	}{
		{"prefix", func(*PathRoute) {}, ""},
		{"exact", func(p *PathRoute) { p.Match = PathMatchExact; p.Path = "/api/world" }, ""},
		{"exact root", func(p *PathRoute) { p.Match = PathMatchExact; p.Path = "/" }, ""},
		{"exact trailing slash", func(p *PathRoute) { p.Match = PathMatchExact; p.Path = "/api/" }, ""},
		{"dotted path", func(p *PathRoute) { p.Path = "/v1.2/x_y-z~" }, "may only contain"},
		{"dot in segment", func(p *PathRoute) { p.Path = "/v1.2/x_y-z" }, ""},
		{"https websocket strip", func(p *PathRoute) {
			p.Upstream.Scheme = SchemeHTTPS
			p.WebSocket = true
			p.StripPrefix = true
		}, ""},
		{"regex match", func(p *PathRoute) { p.Match = "regex" }, "match must be"},
		{"empty match", func(p *PathRoute) { p.Match = "" }, "match must be"},
		{"empty path", func(p *PathRoute) { p.Path = "" }, "path is required"},
		{"relative", func(p *PathRoute) { p.Path = "api" }, "must start with '/'"},
		{"space", func(p *PathRoute) { p.Path = "/a b" }, "may only contain"},
		{"semicolon", func(p *PathRoute) { p.Path = "/a;b" }, "may only contain"},
		{"brace", func(p *PathRoute) { p.Path = "/a{b}" }, "may only contain"},
		{"wildcard", func(p *PathRoute) { p.Path = "/a*" }, "may only contain"},
		{"percent", func(p *PathRoute) { p.Path = "/a%2e" }, "may only contain"},
		{"query", func(p *PathRoute) { p.Path = "/a?b" }, "may only contain"},
		{"double slash", func(p *PathRoute) { p.Path = "/a//b" }, "'//'"},
		{"dot dot", func(p *PathRoute) { p.Path = "/a/../b" }, "segments"},
		{"dot", func(p *PathRoute) { p.Path = "/a/./b" }, "segments"},
		{"too long", func(p *PathRoute) { p.Path = "/" + strings.Repeat("a", 300) }, "longer than"},
		{"prefix root", func(p *PathRoute) { p.Path = "/" }, "default upstream"},
		{"prefix trailing slash", func(p *PathRoute) { p.Path = "/api/" }, "trailing slash"},
		{"strip on exact", func(p *PathRoute) { p.Match = PathMatchExact; p.StripPrefix = true }, "strip prefix"},
		{"bad scheme", func(p *PathRoute) { p.Upstream.Scheme = "ftp" }, "scheme"},
		{"port zero", func(p *PathRoute) { p.Upstream.Port = 0 }, "port"},
		{"port too big", func(p *PathRoute) { p.Upstream.Port = 70000 }, "port"},
		{"no address", func(p *PathRoute) { p.Upstream.Addr = "" }, "address is required"},
		{"bad address", func(p *PathRoute) { p.Upstream.Addr = "a b" }, "not a host name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := ok
			tt.mutate(&p)
			err := p.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePathRoutes(t *testing.T) {
	a := PathRoute{Match: PathMatchPrefix, Path: "/a", Upstream: Upstream{Port: 80}}
	b := PathRoute{Match: PathMatchExact, Path: "/a", Upstream: Upstream{Port: 80}}
	if err := ValidatePathRoutes([]PathRoute{a, b}, false); err != nil {
		t.Fatalf("prefix and exact for one path refused: %v", err)
	}
	if err := ValidatePathRoutes([]PathRoute{a, a}, false); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("duplicate = %v", err)
	}
	if err := ValidatePathRoutes([]PathRoute{a}, true); err == nil {
		t.Fatal("missing address accepted with withAddr")
	}
	many := make([]PathRoute, MaxPathRoutes+1)
	for i := range many {
		many[i] = PathRoute{Match: PathMatchPrefix, Path: "/p" + strings.Repeat("x", i), Upstream: Upstream{Port: 80}}
	}
	if err := ValidatePathRoutes(many, false); err == nil {
		t.Fatal("too many routes accepted")
	}
	r := Route{PathRoutes: []PathRoute{{Match: "regex", Path: "^/a", Upstream: Upstream{Port: 80}}}}
	if err := r.ValidateOptions(); err == nil {
		t.Fatal("ValidateOptions accepted a regex path route")
	}
}

func TestSortedPathRoutes(t *testing.T) {
	in := []PathRoute{
		{Match: PathMatchPrefix, Path: "/a"},
		{Match: PathMatchPrefix, Path: "/a/b"},
		{Match: PathMatchExact, Path: "/z"},
		{Match: PathMatchPrefix, Path: "/b"},
		{Match: PathMatchExact, Path: "/a/b/c"},
	}
	want := []string{"exact /a/b/c", "exact /z", "prefix /a/b", "prefix /a", "prefix /b"}
	var got []string
	for _, p := range SortedPathRoutes(in) {
		got = append(got, string(p.Match)+" "+p.Path)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
	if in[0].Path != "/a" {
		t.Fatal("SortedPathRoutes modified its input")
	}
}

// TestRoute_jsonWithoutPathRoutes keeps the wire form of a route without
// path routes unchanged, so the helper intent digest of existing routes does
// not move.
func TestRoute_jsonWithoutPathRoutes(t *testing.T) {
	data, err := json.Marshal(validStructured())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "PathRoutes") {
		t.Fatalf("route without path routes serializes the field: %s", data)
	}
}

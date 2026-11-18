package generic

import (
	"context"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// TestRender_pathRoutes checks that path routes reach the template most
// specific first, and that a template without the path_routes capability
// refuses a route that has them instead of rendering only the default.
func TestRender_pathRoutes(t *testing.T) {
	route := httpRoute("app.example.com")
	route.PathRoutes = []proxymodel.PathRoute{
		{Match: proxymodel.PathMatchPrefix, Path: "/media", StripPrefix: true, Upstream: proxymodel.Upstream{Addr: "10.0.0.7", Port: 9000}},
		{Match: proxymodel.PathMatchExact, Path: "/api/world", Upstream: proxymodel.Upstream{Addr: "10.0.0.8", Port: 80, Scheme: proxymodel.SchemeHTTPS}},
	}
	tmpl := `{{ range .PathRoutes }}{{ if .Exact }}={{ else }}^{{ end }}{{ .Path }} {{ .Scheme }}://{{ .UpstreamAddr }} strip={{ .StripPrefix }}
{{ end }}default {{ .UpstreamAddr }}`

	b, _ := newBackend(t, tmpl)
	if _, err := b.Render(context.Background(), route); err == nil || !strings.Contains(err.Error(), "path_routes") {
		t.Fatalf("render without the capability = %v, want a path_routes refusal", err)
	}

	b, err := New(proxy.Config{Type: "custom", ConfigDir: t.TempDir(), ReloadCmd: "x", Template: tmpl, DeclaredCaps: &proxy.Capabilities{PathRoutes: true}})
	if err != nil {
		t.Fatal(err)
	}
	art, err := b.Render(context.Background(), route)
	if err != nil {
		t.Fatal(err)
	}
	want := "=/api/world https://10.0.0.8:80 strip=false\n^/media http://10.0.0.7:9000 strip=true\ndefault 10.0.0.5:8080"
	if art.Content != want {
		t.Fatalf("content = %q, want %q", art.Content, want)
	}
}

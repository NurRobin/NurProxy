package caddy

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	agentcaddy "github.com/NurRobin/NurProxy/internal/agent/caddy"
	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/agent/proxy/certstore"
	"github.com/NurRobin/NurProxy/internal/shared/caddygen"
	"github.com/NurRobin/NurProxy/internal/shared/crypto"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// errProbe is a sentinel module-probe failure used by the capability tests.
var errProbe = errors.New("probe failed")

// sampleRoute is a representative structured route used across the table tests.
func sampleRoute() proxymodel.Route {
	return proxymodel.Route{
		Host: "app.example.com",
		Upstream: proxymodel.Upstream{
			Addr: "10.0.0.4",
			Port: 8080,
		},
	}
}

func TestBackend_Info_reportsCaddyKind(t *testing.T) {
	b := New(agentcaddy.NewMockClient())
	if got := b.Info().Kind; got != proxy.Kind("caddy") {
		t.Fatalf("Info().Kind = %q, want %q", got, "caddy")
	}
}

func TestBackend_Detect_alwaysAvailable(t *testing.T) {
	b := New(agentcaddy.NewMockClient())
	ok, err := b.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}
	if !ok {
		t.Fatal("Detect = false, want true (bundled caddy is always available)")
	}
}

// TestBackend_Capabilities_coreAlwaysEnabled verifies the non-module-dependent
// options are always advertised; RateLimit is covered separately since it is
// gated on module probing.
func TestBackend_Capabilities_coreAlwaysEnabled(t *testing.T) {
	b := New(agentcaddy.NewMockClient())
	// Force a deterministic "module present" probe so the core check is isolated.
	b.listModules = func(context.Context) ([]string, error) {
		return []string{rateLimitModule}, nil
	}
	caps := b.Capabilities()
	if !caps.ReverseProxy || !caps.WebSocket || !caps.ForceHTTPS || !caps.CustomHeaders ||
		!caps.PathRewrite || !caps.BasicAuth || !caps.IPFilter || !caps.CentralTLS {
		t.Fatalf("Capabilities core options = %+v, want all true", caps)
	}
}

// TestBackend_Capabilities_rateLimitProbe drives the §8 module probe: RateLimit
// is true only when caddy-ratelimit (http.handlers.rate_limit) is in the module
// list, and a probe error / missing prober degrades to false rather than
// guessing true.
func TestBackend_Capabilities_rateLimitProbe(t *testing.T) {
	tests := []struct {
		name   string
		prober func(context.Context) ([]string, error)
		want   bool
	}{
		{
			name: "module present",
			prober: func(context.Context) ([]string, error) {
				return []string{"http.handlers.reverse_proxy", rateLimitModule}, nil
			},
			want: true,
		},
		{
			name:   "module absent",
			prober: func(context.Context) ([]string, error) { return []string{"http.handlers.reverse_proxy"}, nil },
			want:   false,
		},
		{
			name:   "probe error",
			prober: func(context.Context) ([]string, error) { return nil, errProbe },
			want:   false,
		},
		{
			name:   "nil prober",
			prober: nil,
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := New(agentcaddy.NewMockClient())
			b.listModules = tt.prober
			if got := b.Capabilities().RateLimit; got != tt.want {
				t.Errorf("Capabilities().RateLimit = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestParseListModules(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want []string
	}{
		{
			name: "module ids and summary",
			out: "http.handlers.reverse_proxy\n" +
				"http.handlers.rate_limit\n" +
				"\n" +
				"  Standard modules: 123\n" +
				"  Non-standard modules: 1\n",
			want: []string{"http.handlers.reverse_proxy", "http.handlers.rate_limit"},
		},
		{
			name: "empty output",
			out:  "",
			want: nil,
		},
		{
			name: "whitespace padded ids",
			out:  "  http.handlers.encode  \n\tcaddy.logging.encoders.json\n",
			want: []string{"http.handlers.encode", "caddy.logging.encoders.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseListModules(tt.out)
			if len(got) != len(tt.want) {
				t.Fatalf("parseListModules = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("parseListModules = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestModuleListHas(t *testing.T) {
	mods := []string{"a", "b", rateLimitModule}
	if !moduleListHas(mods, rateLimitModule) {
		t.Error("moduleListHas = false, want true for present module")
	}
	if moduleListHas(mods, "missing") {
		t.Error("moduleListHas = true, want false for absent module")
	}
	if moduleListHas(nil, "x") {
		t.Error("moduleListHas(nil) = true, want false")
	}
}

// TestBackend_Render_matchesCaddygen is the regression guard for invariant #1:
// the backend's Render must emit exactly the bytes caddygen.GenerateRoute
// produces, so routing through the interface is byte-for-byte unchanged.
func TestBackend_Render_matchesCaddygen(t *testing.T) {
	tests := []struct {
		name  string
		route proxymodel.Route
	}{
		{name: "plain reverse proxy", route: sampleRoute()},
		{
			name: "websocket + force https",
			route: func() proxymodel.Route {
				r := sampleRoute()
				r.WebSocket = true
				r.ForceHTTPS = true
				return r
			}(),
		},
		{
			name: "raw escape hatch",
			route: proxymodel.Route{
				Raw: proxymodel.RawConfig{
					Backend: "caddy",
					Content: `{"@id":"domain-raw","match":[{"host":["raw.example.com"]}]}`,
				},
			},
		},
	}

	b := New(agentcaddy.NewMockClient())
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			want, err := caddygen.GenerateRoute(tc.route)
			if err != nil {
				t.Fatalf("caddygen.GenerateRoute error: %v", err)
			}
			art, err := b.Render(context.Background(), tc.route)
			if err != nil {
				t.Fatalf("Render error: %v", err)
			}
			if art.Content != string(want) {
				t.Fatalf("Render content mismatch:\n got: %s\nwant: %s", art.Content, want)
			}
			if art.Target.Kind != proxy.TargetKindCaddyRoute {
				t.Fatalf("Target.Kind = %q, want %q", art.Target.Kind, proxy.TargetKindCaddyRoute)
			}
			if !art.Enabled {
				t.Fatal("Artifact.Enabled = false, want true")
			}
		})
	}
}

func TestBackend_Render_targetCarriesRouteID(t *testing.T) {
	b := New(agentcaddy.NewMockClient())
	art, err := b.Render(context.Background(), sampleRoute())
	if err != nil {
		t.Fatalf("Render error: %v", err)
	}
	want := "caddy:route:domain-app-example-com"
	if art.Target.Path != want {
		t.Fatalf("Target.Path = %q, want %q", art.Target.Path, want)
	}
}

func TestBackend_Render_invalidRoute_errors(t *testing.T) {
	b := New(agentcaddy.NewMockClient())
	if _, err := b.Render(context.Background(), proxymodel.Route{}); err == nil {
		t.Fatal("Render of empty route returned nil error, want error")
	}
}

// TestBackend_Apply_replacesRouteSet verifies Apply applies the full set and
// that ReadManaged round-trips the applied content.
func TestBackend_Apply_replacesRouteSet(t *testing.T) {
	ctx := context.Background()
	b := New(agentcaddy.NewMockClient())

	art, err := b.Render(ctx, sampleRoute())
	if err != nil {
		t.Fatalf("Render error: %v", err)
	}
	if err := b.Apply(ctx, []proxy.Artifact{art}); err != nil {
		t.Fatalf("Apply error: %v", err)
	}

	managed, err := b.ReadManaged(ctx)
	if err != nil {
		t.Fatalf("ReadManaged error: %v", err)
	}
	if len(managed) != 1 {
		t.Fatalf("ReadManaged returned %d artifacts, want 1", len(managed))
	}
	if managed[0].Target.Path != art.Target.Path {
		t.Fatalf("managed target = %q, want %q", managed[0].Target.Path, art.Target.Path)
	}
}

// TestBackend_Apply_clearsPriorRoutes verifies Apply replaces (not appends to)
// the live set, matching the historical EnsureServer→Clear→Add sequence.
func TestBackend_Apply_clearsPriorRoutes(t *testing.T) {
	ctx := context.Background()
	b := New(agentcaddy.NewMockClient())

	first, _ := b.Render(ctx, sampleRoute())
	if err := b.Apply(ctx, []proxy.Artifact{first}); err != nil {
		t.Fatalf("first Apply error: %v", err)
	}

	other := sampleRoute()
	other.Host = "other.example.com"
	second, _ := b.Render(ctx, other)
	if err := b.Apply(ctx, []proxy.Artifact{second}); err != nil {
		t.Fatalf("second Apply error: %v", err)
	}

	managed, err := b.ReadManaged(ctx)
	if err != nil {
		t.Fatalf("ReadManaged error: %v", err)
	}
	if len(managed) != 1 {
		t.Fatalf("after replace, ReadManaged returned %d artifacts, want 1", len(managed))
	}
	if managed[0].Target.Path != second.Target.Path {
		t.Fatalf("live route = %q, want %q", managed[0].Target.Path, second.Target.Path)
	}
}

func TestBackend_Remove_deletesRoute(t *testing.T) {
	ctx := context.Background()
	b := New(agentcaddy.NewMockClient())

	art, _ := b.Render(ctx, sampleRoute())
	if err := b.Apply(ctx, []proxy.Artifact{art}); err != nil {
		t.Fatalf("Apply error: %v", err)
	}
	if err := b.Remove(ctx, art.Target); err != nil {
		t.Fatalf("Remove error: %v", err)
	}

	managed, err := b.ReadManaged(ctx)
	if err != nil {
		t.Fatalf("ReadManaged error: %v", err)
	}
	if len(managed) != 0 {
		t.Fatalf("after Remove, ReadManaged returned %d artifacts, want 0", len(managed))
	}
}

func TestBackend_Remove_invalidTarget_errors(t *testing.T) {
	b := New(agentcaddy.NewMockClient())
	if err := b.Remove(context.Background(), proxy.Target{Path: "not-a-caddy-handle"}); err == nil {
		t.Fatal("Remove with bad target returned nil error, want error")
	}
}

func TestBackend_Validate_readsLiveConfig(t *testing.T) {
	ctx := context.Background()
	b := New(agentcaddy.NewMockClient())
	if err := b.EnsureServer(ctx); err != nil {
		t.Fatalf("EnsureServer error: %v", err)
	}
	if err := b.Validate(ctx); err != nil {
		t.Fatalf("Validate error: %v", err)
	}
}

func TestBackend_InstallCerts_noop(t *testing.T) {
	b := New(agentcaddy.NewMockClient())
	if err := b.InstallCerts(context.Background(), []proxy.CertBundle{{Host: "x.example.com"}}); err != nil {
		t.Fatalf("InstallCerts returned error: %v, want nil (no-op this phase)", err)
	}
}

// TestBackend_satisfiesProxyInterface is a compile-time guard that the backend
// implements proxy.Proxy.
func TestBackend_satisfiesProxyInterface(t *testing.T) {
	var _ proxy.Proxy = New(agentcaddy.NewMockClient())
}

// TestFactory_registered verifies the init()-registered factory builds a backend
// via the registry, mirroring the DNS provider pattern.
func TestFactory_registered(t *testing.T) {
	p, err := proxy.Get("caddy", proxy.Config{Type: "caddy", AdminPort: 2019})
	if err != nil {
		t.Fatalf("proxy.Get(caddy) error: %v", err)
	}
	if p.Info().Kind != proxy.Kind("caddy") {
		t.Fatalf("registered backend Info().Kind = %q, want caddy", p.Info().Kind)
	}
}

// TestBackend_InstallCerts_writesBundleEncrypted verifies InstallCerts writes the
// pushed bundle into the configured cert store, encrypting the key at rest (§7).
func TestBackend_InstallCerts_writesBundleEncrypted(t *testing.T) {
	dir := t.TempDir()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	b := New(agentcaddy.NewMockClient()).WithCertStore(certstore.New(dir, key))

	keyPEM := []byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n")
	err = b.InstallCerts(context.Background(), []proxy.CertBundle{{
		Host:    "app.example.com",
		CertPEM: []byte("CERTDATA"),
		KeyPEM:  keyPEM,
	}})
	if err != nil {
		t.Fatalf("InstallCerts: %v", err)
	}

	// Key on disk must be ciphertext, but ReadKey round-trips to plaintext.
	store := certstore.New(dir, key)
	got, err := store.ReadKey("app.example.com")
	if err != nil {
		t.Fatalf("ReadKey: %v", err)
	}
	if string(got) != string(keyPEM) {
		t.Errorf("installed key = %q, want original", got)
	}
	onDisk, _ := os.ReadFile(filepath.Join(dir, "app.example.com.key.enc"))
	if bytes.Contains(onDisk, []byte("secret")) {
		t.Error("private key must not be stored in plaintext")
	}
}

// TestBackend_InstallCerts_noStore_isNoop verifies that without a cert store
// InstallCerts is a logged no-op (self-ACME fallback applies), never an error
// (invariant #4).
func TestBackend_InstallCerts_noStore_isNoop(t *testing.T) {
	b := New(agentcaddy.NewMockClient())
	if err := b.InstallCerts(context.Background(), []proxy.CertBundle{{
		Host: "app.example.com", CertPEM: []byte("c"), KeyPEM: []byte("k"),
	}}); err != nil {
		t.Fatalf("InstallCerts with no store should be a no-op, got %v", err)
	}
}

// TestBackend_InstallCerts_empty_isNoop verifies an empty bundle list is a no-op.
func TestBackend_InstallCerts_empty_isNoop(t *testing.T) {
	dir := t.TempDir()
	b := New(agentcaddy.NewMockClient()).WithCertStore(certstore.New(dir, nil))
	if err := b.InstallCerts(context.Background(), nil); err != nil {
		t.Fatalf("InstallCerts(nil) should be a no-op, got %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Error("no certs should have been written for an empty push")
	}
}

package proxy_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	// Register the nginx + apache backends so proxy.Get("nginx", ...) resolves the
	// real file backend, exercising the full hot-switch probe path.
	_ "github.com/NurRobin/NurProxy/internal/agent/proxy/apache"
	_ "github.com/NurRobin/NurProxy/internal/agent/proxy/nginx"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// fakeHealth records the last health calls so the Reconfigure tests can assert the
// non-fatal, report-via-health posture.
type fakeHealth struct {
	mu           sync.Mutex
	lastError    string
	caddyRunning bool
	caddySet     bool
}

func (f *fakeHealth) SetError(msg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastError = msg
}
func (f *fakeHealth) SetCaddyRunning(running bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.caddyRunning = running
	f.caddySet = true
}
func (f *fakeHealth) snapshot() (string, bool, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastError, f.caddyRunning, f.caddySet
}

// seedBackend is a minimal Proxy used to seed the Holder so we can observe that
// Reconfigure swaps it out for the real nginx backend.
type seedBackend struct{}

func (seedBackend) Info() proxy.Info                     { return proxy.Info{Kind: "caddy"} }
func (seedBackend) Detect(context.Context) (bool, error) { return true, nil }
func (seedBackend) Capabilities() proxy.Capabilities     { return proxy.Capabilities{} }
func (seedBackend) Render(context.Context, proxymodel.Route) (proxy.Artifact, error) {
	return proxy.Artifact{}, nil
}
func (seedBackend) ReadManaged(context.Context) ([]proxy.Artifact, error)  { return nil, nil }
func (seedBackend) Apply(context.Context, []proxy.Artifact) error          { return nil }
func (seedBackend) Remove(context.Context, proxy.Target) error             { return nil }
func (seedBackend) Validate(context.Context) error                         { return nil }
func (seedBackend) InstallCerts(context.Context, []proxy.CertBundle) error { return nil }

// nginxLayoutTempDir builds an nginx Debian-style layout under a t.TempDir so the
// permission probe's write check passes (the dirs are writable temp dirs).
func nginxLayoutTempDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"sites-available", "sites-enabled"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	return root
}

func TestReconfigureBuiltInToExisting_WritableDir(t *testing.T) {
	root := nginxLayoutTempDir(t)
	h := proxy.NewHolder(seedBackend{}, "built-in")
	hs := &fakeHealth{}

	var stopped bool
	deps := proxy.ReconfigureDeps{
		Health:    hs,
		StopCaddy: func() error { stopped = true; return nil },
		OSUser:    "agentuser",
	}

	res := h.Reconfigure(context.Background(), proxy.ReconfigureRequest{
		Mode:      "existing",
		Type:      "nginx",
		ConfigDir: root,
		// Point the test command at a binary that exists and exits 0 so the reload
		// probe sees no permission denial. "true" always succeeds.
		TestCmd: "/bin/true",
	}, deps)

	if !stopped {
		t.Error("StopCaddy should have been called when leaving built-in mode")
	}
	// The backend must have been swapped to the real nginx backend regardless of
	// probe outcome.
	if got := h.Current().Info().Kind; got != "nginx" {
		t.Errorf("Current backend kind = %q, want nginx", got)
	}
	if !res.OK {
		t.Errorf("expected OK switch with writable dir + passing reload probe, got: %+v", res)
	}
	if res.Remediation != nil {
		t.Errorf("expected no remediation on a passing probe, got %+v", res.Remediation)
	}
	_, _, caddySet := hs.snapshot()
	if !caddySet {
		t.Error("expected SetCaddyRunning to be called after leaving built-in")
	}
}

func TestReconfigureBuiltInToExisting_BogusDirFailsButSwaps(t *testing.T) {
	h := proxy.NewHolder(seedBackend{}, "built-in")
	hs := &fakeHealth{}

	var stopped bool
	deps := proxy.ReconfigureDeps{
		Health:    hs,
		StopCaddy: func() error { stopped = true; return nil },
		OSUser:    "agentuser",
	}

	res := func() (r proxy.ReconfigureResult) {
		defer func() {
			if p := recover(); p != nil {
				t.Fatalf("Reconfigure panicked on a failing probe: %v", p)
			}
		}()
		return h.Reconfigure(context.Background(), proxy.ReconfigureRequest{
			Mode:      "existing",
			Type:      "nginx",
			ConfigDir: "/nonexistent/nurproxy/bogus-config-dir",
			TestCmd:   "/bin/true",
		}, deps)
	}()

	if !stopped {
		t.Error("StopCaddy should still be called even when the probe fails")
	}
	if got := h.Current().Info().Kind; got != "nginx" {
		t.Errorf("swap should still happen on a failing probe; Current kind = %q, want nginx", got)
	}
	if res.OK {
		t.Error("expected OK=false on a failing write probe")
	}
	if res.Remediation == nil {
		t.Fatal("expected non-nil Remediation on a failing probe")
	}
	if len(res.Remediation.Steps) == 0 {
		t.Error("expected remediation steps for the missing write grant")
	}
	lastErr, _, _ := hs.snapshot()
	if lastErr == "" {
		t.Error("expected an actionable health error to be set on a failing probe")
	}
}

func TestReconfigureUnknownTypeIsNonFatal(t *testing.T) {
	h := proxy.NewHolder(seedBackend{}, "built-in")
	hs := &fakeHealth{}

	res := h.Reconfigure(context.Background(), proxy.ReconfigureRequest{
		Mode: "existing",
		Type: "does-not-exist",
	}, proxy.ReconfigureDeps{Health: hs})

	if res.OK {
		t.Error("unknown backend type should not report OK")
	}
	// The backend must NOT have been swapped to a broken backend.
	if got := h.Current().Info().Kind; got != "caddy" {
		t.Errorf("Current should stay the seed backend on a build failure, got %q", got)
	}
	if lastErr, _, _ := hs.snapshot(); lastErr == "" {
		t.Error("expected a health error explaining the unknown backend")
	}
}

func TestReconfigureBackToBuiltIn(t *testing.T) {
	h := proxy.NewHolder(seedBackend{}, "built-in")
	hs := &fakeHealth{}

	var built bool
	deps := proxy.ReconfigureDeps{
		Health: hs,
		CaddyFactory: func() proxy.Proxy {
			built = true
			return seedBackend{}
		},
	}
	res := h.Reconfigure(context.Background(), proxy.ReconfigureRequest{Mode: "built-in"}, deps)
	if !built {
		t.Error("CaddyFactory should be invoked for a switch back to built-in")
	}
	if !res.OK {
		t.Errorf("switch back to built-in should report OK (best-effort), got %+v", res)
	}
}

// TestHolderModeTracksReconfigure asserts the Holder's reported mode (§19, the
// value the heartbeat sends so the dashboard reflects reality) follows the live
// backend across hot-switches: it seeds from NewHolder, becomes "existing" after
// a successful switch to a file backend, and "built-in" again on the way back.
func TestHolderModeTracksReconfigure(t *testing.T) {
	if got := proxy.NewHolder(seedBackend{}, "").Mode(); got != "built-in" {
		t.Errorf("empty seed mode should normalize to built-in, got %q", got)
	}

	root := nginxLayoutTempDir(t)
	h := proxy.NewHolder(seedBackend{}, "built-in")
	if got := h.Mode(); got != "built-in" {
		t.Fatalf("seeded mode = %q, want built-in", got)
	}

	deps := proxy.ReconfigureDeps{
		Health:       &fakeHealth{},
		StopCaddy:    func() error { return nil },
		CaddyFactory: func() proxy.Proxy { return seedBackend{} },
	}

	h.Reconfigure(context.Background(), proxy.ReconfigureRequest{
		Mode: "existing", Type: "nginx", ConfigDir: root, TestCmd: "/bin/true",
	}, deps)
	if got := h.Mode(); got != "existing" {
		t.Errorf("mode after switch to existing = %q, want existing", got)
	}

	// Even an applied-with-warnings switch (failing probe) is still "existing": the
	// live backend was swapped, which is what the mode reports.
	h2 := proxy.NewHolder(seedBackend{}, "built-in")
	h2.Reconfigure(context.Background(), proxy.ReconfigureRequest{
		Mode: "existing", Type: "nginx", ConfigDir: "/nonexistent/bogus", TestCmd: "/bin/true",
	}, deps)
	if got := h2.Mode(); got != "existing" {
		t.Errorf("mode after applied-with-warnings switch = %q, want existing", got)
	}

	h.Reconfigure(context.Background(), proxy.ReconfigureRequest{Mode: "built-in"}, deps)
	if got := h.Mode(); got != "built-in" {
		t.Errorf("mode after switch back = %q, want built-in", got)
	}
}

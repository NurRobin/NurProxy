package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// recordingBackend is a fake backend that records which forwarded method the
// Holder called on it. It implements both proxy.Proxy and the admin-API caddyOps
// primitives, so it can stand in for the bundled caddy backend in delegation
// tests without a real Caddy.
type recordingBackend struct {
	calls map[string]int

	caps     Capabilities
	info     Info
	detect   bool
	getCfg   json.RawMessage
	rendered Artifact
	managed  []Artifact

	// err, when non-nil, is returned by the error-returning methods so the test can
	// assert the Holder forwards return values verbatim.
	err error
}

func newRecordingBackend() *recordingBackend {
	return &recordingBackend{
		calls:  map[string]int{},
		getCfg: json.RawMessage(`{"recorded":true}`),
	}
}

func (r *recordingBackend) mark(name string) { r.calls[name]++ }

func (r *recordingBackend) Info() Info { r.mark("Info"); return r.info }
func (r *recordingBackend) Detect(context.Context) (bool, error) {
	r.mark("Detect")
	return r.detect, r.err
}
func (r *recordingBackend) Capabilities() Capabilities { r.mark("Capabilities"); return r.caps }
func (r *recordingBackend) Render(context.Context, proxymodel.Route) (Artifact, error) {
	r.mark("Render")
	return r.rendered, r.err
}
func (r *recordingBackend) ReadManaged(context.Context) ([]Artifact, error) {
	r.mark("ReadManaged")
	return r.managed, r.err
}
func (r *recordingBackend) Apply(context.Context, []Artifact) error { r.mark("Apply"); return r.err }
func (r *recordingBackend) Remove(context.Context, Target) error    { r.mark("Remove"); return r.err }
func (r *recordingBackend) Validate(context.Context) error          { r.mark("Validate"); return r.err }
func (r *recordingBackend) InstallCerts(context.Context, []CertBundle) error {
	r.mark("InstallCerts")
	return r.err
}

// admin-API primitives (caddyOps).
func (r *recordingBackend) EnsureServer(context.Context) error { r.mark("EnsureServer"); return r.err }
func (r *recordingBackend) ClearRoutes(context.Context) error  { r.mark("ClearRoutes"); return r.err }
func (r *recordingBackend) AddRoute(context.Context, json.RawMessage) error {
	r.mark("AddRoute")
	return r.err
}
func (r *recordingBackend) RemoveRoute(context.Context, string) error {
	r.mark("RemoveRoute")
	return r.err
}
func (r *recordingBackend) GetConfig(context.Context) (json.RawMessage, error) {
	r.mark("GetConfig")
	return r.getCfg, r.err
}
func (r *recordingBackend) EnsureServerTLS(context.Context, []TLSIntent) error {
	r.mark("EnsureServerTLS")
	return r.err
}

// Compile-time guards: recordingBackend is a full Proxy and a full caddyOps.
var (
	_ Proxy    = (*recordingBackend)(nil)
	_ caddyOps = (*recordingBackend)(nil)
)

func TestHolderForwardsEveryMethod(t *testing.T) {
	be := newRecordingBackend()
	h := NewHolder(be, "built-in")
	ctx := context.Background()

	// Each call must hit the current backend exactly once.
	h.Info()
	h.Detect(ctx)
	h.Capabilities()
	h.Render(ctx, proxymodel.Route{})
	h.ReadManaged(ctx)
	h.Apply(ctx, nil)
	h.Remove(ctx, Target{})
	h.Validate(ctx)
	h.InstallCerts(ctx, nil)
	h.EnsureServer(ctx)
	h.ClearRoutes(ctx)
	h.AddRoute(ctx, nil)
	h.RemoveRoute(ctx, "id")
	h.GetConfig(ctx)
	h.EnsureServerTLS(ctx, nil)

	want := []string{
		"Info", "Detect", "Capabilities", "Render", "ReadManaged", "Apply",
		"Remove", "Validate", "InstallCerts", "EnsureServer", "ClearRoutes",
		"AddRoute", "RemoveRoute", "GetConfig", "EnsureServerTLS",
	}
	for _, m := range want {
		if be.calls[m] != 1 {
			t.Errorf("method %s forwarded %d times, want 1", m, be.calls[m])
		}
	}
}

func TestHolderForwardsReturnValues(t *testing.T) {
	be := newRecordingBackend()
	be.err = errors.New("boom")
	be.getCfg = json.RawMessage(`{"k":"v"}`)
	h := NewHolder(be, "built-in")
	ctx := context.Background()

	if err := h.EnsureServer(ctx); err == nil {
		t.Error("EnsureServer: expected forwarded error, got nil")
	}
	got, _ := h.GetConfig(ctx)
	if string(got) != `{"k":"v"}` {
		t.Errorf("GetConfig forwarded %s, want %s", got, `{"k":"v"}`)
	}
}

func TestHolderCurrentReflectsSwap(t *testing.T) {
	a := newRecordingBackend()
	b := newRecordingBackend()
	h := NewHolder(a, "built-in")

	if h.Current() != Proxy(a) {
		t.Fatal("Current should return the seeded backend")
	}
	h.mu.Lock()
	h.current = b
	h.mu.Unlock()
	if h.Current() != Proxy(b) {
		t.Fatal("Current should return the swapped backend")
	}
}

func TestHolderNoOpsWhenBackendIsNotAdminAPI(t *testing.T) {
	// A bare Proxy (no admin-API methods) — use a struct that only implements Proxy.
	h := NewHolder(proxyOnly{}, "built-in")
	ctx := context.Background()

	if err := h.EnsureServer(ctx); err != nil {
		t.Errorf("EnsureServer on non-admin backend: want nil no-op, got %v", err)
	}
	if err := h.ClearRoutes(ctx); err != nil {
		t.Errorf("ClearRoutes: want nil no-op, got %v", err)
	}
	if err := h.AddRoute(ctx, nil); err != nil {
		t.Errorf("AddRoute: want nil no-op, got %v", err)
	}
	if err := h.RemoveRoute(ctx, "id"); err != nil {
		t.Errorf("RemoveRoute: want nil no-op, got %v", err)
	}
	if err := h.EnsureServerTLS(ctx, nil); err != nil {
		t.Errorf("EnsureServerTLS: want nil no-op, got %v", err)
	}
	got, err := h.GetConfig(ctx)
	if err != nil || string(got) != "{}" {
		t.Errorf("GetConfig on non-admin backend = (%s, %v), want ({}, nil)", got, err)
	}
}

// proxyOnly implements only the proxy.Proxy interface (no admin-API primitives).
type proxyOnly struct{}

func (proxyOnly) Info() Info                           { return Info{} }
func (proxyOnly) Detect(context.Context) (bool, error) { return false, nil }
func (proxyOnly) Capabilities() Capabilities           { return Capabilities{} }
func (proxyOnly) Render(context.Context, proxymodel.Route) (Artifact, error) {
	return Artifact{}, nil
}
func (proxyOnly) ReadManaged(context.Context) ([]Artifact, error)  { return nil, nil }
func (proxyOnly) Apply(context.Context, []Artifact) error          { return nil }
func (proxyOnly) Remove(context.Context, Target) error             { return nil }
func (proxyOnly) Validate(context.Context) error                   { return nil }
func (proxyOnly) InstallCerts(context.Context, []CertBundle) error { return nil }

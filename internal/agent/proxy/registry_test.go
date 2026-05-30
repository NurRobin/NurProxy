package proxy

import (
	"context"
	"errors"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// fakeProxy is a no-op Proxy used to exercise the registry without a real
// backend. Only Info is meaningful for the assertions below.
type fakeProxy struct {
	kind Kind
}

func (f fakeProxy) Info() Info                           { return Info{Kind: f.kind} }
func (f fakeProxy) Detect(context.Context) (bool, error) { return false, nil }
func (f fakeProxy) Capabilities() Capabilities           { return Capabilities{} }
func (f fakeProxy) Render(context.Context, proxymodel.Route) (Artifact, error) {
	return Artifact{}, nil
}
func (f fakeProxy) ReadManaged(context.Context) ([]Artifact, error)  { return nil, nil }
func (f fakeProxy) Apply(context.Context, []Artifact) error          { return nil }
func (f fakeProxy) Remove(context.Context, Target) error             { return nil }
func (f fakeProxy) Validate(context.Context) error                   { return nil }
func (f fakeProxy) InstallCerts(context.Context, []CertBundle) error { return nil }

func TestRegisterAndGet_registeredBackend_returnsProxy(t *testing.T) {
	const name = "test-register-and-get"
	Register(name, func(cfg Config) (Proxy, error) {
		return fakeProxy{kind: Kind(cfg.Type)}, nil
	})

	p, err := Get(name, Config{Type: name})
	if err != nil {
		t.Fatalf("Get(%q) returned error: %v", name, err)
	}
	if got := p.Info().Kind; got != Kind(name) {
		t.Fatalf("Info().Kind = %q, want %q", got, name)
	}
}

func TestGet_unknownBackend_returnsError(t *testing.T) {
	_, err := Get("does-not-exist", Config{})
	if err == nil {
		t.Fatal("Get(unknown) returned nil error, want error")
	}
}

func TestGet_factoryError_propagates(t *testing.T) {
	const name = "test-factory-error"
	wantErr := errors.New("boom")
	Register(name, func(Config) (Proxy, error) {
		return nil, wantErr
	})

	_, err := Get(name, Config{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Get returned %v, want %v", err, wantErr)
	}
}

func TestRegister_invalidArgs_panics(t *testing.T) {
	tests := []struct {
		name    string
		regName string
		factory Factory
	}{
		{name: "empty name", regName: "", factory: func(Config) (Proxy, error) { return nil, nil }},
		{name: "nil factory", regName: "test-nil-factory", factory: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("Register(%q) did not panic", tc.regName)
				}
			}()
			Register(tc.regName, tc.factory)
		})
	}
}

func TestRegister_duplicateName_panics(t *testing.T) {
	const name = "test-duplicate"
	Register(name, func(Config) (Proxy, error) { return fakeProxy{}, nil })

	defer func() {
		if recover() == nil {
			t.Fatal("second Register did not panic")
		}
	}()
	Register(name, func(Config) (Proxy, error) { return fakeProxy{}, nil })
}

func TestRegistered_includesRegistered(t *testing.T) {
	const name = "test-registered-list"
	Register(name, func(Config) (Proxy, error) { return fakeProxy{}, nil })

	found := false
	for _, n := range Registered() {
		if n == name {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Registered() = %v, missing %q", Registered(), name)
	}
}

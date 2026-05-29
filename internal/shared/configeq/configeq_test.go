package configeq

import (
	"sort"
	"testing"
)

func TestRawEqual_scenarios(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{name: "identical empty", a: "", b: "", want: true},
		{name: "identical bytes", a: "server { listen 80; }", b: "server { listen 80; }", want: true},
		{name: "one differing byte", a: "listen 80;", b: "listen 81;", want: false},
		{name: "whitespace differs", a: "a b", b: "a  b", want: false},
		{name: "trailing newline differs", a: "x", b: "x\n", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RawEqual(tt.a, tt.b); got != tt.want {
				t.Fatalf("RawEqual(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestEqual_unregisteredBackend_fallsBackToRaw(t *testing.T) {
	// "nginx"/"apache" are file backends with no semantic Equaler registered in
	// this package's tests: Equal must behave like raw byte equality.
	if !Equal("nginx", "server { }", "server { }") {
		t.Fatal("Equal should report identical nginx content equal")
	}
	if Equal("nginx", "server { listen 80; }", "server { listen 81; }") {
		t.Fatal("Equal should report differing nginx content not equal")
	}
	// An entirely unknown backend name also falls back to raw, never panics.
	if !Equal("totally-unknown", "same", "same") {
		t.Fatal("unknown backend should fall back to raw equality")
	}
}

func TestEqual_registeredBackend_usesEqualer(t *testing.T) {
	// Register a fake backend that considers everything equal, to prove the
	// registry dispatches to the registered Equaler rather than raw equality.
	const backend = "configeq-test-fake"
	Register(backend, func(a, b string) bool { return true })

	if !Equal(backend, "a", "b") {
		t.Fatal("registered Equaler should have been used (all-equal), got false")
	}
}

func TestRegister_panics(t *testing.T) {
	tests := []struct {
		name    string
		backend string
		eq      Equaler
	}{
		{name: "empty name", backend: "", eq: RawEqual},
		{name: "nil equaler", backend: "configeq-test-nil", eq: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("Register(%q) should have panicked", tt.backend)
				}
			}()
			Register(tt.backend, tt.eq)
		})
	}
}

func TestRegister_duplicatePanics(t *testing.T) {
	const backend = "configeq-test-dup"
	Register(backend, RawEqual)
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate Register should have panicked")
		}
	}()
	Register(backend, RawEqual)
}

func TestRegistered_includesRegistered(t *testing.T) {
	const backend = "configeq-test-listed"
	Register(backend, RawEqual)
	names := Registered()
	sort.Strings(names)
	found := false
	for _, n := range names {
		if n == backend {
			found = true
		}
	}
	if !found {
		t.Fatalf("Registered() = %v, missing %q", names, backend)
	}
}

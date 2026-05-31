// Package configeq decides whether two pieces of config content are
// *semantically* equal for a given proxy backend (§4, §11). It is the single
// gate behind "write a new version only on semantic change": the orchestrator
// consults Equal before appending a config_artifact_versions row, so a backend
// that re-serializes its config on reload (Caddy) does not spawn phantom
// versions, and history stays small.
//
// Comparison is per-backend (§11):
//
//   - Caddy ("caddy"): semantic JSON equality of the route blob — key order and
//     insignificant whitespace are ignored, mirroring (and reusing the idea of)
//     the reconciler's routesMatch. Built-in Caddy participates here: its
//     artifact content is route JSON (Target.Kind == "caddy-route").
//   - File backends ("nginx", "apache", external caddy files): raw byte equality
//     (checksum) — the on-disk text *is* the source of truth, so any byte change
//     is a real change and any identical bytes are identical config.
//
// The package mirrors the DNS provider / proxy-backend plugin pattern
// (Register/Get + init): a backend registers an Equaler under its name; an
// unregistered backend falls back to raw equality, which is always safe (it can
// only ever produce *more* versions, never silently swallow a real change).
package configeq

import "sync"

// Equaler reports whether two config-content strings are semantically equal for
// a particular backend. Implementations MUST be pure (no I/O, no host access)
// and deterministic, so they are trivially table-driven testable — the testable
// core of the version-gating logic.
//
// Contract:
//   - Reflexive: Equal(x, x) == true for every x.
//   - Symmetric: Equal(a, b) == Equal(b, a).
//   - On unparseable input a semantic implementation MUST fall back to raw
//     equality rather than report a spurious match, so malformed content is
//     never collapsed away.
type Equaler func(a, b string) bool

var (
	mu       sync.RWMutex
	equalers = make(map[string]Equaler)
)

// Register installs an Equaler for a backend name (e.g. "caddy"). It is called
// from a backend's init(). Registering an empty name or a nil Equaler, or the
// same backend twice, panics — these are programmer errors caught at startup,
// exactly like the DNS provider and proxy-backend registries.
func Register(backend string, eq Equaler) {
	mu.Lock()
	defer mu.Unlock()
	if backend == "" {
		panic("configeq: Register called with empty backend name")
	}
	if eq == nil {
		panic("configeq: Register called with nil Equaler for " + backend)
	}
	if _, dup := equalers[backend]; dup {
		panic("configeq: Register called twice for " + backend)
	}
	equalers[backend] = eq
}

// Equal reports whether content a and b are semantically equal for the given
// backend. It is the gate the orchestrator uses before appending a version: a
// true result means "no semantic change, do not write a phantom version."
//
// If no backend-specific Equaler is registered, Equal falls back to raw byte
// equality (RawEqual). That fallback is deliberately conservative: it never
// reports a spurious match, so an unknown backend can at worst keep an
// already-identical version from being suppressed — it can never hide a real
// change.
func Equal(backend, a, b string) bool {
	mu.RLock()
	eq, ok := equalers[backend]
	mu.RUnlock()
	if !ok {
		return RawEqual(a, b)
	}
	return eq(a, b)
}

// RawEqual is the file-backend comparator: byte-for-byte equality. The on-disk
// text is the source of truth for file backends (nginx/apache, external caddy
// files), so any differing byte is a real change worth a new version.
//
// It is exported both as the registry fallback and so file backends can
// register it explicitly for clarity.
func RawEqual(a, b string) bool {
	return a == b
}

// Registered returns the names of all backends with a registered Equaler, for
// diagnostics and tests.
func Registered() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(equalers))
	for name := range equalers {
		names = append(names, name)
	}
	return names
}

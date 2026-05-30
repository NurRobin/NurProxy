// Package caddyeq registers the Caddy backend's semantic config comparator with
// the configeq registry (§4, §11). Caddy's content is route JSON; Caddy
// re-serializes it on every admin-API load (key order, whitespace, numeric
// formatting may all shift), so a raw checksum would spawn a phantom version on
// each reload. Equal compares the JSON *semantically* — structure and values,
// not byte layout — so a version is appended only on a real intent change.
//
// Built-in Caddy participates through this comparator: its artifact has
// Target.Kind == "caddy-route" and Content == route JSON, and that JSON is what
// flows through Equal.
//
// Importing this package for side effects registers the comparator:
//
//	import _ "github.com/NurRobin/NurProxy/internal/shared/configeq/caddyeq"
package caddyeq

import (
	"encoding/json"

	"github.com/NurRobin/NurProxy/internal/shared/configeq"
)

// Backend is the registry key for the Caddy backend.
const Backend = "caddy"

func init() {
	configeq.Register(Backend, Equal)
}

// Equal reports whether two Caddy route-JSON blobs are semantically equal,
// ignoring key order and insignificant whitespace. It extends the reconciler's
// routesMatch idea (normalize by unmarshal + canonical re-marshal) but compares
// the decoded values directly, so the result is independent of Go's map-key
// ordering and of any numeric re-formatting Caddy applies on reload.
//
// On unparseable input either side, Equal falls back to raw byte equality
// rather than reporting a spurious match: malformed JSON is never collapsed
// away, so we never lose a version through a parse failure.
func Equal(a, b string) bool {
	if a == b {
		return true
	}
	var va, vb any
	if err := json.Unmarshal([]byte(a), &va); err != nil {
		return configeq.RawEqual(a, b)
	}
	if err := json.Unmarshal([]byte(b), &vb); err != nil {
		return configeq.RawEqual(a, b)
	}
	return jsonValueEqual(va, vb)
}

// jsonValueEqual compares two decoded JSON values for deep semantic equality.
// Objects match regardless of key order; arrays are order-sensitive (route and
// handler order is significant in Caddy); scalars compare by value. encoding/json
// decodes every number into float64, so numeric comparison is exact for the
// values Caddy emits.
func jsonValueEqual(a, b any) bool {
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, sub := range av {
			other, ok := bv[k]
			if !ok || !jsonValueEqual(sub, other) {
				return false
			}
		}
		return true
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !jsonValueEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	default:
		// Scalars (string, float64, bool, nil): compare by value.
		return a == b
	}
}

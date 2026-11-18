// Package discovery defines the plugin interface for server discovery sources:
// systems that know about machines an agent could proxy to (a hypervisor, a
// cloud account, a network scan). A source returns candidates; the operator
// decides which of them become servers. Implementations register themselves in
// init(), the same way DNS providers do in internal/provider.
package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
)

// Discoverer is one kind of discovery source (e.g. "proxmox").
type Discoverer interface {
	Info() Info
	// ValidateConfig checks the config's shape without contacting anything.
	ValidateConfig(config json.RawMessage) error
	// Test checks that the source is reachable and the credentials work.
	Test(ctx context.Context, config json.RawMessage) error
	// Discover lists the machines the source knows about.
	Discover(ctx context.Context, config json.RawMessage) (*Result, error)
	// Summary describes the config for display. It must never include a
	// secret.
	Summary(config json.RawMessage) string
}

// IdentityKeyer is implemented by discoverers whose ExternalIDs carry a part
// that can change while the machine stays the same (a Proxmox VM migrated to
// another cluster node). IdentityKey maps an ExternalID to the part that
// stays stable; two IDs with the same key are the same machine.
type IdentityKeyer interface {
	IdentityKey(externalID string) string
}

// Info describes a discoverer type.
type Info struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// SecretFields are the config keys that hold credentials. They are never
	// returned by the API.
	SecretFields []string `json:"secret_fields"`
	// SecretBoundFields are the config keys that decide where a secret is
	// sent and how the peer is authenticated (endpoint, TLS checks). A stored
	// secret is only kept while all of them stay unchanged.
	SecretBoundFields []string `json:"secret_bound_fields,omitempty"`
}

// Candidate is one machine a source reported.
type Candidate struct {
	// ExternalID identifies the machine within its source, e.g.
	// "pve/node1/qemu/103". Imported servers keep it for de-duplication and
	// re-sync.
	ExternalID string `json:"external_id"`
	Name       string `json:"name"`
	// Kind is the source's machine type, e.g. "qemu" or "lxc".
	Kind string `json:"kind,omitempty"`
	// Location is where the machine runs inside the source, e.g. the node.
	Location string `json:"location,omitempty"`
	// Status is the source's run state, e.g. "running" or "stopped".
	Status string `json:"status,omitempty"`
	// Addresses holds every address the source reported, including the ones
	// that are never suggested (loopback, link-local, container bridges).
	Addresses []Address `json:"addresses"`
	// SuggestedAddress is the best guess for the address the agent should
	// connect to. Empty when nothing usable was found.
	SuggestedAddress string `json:"suggested_address,omitempty"`
	// AddressSource says where the addresses came from, e.g. "guest-agent".
	AddressSource string `json:"address_source,omitempty"`
	Notes         string `json:"notes,omitempty"`
}

// Result is the outcome of one discovery run.
type Result struct {
	Candidates []Candidate `json:"candidates"`
	// Warnings are non-fatal problems, e.g. a cluster node that was offline.
	Warnings []string `json:"warnings,omitempty"`
	// Incomplete lists ExternalID prefixes the run could not enumerate (for
	// Proxmox: "pve/<node>/" of an offline node). Machines under such a
	// prefix that are missing from Candidates are not reported as gone.
	Incomplete []string `json:"incomplete,omitempty"`
}

// Covers reports whether the run enumerated the part of the source that
// externalID belongs to, so its absence from the result means it is gone.
func (r *Result) Covers(externalID string) bool {
	for _, p := range r.Incomplete {
		if strings.HasPrefix(externalID, p) {
			return false
		}
	}
	return true
}

// SameMachine reports whether two ExternalIDs from the same source refer to
// the same machine.
func SameMachine(d Discoverer, a, b string) bool {
	if a == b {
		return true
	}
	if k, ok := d.(IdentityKeyer); ok {
		return k.IdentityKey(a) == k.IdentityKey(b)
	}
	return false
}

var (
	mu          sync.RWMutex
	discoverers = make(map[string]Discoverer)
)

// Register makes a discoverer available under its Info().ID.
func Register(d Discoverer) {
	mu.Lock()
	defer mu.Unlock()
	discoverers[d.Info().ID] = d
}

// Get returns the discoverer registered under id.
func Get(id string) (Discoverer, error) {
	mu.RLock()
	defer mu.RUnlock()
	d, ok := discoverers[id]
	if !ok {
		return nil, fmt.Errorf("discovery type %q not registered", id)
	}
	return d, nil
}

// List returns the registered discoverer types, sorted by ID.
func List() []Info {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Info, 0, len(discoverers))
	for _, d := range discoverers {
		out = append(out, d.Info())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ErrSecretRequired is returned by MergeConfig when an update changes a field
// the stored secret is bound to without sending the secret again.
var ErrSecretRequired = errors.New("secret required")

// MergeConfig overlays the top-level keys of update onto base. It lets a
// client change one setting of a stored config without resending the secret:
// a secret field left out or sent as an empty string keeps the stored value.
// That only holds while every field in info.SecretBoundFields stays the same;
// otherwise a stored secret could be redirected to a different endpoint or sent
// over a weaker TLS check, so every kept secret must be sent again.
func MergeConfig(base, update json.RawMessage, info Info) (json.RawMessage, error) {
	stored := map[string]json.RawMessage{}
	if len(base) > 0 {
		if err := json.Unmarshal(base, &stored); err != nil {
			return nil, fmt.Errorf("stored config is not a JSON object: %w", err)
		}
	}
	var patch map[string]json.RawMessage
	if err := json.Unmarshal(update, &patch); err != nil || patch == nil {
		return nil, errors.New("config must be a JSON object")
	}
	// encoding/json matches keys case-insensitively, so a key that only differs
	// in case from a protected one would reach the same field while the exact
	// comparison below sees no change.
	protected := append(slices.Clone(info.SecretFields), info.SecretBoundFields...)
	for k := range patch {
		for _, f := range protected {
			if k != f && strings.EqualFold(k, f) {
				return nil, fmt.Errorf("config key %q must be written %q", k, f)
			}
		}
	}
	merged := make(map[string]json.RawMessage, len(stored)+len(patch))
	for k, v := range stored {
		merged[k] = v
	}
	var kept []string
	for k, v := range patch {
		if slices.Contains(info.SecretFields, k) && isEmptyString(v) {
			continue
		}
		merged[k] = v
	}
	for _, k := range info.SecretFields {
		if v, ok := stored[k]; ok && !isEmptyString(v) && !sentNonEmpty(patch, k) {
			kept = append(kept, k)
		}
	}
	if len(kept) > 0 {
		for _, k := range info.SecretBoundFields {
			if !sameJSON(stored[k], merged[k]) {
				return nil, fmt.Errorf("%w: changing %s needs %s sent again", ErrSecretRequired, k, strings.Join(kept, ", "))
			}
		}
	}
	return json.Marshal(merged)
}

func sentNonEmpty(patch map[string]json.RawMessage, key string) bool {
	v, ok := patch[key]
	return ok && !isEmptyString(v)
}

func isEmptyString(v json.RawMessage) bool {
	var s string
	return json.Unmarshal(v, &s) == nil && s == ""
}

// sameJSON compares two JSON values by meaning, so formatting differences do
// not count as a change. An absent value, null, false, "" and 0 are all the
// unset value: a form that sends every field must not look like a change.
func sameJSON(a, b json.RawMessage) bool {
	var va, vb any
	if len(a) > 0 && json.Unmarshal(a, &va) != nil {
		return false
	}
	if len(b) > 0 && json.Unmarshal(b, &vb) != nil {
		return false
	}
	return reflect.DeepEqual(unsetToNil(va), unsetToNil(vb))
}

func unsetToNil(v any) any {
	switch x := v.(type) {
	case bool:
		if !x {
			return nil
		}
	case string:
		if x == "" {
			return nil
		}
	case float64:
		if x == 0 {
			return nil
		}
	}
	return v
}

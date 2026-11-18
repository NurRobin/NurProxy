// Package discovery defines the plugin interface for server discovery sources:
// systems that know about machines an agent could proxy to (a hypervisor, a
// cloud account, a network scan). A source returns candidates; the operator
// decides which of them become servers. Implementations register themselves in
// init(), the same way DNS providers do in internal/provider.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
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

// MergeConfig overlays the top-level keys of update onto base. It lets a
// client change one setting of a stored config without resending the secret:
// a secret field sent as an empty string keeps the stored value.
func MergeConfig(base, update json.RawMessage, secretFields []string) (json.RawMessage, error) {
	merged := map[string]json.RawMessage{}
	if len(base) > 0 {
		if err := json.Unmarshal(base, &merged); err != nil {
			return nil, fmt.Errorf("stored config is not a JSON object: %w", err)
		}
	}
	var patch map[string]json.RawMessage
	if err := json.Unmarshal(update, &patch); err != nil {
		return nil, fmt.Errorf("config must be a JSON object: %w", err)
	}
	for k, v := range patch {
		if isSecret(k, secretFields) && string(v) == `""` {
			if _, kept := merged[k]; kept {
				continue
			}
		}
		merged[k] = v
	}
	return json.Marshal(merged)
}

func isSecret(key string, secretFields []string) bool {
	for _, f := range secretFields {
		if f == key {
			return true
		}
	}
	return false
}

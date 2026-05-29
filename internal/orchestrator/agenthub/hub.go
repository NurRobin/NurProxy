// Package agenthub maintains the live, agent-initiated connections that let the
// orchestrator push configuration to agents the instant it changes — without
// ever needing to reach the agent inbound.
//
// The model mirrors how production fleet agents work (Cloudflare Tunnel,
// Tailscale, the GitHub Actions runner): the agent dials out and holds one
// long-lived connection (here, an SSE stream); the orchestrator pushes events
// down it. The open connection is also the strongest possible liveness signal —
// no inbound probing, no NAT holes, no polling lag.
package agenthub

import (
	"encoding/json"
	"sync"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// Event is a single message pushed to an agent over its stream.
type Event struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

// Event type constants.
const (
	// EventRoutes carries the agent's full desired intent set (a sync snapshot).
	// As of Phase 3 the payload is a proxymodel.IntentSet, not pre-rendered Caddy
	// JSON: the agent renders the intent natively and reports the rendered
	// artifact back in its apply-ACK (§3/B1).
	EventRoutes = "routes"
	// EventPing is a keepalive used to detect dead connections promptly.
	EventPing = "ping"
)

// subscriber is one live connection for an agent.
type subscriber struct {
	ch chan Event
}

// Hub tracks live agent connections and fans events out to them. It is safe for
// concurrent use. An agent may briefly have more than one connection (e.g. a
// reconnect racing a stale connection's teardown), so subscribers are tracked
// as a set per agent and every one receives each event.
type Hub struct {
	mu   sync.RWMutex
	subs map[string]map[*subscriber]struct{} // agentID -> set of subscribers
}

// New creates an empty Hub.
func New() *Hub {
	return &Hub{subs: make(map[string]map[*subscriber]struct{})}
}

// Subscribe registers a new connection for agentID and returns its event channel
// plus an unsubscribe function that must be called when the connection ends. The
// channel is buffered so a slow consumer doesn't block publishers; if it fills,
// further events for that connection are dropped (the agent recovers via the
// full-sync snapshot it receives on its next reconnect).
func (h *Hub) Subscribe(agentID string) (<-chan Event, func()) {
	sub := &subscriber{ch: make(chan Event, 16)}

	h.mu.Lock()
	if h.subs[agentID] == nil {
		h.subs[agentID] = make(map[*subscriber]struct{})
	}
	h.subs[agentID][sub] = struct{}{}
	h.mu.Unlock()

	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			h.mu.Lock()
			if set, ok := h.subs[agentID]; ok {
				delete(set, sub)
				if len(set) == 0 {
					delete(h.subs, agentID)
				}
			}
			h.mu.Unlock()
			close(sub.ch)
		})
	}

	return sub.ch, unsubscribe
}

// Connected reports whether the agent currently has at least one live connection.
func (h *Hub) Connected(agentID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs[agentID]) > 0
}

// Publish sends ev to every live connection for agentID. It never blocks: a
// connection whose buffer is full simply drops this event. Returns true if the
// agent had at least one connection to deliver to.
func (h *Hub) Publish(agentID string, ev Event) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	set := h.subs[agentID]
	if len(set) == 0 {
		return false
	}
	for sub := range set {
		select {
		case sub.ch <- ev:
		default:
			// Buffer full — drop. The agent re-syncs fully on reconnect.
		}
	}
	return true
}

// PublishIntents is a convenience wrapper that pushes a full intent-set snapshot
// (the agent's complete desired state) with no cert material. The agent renders
// each intent natively and reconciles its managed set against the snapshot
// (§3/B1).
func (h *Hub) PublishIntents(agentID string, intents []proxymodel.RouteIntent) bool {
	return h.PublishIntentSet(agentID, proxymodel.IntentSet{Intents: intents})
}

// PublishIntentSet pushes a full intent-set snapshot that may carry cert bundles
// alongside the intents (§5/§7). The orchestrator gathers/issues the certs first,
// then pushes them with the config in one "everything is ready, go live" message;
// the agent installs the certs (InstallCerts) before applying any referencing
// config (preflight ordering). Certs ride this agent-initiated stream — there is
// no inbound probe of the agent (invariant #2).
func (h *Hub) PublishIntentSet(agentID string, set proxymodel.IntentSet) bool {
	data, err := json.Marshal(set)
	if err != nil {
		return false
	}
	return h.Publish(agentID, Event{Type: EventRoutes, Data: data})
}

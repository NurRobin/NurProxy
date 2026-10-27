// Package notifier delivers NurProxy lifecycle events to external sinks (#72).
// This is the issue's deliberate MVP shape: a single operator-configured
// webhook that mirrors (a filtered subset of) audit events, generalizable to
// stored per-notifier configs later. The dispatcher consumes the audit stream —
// every subsystem (API, reconciler, TLS renewer, agent ACKs) already audits its
// lifecycle events there, so hooking the audit insert covers all sources
// without touching each one.
package notifier

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Event is one lifecycle occurrence delivered to a sink. It mirrors the audit
// entry shape (that is the stream it is derived from).
type Event struct {
	// Action names what happened (e.g. "renewed", "cert_ca_unreachable").
	Action string `json:"action"`
	// EntityType / EntityID identify the subject ("domain", "certificate", ...).
	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
	// Actor is who triggered it; Source the channel (ui/api/mcp/agent/system).
	Actor  string `json:"actor,omitempty"`
	Source string `json:"source,omitempty"`
	// Details is the human-readable description.
	Details string `json:"details,omitempty"`
	// Time is when the event happened (UTC).
	Time time.Time `json:"time"`
}

// Sink delivers one event to an external system. Implementations must be safe
// for concurrent use; delivery errors are the sink's to report (the dispatcher
// logs and drops — notification delivery is best-effort by design and must
// never block or fail the operation that produced the event).
type Sink interface {
	// Notify delivers the event. The context carries the delivery timeout.
	Notify(ctx context.Context, ev Event) error
}

// DefaultEvents is the curated action set delivered when the operator has not
// configured an explicit filter: state-changing and failure events an operator
// wants to hear about, WITHOUT the high-frequency routine noise (apply,
// heartbeat-driven status flaps would drown a chat channel). Keep this list
// boring: adding a noisy action here spams every default-configured webhook.
var DefaultEvents = []string{
	"renewed", "renew_failed", "issue_failed",
	"cert_rate_limited", "cert_ca_unreachable",
	"apply_failed", "drift_detected",
	"adopt", "delete", "dns_takeover",
}

// queueSize bounds the in-memory event buffer. A burst beyond it drops the
// OLDEST queued events (the newest state is the interesting one) — an
// unreachable webhook must never grow memory without bound.
const queueSize = 256

// Dispatcher fans audit-derived events out to a sink, asynchronously: Publish
// never blocks the caller beyond a queue append. Filtering happens at publish
// time against the configured action set.
type Dispatcher struct {
	sink Sink
	// filter resolves the action allow-list at publish time (nil entries =
	// DefaultEvents), so settings changes take effect without a restart.
	filter func() []string
	logger *slog.Logger

	mu     sync.Mutex
	queue  chan Event
	closed bool
}

// New builds a dispatcher over sink. filter returns the allowed action list
// (empty = DefaultEvents); it is consulted per event so config changes apply
// live. Call Start to launch the delivery worker.
func New(sink Sink, filter func() []string, logger *slog.Logger) *Dispatcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &Dispatcher{
		sink:   sink,
		filter: filter,
		logger: logger,
		queue:  make(chan Event, queueSize),
	}
}

// Start launches the delivery worker until ctx is done.
func (d *Dispatcher) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-d.queue:
				// Per-event delivery timeout; the sink implements its own retries
				// within it. A failure is logged and the event dropped — delivery
				// is best-effort and must never wedge the queue.
				dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
				if err := d.sink.Notify(dctx, ev); err != nil {
					d.logger.WarnContext(ctx, "notifier: delivery failed (event dropped)",
						slog.String("action", ev.Action),
						slog.String("entity", ev.EntityType+"/"+ev.EntityID),
						slog.Any("error", err))
				}
				cancel()
			}
		}
	}()
}

// Publish enqueues an event if its action passes the filter. Never blocks: on
// a full queue the oldest event is dropped to make room. Safe from any
// goroutine.
func (d *Dispatcher) Publish(ev Event) {
	if !d.actionAllowed(ev.Action) {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	for {
		select {
		case d.queue <- ev:
			return
		default:
			// Full: drop the oldest and retry — the newest state wins.
			select {
			case <-d.queue:
			default:
			}
		}
	}
}

func (d *Dispatcher) actionAllowed(action string) bool {
	allowed := DefaultEvents
	if d.filter != nil {
		if custom := d.filter(); len(custom) > 0 {
			allowed = custom
		}
	}
	for _, a := range allowed {
		if strings.EqualFold(strings.TrimSpace(a), action) {
			return true
		}
	}
	return false
}

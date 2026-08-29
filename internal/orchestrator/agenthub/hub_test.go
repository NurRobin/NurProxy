package agenthub

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

func TestPublishRecoveryPolicyTyped(t *testing.T) {
	h := New()
	ch, unsub := h.Subscribe("a1")
	defer unsub()

	if !h.PublishRecoveryPolicy("a1", true) {
		t.Fatal("policy should be delivered")
	}
	ev := <-ch
	if ev.Type != EventRecoveryPolicy {
		t.Fatalf("event type = %q, want %q", ev.Type, EventRecoveryPolicy)
	}
	var got proxymodel.RecoveryPolicyEnvelope
	if err := json.Unmarshal(ev.Data, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Policy.SafeAutoRepair {
		t.Fatal("safe auto repair policy was not preserved")
	}
}

func TestPublishManagedIntentSetKeepsSignedDesiredStateAtomic(t *testing.T) {
	h := New()
	ch, unsub := h.Subscribe("a1")
	defer unsub()
	set := proxymodel.IntentSet{Intents: []proxymodel.RouteIntent{{ArtifactID: "dom-1", Backend: "nginx", Route: proxymodel.Route{Host: "app.example", Upstream: proxymodel.Upstream{Addr: "10.0.0.2", Port: 8080}}}}}
	now := time.Date(2026, 8, 29, 17, 0, 0, 0, time.UTC)
	revision, err := helperprotocol.Digest(set)
	if err != nil {
		t.Fatal(err)
	}
	intent := helperprotocol.ApplyIntent{AgentID: "a1", HelperInstanceID: "helper-1", OperationID: "apply-1", DesiredStateRevision: revision, Resources: []string{"dom-1"}, Artifacts: []helperprotocol.LogicalArtifact{}, DeletionSet: []string{}, Routes: set.Intents, CertificateKeep: []string{}, AuthorizationKind: helperprotocol.AuthorizationStoredConvergence, AuthorizationEventID: "event-1", IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := helperprotocol.Sign("key-1", private, helperprotocol.NewEnvelope(helperprotocol.MessageApplyIntent, intent))
	if err != nil {
		t.Fatal(err)
	}
	if !h.PublishManagedIntentSet("a1", helperprotocol.ManagedIntentSetEnvelope{IntentSet: set, Intent: signed}) {
		t.Fatal("managed intent set was not delivered")
	}
	event := <-ch
	if event.Type != EventManagedRoutes {
		t.Fatalf("event type = %q", event.Type)
	}
	var decoded helperprotocol.ManagedIntentSetEnvelope
	if err := json.Unmarshal(event.Data, &decoded); err != nil || decoded.Validate() != nil {
		t.Fatalf("invalid managed envelope: %v", err)
	}
}

func TestPublishRepairRequestTyped(t *testing.T) {
	h := New()
	ch, unsub := h.Subscribe("a1")
	defer unsub()
	now := time.Now().UTC()
	want := recoverymodel.RepairRequest{OperationID: "op-1", DiagnosticID: "diag-1", Action: recoverymodel.ActionRemoveManagedTemp, StartedAt: now, InitialStep: recoverymodel.Step{Name: "planned", State: recoverymodel.OperationStatePlanned, At: now}}

	if !h.PublishRepairRequest("a1", want) {
		t.Fatal("repair request should be delivered")
	}
	ev := <-ch
	if ev.Type != EventRepairRequest {
		t.Fatalf("event type = %q, want %q", ev.Type, EventRepairRequest)
	}
	var got proxymodel.RepairRequestEnvelope
	if err := json.Unmarshal(ev.Data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Request != want {
		t.Fatalf("request = %#v, want %#v", got.Request, want)
	}
	if h.PublishRepairRequest("a1", recoverymodel.RepairRequest{}) {
		t.Fatal("invalid repair request must fail closed")
	}
}

func TestPublishToSubscriber(t *testing.T) {
	h := New()
	ch, unsub := h.Subscribe("a1")
	defer unsub()

	if !h.Connected("a1") {
		t.Fatal("expected a1 connected after Subscribe")
	}

	if !h.Publish("a1", Event{Type: EventPing}) {
		t.Fatal("Publish should report delivery to a connected agent")
	}

	ev := <-ch
	if ev.Type != EventPing {
		t.Errorf("got event type %q, want %q", ev.Type, EventPing)
	}
}

func TestPublishToUnknownAgent(t *testing.T) {
	h := New()
	if h.Connected("ghost") {
		t.Fatal("unknown agent should not be connected")
	}
	if h.Publish("ghost", Event{Type: EventPing}) {
		t.Error("Publish to an unconnected agent should return false")
	}
}

func TestUnsubscribeRemovesAgent(t *testing.T) {
	h := New()
	_, unsub := h.Subscribe("a1")
	unsub()
	if h.Connected("a1") {
		t.Error("agent should be disconnected after unsubscribe")
	}
	// Unsubscribing twice must be safe (idempotent).
	unsub()
}

func TestMultipleSubscribersBothReceive(t *testing.T) {
	h := New()
	ch1, unsub1 := h.Subscribe("a1")
	defer unsub1()
	ch2, unsub2 := h.Subscribe("a1")
	defer unsub2()

	h.Publish("a1", Event{Type: EventPing})

	for i, ch := range []<-chan Event{ch1, ch2} {
		select {
		case ev := <-ch:
			if ev.Type != EventPing {
				t.Errorf("subscriber %d: got %q", i, ev.Type)
			}
		default:
			t.Errorf("subscriber %d did not receive the event", i)
		}
	}
}

func TestPublishIntents(t *testing.T) {
	h := New()
	ch, unsub := h.Subscribe("a1")
	defer unsub()

	intents := []proxymodel.RouteIntent{{
		ArtifactID: "dom-1",
		Backend:    "caddy",
		Route:      proxymodel.Route{Host: "app.example.com"},
	}}
	if !h.PublishIntents("a1", intents) {
		t.Fatal("PublishIntents should deliver")
	}

	ev := <-ch
	if ev.Type != EventRoutes {
		t.Fatalf("got type %q, want %q", ev.Type, EventRoutes)
	}
	var got proxymodel.IntentSet
	if err := json.Unmarshal(ev.Data, &got); err != nil {
		t.Fatalf("unmarshal intents: %v", err)
	}
	if len(got.Intents) != 1 {
		t.Fatalf("got %d intents, want 1", len(got.Intents))
	}
	if got.Intents[0].ArtifactID != "dom-1" || got.Intents[0].Route.Host != "app.example.com" {
		t.Errorf("unexpected intent: %+v", got.Intents[0])
	}
}

func TestSubscribeCapsConcurrentStreamsPerAgent(t *testing.T) {
	h := New()

	chans := make([]<-chan Event, 0, maxStreamsPerAgent+1)
	for i := 0; i < maxStreamsPerAgent+1; i++ {
		ch, unsub := h.Subscribe("a1")
		defer unsub()
		chans = append(chans, ch)
	}

	// Only maxStreamsPerAgent streams may remain registered.
	h.mu.RLock()
	got := len(h.subs["a1"])
	h.mu.RUnlock()
	if got != maxStreamsPerAgent {
		t.Fatalf("agent has %d streams, want cap of %d", got, maxStreamsPerAgent)
	}

	// The oldest stream (chans[0]) must have been evicted: its channel is closed.
	select {
	case _, ok := <-chans[0]:
		if ok {
			t.Fatal("oldest stream should be evicted (channel closed), got a value")
		}
	default:
		t.Fatal("oldest stream channel should be closed after eviction, but it blocked")
	}

	// The surviving (newest) stream still receives events.
	if !h.Publish("a1", Event{Type: EventPing}) {
		t.Fatal("Publish should deliver to surviving stream")
	}
	newest := chans[len(chans)-1]
	select {
	case ev := <-newest:
		if ev.Type != EventPing {
			t.Errorf("got %q, want %q", ev.Type, EventPing)
		}
	default:
		t.Fatal("newest stream did not receive the event")
	}
}

func TestSubscribeCapIsPerAgentIndependent(t *testing.T) {
	h := New()

	// Saturate a1's cap.
	for i := 0; i < maxStreamsPerAgent+2; i++ {
		_, unsub := h.Subscribe("a1")
		defer unsub()
	}
	// a2 is a different agent and must be unaffected by a1's eviction.
	ch2, unsub2 := h.Subscribe("a2")
	defer unsub2()

	h.mu.RLock()
	gotA1 := len(h.subs["a1"])
	gotA2 := len(h.subs["a2"])
	h.mu.RUnlock()
	if gotA1 != maxStreamsPerAgent {
		t.Errorf("a1 has %d streams, want cap of %d", gotA1, maxStreamsPerAgent)
	}
	if gotA2 != 1 {
		t.Errorf("a2 has %d streams, want 1 (independent of a1)", gotA2)
	}

	if !h.Publish("a2", Event{Type: EventPing}) {
		t.Fatal("Publish to a2 should deliver")
	}
	select {
	case ev := <-ch2:
		if ev.Type != EventPing {
			t.Errorf("a2: got %q, want %q", ev.Type, EventPing)
		}
	default:
		t.Fatal("a2 stream did not receive the event")
	}
}

func TestEvictedStreamUnsubscribeIsSafe(t *testing.T) {
	h := New()

	// First stream will be evicted by the (maxStreamsPerAgent+1)-th Subscribe.
	_, unsubEvicted := h.Subscribe("a1")
	for i := 0; i < maxStreamsPerAgent; i++ {
		_, unsub := h.Subscribe("a1")
		defer unsub()
	}

	// Calling unsubscribe on an already-evicted stream must not panic
	// (double-close) and must leave the surviving streams intact.
	unsubEvicted()
	unsubEvicted() // idempotent

	h.mu.RLock()
	got := len(h.subs["a1"])
	h.mu.RUnlock()
	if got != maxStreamsPerAgent {
		t.Fatalf("agent has %d streams after evicted unsubscribe, want %d", got, maxStreamsPerAgent)
	}
}

func TestPublishDoesNotBlockWhenBufferFull(t *testing.T) {
	h := New()
	// Subscribe but never drain — fill past the buffer to prove Publish drops
	// rather than blocks.
	_, unsub := h.Subscribe("a1")
	defer unsub()
	for i := 0; i < 100; i++ {
		h.Publish("a1", Event{Type: EventPing})
	}
}

func TestPublishReportsWhetherAnySubscriberActuallyEnqueued(t *testing.T) {
	h := New()
	first, unsubFirst := h.Subscribe("a1")
	defer unsubFirst()
	second, unsubSecond := h.Subscribe("a1")
	defer unsubSecond()

	for i := 0; i < cap(first); i++ {
		if !h.Publish("a1", Event{Type: EventPing}) {
			t.Fatalf("fill publish %d unexpectedly failed", i)
		}
	}
	if h.Publish("a1", Event{Type: EventPing}) {
		t.Fatal("publish with every subscriber buffer full reported delivery")
	}

	<-second
	if !h.Publish("a1", Event{Type: EventPing}) {
		t.Fatal("publish with one available subscriber did not report delivery")
	}
}

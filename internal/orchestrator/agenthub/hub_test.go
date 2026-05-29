package agenthub

import (
	"encoding/json"
	"testing"
)

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

func TestPublishRoutes(t *testing.T) {
	h := New()
	ch, unsub := h.Subscribe("a1")
	defer unsub()

	routes := []json.RawMessage{json.RawMessage(`{"@id":"r1"}`)}
	if !h.PublishRoutes("a1", routes) {
		t.Fatal("PublishRoutes should deliver")
	}

	ev := <-ch
	if ev.Type != EventRoutes {
		t.Fatalf("got type %q, want %q", ev.Type, EventRoutes)
	}
	var got []json.RawMessage
	if err := json.Unmarshal(ev.Data, &got); err != nil {
		t.Fatalf("unmarshal routes: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %d routes, want 1", len(got))
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

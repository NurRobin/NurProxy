package notifier

import (
	"context"
	"sync"
	"testing"
	"time"
)

// captureSink records delivered events.
type captureSink struct {
	mu     sync.Mutex
	events []Event
}

func (s *captureSink) Notify(_ context.Context, ev Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	return nil
}

func (s *captureSink) list() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.events...)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached in time")
}

func TestDispatcher_defaultFilterAndDelivery(t *testing.T) {
	sink := &captureSink{}
	d := New(sink, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)

	// A curated-default action is delivered; routine noise is not.
	d.Publish(Event{Action: "renewed", EntityType: "certificate", EntityID: "a.example.com"})
	d.Publish(Event{Action: "apply", EntityType: "domain", EntityID: "1"}) // not in defaults
	d.Publish(Event{Action: "heartbeat", EntityType: "agent", EntityID: "x"})

	waitFor(t, func() bool { return len(sink.list()) >= 1 })
	got := sink.list()
	if len(got) != 1 || got[0].Action != "renewed" {
		t.Errorf("delivered = %+v, want exactly the renewed event", got)
	}
}

func TestDispatcher_customFilter(t *testing.T) {
	sink := &captureSink{}
	d := New(sink, func() []string { return []string{"apply", " CREATE "} }, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)

	d.Publish(Event{Action: "apply"})
	d.Publish(Event{Action: "create"}) // filter entries are trimmed + case-insensitive
	d.Publish(Event{Action: "renewed"})

	waitFor(t, func() bool { return len(sink.list()) >= 2 })
	if got := sink.list(); len(got) != 2 {
		t.Errorf("delivered = %+v, want apply + create only", got)
	}
}

func TestDispatcher_publishNeverBlocksOnFullQueue(t *testing.T) {
	// No worker started: the queue fills. Publish must still return (dropping
	// the oldest), never deadlock the audit path feeding it.
	d := New(&captureSink{}, func() []string { return []string{"x"} }, nil)
	done := make(chan struct{})
	go func() {
		for i := 0; i < queueSize*3; i++ {
			d.Publish(Event{Action: "x"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Publish blocked on a full queue")
	}
}

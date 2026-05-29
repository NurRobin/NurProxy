package stream

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/caddy"
	"github.com/NurRobin/NurProxy/internal/agent/health"
)

func TestStreamAppliesRoutesAndAcks(t *testing.T) {
	ackCh := make(chan map[string]interface{}, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/agents/{id}/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()

		routes := `[{"@id":"r1","match":[{"host":["app.example.com"]}]}]`
		fmt.Fprintf(w, "event: routes\ndata: %s\n\n", routes)
		w.(http.Flusher).Flush()

		// Hold the connection open until the client goes away, so it doesn't
		// reconnect in a tight loop during the test.
		<-r.Context().Done()
	})
	mux.HandleFunc("POST /api/v1/agents/{id}/routes/ack", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]interface{}
		_ = json.Unmarshal(body, &parsed)
		ackCh <- parsed
		w.WriteHeader(http.StatusOK)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := New(ts.URL, "agent-1", "tok", caddy.NewMockClient(), health.New())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	select {
	case ack := <-ackCh:
		applied, ok := ack["applied"].([]interface{})
		if !ok || len(applied) != 1 {
			t.Fatalf("expected 1 applied route, got %#v", ack["applied"])
		}
		if got := applied[0].(string); got != "app.example.com" {
			t.Errorf("applied host = %q, want app.example.com", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for route ack")
	}
}

func TestStreamReconnectsOnError(t *testing.T) {
	var attempts int
	done := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/agents/{id}/stream", func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			// First attempt: fail so the client must retry.
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		close(done)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := New(ts.URL, "agent-1", "tok", caddy.NewMockClient(), health.New())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	select {
	case <-done:
		// Reconnected successfully after the initial failure.
	case <-time.After(5 * time.Second):
		t.Fatal("client did not reconnect after an error")
	}
}

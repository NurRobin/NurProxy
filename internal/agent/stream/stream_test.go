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
	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	caddybackend "github.com/NurRobin/NurProxy/internal/agent/proxy/caddy"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

func TestStreamRendersIntentAppliesAndAcks(t *testing.T) {
	ackCh := make(chan proxymodel.ApplyAck, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/agents/{id}/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()

		// The orchestrator now pushes intent, not pre-rendered Caddy JSON.
		set := proxymodel.IntentSet{Intents: []proxymodel.RouteIntent{{
			ArtifactID: "dom-7",
			Backend:    "caddy",
			Route: proxymodel.Route{
				Host:     "app.example.com",
				Upstream: proxymodel.Upstream{Addr: "10.0.0.1", Port: 8080},
			},
		}}}
		data, _ := json.Marshal(set)
		fmt.Fprintf(w, "event: routes\ndata: %s\n\n", data)
		w.(http.Flusher).Flush()

		// Hold the connection open until the client goes away, so it doesn't
		// reconnect in a tight loop during the test.
		<-r.Context().Done()
	})
	mux.HandleFunc("POST /api/v1/agents/{id}/routes/ack", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed proxymodel.ApplyAck
		_ = json.Unmarshal(body, &parsed)
		ackCh <- parsed
		w.WriteHeader(http.StatusOK)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	backend := caddybackend.New(caddy.NewMockClient())
	c := New(ts.URL, "agent-1", "tok", backend, health.New())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	select {
	case ack := <-ackCh:
		if len(ack.Reports) != 1 {
			t.Fatalf("expected 1 artifact report, got %d", len(ack.Reports))
		}
		rep := ack.Reports[0]
		if rep.ArtifactID != "dom-7" {
			t.Errorf("report artifact id = %q, want dom-7", rep.ArtifactID)
		}
		if rep.Host != "app.example.com" {
			t.Errorf("report host = %q, want app.example.com", rep.Host)
		}
		if rep.Error != "" {
			t.Errorf("unexpected apply error: %q", rep.Error)
		}
		// The agent renders natively and round-trips content + checksum.
		if rep.Content == "" {
			t.Error("report should carry rendered content")
		}
		if rep.Checksum != checksum(rep.Content) {
			t.Errorf("report checksum %q does not match content", rep.Checksum)
		}
		if rep.TargetKind != "caddy-route" {
			t.Errorf("report target kind = %q, want caddy-route", rep.TargetKind)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for apply ack")
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

	c := New(ts.URL, "agent-1", "tok", caddybackend.New(caddy.NewMockClient()), health.New())
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

// orderingBackend records the order of InstallCerts vs route-apply calls so the
// preflight ordering (§5) can be asserted: certs must be installed BEFORE Apply of
// the referencing config.
type orderingBackend struct {
	calls       []string
	installedCN string
}

func (o *orderingBackend) EnsureServer(ctx context.Context) error { return nil }
func (o *orderingBackend) ClearRoutes(ctx context.Context) error  { return nil }
func (o *orderingBackend) AddRoute(ctx context.Context, route json.RawMessage) error {
	o.calls = append(o.calls, "apply")
	return nil
}
func (o *orderingBackend) Render(ctx context.Context, route proxymodel.Route) (proxy.Artifact, error) {
	return proxy.Artifact{
		Target:  proxy.Target{Kind: proxy.TargetKindCaddyRoute, Path: "caddy:route:r1"},
		Content: `{"@id":"r1"}`,
		Enabled: true,
	}, nil
}
func (o *orderingBackend) InstallCerts(ctx context.Context, certs []proxy.CertBundle) error {
	o.calls = append(o.calls, "install")
	if len(certs) > 0 {
		o.installedCN = certs[0].Host
	}
	return nil
}

func TestApplyIntents_installsCertsBeforeApply(t *testing.T) {
	be := &orderingBackend{}
	c := New("http://unused", "agent-1", "tok", be, health.New())

	set := proxymodel.IntentSet{
		Intents: []proxymodel.RouteIntent{{
			ArtifactID: "dom-1",
			Backend:    "caddy",
			Route:      proxymodel.Route{Host: "app.example.com", Upstream: proxymodel.Upstream{Addr: "10.0.0.1", Port: 80}},
		}},
		Certs: []proxymodel.CertBundle{{
			Host:    "app.example.com",
			CertPEM: "CERT",
			KeyPEM:  "KEY",
		}},
	}

	// sendAck POSTs to a dead URL; that is fine — we only assert call ordering.
	c.applyIntents(context.Background(), set)

	if be.installedCN != "app.example.com" {
		t.Errorf("installed cert host = %q, want app.example.com", be.installedCN)
	}
	// The first cert-related/apply call must be the install, and it must precede
	// every apply.
	firstInstall, firstApply := -1, -1
	for i, call := range be.calls {
		if call == "install" && firstInstall == -1 {
			firstInstall = i
		}
		if call == "apply" && firstApply == -1 {
			firstApply = i
		}
	}
	if firstInstall == -1 {
		t.Fatal("InstallCerts was never called")
	}
	if firstApply == -1 {
		t.Fatal("Apply was never called")
	}
	if firstInstall > firstApply {
		t.Errorf("preflight violated: install at %d came after apply at %d (calls=%v)", firstInstall, firstApply, be.calls)
	}
}

func TestApplyIntents_noCerts_doesNotInstall(t *testing.T) {
	be := &orderingBackend{}
	c := New("http://unused", "agent-1", "tok", be, health.New())

	c.applyIntents(context.Background(), proxymodel.IntentSet{
		Intents: []proxymodel.RouteIntent{{
			ArtifactID: "dom-1", Backend: "caddy",
			Route: proxymodel.Route{Host: "h.example.com", Upstream: proxymodel.Upstream{Addr: "1.1.1.1", Port: 80}},
		}},
	})

	for _, call := range be.calls {
		if call == "install" {
			t.Error("InstallCerts should not run when no certs are pushed")
		}
	}
}

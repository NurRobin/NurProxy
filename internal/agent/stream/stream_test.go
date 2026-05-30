package stream

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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

func TestLogTail_followsAllowedFile_postsChunks_stopsOnStop(t *testing.T) {
	chunkCh := make(chan proxymodel.LogChunk, 32)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agents/{id}/logs/chunk", func(w http.ResponseWriter, r *http.Request) {
		var ch proxymodel.LogChunk
		_ = json.NewDecoder(r.Body).Decode(&ch)
		chunkCh <- ch
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	dir := t.TempDir()
	logPath := dir + "/access.log"
	if err := os.WriteFile(logPath, []byte("backlog1\nbacklog2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	backend := caddybackend.New(caddy.NewMockClient())
	c := New(ts.URL, "agent-1", "tok", backend, health.New()).WithLogPaths([]string{dir})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.startLogTail(ctx, proxymodel.LogTailRequest{SessionID: "s1", Path: logPath, Lines: 10})

	var got []string
	deadline := time.After(3 * time.Second)
	for len(got) < 2 {
		select {
		case ch := <-chunkCh:
			if ch.Error != "" {
				t.Fatalf("unexpected chunk error: %s", ch.Error)
			}
			got = append(got, ch.Lines...)
		case <-deadline:
			t.Fatalf("timed out waiting for backlog; got %v", got)
		}
	}
	if got[0] != "backlog1" || got[1] != "backlog2" {
		t.Fatalf("backlog = %v, want [backlog1 backlog2]", got)
	}

	// Stopping the session must cancel the tailer and emit a terminal EOF chunk.
	c.stopLogTail("s1")
	select {
	case ch := <-chunkCh:
		if !ch.EOF {
			// A late follow chunk may arrive first; drain until EOF.
			for {
				select {
				case ch2 := <-chunkCh:
					if ch2.EOF {
						return
					}
				case <-time.After(2 * time.Second):
					t.Fatal("no EOF chunk after stop")
				}
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no chunk after stop")
	}
}

func TestLogTail_refusesPathOutsideAllowlist_postsErrorChunk(t *testing.T) {
	chunkCh := make(chan proxymodel.LogChunk, 4)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agents/{id}/logs/chunk", func(w http.ResponseWriter, r *http.Request) {
		var ch proxymodel.LogChunk
		_ = json.NewDecoder(r.Body).Decode(&ch)
		chunkCh <- ch
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	backend := caddybackend.New(caddy.NewMockClient())
	c := New(ts.URL, "agent-1", "tok", backend, health.New()).WithLogPaths([]string{"/var/log/nginx"})

	c.startLogTail(context.Background(), proxymodel.LogTailRequest{SessionID: "bad", Path: "/etc/passwd"})

	select {
	case ch := <-chunkCh:
		if ch.Error == "" {
			t.Fatal("expected a terminal error chunk for a disallowed path")
		}
		if !ch.EOF {
			t.Error("refusal chunk should be terminal (EOF)")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no error chunk for disallowed path")
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
	tlsIntents  []proxy.TLSIntent
}

func (o *orderingBackend) EnsureServer(ctx context.Context) error { return nil }
func (o *orderingBackend) ClearRoutes(ctx context.Context) error  { return nil }
func (o *orderingBackend) AddRoute(ctx context.Context, route json.RawMessage) error {
	o.calls = append(o.calls, "apply")
	return nil
}
func (o *orderingBackend) Apply(ctx context.Context, arts []proxy.Artifact) error {
	o.calls = append(o.calls, "fileapply")
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
func (o *orderingBackend) EnsureServerTLS(ctx context.Context, intents []proxy.TLSIntent) error {
	o.calls = append(o.calls, "tls")
	o.tlsIntents = intents
	return nil
}
func (o *orderingBackend) Prune(ctx context.Context, keep []proxy.Target) (int, error) {
	o.calls = append(o.calls, "prune")
	return 0, nil
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

	// TLS strategy must be configured after the certs are installed and before any
	// route is applied (§7: built-in Caddy serves provided certs from the start).
	firstTLS := -1
	for i, call := range be.calls {
		if call == "tls" {
			firstTLS = i
			break
		}
	}
	if firstTLS == -1 {
		t.Fatal("EnsureServerTLS was never called")
	}
	if firstTLS < firstInstall {
		t.Errorf("TLS configured at %d before cert install at %d (calls=%v)", firstTLS, firstInstall, be.calls)
	}
	if firstTLS > firstApply {
		t.Errorf("TLS configured at %d after route apply at %d (calls=%v)", firstTLS, firstApply, be.calls)
	}
	// A host with no explicit policy defaults to central provided certs (§7).
	if len(be.tlsIntents) != 1 || be.tlsIntents[0].Policy != proxymodel.TLSPolicyCentral {
		t.Errorf("tls intents = %+v, want one central-policy host", be.tlsIntents)
	}
}

func TestApplyIntents_selfACMEPolicyFlowsToBackend(t *testing.T) {
	be := &orderingBackend{}
	c := New("http://unused", "agent-1", "tok", be, health.New())

	c.applyIntents(context.Background(), proxymodel.IntentSet{
		Intents: []proxymodel.RouteIntent{{
			ArtifactID: "dom-1", Backend: "caddy",
			Route: proxymodel.Route{
				Host:     "fallback.example.com",
				Upstream: proxymodel.Upstream{Addr: "1.1.1.1", Port: 80},
				TLS:      proxymodel.TLSConfig{Policy: proxymodel.TLSPolicySelfACME},
			},
		}},
	})

	if len(be.tlsIntents) != 1 {
		t.Fatalf("expected 1 tls intent, got %d", len(be.tlsIntents))
	}
	if be.tlsIntents[0].Policy != proxymodel.TLSPolicySelfACME {
		t.Errorf("policy = %q, want self-acme (the explicit fallback)", be.tlsIntents[0].Policy)
	}
}

// fileBackend is a fake file-based proxy backend: Render emits a file-kind
// artifact and Apply writes its content to disk (the real backends do this
// atomically). It records whether AddRoute was (wrongly) used so the test can
// prove file artifacts go through Apply, not the admin-API no-op.
type fileBackend struct {
	path        string
	content     string
	addRouteHit bool
	applyHit    bool
	applyErr    error
	pruneKeep   []proxy.Target // records the keep set Prune was last called with
	pruneHit    bool
}

func (f *fileBackend) EnsureServer(ctx context.Context) error { return nil }
func (f *fileBackend) ClearRoutes(ctx context.Context) error  { return nil }
func (f *fileBackend) AddRoute(ctx context.Context, route json.RawMessage) error {
	f.addRouteHit = true
	return nil
}
func (f *fileBackend) Apply(ctx context.Context, arts []proxy.Artifact) error {
	f.applyHit = true
	if f.applyErr != nil {
		return f.applyErr
	}
	for _, a := range arts {
		if err := os.WriteFile(a.Target.Path, []byte(a.Content), 0o644); err != nil {
			return err
		}
	}
	return nil
}
func (f *fileBackend) Render(ctx context.Context, route proxymodel.Route) (proxy.Artifact, error) {
	return proxy.Artifact{
		Target:  proxy.Target{Kind: proxy.TargetKindFile, Path: f.path},
		Content: f.content,
		Enabled: true,
	}, nil
}
func (f *fileBackend) InstallCerts(ctx context.Context, certs []proxy.CertBundle) error { return nil }
func (f *fileBackend) EnsureServerTLS(ctx context.Context, intents []proxy.TLSIntent) error {
	return nil
}
func (f *fileBackend) Prune(ctx context.Context, keep []proxy.Target) (int, error) {
	f.pruneHit = true
	f.pruneKeep = keep
	return 0, nil
}

// TestApplyIntents_fileBackendWritesViaApply proves a file backend applies config
// through Apply (write/validate/reload) rather than the admin-API AddRoute no-op,
// and that the heartbeat drift signal re-reads the on-disk file so a manual edit
// surfaces as drift.
func TestApplyIntents_fileBackendWritesViaApply(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/app.conf"
	be := &fileBackend{path: path, content: "server { listen 80; }"}
	c := New("http://unused", "agent-1", "tok", be, health.New())

	c.applyIntents(context.Background(), proxymodel.IntentSet{
		Intents: []proxymodel.RouteIntent{{
			ArtifactID: "dom-1", Backend: "nginx",
			Route: proxymodel.Route{Host: "app.example.com", Upstream: proxymodel.Upstream{Addr: "10.0.0.1", Port: 80}},
		}},
	})

	if be.addRouteHit {
		t.Error("file artifact must not go through the admin-API AddRoute no-op")
	}
	if !be.applyHit {
		t.Fatal("file artifact was never applied via Apply")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != be.content {
		t.Fatalf("Apply did not write the config: content=%q err=%v", got, err)
	}
	// applyIntents prunes orphaned vhosts over the stream (§3): Prune is called with
	// the desired file targets so a deleted domain's leftover gets removed.
	if !be.pruneHit {
		t.Error("applyIntents must call Prune to remove orphaned vhosts")
	}
	if len(be.pruneKeep) != 1 || be.pruneKeep[0].Path != path {
		t.Errorf("Prune keep set = %+v, want the one desired target %q", be.pruneKeep, path)
	}

	// The managed checksum tracks the artifact and matches the on-disk content.
	sums := c.ManagedChecksums()
	if len(sums) != 1 || sums[0].ArtifactID != "dom-1" {
		t.Fatalf("expected one managed checksum for dom-1, got %+v", sums)
	}
	if sums[0].Checksum != checksum(be.content) {
		t.Errorf("managed checksum %q does not match applied content", sums[0].Checksum)
	}

	// A manual on-disk edit must surface as a different checksum (drift, §11) —
	// the in-memory apply-time checksum alone would miss it.
	if err := os.WriteFile(path, []byte("server { listen 8080; }"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := c.ManagedChecksums(); got[0].Checksum == checksum(be.content) {
		t.Error("heartbeat drift signal did not re-read the on-disk file after a manual edit")
	}
}

// TestApplyIntents_keepRetainsDriftedArtifactInManaged proves the §11 drift
// auto-clear fix: when a later push omits an artifact but lists its path in Keep
// (the orchestrator skipped a drifted artifact awaiting review), the agent carries
// it forward in the managed set so the heartbeat keeps reporting its checksum — the
// drift can still clear when the operator reverts and drift_content can refresh.
func TestApplyIntents_keepRetainsDriftedArtifactInManaged(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/app.conf"
	be := &fileBackend{path: path, content: "server { listen 80; }"}
	c := New("http://unused", "agent-1", "tok", be, health.New())

	// First push applies dom-1 → tracked in managed.
	c.applyIntents(context.Background(), proxymodel.IntentSet{
		Intents: []proxymodel.RouteIntent{{
			ArtifactID: "dom-1", Backend: "nginx",
			Route: proxymodel.Route{Host: "app.example.com", Upstream: proxymodel.Upstream{Addr: "10.0.0.1", Port: 80}},
		}},
	})
	if sums := c.ManagedChecksums(); len(sums) != 1 {
		t.Fatalf("after first apply: expected 1 managed, got %d", len(sums))
	}

	// Second push omits dom-1 from intents but retains its path via Keep (the
	// orchestrator skipped it because it drifted). It must stay tracked.
	c.applyIntents(context.Background(), proxymodel.IntentSet{
		Intents: nil,
		Keep:    []string{path},
	})
	sums := c.ManagedChecksums()
	if len(sums) != 1 || sums[0].ArtifactID != "dom-1" {
		t.Fatalf("Keep'd drifted artifact dropped from managed: %+v", sums)
	}

	// A third push WITHOUT the path in Keep (domain truly deleted) drops it.
	c.applyIntents(context.Background(), proxymodel.IntentSet{Intents: nil})
	if sums := c.ManagedChecksums(); len(sums) != 0 {
		t.Fatalf("artifact not in intents or Keep should be dropped, got %+v", sums)
	}
}

// TestApplyIntents_fileBackendApplyFailureAttributed proves a failed batch Apply
// is reported as a per-artifact error and leaves nothing tracked as live.
func TestApplyIntents_fileBackendApplyFailureAttributed(t *testing.T) {
	ackCh := make(chan proxymodel.ApplyAck, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agents/{id}/routes/ack", func(w http.ResponseWriter, r *http.Request) {
		var parsed proxymodel.ApplyAck
		_ = json.NewDecoder(r.Body).Decode(&parsed)
		ackCh <- parsed
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	be := &fileBackend{path: t.TempDir() + "/x.conf", content: "bad", applyErr: fmt.Errorf("nginx -t failed")}
	c := New(ts.URL, "agent-1", "tok", be, health.New())

	c.applyIntents(context.Background(), proxymodel.IntentSet{
		Intents: []proxymodel.RouteIntent{{
			ArtifactID: "dom-1", Backend: "nginx",
			Route: proxymodel.Route{Host: "app.example.com", Upstream: proxymodel.Upstream{Addr: "10.0.0.1", Port: 80}},
		}},
	})

	select {
	case ack := <-ackCh:
		if len(ack.Reports) != 1 || ack.Reports[0].Error == "" {
			t.Fatalf("a failed batch Apply must be attributed per-artifact: %+v", ack.Reports)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for ack")
	}
	if len(c.ManagedChecksums()) != 0 {
		t.Error("a failed apply must not track the artifact as live (false drift)")
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

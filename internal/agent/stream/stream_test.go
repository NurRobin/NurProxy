package stream

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/caddy"
	"github.com/NurRobin/NurProxy/internal/agent/health"
	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	caddybackend "github.com/NurRobin/NurProxy/internal/agent/proxy/caddy"
	nginxproxy "github.com/NurRobin/NurProxy/internal/agent/proxy/nginx"
	"github.com/NurRobin/NurProxy/internal/agent/recovery"
	"github.com/NurRobin/NurProxy/internal/agent/recoverycontrol"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

type managedApplierMock struct {
	calls   int
	receipt helperprotocol.Signed[helperprotocol.HelperReceipt]
	err     error
}

func (m *managedApplierMock) Apply(context.Context, helperprotocol.ManagedIntentSetEnvelope) (helperprotocol.Signed[helperprotocol.HelperReceipt], error) {
	m.calls++
	return m.receipt, m.err
}

func TestManagedRoutesUseHelperApplierWithoutLegacyMutation(t *testing.T) {
	_, authorityKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, helperKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	set := helperprotocol.NormalizeManagedIntentSet(proxymodel.IntentSet{Intents: []proxymodel.RouteIntent{{
		ArtifactID: "artifact-1", Backend: "nginx", Route: proxymodel.Route{Host: "app.example.test", Upstream: proxymodel.Upstream{Addr: "127.0.0.1", Port: 3000}},
	}}})
	revision, err := helperprotocol.Digest(set)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	intent := helperprotocol.ApplyIntent{
		AgentID: "agent-1", HelperInstanceID: "helper-1", OperationID: "apply-operation-1", DesiredStateRevision: revision,
		Resources: []string{"artifact-1"}, Artifacts: []helperprotocol.LogicalArtifact{}, DeletionSet: []helperprotocol.ManagedDeletion{}, Routes: set.Intents,
		CertificateKeep: []string{}, AuthorizationKind: helperprotocol.AuthorizationStoredConvergence,
		AuthorizationEventID: "desired-event-1", IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
	}
	signedIntent, err := helperprotocol.Sign("authority-1", authorityKey, helperprotocol.NewEnvelope(helperprotocol.MessageApplyIntent, intent))
	if err != nil {
		t.Fatal(err)
	}
	receipt := helperprotocol.HelperReceipt{OperationID: intent.OperationID, CanonicalRequestDigest: strings.Repeat("a", 64),
		HelperInstanceID: "helper-1", Action: helperprotocol.ActionApplyManagedProxyState, State: helperprotocol.JournalSucceeded,
		RollbackCoverage: helperprotocol.RollbackCoveragePartial, SnapshotDigest: strings.Repeat("b", 64),
		SanitizedResult: "applied", UpdatedAt: now.Format(time.RFC3339Nano)}
	signedReceipt, err := helperprotocol.Sign("attestation-1", helperKey, helperprotocol.NewEnvelope(helperprotocol.MessageHelperReceipt, receipt))
	if err != nil {
		t.Fatal(err)
	}
	applier := &managedApplierMock{receipt: signedReceipt}
	backend := &fakeCaddyBackend{}
	client := New("http://orchestrator.invalid", "agent-1", "token", backend, health.New()).WithManagedApply(applier)
	payload, err := helperprotocol.CanonicalBytes(helperprotocol.ManagedIntentSetEnvelope{IntentSet: set, Intent: signedIntent})
	if err != nil {
		t.Fatal(err)
	}
	client.handleEvent(context.Background(), "managed_routes", string(payload))
	if applier.calls != 1 {
		t.Fatalf("managed applier calls = %d", applier.calls)
	}
	if backend.addRoutes != 0 {
		t.Fatalf("legacy backend mutated %d route(s)", backend.addRoutes)
	}
}

func TestRecoveryPolicyEventIsStrictAndFailClosed(t *testing.T) {
	coordinator := recovery.NewCoordinator("agent-1", nil, nil, nil, nil, nil, nil)
	c := New("http://orchestrator", "agent-1", "token", &fakeCaddyBackend{}, health.New()).WithRecovery(coordinator)
	c.handleEvent(context.Background(), "recovery_policy", `{"policy":{"safe_auto_repair":true}}`)
	if enabled, known := coordinator.Policy(); !known || !enabled {
		t.Fatalf("policy=(%t,%t)", enabled, known)
	}
	c.handleEvent(context.Background(), "recovery_policy", `{"policy":{"safe_auto_repair":false,"command":"rm"}}`)
	if enabled, known := coordinator.Policy(); !known || !enabled {
		t.Fatal("invalid policy changed effective state")
	}
}

func TestRepairRequestRejectsUnknownDiagnosticAndInjectedFields(t *testing.T) {
	coordinator := recovery.NewCoordinator("agent-1", nil, nil, nil, nil, nil, nil)
	c := New("http://orchestrator", "agent-1", "token", &fakeCaddyBackend{}, health.New()).WithRecovery(coordinator)
	c.handleEvent(context.Background(), "repair_request", `{"request":{"operation_id":"op-1","diagnostic_id":"other-agent-diag","action":"remove_managed_temp"}}`)
	c.handleEvent(context.Background(), "repair_request", `{"request":{"operation_id":"op-2","diagnostic_id":"diag","action":"remove_managed_temp","path":"/etc/passwd"}}`)
	// Both are rejection paths; most importantly they do not make policy known or
	// mutate any backend state while handling an untrusted SSE payload.
	if _, known := coordinator.Policy(); known {
		t.Fatal("repair request changed policy")
	}
}

type recoveryStreamBackend struct {
	candidate proxy.RecoveryCandidate
	info      proxy.Info
	order     []string
}

func (b *recoveryStreamBackend) Info() proxy.Info {
	if b.info.Kind == "" {
		return proxy.Info{Kind: proxy.KindNginx}
	}
	return b.info
}
func (b *recoveryStreamBackend) InspectRecovery(context.Context, proxy.RecoveryDesired) ([]proxy.RecoveryCandidate, error) {
	b.order = append(b.order, "inspect")
	if b.candidate.Action == "" {
		return nil, nil
	}
	return []proxy.RecoveryCandidate{b.candidate}, nil
}
func (b *recoveryStreamBackend) ExecuteRecovery(_ context.Context, candidate proxy.RecoveryCandidate, _ map[string]proxy.CertBundle) error {
	b.order = append(b.order, "recover")
	return proxy.RemoveRecoveryCandidatePaths(candidate)
}
func (b *recoveryStreamBackend) Validate(context.Context) error {
	b.order = append(b.order, "validate")
	return nil
}
func (b *recoveryStreamBackend) ReloadRecovery(context.Context) error {
	b.order = append(b.order, "activate")
	return nil
}
func (b *recoveryStreamBackend) EnsureServer(context.Context) error {
	b.order = append(b.order, "ensure")
	return nil
}
func (b *recoveryStreamBackend) ClearRoutes(context.Context) error {
	b.order = append(b.order, "clear")
	return nil
}
func (b *recoveryStreamBackend) AddRoute(context.Context, json.RawMessage) error { return nil }
func (b *recoveryStreamBackend) Apply(context.Context, []proxy.Artifact) error   { return nil }
func (b *recoveryStreamBackend) Prune(context.Context, []proxy.Target) (int, error) {
	b.order = append(b.order, "prune")
	return 0, nil
}
func (b *recoveryStreamBackend) Render(context.Context, proxymodel.Route) (proxy.Artifact, error) {
	return proxy.Artifact{}, nil
}
func (b *recoveryStreamBackend) InstallCerts(context.Context, []proxy.CertBundle) error   { return nil }
func (b *recoveryStreamBackend) EnsureServerTLS(context.Context, []proxy.TLSIntent) error { return nil }

func TestManagedStagingAccessFailureBecomesExactHardDiagnostic(t *testing.T) {
	backend := &recoveryStreamBackend{info: proxy.Info{Kind: proxy.KindNginx}}
	coordinator := recovery.NewCoordinator("agent-1", backend, nil, nil, nil, nil, nil)
	coordinator.SetContext(recovery.Context{AgentID: "agent-1", ProxyInfo: backend.info})
	applier := &managedApplierMock{err: fmt.Errorf("stage desired state: %w", recoverycontrol.ErrManagedStagingAccess)}
	client := New("http://orchestrator.invalid", "agent-1", "token", backend, health.New()).WithRecovery(coordinator).WithManagedApply(applier)
	client.applyManagedIntents(context.Background(), helperprotocol.ManagedIntentSetEnvelope{})
	diagnostics := coordinator.ActiveDiagnostics()
	if len(diagnostics) != 1 || diagnostics[0].Code != recoverymodel.CodePermissionDenied ||
		diagnostics[0].RepairScope != recoverymodel.RepairScopeExclusiveManagedDirectory || !diagnostics[0].RepairEligible || !diagnostics[0].HardChange {
		t.Fatalf("managed staging failure diagnostic = %#v", diagnostics)
	}
}

func TestApplyIntentsRepairsBeforeOneFreshReconcile(t *testing.T) {
	root := t.TempDir()
	managed := filepath.Join(root, "managed")
	if err := os.Mkdir(managed, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(managed, "nurproxy-stale.example.test.conf.nurproxy-tmp")
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := proxy.CaptureRecoveryPath(path)
	if err != nil {
		t.Fatal(err)
	}
	backend := &recoveryStreamBackend{candidate: proxy.NewRecoveryCandidate(recoverymodel.ActionRemoveManagedTemp, "stale.example.test", identity)}
	store, err := recovery.NewSnapshotStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	guard, err := recovery.NewPathGuard(managed)
	if err != nil {
		t.Fatal(err)
	}
	coordinator := recovery.NewCoordinator("agent-1", backend, store, recovery.NewBreaker(), nil, guard, nil)
	coordinator.SetPolicy(true)
	c := New("http://orchestrator.invalid", "agent-1", "token", backend, health.New()).WithRecovery(coordinator)
	c.applyIntents(context.Background(), proxymodel.IntentSet{})
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale path remains: %v", err)
	}
	if got := strings.Join(backend.order, ","); got != "inspect,recover,validate,activate,ensure,clear,prune,inspect" {
		t.Fatalf("order=%s", got)
	}
}

func TestApplyIntentsAllowsOwnedActivationSymlinkFromExactEnabledRoot(t *testing.T) {
	root := t.TempDir()
	available := filepath.Join(root, "sites-available")
	enabled := filepath.Join(root, "sites-enabled")
	data := filepath.Join(root, "data")
	for _, dir := range []string{available, enabled} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	config := filepath.Join(available, "nurproxy-stale.example.test.conf")
	link := filepath.Join(enabled, filepath.Base(config))
	if err := os.WriteFile(config, []byte(proxy.StampManagedArtifact("server {}\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(config, link); err != nil {
		t.Fatal(err)
	}
	configID, err := proxy.CaptureRecoveryPath(config)
	if err != nil {
		t.Fatal(err)
	}
	linkID, err := proxy.CaptureRecoveryPath(link)
	if err != nil {
		t.Fatal(err)
	}
	backend := &recoveryStreamBackend{
		candidate: proxy.NewRecoveryCandidate(recoverymodel.ActionPruneManagedOrphan, "stale.example.test", configID, linkID),
		info: proxy.Info{
			Kind:         proxy.KindNginx,
			ConfigDir:    available,
			ManagedRoots: []string{available, enabled},
		},
	}
	store, err := recovery.NewSnapshotStore(data)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	guard, err := recovery.NewPathGuard(data, available, enabled)
	if err != nil {
		t.Fatal(err)
	}
	coordinator := recovery.NewCoordinator("agent-1", backend, store, recovery.NewBreaker(), nil, guard, nil)
	coordinator.SetContext(recovery.Context{AgentID: "agent-1", ProxyInfo: backend.info, ManagedRoots: backend.info.ManagedRoots, AgentDataRoot: data})
	coordinator.SetPolicy(true)
	New("http://orchestrator.invalid", "agent-1", "token", backend, health.New()).WithRecovery(coordinator).
		applyIntents(context.Background(), proxymodel.IntentSet{})
	for _, path := range []string{link, config} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("owned recovery path %q remains: %v", path, err)
		}
	}
	if _, err := os.Lstat(root); err != nil {
		t.Fatalf("broad parent was changed: %v", err)
	}
}

func TestDesiredTargetProtectsNormalFileBackedIntentBeforeRender(t *testing.T) {
	for _, tc := range []struct {
		info proxy.Info
		want string
	}{
		{proxy.Info{Kind: proxy.KindNginx, ConfigDir: "/etc/nginx/sites-available"}, "/etc/nginx/sites-available/nurproxy-app.example.com.conf"},
		{proxy.Info{Kind: proxy.KindApache, ConfigDir: "/etc/apache2/sites-available"}, "/etc/apache2/sites-available/nurproxy-app.example.com.conf"},
	} {
		if got := desiredTarget(tc.info, "app.example.com"); got.Kind != proxy.TargetKindFile || got.Path != tc.want {
			t.Fatalf("desired target for %s = %#v, want %q", tc.info.Kind, got, tc.want)
		}
	}
}

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

func (o *orderingBackend) Info() proxy.Info                       { return proxy.Info{Kind: proxy.KindCaddy} }
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
	path            string
	content         string
	addRouteHit     bool
	applyHit        bool
	applyErr        error
	applyNeedsPrune bool
	managedPaths    []string
	prunedPaths     []string
	pruneKeep       []proxy.Target // records the keep set Prune was last called with
	pruneHit        bool
}

func (f *fileBackend) Info() proxy.Info                       { return proxy.Info{Kind: proxy.KindNginx} }
func (f *fileBackend) EnsureServer(ctx context.Context) error { return nil }
func (f *fileBackend) ClearRoutes(ctx context.Context) error  { return nil }
func (f *fileBackend) AddRoute(ctx context.Context, route json.RawMessage) error {
	f.addRouteHit = true
	return nil
}
func (f *fileBackend) Apply(ctx context.Context, arts []proxy.Artifact) error {
	f.applyHit = true
	if f.applyNeedsPrune && len(f.prunedPaths) == 0 {
		return errors.New("stale orphan still makes proxy validation fail")
	}
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

func TestApplyIntents_prunesStaleFileBeforeBatchValidation(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/app.conf"
	driftedPath := dir + "/drifted.conf"
	stalePath := dir + "/deleted.conf"
	be := &fileBackend{
		path:            path,
		content:         "server { listen 80; }",
		applyNeedsPrune: true,
		managedPaths:    []string{path, driftedPath, stalePath},
	}
	c := New("http://unused", "agent-1", "tok", be, health.New())

	c.applyIntents(context.Background(), proxymodel.IntentSet{
		Intents: []proxymodel.RouteIntent{{
			ArtifactID: "dom-1", Backend: "nginx",
			Route: proxymodel.Route{Host: "app.example.com", Upstream: proxymodel.Upstream{Addr: "10.0.0.1", Port: 80}},
		}},
		Keep: []string{driftedPath},
	})

	if !be.pruneHit {
		t.Fatal("stale managed vhosts were not pruned")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != be.content {
		t.Fatalf("batch apply stayed blocked by the stale vhost: content=%q err=%v", got, err)
	}
	if len(be.prunedPaths) != 1 || be.prunedPaths[0] != stalePath {
		t.Fatalf("pruned paths = %v, want only stale path %q", be.prunedPaths, stalePath)
	}
	if len(be.pruneKeep) != 2 {
		t.Fatalf("prune keep set = %+v, want desired and drifted paths", be.pruneKeep)
	}
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
	wanted := make(map[string]bool, len(keep))
	for _, target := range keep {
		wanted[target.Path] = true
	}
	for _, path := range f.managedPaths {
		if !wanted[path] {
			f.prunedPaths = append(f.prunedPaths, path)
		}
	}
	return len(f.prunedPaths), nil
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

// fakeCaddyBackend renders a built-in-Caddy admin-API route target, exercising the
// AddRoute path (not the file Apply path) and recording the Prune keep set.
type fakeCaddyBackend struct {
	addRoutes int
	pruneHit  bool
	pruneKeep []proxy.Target
}

type managedLiveFileBackend struct {
	dir         string
	liveContent string
	renderCalls int
}

func (b *managedLiveFileBackend) Info() proxy.Info {
	return proxy.Info{Kind: proxy.KindNginx, ConfigDir: b.dir}
}
func (b *managedLiveFileBackend) EnsureServer(context.Context) error              { return nil }
func (b *managedLiveFileBackend) ClearRoutes(context.Context) error               { return nil }
func (b *managedLiveFileBackend) AddRoute(context.Context, json.RawMessage) error { return nil }
func (b *managedLiveFileBackend) Apply(context.Context, []proxy.Artifact) error   { return nil }
func (b *managedLiveFileBackend) Prune(context.Context, []proxy.Target) (int, error) {
	return 0, nil
}
func (b *managedLiveFileBackend) Render(_ context.Context, route proxymodel.Route) (proxy.Artifact, error) {
	b.renderCalls++
	return proxy.Artifact{
		Target:  proxy.Target{Kind: proxy.TargetKindFile, Path: filepath.Join(b.dir, nginxproxy.ManagedFileName(route.Host))},
		Content: "legacy renderer without helper-owned TLS",
		Enabled: true,
	}, nil
}
func (b *managedLiveFileBackend) ReadManaged(context.Context) ([]proxy.Artifact, error) {
	return []proxy.Artifact{{
		Target:  proxy.Target{Kind: proxy.TargetKindFile, Path: filepath.Join(b.dir, nginxproxy.ManagedFileName("tls.example.test"))},
		Content: b.liveContent,
		Enabled: true,
	}}, nil
}
func (b *managedLiveFileBackend) InstallCerts(context.Context, []proxy.CertBundle) error {
	return nil
}
func (b *managedLiveFileBackend) EnsureServerTLS(context.Context, []proxy.TLSIntent) error {
	return nil
}

func TestManagedAckUsesHelperInstalledLiveArtifact(t *testing.T) {
	live := proxy.StampManagedArtifact("server { listen 443 ssl; }\n")
	backend := &managedLiveFileBackend{dir: t.TempDir(), liveContent: live}
	client := New("http://unused", "agent-1", "token", backend, health.New())
	set := proxymodel.IntentSet{Intents: []proxymodel.RouteIntent{{
		ArtifactID: "dom-1", Backend: "nginx", Route: proxymodel.Route{
			Host: "tls.example.test", Upstream: proxymodel.Upstream{Addr: "127.0.0.1", Port: 8080}, ForceHTTPS: true,
		},
	}}}

	reports, managed := client.managedAckReports(context.Background(), set, "")
	if len(reports) != 1 || reports[0].Error != "" {
		t.Fatalf("reports = %#v", reports)
	}
	if reports[0].Content != live || reports[0].Checksum != checksum(live) || !reports[0].Enabled {
		t.Fatalf("ACK did not describe helper-installed artifact: %#v", reports[0])
	}
	if backend.renderCalls != 0 {
		t.Fatalf("legacy renderer called %d time(s)", backend.renderCalls)
	}
	if got := managed["dom-1"]; got.targetPath != reports[0].TargetPath || got.checksum != reports[0].Checksum {
		t.Fatalf("managed state = %#v, report = %#v", got, reports[0])
	}
}

func TestManagedAckRejectsLiveArtifactWithoutHelperProvenance(t *testing.T) {
	backend := &managedLiveFileBackend{dir: t.TempDir(), liveContent: "server { listen 80; }\n"}
	client := New("http://unused", "agent-1", "token", backend, health.New())
	set := proxymodel.IntentSet{Intents: []proxymodel.RouteIntent{{
		ArtifactID: "dom-1", Backend: "nginx", Route: proxymodel.Route{
			Host: "tls.example.test", Upstream: proxymodel.Upstream{Addr: "127.0.0.1", Port: 8080},
		},
	}}}

	reports, managed := client.managedAckReports(context.Background(), set, "")
	if len(reports) != 1 || reports[0].Error != "post-apply live artifact verification failed" {
		t.Fatalf("reports = %#v", reports)
	}
	if len(managed) != 0 || backend.renderCalls != 0 {
		t.Fatalf("unprovenanced artifact entered managed state: managed=%#v render_calls=%d", managed, backend.renderCalls)
	}
}

func (c *fakeCaddyBackend) Info() proxy.Info                       { return proxy.Info{Kind: proxy.KindCaddy} }
func (c *fakeCaddyBackend) EnsureServer(ctx context.Context) error { return nil }
func (c *fakeCaddyBackend) ClearRoutes(ctx context.Context) error  { return nil }
func (c *fakeCaddyBackend) AddRoute(ctx context.Context, route json.RawMessage) error {
	c.addRoutes++
	return nil
}
func (c *fakeCaddyBackend) Apply(ctx context.Context, arts []proxy.Artifact) error { return nil }
func (c *fakeCaddyBackend) Render(ctx context.Context, route proxymodel.Route) (proxy.Artifact, error) {
	return proxy.Artifact{
		Target:  proxy.Target{Kind: proxy.TargetKindCaddyRoute, Path: "caddy:route:" + route.Host},
		Content: `{"@id":"caddy:route:` + route.Host + `"}`,
		Enabled: true,
	}, nil
}
func (c *fakeCaddyBackend) InstallCerts(ctx context.Context, certs []proxy.CertBundle) error {
	return nil
}
func (c *fakeCaddyBackend) EnsureServerTLS(ctx context.Context, intents []proxy.TLSIntent) error {
	return nil
}
func (c *fakeCaddyBackend) Prune(ctx context.Context, keep []proxy.Target) (int, error) {
	c.pruneHit = true
	c.pruneKeep = keep
	return 0, nil
}

// A live built-in-Caddy route's target must be in the keep set passed to Prune, so
// Prune does not scrub the provided cert material of a still-active route. Regression
// for the bug where keep was built only from file targets: a pure-Caddy agent's keep
// held no route targets, so Prune scrubbed every live route's central-TLS cert (the
// cert was written on the issuing apply, then deleted on the next).
func TestApplyIntents_caddyRouteRetainedInPruneKeep(t *testing.T) {
	be := &fakeCaddyBackend{}
	c := New("http://unused", "agent-1", "tok", be, health.New())

	c.applyIntents(context.Background(), proxymodel.IntentSet{
		Intents: []proxymodel.RouteIntent{{
			ArtifactID: "dom-1", Backend: "caddy",
			Route: proxymodel.Route{Host: "app.example.com", Upstream: proxymodel.Upstream{Addr: "10.0.0.1", Port: 80}},
		}},
	})

	if be.addRoutes != 1 {
		t.Fatalf("caddy route must apply via AddRoute, got %d AddRoute call(s)", be.addRoutes)
	}
	if !be.pruneHit {
		t.Fatal("applyIntents must call Prune")
	}
	want := "caddy:route:app.example.com"
	found := false
	for _, k := range be.pruneKeep {
		if k.Path == want {
			found = true
		}
	}
	if !found {
		t.Errorf("Prune keep set %+v missing the live caddy route target %q — it would be scrubbed", be.pruneKeep, want)
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

// TestApplyIntents_suppressesUnchangedSet pins the change-suppression gate: the
// periodic reconcile tick re-pushes the same desired set every interval, and an
// identical push within suppressionTTL must skip the apply phase (no Apply, no
// Prune — on a real nginx that is a validate + reload per tick) while still
// ACKing so domain status stays fresh. The TTL bounds it: out-of-band divergence
// the agent cannot see self-heals on the next full apply.
func TestApplyIntents_suppressesUnchangedSet(t *testing.T) {
	var acks atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agents/{id}/routes/ack", func(w http.ResponseWriter, r *http.Request) {
		acks.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	be := &fileBackend{path: dir + "/app.conf", content: "server { listen 80; }"}
	c := New(srv.URL, "agent-1", "tok", be, health.New())

	set := proxymodel.IntentSet{
		Intents: []proxymodel.RouteIntent{{
			ArtifactID: "dom-1", Backend: "nginx",
			Route: proxymodel.Route{Host: "app.example.com", Upstream: proxymodel.Upstream{Addr: "10.0.0.1", Port: 80}},
		}},
	}
	c.applyIntents(context.Background(), set)
	if !be.applyHit {
		t.Fatal("first push must apply")
	}

	be.applyHit, be.pruneHit = false, false
	c.applyIntents(context.Background(), set)
	if be.applyHit {
		t.Error("identical second push within the TTL must be suppressed (no Apply)")
	}
	if be.pruneHit {
		t.Error("suppressed push must not Prune")
	}
	if got := acks.Load(); got != 2 {
		t.Errorf("acks = %d, want 2 (a suppressed push still ACKs)", got)
	}
	// The managed snapshot survives suppression — the heartbeat drift signal
	// must keep reporting the artifact.
	sums := c.ManagedChecksums()
	if len(sums) != 1 || sums[0].ArtifactID != "dom-1" {
		t.Fatalf("managed snapshot lost across a suppressed push: %+v", sums)
	}

	// Past the TTL the same set re-applies in full (self-heal bound).
	c.applyStateMu.Lock()
	c.lastFullApply = time.Now().Add(-suppressionTTL - time.Minute)
	c.applyStateMu.Unlock()
	c.applyIntents(context.Background(), set)
	if !be.applyHit {
		t.Error("push after suppressionTTL must re-apply in full")
	}

	// A content change defeats suppression immediately.
	be.applyHit = false
	be.content = "server { listen 8080; }"
	c.applyIntents(context.Background(), set)
	if !be.applyHit {
		t.Error("a push whose rendered content changed must re-apply")
	}
}

// TestApplyIntents_changedCertDefeatsSuppression proves a renewed certificate
// forces a full re-apply even though the rendered route content is unchanged —
// the proxy must reload to pick up the new cert material (§7 renewal).
func TestApplyIntents_changedCertDefeatsSuppression(t *testing.T) {
	be := &fakeCaddyBackend{}
	c := New("http://unused", "agent-1", "tok", be, health.New())

	set := proxymodel.IntentSet{
		Intents: []proxymodel.RouteIntent{{
			ArtifactID: "dom-1", Backend: "caddy",
			Route: proxymodel.Route{Host: "app.example.com", Upstream: proxymodel.Upstream{Addr: "10.0.0.1", Port: 80}},
		}},
		Certs: []proxymodel.CertBundle{{Host: "app.example.com", CertPEM: "CERT-V1", KeyPEM: "KEY-V1"}},
	}
	c.applyIntents(context.Background(), set)
	if be.addRoutes != 1 {
		t.Fatalf("first push: addRoutes = %d, want 1", be.addRoutes)
	}

	c.applyIntents(context.Background(), set)
	if be.addRoutes != 1 {
		t.Fatalf("identical push must be suppressed: addRoutes = %d, want 1", be.addRoutes)
	}

	set.Certs = []proxymodel.CertBundle{{Host: "app.example.com", CertPEM: "CERT-V2", KeyPEM: "KEY-V2"}}
	c.applyIntents(context.Background(), set)
	if be.addRoutes != 2 {
		t.Errorf("renewed cert must defeat suppression: addRoutes = %d, want 2", be.addRoutes)
	}
}

// TestApplyIntents_uncleanApplyDefeatsSuppression proves a failed apply never
// seeds the suppression gate: the next push — even an identical one — must retry
// the apply phase rather than silently staying broken until the TTL.
func TestApplyIntents_uncleanApplyDefeatsSuppression(t *testing.T) {
	dir := t.TempDir()
	be := &fileBackend{path: dir + "/app.conf", content: "server { listen 80; }", applyErr: fmt.Errorf("nginx -t failed")}
	c := New("http://unused", "agent-1", "tok", be, health.New())

	set := proxymodel.IntentSet{
		Intents: []proxymodel.RouteIntent{{
			ArtifactID: "dom-1", Backend: "nginx",
			Route: proxymodel.Route{Host: "app.example.com", Upstream: proxymodel.Upstream{Addr: "10.0.0.1", Port: 80}},
		}},
	}
	c.applyIntents(context.Background(), set)
	if !be.applyHit {
		t.Fatal("first push must attempt the apply")
	}

	be.applyErr = nil
	be.applyHit = false
	c.applyIntents(context.Background(), set)
	if !be.applyHit {
		t.Error("a push after a failed apply must not be suppressed")
	}
}

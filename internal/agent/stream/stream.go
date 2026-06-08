// Package stream maintains the agent's long-lived outbound connection to the
// orchestrator. The agent dials out (so it works behind NAT) and holds a
// Server-Sent Events stream open; the orchestrator pushes the agent's desired
// route set down it. The agent applies the set to its local Caddy and reports
// back which routes it applied. This is the push half of the control plane; the
// heartbeat is the agent's periodic self-report.
package stream

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/health"
	"github.com/NurRobin/NurProxy/internal/agent/logtail"
	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

const (
	maxBackoff = 30 * time.Second
	// maxLine bounds a single SSE data line; route snapshots can be large.
	maxLine = 4 << 20 // 4 MiB
)

// caddyBackend is the subset of the bundled-Caddy proxy backend the stream
// drives. It is satisfied by *proxy/caddy.Backend (the admin-API Proxy
// implementation), so the agent reconciles routes through the proxy backend
// rather than the raw admin client.
//
// As of Phase 3 the orchestrator pushes *intent* (proxymodel.Route), so the
// agent renders each intent natively here (Render) before applying it — only the
// agent knows the host's proxy facts (§3/B1). The rendered artifact + checksum
// is then reported back atomically in the apply-ACK. EnsureServer is kept
// separate from a single Apply so the classic ports-80/443 bind-failure stays
// distinctly attributed (and clears health on success), exactly as before.
type caddyBackend interface {
	EnsureServer(ctx context.Context) error
	ClearRoutes(ctx context.Context) error
	AddRoute(ctx context.Context, route json.RawMessage) error
	// Apply writes, validates, and activates file-backed artifacts atomically
	// (nginx/apache/external caddy, §10). The admin-API built-in Caddy uses
	// AddRoute instead; applyIntents dispatches by the rendered artifact's target
	// kind so a file backend actually writes + reloads rather than no-op'ing
	// through AddRoute.
	Apply(ctx context.Context, arts []proxy.Artifact) error
	// Prune removes NurProxy-generated artifacts not in the desired set, so a
	// deleted domain leaves no ghost vhost (§3). Called after Apply with the full
	// desired file-target set; a no-op for the admin-API Caddy.
	Prune(ctx context.Context, keep []proxy.Target) (int, error)
	Render(ctx context.Context, route proxymodel.Route) (proxy.Artifact, error)
	// InstallCerts writes the pushed cert bundles to disk before any referencing
	// config is applied (preflight ordering, §5). It is called first in
	// applyIntents so a generated config never validates against a missing file.
	InstallCerts(ctx context.Context, certs []proxy.CertBundle) error
	// EnsureServerTLS configures the bundled Caddy's TLS strategy from each host's
	// policy (§7): central provided certs (automatic_https disabled, bundle fed in)
	// vs Caddy self-ACME fallback. It runs after InstallCerts (cert files must
	// exist) and before route apply, so the server already serves the right certs.
	EnsureServerTLS(ctx context.Context, intents []proxy.TLSIntent) error
}

// managedArtifact records what the agent applied for one artifact so the
// heartbeat can report its CURRENT drift signal (§11). For a file backend the
// live state is the on-disk file, so the heartbeat re-reads targetPath and
// re-checksums it — a manual edit then surfaces as drift. For the admin-API
// built-in Caddy the rendered content IS the live state, so the apply-time
// checksum is authoritative and no file is read.
type managedArtifact struct {
	targetKind string
	targetPath string
	checksum   string
}

// Client manages the agent's stream connection and applies pushed routes.
type Client struct {
	orchestratorURL string
	agentID         string
	token           string
	caddy           caddyBackend
	health          *health.State
	http            *http.Client

	// managedMu guards managed, the agent's snapshot of the artifacts it currently
	// has applied (artifactID -> applied state). It is refreshed on every successful
	// apply and read by the heartbeat so the orchestrator can detect drift (on-disk
	// != accepted, §11). For the built-in Caddy admin-API path the rendered route
	// content IS the live state, so the apply-time checksum is the drift signal; for
	// a file backend the live state is the on-disk file, so the heartbeat re-reads
	// targetPath (see ManagedChecksums).
	managedMu sync.RWMutex
	managed   map[string]managedArtifact

	// logPaths is the operator-configured proxy_log_paths allowlist (§9). An
	// on-demand tail (§15) is refused unless its path is within this set, so a
	// compromised orchestrator can never use the tail to read arbitrary host files.
	// Empty means no tail is permitted (fail closed).
	logPaths []string
	// tailsMu guards tails, the live on-demand tail sessions keyed by session ID.
	// Each session has a cancel func that the matching stop event (or Run's
	// shutdown) calls to end the tailer.
	tailsMu sync.Mutex
	tails   map[string]context.CancelFunc
}

// New creates a stream Client. backend is the bundled-Caddy proxy backend the
// agent reconciles routes through.
func New(orchestratorURL, agentID, token string, backend caddyBackend, hs *health.State) *Client {
	return &Client{
		orchestratorURL: strings.TrimRight(orchestratorURL, "/"),
		agentID:         agentID,
		token:           token,
		caddy:           backend,
		health:          hs,
		managed:         make(map[string]managedArtifact),
		tails:           make(map[string]context.CancelFunc),
		// No client timeout: this connection is meant to stay open. Reconnects
		// are driven by the context and by read errors.
		http: &http.Client{},
	}
}

// WithLogPaths sets the proxy_log_paths allowlist that bounds on-demand log
// tailing (§15). A tail request for a path outside this set is refused. Returns
// the receiver for chaining.
func (c *Client) WithLogPaths(paths []string) *Client {
	c.logPaths = paths
	return c
}

// ManagedChecksums returns the agent's current per-artifact checksum snapshot for
// the heartbeat (§11). The orchestrator compares each against the accepted state
// to detect drift. The returned slice is a copy, safe to use after the call.
func (c *Client) ManagedChecksums() []proxymodel.ArtifactChecksum {
	c.managedMu.RLock()
	snapshot := make(map[string]managedArtifact, len(c.managed))
	for id, m := range c.managed {
		snapshot[id] = m
	}
	c.managedMu.RUnlock()

	out := make([]proxymodel.ArtifactChecksum, 0, len(snapshot))
	for id, m := range snapshot {
		sum := m.checksum
		var content string
		// File backends: the live state is on disk, so re-read and re-checksum the
		// file each beat. A manual edit since the last apply then diverges from the
		// accepted checksum and the orchestrator flags drift (§11) — the in-memory
		// apply-time checksum alone would never catch an on-disk change. A read
		// error (file removed, perms) falls back to the last-applied checksum. The
		// admin-API built-in Caddy keeps its in-memory checksum: the rendered route
		// content is itself the live state, with no file to read.
		if m.targetKind == string(proxy.TargetKindFile) && m.targetPath != "" {
			if data, err := os.ReadFile(m.targetPath); err == nil {
				sum = checksum(string(data))
				// Ship the on-disk bytes ONLY when they diverge from the last-applied
				// state, so the orchestrator can capture the drifted content for the
				// accepted-vs-on-disk diff and persist it on Accept (§11). A matching
				// beat carries no content.
				if sum != m.checksum {
					content = string(data)
				}
			}
		}
		out = append(out, proxymodel.ArtifactChecksum{ArtifactID: id, Checksum: sum, Content: content})
	}
	return out
}

// setManaged replaces the managed-artifact snapshot atomically after an apply, so
// the heartbeat always reports the agent's true current set (added and removed
// artifacts both reflected).
func (c *Client) setManaged(m map[string]managedArtifact) {
	c.managedMu.Lock()
	c.managed = m
	c.managedMu.Unlock()
}

// Run connects to the orchestrator and keeps the stream open, reconnecting with
// exponential backoff until ctx is canceled. It blocks, so callers typically
// run it in a goroutine.
func (c *Client) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := c.connect(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("Stream: disconnected (%v); reconnecting in %s", err, backoff)
			if !sleep(ctx, backoff) {
				return
			}
			if backoff *= 2; backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		// Clean end (server closed) — reconnect promptly.
		backoff = time.Second
	}
}

// connect opens one stream and reads events until it ends or errors.
func (c *Client) connect(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/v1/agents/%s/stream", c.orchestratorURL, c.agentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("stream returned status %d", resp.StatusCode)
	}
	log.Printf("Stream: connected to orchestrator")

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLine)

	var eventType string
	var data strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			// Blank line dispatches the accumulated event.
			if eventType != "" {
				c.handleEvent(ctx, eventType, data.String())
			}
			eventType = ""
			data.Reset()
		case strings.HasPrefix(line, ":"):
			// Comment / keepalive — ignore.
		case strings.HasPrefix(line, "event:"):
			eventType = strings.TrimSpace(line[len("event:"):])
		case strings.HasPrefix(line, "data:"):
			data.WriteString(strings.TrimSpace(line[len("data:"):]))
		}
	}
	return scanner.Err()
}

// handleEvent dispatches a single parsed SSE event.
func (c *Client) handleEvent(ctx context.Context, eventType, data string) {
	switch eventType {
	case "routes":
		var set proxymodel.IntentSet
		if err := json.Unmarshal([]byte(data), &set); err != nil {
			log.Printf("Stream: bad intent payload: %v", err)
			return
		}
		c.applyIntents(ctx, set)
	case "ping":
		// Liveness only — nothing to do.
	case "log_tail":
		var req proxymodel.LogTailRequest
		if err := json.Unmarshal([]byte(data), &req); err != nil {
			log.Printf("Stream: bad log_tail payload: %v", err)
			return
		}
		c.startLogTail(ctx, req)
	case "log_tail_stop":
		var stop proxymodel.LogTailStop
		if err := json.Unmarshal([]byte(data), &stop); err != nil {
			log.Printf("Stream: bad log_tail_stop payload: %v", err)
			return
		}
		c.stopLogTail(stop.SessionID)
	default:
		log.Printf("Stream: ignoring unknown event %q", eventType)
	}
}

// startLogTail begins an on-demand tail for the requested session (§15). The path
// is checked against the configured proxy_log_paths allowlist (fail closed); a
// refused path is reported back as a terminal error chunk rather than silently
// dropped, so the dashboard shows why. The tailer runs in its own goroutine under
// a child context whose cancel is stored so a stop event (or stream shutdown) can
// end it. Re-starting an already-running session is a no-op. Chunks are POSTed
// back up the agent-initiated control plane — the orchestrator never reads the
// agent inbound (invariant #2).
func (c *Client) startLogTail(ctx context.Context, req proxymodel.LogTailRequest) {
	if req.SessionID == "" {
		return
	}
	c.tailsMu.Lock()
	if _, running := c.tails[req.SessionID]; running {
		c.tailsMu.Unlock()
		return
	}
	tailer, err := logtail.NewTailer(req.Path, req.Lines, c.logPaths, func(ch logtail.Chunk) {
		c.sendLogChunk(ctx, req.SessionID, req.Path, ch)
	})
	if err != nil {
		c.tailsMu.Unlock()
		log.Printf("Stream: refusing log tail for %q: %v", req.Path, err)
		c.sendLogChunk(ctx, req.SessionID, req.Path, logtail.Chunk{Err: err, EOF: true})
		return
	}
	tailCtx, cancel := context.WithCancel(ctx)
	c.tails[req.SessionID] = cancel
	c.tailsMu.Unlock()

	log.Printf("Stream: starting log tail session %s for %q", req.SessionID, req.Path)
	go func() {
		tailer.Run(tailCtx)
		// Tailer ended (stop or shutdown): drop the session so a later start can reuse
		// the ID and a stop becomes a no-op.
		c.tailsMu.Lock()
		delete(c.tails, req.SessionID)
		c.tailsMu.Unlock()
	}()
}

// stopLogTail cancels the tailer for a session (§15). Stopping an unknown or
// already-stopped session is a no-op. The tailer's own goroutine emits the
// terminal EOF chunk and removes the session entry.
func (c *Client) stopLogTail(sessionID string) {
	c.tailsMu.Lock()
	cancel := c.tails[sessionID]
	c.tailsMu.Unlock()
	if cancel != nil {
		log.Printf("Stream: stopping log tail session %s", sessionID)
		cancel()
	}
}

// sendLogChunk POSTs one tailed chunk back to the orchestrator over the
// agent-initiated control plane (§15). A send failure is logged but never fatal:
// the dashboard simply sees a gap and the operator can reopen the view.
func (c *Client) sendLogChunk(ctx context.Context, sessionID, path string, ch logtail.Chunk) {
	chunk := proxymodel.LogChunk{
		SessionID: sessionID,
		Path:      path,
		Lines:     ch.Lines,
		EOF:       ch.EOF,
	}
	if ch.Err != nil {
		chunk.Error = ch.Err.Error()
	}
	body, err := json.Marshal(chunk)
	if err != nil {
		return
	}
	url := fmt.Sprintf("%s/api/v1/agents/%s/logs/chunk", c.orchestratorURL, c.agentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Stream: failed to send log chunk for session %s: %v", sessionID, err)
		return
	}
	_ = resp.Body.Close()
}

// applyIntents renders the pushed intent snapshot natively, replaces the agent's
// entire route set with it, and reports each rendered artifact back to the
// orchestrator in one atomic apply-ACK (§3/B1). The agent owns rendering: the
// orchestrator pushes backend-neutral intent, the agent produces native config
// (here, Caddy route JSON) and round-trips the rendered content + checksum so the
// store becomes the authoritative versioned artifact without the orchestrator
// modeling the host.
//
// Preflight ordering (§5): the push is "everything is ready, go live" — it carries
// both the cert bundles and the intent set. The agent installs the certs FIRST
// (InstallCerts), then applies the config that references them, so a generated
// config never validates against a missing cert file. A cert-install failure is
// surfaced via health and the apply still proceeds for the built-in Caddy path
// (which can self-ACME as a fallback, §7); file backends that hard-require the
// cert will fail their own validate, attributed per-artifact.
func (c *Client) applyIntents(ctx context.Context, set proxymodel.IntentSet) {
	c.installCerts(ctx, set.Certs)

	intents := set.Intents
	reports := make([]proxymodel.ArtifactReport, 0, len(intents))
	// managed is the fresh snapshot of artifacts this apply leaves live (artifactID
	// -> applied state). It replaces the prior snapshot wholesale, so artifacts
	// dropped from the intent set stop being reported (no stale drift on removed
	// configs).
	managed := make(map[string]managedArtifact, len(intents))
	applied := 0

	// Ensure the server exists first (creates the config path), then clear, then
	// add — so clearing doesn't hit a not-yet-created path on a fresh Caddy. These
	// admin-API primitives are safe no-ops on a file backend (the Holder forwards
	// them only when the current backend implements them).
	if err := c.caddy.EnsureServer(ctx); err != nil {
		log.Printf("Stream: failed to ensure server: %v", err)
		if c.health != nil {
			c.health.SetCaddyRunning(false)
			c.health.SetError(fmt.Sprintf("Caddy could not start its HTTP server (ports 80/443 in use?): %v", err))
		}
	} else if c.health != nil {
		// Server is up — clear any prior bind error.
		c.health.SetCaddyRunning(true)
		c.health.SetError("")
	}
	if err := c.caddy.ClearRoutes(ctx); err != nil {
		log.Printf("Stream: failed to clear routes: %v", err)
	}

	// Configure the server's TLS strategy from each host's policy (§7): central
	// provided certs run with automatic_https disabled and the installed bundle
	// fed in; self-ACME hosts keep Caddy's own ACME (the explicit fallback). This
	// runs after the certs are installed and the server exists, before routes are
	// applied. A failure is logged + surfaced via health but never aborts the
	// apply (invariant #1: the running Caddy path keeps serving; self-ACME still
	// covers TLS).
	c.applyServerTLS(ctx, intents)

	// fileArtifact ties a file-backed render to its slot in reports, so the batch
	// Apply below can attribute the outcome back per artifact. reportIdx is stable:
	// reports is fully built by the render loop and never appended to afterwards.
	type fileArtifact struct {
		intent    proxymodel.RouteIntent
		art       proxy.Artifact
		reportIdx int
	}
	var fileArts []fileArtifact
	// caddyKept collects the targets of successfully-applied built-in-Caddy routes so
	// the post-apply Prune retains their cert material. Without it a pure-Caddy agent's
	// keep set holds only file targets; Prune's route-ID match then finds nothing
	// wanted and scrubs the provided cert of every live route, breaking central-TLS
	// (the cert is written on the issuing apply, then deleted on the next one).
	var caddyKept []proxy.Target

	for _, in := range intents {
		host := in.Route.Host

		// Render the intent natively. A render failure is a per-artifact error;
		// it never aborts the whole batch (invariant #4).
		art, err := c.caddy.Render(ctx, in.Route)
		if err != nil {
			log.Printf("Stream: failed to render intent for %s: %v", host, err)
			reports = append(reports, proxymodel.ArtifactReport{
				ArtifactID: in.ArtifactID,
				Host:       host,
				Backend:    in.Backend,
				Error:      err.Error(),
			})
			continue
		}

		report := proxymodel.ArtifactReport{
			ArtifactID: in.ArtifactID,
			Host:       host,
			Backend:    in.Backend,
			TargetKind: string(art.Target.Kind),
			TargetPath: art.Target.Path,
			Content:    art.Content,
			Checksum:   checksum(art.Content),
			Enabled:    art.Enabled,
			// Carry the dropped-option warnings back so the orchestrator audits
			// each one (invariant #4: dropped, logged, and audited).
			Warnings: art.Warnings,
		}

		// Dispatch by target kind. A file-backed artifact (nginx/apache/external
		// caddy) is deferred to the atomic batch Apply below — AddRoute is a no-op
		// for those backends, so applying through it would ACK success without ever
		// writing the file or reloading the proxy (§10). The admin-API built-in
		// Caddy applies its route directly here.
		if art.Target.Kind == proxy.TargetKindFile {
			reports = append(reports, report)
			fileArts = append(fileArts, fileArtifact{intent: in, art: art, reportIdx: len(reports) - 1})
			continue
		}

		if err := c.caddy.AddRoute(ctx, json.RawMessage(art.Content)); err != nil {
			log.Printf("Stream: failed to apply route for %s: %v", host, err)
			report.Error = err.Error()
			reports = append(reports, report)
			continue
		}
		applied++
		caddyKept = append(caddyKept, art.Target)
		reports = append(reports, report)
		// Track the successfully-applied artifact for the heartbeat drift check.
		if in.ArtifactID != "" {
			managed[in.ArtifactID] = managedArtifact{
				targetKind: report.TargetKind,
				targetPath: report.TargetPath,
				checksum:   report.Checksum,
			}
		}
	}

	// Apply the file-backed artifacts as one atomic batch (write → validate →
	// reload). On failure the backend rolls back to the prior on-disk state, so we
	// attribute the error to every artifact in the batch and track none as live (no
	// false drift signal for config that never went live).
	fileApplyOK := true
	if len(fileArts) > 0 {
		arts := make([]proxy.Artifact, 0, len(fileArts))
		for _, fa := range fileArts {
			arts = append(arts, fa.art)
		}
		if err := c.caddy.Apply(ctx, arts); err != nil {
			fileApplyOK = false
			log.Printf("Stream: failed to apply %d file artifact(s): %v", len(arts), err)
			if c.health != nil {
				c.health.SetError(fmt.Sprintf("failed to apply proxy config: %v", err))
			}
			for _, fa := range fileArts {
				reports[fa.reportIdx].Error = err.Error()
			}
		} else {
			if c.health != nil {
				c.health.SetError("")
			}
			for _, fa := range fileArts {
				applied++
				rep := reports[fa.reportIdx]
				if fa.intent.ArtifactID != "" {
					managed[fa.intent.ArtifactID] = managedArtifact{
						targetKind: rep.TargetKind,
						targetPath: rep.TargetPath,
						checksum:   rep.Checksum,
					}
				}
			}
		}
	}

	// Prune ghost vhosts: any NurProxy-generated file on disk that is NOT in this
	// (authoritative) desired set is a deleted domain's leftover. The backend removes
	// it and reloads — over the dial-out stream, never an inbound probe (§3,
	// invariant #2). Caddy is a no-op (ClearRoutes already handled it). Skipped when
	// the file apply rolled back, so we never disturb the restored prior state.
	if fileApplyOK {
		keep := make([]proxy.Target, 0, len(fileArts)+len(set.Keep))
		for _, fa := range fileArts {
			keep = append(keep, fa.art.Target)
		}
		// set.Keep carries generated files the orchestrator deliberately did NOT push
		// this round but the agent must retain — currently drifted artifacts awaiting
		// review. Including them stops the prune from clobbering a drifted file
		// (invariant #3, no overwrite while drifted).
		for _, p := range set.Keep {
			keep = append(keep, proxy.Target{Kind: proxy.TargetKindFile, Path: p})
		}
		// Built-in-Caddy routes applied above are admin-API targets, not files; include
		// them so Prune retains their (still-wanted) cert material instead of scrubbing it.
		keep = append(keep, caddyKept...)
		if n, err := c.caddy.Prune(ctx, keep); err != nil {
			log.Printf("Stream: prune of orphaned vhosts failed: %v", err)
		} else if n > 0 {
			log.Printf("Stream: pruned %d orphaned vhost(s)", n)
		}
	}

	// Carry forward the managed entries for Keep'd paths (drifted artifacts the
	// orchestrator retained but did not re-push). Keeping them in the managed set
	// means the heartbeat keeps reporting their checksum, so the drift auto-clears
	// when the operator reverts the file and drift_content refreshes on a re-edit
	// (§11). Their last-applied checksum is the accepted baseline the orchestrator
	// compares against, so this never masks a genuine divergence.
	if len(set.Keep) > 0 {
		keepPaths := make(map[string]bool, len(set.Keep))
		for _, p := range set.Keep {
			keepPaths[p] = true
		}
		c.managedMu.RLock()
		for id, m := range c.managed {
			if _, alreadyApplied := managed[id]; !alreadyApplied && keepPaths[m.targetPath] {
				managed[id] = m
			}
		}
		c.managedMu.RUnlock()
	}

	// Replace the managed snapshot so the heartbeat reports exactly what is live
	// now (additions and removals both reflected).
	c.setManaged(managed)

	log.Printf("Stream: applied %d/%d intents", applied, len(intents))
	c.sendAck(ctx, reports)
}

// installCerts runs the preflight cert install for a push (§5/§7): it converts the
// wire cert bundles into the agent-side proxy.CertBundle form and hands them to the
// backend, which writes them to disk (encrypting keys at rest) BEFORE applyIntents
// applies any referencing config. An install error is logged and surfaced via
// health but never aborts the apply: the built-in Caddy can self-ACME as a fallback
// (§7), and per-artifact validation still attributes a genuinely missing cert. A
// nil/empty slice is a no-op (no TLS material in this push).
func (c *Client) installCerts(ctx context.Context, certs []proxymodel.CertBundle) {
	if len(certs) == 0 {
		return
	}
	bundles := make([]proxy.CertBundle, 0, len(certs))
	for _, cb := range certs {
		bundles = append(bundles, proxy.CertBundle{
			Host:    cb.Host,
			CertPEM: []byte(cb.CertPEM),
			KeyPEM:  []byte(cb.KeyPEM),
		})
	}
	if err := c.caddy.InstallCerts(ctx, bundles); err != nil {
		log.Printf("Stream: failed to install %d cert bundle(s): %v", len(bundles), err)
		if c.health != nil {
			c.health.SetError(fmt.Sprintf("failed to install TLS certificates: %v", err))
		}
		return
	}
	log.Printf("Stream: installed %d cert bundle(s) before apply", len(bundles))
}

// applyServerTLS derives each host's TLS policy from its pushed intent and asks
// the backend to configure the bundled Caddy's TLS strategy (§7). The default
// policy is central provided certs (automatic_https disabled, the installed
// bundle fed in); a host whose Route.TLS.Policy is self-acme keeps Caddy's own
// ACME as the explicit fallback. Raw-escape-hatch routes carry no structured TLS
// policy, so they are left out (the operator's raw config owns its own TLS).
//
// A failure is logged and surfaced via health but never aborts the apply: the
// already-running Caddy keeps serving and self-ACME still covers TLS, preserving
// invariant #1.
func (c *Client) applyServerTLS(ctx context.Context, intents []proxymodel.RouteIntent) {
	tlsIntents := make([]proxy.TLSIntent, 0, len(intents))
	for _, in := range intents {
		if in.Route.IsRaw() || in.Route.Host == "" {
			continue
		}
		policy := in.Route.TLS.Policy
		if policy == "" {
			policy = proxymodel.TLSPolicyCentral
		}
		tlsIntents = append(tlsIntents, proxy.TLSIntent{Host: in.Route.Host, Policy: policy})
	}
	if err := c.caddy.EnsureServerTLS(ctx, tlsIntents); err != nil {
		log.Printf("Stream: failed to configure TLS strategy: %v", err)
		if c.health != nil {
			c.health.SetError(fmt.Sprintf("failed to configure TLS strategy: %v", err))
		}
	}
}

// checksum returns the hex-encoded SHA-256 of the rendered content. It matches
// db.ChecksumContent on the orchestrator so the round-tripped checksum agrees
// across the wire.
func checksum(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// sendAck reports the rendered artifacts (content + checksum) and per-artifact
// errors to the orchestrator in one atomic apply-ACK (§3/B1).
func (c *Client) sendAck(ctx context.Context, reports []proxymodel.ArtifactReport) {
	body, err := json.Marshal(proxymodel.ApplyAck{Reports: reports})
	if err != nil {
		return
	}

	url := fmt.Sprintf("%s/api/v1/agents/%s/routes/ack", c.orchestratorURL, c.agentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	ackClient := &http.Client{Timeout: 15 * time.Second}
	resp, err := ackClient.Do(req)
	if err != nil {
		log.Printf("Stream: failed to send route ack: %v", err)
		return
	}
	_ = resp.Body.Close()
}

// sleep waits for d or until ctx is canceled. It returns false if ctx ended.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

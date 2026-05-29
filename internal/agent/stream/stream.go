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
	"strings"
	"sync"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/health"
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

// Client manages the agent's stream connection and applies pushed routes.
type Client struct {
	orchestratorURL string
	agentID         string
	token           string
	caddy           caddyBackend
	health          *health.State
	http            *http.Client

	// managedMu guards managed, the agent's snapshot of the artifacts it currently
	// has applied (artifactID -> checksum of the rendered content). It is refreshed
	// on every successful apply and read by the heartbeat so the orchestrator can
	// detect drift (on-disk != accepted, §11). For the built-in Caddy admin-API
	// path the rendered route content IS the live state, so its checksum is the
	// drift signal.
	managedMu sync.RWMutex
	managed   map[string]string
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
		managed:         make(map[string]string),
		// No client timeout: this connection is meant to stay open. Reconnects
		// are driven by the context and by read errors.
		http: &http.Client{},
	}
}

// ManagedChecksums returns the agent's current per-artifact checksum snapshot for
// the heartbeat (§11). The orchestrator compares each against the accepted state
// to detect drift. The returned slice is a copy, safe to use after the call.
func (c *Client) ManagedChecksums() []proxymodel.ArtifactChecksum {
	c.managedMu.RLock()
	defer c.managedMu.RUnlock()
	out := make([]proxymodel.ArtifactChecksum, 0, len(c.managed))
	for id, sum := range c.managed {
		out = append(out, proxymodel.ArtifactChecksum{ArtifactID: id, Checksum: sum})
	}
	return out
}

// setManaged replaces the managed-artifact checksum snapshot atomically after an
// apply, so the heartbeat always reports the agent's true current set (added and
// removed artifacts both reflected).
func (c *Client) setManaged(m map[string]string) {
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
	default:
		log.Printf("Stream: ignoring unknown event %q", eventType)
	}
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
	// -> checksum). It replaces the prior snapshot wholesale, so artifacts dropped
	// from the intent set stop being reported (no stale drift on removed configs).
	managed := make(map[string]string, len(intents))
	applied := 0

	// Ensure the server exists first (creates the config path), then clear, then
	// add — so clearing doesn't hit a not-yet-created path on a fresh Caddy.
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
		}

		if err := c.caddy.AddRoute(ctx, json.RawMessage(art.Content)); err != nil {
			log.Printf("Stream: failed to apply route for %s: %v", host, err)
			report.Error = err.Error()
			reports = append(reports, report)
			continue
		}
		applied++
		reports = append(reports, report)
		// Track the successfully-applied artifact for the heartbeat drift check.
		if in.ArtifactID != "" {
			managed[in.ArtifactID] = report.Checksum
		}
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

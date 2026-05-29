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
}

// Client manages the agent's stream connection and applies pushed routes.
type Client struct {
	orchestratorURL string
	agentID         string
	token           string
	caddy           caddyBackend
	health          *health.State
	http            *http.Client
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
		// No client timeout: this connection is meant to stay open. Reconnects
		// are driven by the context and by read errors.
		http: &http.Client{},
	}
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
		c.applyIntents(ctx, set.Intents)
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
func (c *Client) applyIntents(ctx context.Context, intents []proxymodel.RouteIntent) {
	reports := make([]proxymodel.ArtifactReport, 0, len(intents))
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
	}

	log.Printf("Stream: applied %d/%d intents", applied, len(intents))
	c.sendAck(ctx, reports)
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

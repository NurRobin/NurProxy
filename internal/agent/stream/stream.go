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
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/caddy"
	"github.com/NurRobin/NurProxy/internal/agent/health"
)

const (
	maxBackoff = 30 * time.Second
	// maxLine bounds a single SSE data line; route snapshots can be large.
	maxLine = 4 << 20 // 4 MiB
)

// Client manages the agent's stream connection and applies pushed routes.
type Client struct {
	orchestratorURL string
	agentID         string
	token           string
	caddy           *caddy.Client
	health          *health.State
	http            *http.Client
}

// New creates a stream Client.
func New(orchestratorURL, agentID, token string, caddyClient *caddy.Client, hs *health.State) *Client {
	return &Client{
		orchestratorURL: strings.TrimRight(orchestratorURL, "/"),
		agentID:         agentID,
		token:           token,
		caddy:           caddyClient,
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
		var routes []json.RawMessage
		if err := json.Unmarshal([]byte(data), &routes); err != nil {
			log.Printf("Stream: bad routes payload: %v", err)
			return
		}
		c.applyRoutes(ctx, routes)
	case "ping":
		// Liveness only — nothing to do.
	default:
		log.Printf("Stream: ignoring unknown event %q", eventType)
	}
}

// applyRoutes replaces the agent's entire route set with the pushed snapshot,
// then reports the result back to the orchestrator.
func (c *Client) applyRoutes(ctx context.Context, routes []json.RawMessage) {
	applied := make([]string, 0, len(routes))
	errs := make(map[string]string)

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

	for _, route := range routes {
		host := hostFromRoute(route)
		if err := c.caddy.AddRoute(ctx, route); err != nil {
			log.Printf("Stream: failed to apply route for %s: %v", host, err)
			if host != "" {
				errs[host] = err.Error()
			}
			continue
		}
		if host != "" {
			applied = append(applied, host)
		}
	}

	log.Printf("Stream: applied %d/%d routes", len(applied), len(routes))
	c.sendAck(ctx, applied, errs)
}

// sendAck reports applied routes and per-route errors to the orchestrator.
func (c *Client) sendAck(ctx context.Context, applied []string, errs map[string]string) {
	body, err := json.Marshal(struct {
		Applied []string          `json:"applied"`
		Errors  map[string]string `json:"errors"`
	}{Applied: applied, Errors: errs})
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

// hostFromRoute extracts the first host out of a Caddy route's match block.
func hostFromRoute(raw json.RawMessage) string {
	var partial struct {
		Match []struct {
			Host []string `json:"host"`
		} `json:"match"`
	}
	if err := json.Unmarshal(raw, &partial); err != nil {
		return ""
	}
	if len(partial.Match) > 0 && len(partial.Match[0].Host) > 0 {
		return partial.Match[0].Host[0]
	}
	return ""
}

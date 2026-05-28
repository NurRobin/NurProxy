// Package agentclient provides an HTTP client for communicating with NurProxy agents.
package agentclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to remote NurProxy agents over their HTTP API.
type Client struct {
	http *http.Client
}

// New creates a Client with sensible defaults.
func New() *Client {
	return &Client{
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

// NewWithHTTPClient creates a Client backed by the supplied http.Client.
func NewWithHTTPClient(hc *http.Client) *Client {
	return &Client{http: hc}
}

// Health checks if the agent is reachable.
func (c *Client) Health(ctx context.Context, agentURL, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, trimSlash(agentURL)+"/health", nil)
	if err != nil {
		return fmt.Errorf("creating health request: %w", err)
	}
	setAuth(req, token)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}
	return nil
}

// PushRoute adds or updates a single route on the agent. The agent keys routes
// by domain, so the domain (the route's host) is sent alongside the route. This
// maps to the agent's `POST /routes` single-route handler.
func (c *Client) PushRoute(ctx context.Context, agentURL, token string, route json.RawMessage) error {
	domain := hostFromRoute(route)
	if domain == "" {
		return fmt.Errorf("cannot push route: no host found in route config")
	}

	body, err := json.Marshal(struct {
		Domain string          `json:"domain"`
		Route  json.RawMessage `json:"route"`
	}{Domain: domain, Route: route})
	if err != nil {
		return fmt.Errorf("marshaling route payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, trimSlash(agentURL)+"/routes", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating push request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	setAuth(req, token)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("pushing route: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("push route returned status %d", resp.StatusCode)
	}
	return nil
}

// DeleteRoute removes a route by domain from the agent.
func (c *Client) DeleteRoute(ctx context.Context, agentURL, token, domain string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, trimSlash(agentURL)+"/routes/"+domain, nil)
	if err != nil {
		return fmt.Errorf("creating delete request: %w", err)
	}
	setAuth(req, token)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("deleting route: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("delete route returned status %d", resp.StatusCode)
	}
	return nil
}

// SyncRoutes replaces the agent's entire route set in one call. The agent's
// `PUT /routes` handler expects a map of domain -> route config.
func (c *Client) SyncRoutes(ctx context.Context, agentURL, token string, routes []json.RawMessage) error {
	byDomain := make(map[string]json.RawMessage, len(routes))
	for _, r := range routes {
		if domain := hostFromRoute(r); domain != "" {
			byDomain[domain] = r
		}
	}

	body, err := json.Marshal(byDomain)
	if err != nil {
		return fmt.Errorf("marshaling routes: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, trimSlash(agentURL)+"/routes", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating sync request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	setAuth(req, token)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("syncing routes: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sync routes returned status %d", resp.StatusCode)
	}
	return nil
}

// GetRoutes fetches all currently active routes from the agent. The agent
// returns a map of domain -> route config; the values are returned as a slice.
func (c *Client) GetRoutes(ctx context.Context, agentURL, token string) ([]json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, trimSlash(agentURL)+"/routes", nil)
	if err != nil {
		return nil, fmt.Errorf("creating get routes request: %w", err)
	}
	setAuth(req, token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getting routes: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("get routes returned status %d", resp.StatusCode)
	}

	var byDomain map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&byDomain); err != nil {
		return nil, fmt.Errorf("decoding routes: %w", err)
	}
	routes := make([]json.RawMessage, 0, len(byDomain))
	for _, r := range byDomain {
		routes = append(routes, r)
	}
	return routes, nil
}

// hostFromRoute extracts the first host from a Caddy route's match block so the
// orchestrator can key routes by domain the same way the agent does.
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

func setAuth(req *http.Request, token string) {
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

func trimSlash(url string) string {
	return strings.TrimRight(url, "/")
}

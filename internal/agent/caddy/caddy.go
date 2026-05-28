package caddy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"sync"
	"time"
)

// Process manages a Caddy subprocess.
type Process struct {
	adminPort int
	cmd       *exec.Cmd
	mu        sync.Mutex
	mock      bool
	running   bool
}

// NewProcess creates a new Caddy process manager.
func NewProcess(adminPort int) *Process {
	return &Process{
		adminPort: adminPort,
	}
}

// Start launches the Caddy process. If the caddy binary is not found, it runs
// in mock mode (tracking routes in memory only).
func (p *Process) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	caddyPath, err := exec.LookPath("caddy")
	if err != nil {
		log.Printf("WARNING: caddy binary not found, running in mock mode")
		p.mock = true
		p.running = true
		return nil
	}

	// Build minimal initial config with the admin listener.
	initialConfig := map[string]interface{}{
		"admin": map[string]interface{}{
			"listen": fmt.Sprintf("localhost:%d", p.adminPort),
		},
	}
	configBytes, err := json.Marshal(initialConfig)
	if err != nil {
		return fmt.Errorf("marshaling initial config: %w", err)
	}

	p.cmd = exec.CommandContext(ctx, caddyPath, "run", "--config", "-", "--adapter", "")
	p.cmd.Stdin = bytes.NewReader(configBytes)

	if err := p.cmd.Start(); err != nil {
		return fmt.Errorf("starting caddy: %w", err)
	}

	p.running = true
	log.Printf("Caddy started (PID %d, admin on localhost:%d)", p.cmd.Process.Pid, p.adminPort)

	// Wait for process in background so we detect exits.
	go func() {
		if err := p.cmd.Wait(); err != nil {
			log.Printf("Caddy process exited: %v", err)
		}
		p.mu.Lock()
		p.running = false
		p.mu.Unlock()
	}()

	return nil
}

// Stop stops the Caddy process.
func (p *Process) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.mock {
		p.running = false
		return nil
	}

	if p.cmd != nil && p.cmd.Process != nil {
		if err := p.cmd.Process.Kill(); err != nil {
			return fmt.Errorf("killing caddy: %w", err)
		}
	}

	p.running = false
	return nil
}

// Running returns whether the Caddy process is alive.
func (p *Process) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}

// IsMock returns true if running in mock mode (no caddy binary).
func (p *Process) IsMock() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.mock
}

// Client communicates with the Caddy Admin API.
type Client struct {
	baseURL    string
	http       *http.Client
	mock       bool
	mockConfig map[string]interface{}
	mu         sync.Mutex
}

// NewClient creates a new Caddy Admin API client.
func NewClient(adminPort int) *Client {
	return &Client{
		baseURL: fmt.Sprintf("http://localhost:%d", adminPort),
		http: &http.Client{
			Timeout: 10 * time.Second,
		},
		mockConfig: make(map[string]interface{}),
	}
}

// NewMockClient creates a client that operates in mock mode (no real Caddy).
func NewMockClient() *Client {
	return &Client{
		mock:       true,
		mockConfig: make(map[string]interface{}),
		http: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SetMock enables or disables mock mode.
func (c *Client) SetMock(mock bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mock = mock
}

// EnsureServer checks if the http server exists in Caddy config and creates it
// if not.
func (c *Client) EnsureServer(ctx context.Context) error {
	c.mu.Lock()
	if c.mock {
		if c.mockConfig["server"] == nil {
			c.mockConfig["server"] = map[string]interface{}{
				"listen": []string{":443", ":80"},
				"routes": []json.RawMessage{},
			}
		}
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	// Check if server exists.
	_, err := c.doRequest(ctx, http.MethodGet, "/config/apps/http/servers/srv0", nil)
	if err == nil {
		return nil
	}

	// Create initial http app structure.
	serverCfg := map[string]interface{}{
		"listen": []string{":443", ":80"},
	}
	data, err := json.Marshal(serverCfg)
	if err != nil {
		return fmt.Errorf("marshaling server config: %w", err)
	}

	_, err = c.doRequest(ctx, http.MethodPost, "/config/apps/http/servers/srv0", data)
	if err != nil {
		return fmt.Errorf("creating server: %w", err)
	}

	return nil
}

// AddRoute adds a route to the Caddy configuration.
func (c *Client) AddRoute(ctx context.Context, route json.RawMessage) error {
	c.mu.Lock()
	if c.mock {
		var parsed map[string]interface{}
		if err := json.Unmarshal(route, &parsed); err == nil {
			id, _ := parsed["@id"].(string)
			if id != "" {
				c.mockConfig["route:"+id] = parsed
			}
		}
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	_, err := c.doRequest(ctx, http.MethodPost, "/config/apps/http/servers/srv0/routes", route)
	if err != nil {
		return fmt.Errorf("adding route: %w", err)
	}
	return nil
}

// RemoveRoute removes a route from the Caddy configuration by its ID.
func (c *Client) RemoveRoute(ctx context.Context, routeID string) error {
	c.mu.Lock()
	if c.mock {
		delete(c.mockConfig, "route:"+routeID)
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	_, err := c.doRequest(ctx, http.MethodDelete, "/id/"+routeID, nil)
	if err != nil {
		return fmt.Errorf("removing route %s: %w", routeID, err)
	}
	return nil
}

// ListRoutes retrieves all routes from the Caddy configuration.
func (c *Client) ListRoutes(ctx context.Context) ([]json.RawMessage, error) {
	c.mu.Lock()
	if c.mock {
		var routes []json.RawMessage
		for k, v := range c.mockConfig {
			if len(k) > 6 && k[:6] == "route:" {
				data, _ := json.Marshal(v)
				routes = append(routes, json.RawMessage(data))
			}
		}
		c.mu.Unlock()
		return routes, nil
	}
	c.mu.Unlock()

	body, err := c.doRequest(ctx, http.MethodGet, "/config/apps/http/servers/srv0/routes", nil)
	if err != nil {
		return nil, fmt.Errorf("listing routes: %w", err)
	}

	var routes []json.RawMessage
	if err := json.Unmarshal(body, &routes); err != nil {
		return nil, fmt.Errorf("parsing routes: %w", err)
	}
	return routes, nil
}

// GetConfig retrieves the full Caddy configuration.
func (c *Client) GetConfig(ctx context.Context) (json.RawMessage, error) {
	c.mu.Lock()
	if c.mock {
		data, _ := json.Marshal(c.mockConfig)
		c.mu.Unlock()
		return json.RawMessage(data), nil
	}
	c.mu.Unlock()

	body, err := c.doRequest(ctx, http.MethodGet, "/config/", nil)
	if err != nil {
		return nil, fmt.Errorf("getting config: %w", err)
	}
	return json.RawMessage(body), nil
}

// ClearRoutes removes all routes from the mock config or the Caddy config.
func (c *Client) ClearRoutes(ctx context.Context) error {
	c.mu.Lock()
	if c.mock {
		for k := range c.mockConfig {
			if len(k) > 6 && k[:6] == "route:" {
				delete(c.mockConfig, k)
			}
		}
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	_, err := c.doRequest(ctx, http.MethodDelete, "/config/apps/http/servers/srv0/routes", nil)
	if err != nil {
		return fmt.Errorf("clearing routes: %w", err)
	}
	return nil
}

func (c *Client) doRequest(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("caddy API returned %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

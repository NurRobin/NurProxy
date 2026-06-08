package caddy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
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

	// Build a minimal initial config with just the admin listener. Keeping the
	// HTTP server out of the bootstrap means Caddy reliably starts (binding only
	// localhost admin), so its admin API stays up even when ports 80/443 are
	// taken — letting the agent introspect and report accurately. EnsureServer
	// creates the HTTP server afterwards.
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

	// Wait for the admin API to accept connections before returning, so the very
	// first EnsureServer/route push doesn't race the listener and fail with
	// "connection refused".
	waitAdminReady(p.adminPort, 5*time.Second)

	return nil
}

// waitAdminReady blocks until Caddy's admin port accepts a TCP connection or the
// timeout elapses. It's best-effort: callers proceed regardless.
func waitAdminReady(adminPort int, timeout time.Duration) {
	addr := fmt.Sprintf("localhost:%d", adminPort)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
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

	// Already present? Ensure it still has a routes array before returning: a TLS
	// strategy apply (ApplyTLS) may have created srv0 with only automatic_https and
	// no routes, in which case a later AddRoute POST writes an object Caddy cannot
	// load as a RouteList. Seed an empty routes array when it is missing.
	if body, err := c.doRequest(ctx, http.MethodGet, "/config/apps/http/servers/srv0", nil); err == nil {
		var existing struct {
			Routes json.RawMessage `json:"routes"`
		}
		_ = json.Unmarshal(body, &existing)
		if len(existing.Routes) == 0 {
			empty, _ := json.Marshal([]json.RawMessage{})
			if _, err := c.doRequest(ctx, http.MethodPut, "/config/apps/http/servers/srv0/routes", empty); err != nil {
				return fmt.Errorf("seeding routes array on existing srv0: %w", err)
			}
		}
		return nil
	}

	// The fresh srv0 (no routes yet — routes are added afterwards). We only get
	// here when srv0 is absent, so there are no existing routes to preserve.
	server := map[string]interface{}{
		"listen": []string{":443", ":80"},
		"routes": []json.RawMessage{},
	}

	// The Caddy admin API does not create intermediate config paths, so we build
	// from the deepest existing ancestor downward to avoid "invalid traversal
	// path" errors, while never clobbering sibling config (other apps/servers).
	if body, err := c.doRequest(ctx, http.MethodGet, "/config/apps/http", nil); err == nil {
		// http app exists — merge srv0 into its servers and PUT the app back so a
		// missing "servers" object is created without disturbing other servers.
		var httpApp struct {
			Servers map[string]json.RawMessage `json:"servers"`
		}
		_ = json.Unmarshal(body, &httpApp)
		if httpApp.Servers == nil {
			httpApp.Servers = map[string]json.RawMessage{}
		}
		srvData, _ := json.Marshal(server)
		httpApp.Servers["srv0"] = srvData
		appData, err := json.Marshal(map[string]interface{}{"servers": httpApp.Servers})
		if err != nil {
			return fmt.Errorf("marshaling http app: %w", err)
		}
		if _, err := c.doRequest(ctx, http.MethodPut, "/config/apps/http", appData); err != nil {
			return fmt.Errorf("creating server: %w", err)
		}
		return nil
	}

	httpApp := map[string]interface{}{"servers": map[string]interface{}{"srv0": server}}

	if _, err := c.doRequest(ctx, http.MethodGet, "/config/apps", nil); err == nil {
		// apps exists but http doesn't — create just the http app.
		data, err := json.Marshal(httpApp)
		if err != nil {
			return fmt.Errorf("marshaling http app: %w", err)
		}
		if _, err := c.doRequest(ctx, http.MethodPut, "/config/apps/http", data); err != nil {
			return fmt.Errorf("creating http app: %w", err)
		}
		return nil
	}

	// No apps object at all — create it with the http app inside.
	data, err := json.Marshal(map[string]interface{}{"http": httpApp})
	if err != nil {
		return fmt.Errorf("marshaling apps: %w", err)
	}
	if _, err := c.doRequest(ctx, http.MethodPut, "/config/apps", data); err != nil {
		return fmt.Errorf("creating apps: %w", err)
	}
	return nil
}

// ApplyTLS configures the bundled Caddy's TLS strategy (§7): it loads the
// provided certificate files into Caddy's tls app and sets srv0's automatic_https
// policy, so the built-in Caddy serves centrally-provisioned certs instead of
// running its own ACME. loadFiles is the tls app's certificates/load_files (one
// per provided-cert host); automaticHTTPS is the http server's automatic_https
// block (Disable when every host is on provided certs, otherwise Skip the
// provided hosts so self-ACME hosts still get managed). Caller renders both with
// caddygen.GenerateServerTLS, keeping the strategy a pure, tested decision.
//
// It PUTs the tls app's load_files (creating the tls app if absent) and PUTs
// srv0's automatic_https, building from the deepest existing ancestor down so it
// never clobbers sibling config — the same conservative approach EnsureServer
// uses. A nil/empty load_files set still writes automatic_https (e.g. disable for
// a pure-provided fleet or a managed self-ACME server with no loaded files).
func (c *Client) ApplyTLS(ctx context.Context, loadFiles json.RawMessage, automaticHTTPS json.RawMessage, connPolicies json.RawMessage) error {
	c.mu.Lock()
	if c.mock {
		c.mockConfig["tls_load_files"] = loadFiles
		c.mockConfig["automatic_https"] = automaticHTTPS
		c.mockConfig["tls_connection_policies"] = connPolicies
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	// Set the http server's automatic_https policy. srv0 must already exist
	// (EnsureServer runs first); PUT replaces just the automatic_https sub-object.
	if len(automaticHTTPS) > 0 {
		if _, err := c.doRequest(ctx, http.MethodPut, "/config/apps/http/servers/srv0/automatic_https", automaticHTTPS); err != nil {
			return fmt.Errorf("setting automatic_https: %w", err)
		}
	}

	// With automatic_https disabled, Caddy creates no TLS connection policy, so
	// without this srv0 serves plaintext on :443. PUT the default policy so it
	// terminates TLS using the provided certs loaded below (matched by SNI).
	if len(connPolicies) > 0 {
		if _, err := c.doRequest(ctx, http.MethodPut, "/config/apps/http/servers/srv0/tls_connection_policies", connPolicies); err != nil {
			return fmt.Errorf("setting tls_connection_policies: %w", err)
		}
	}

	// Load the provided certificate files into the tls app. Build from the deepest
	// existing ancestor down so we never clobber sibling tls config (e.g. an
	// operator's automation policies), mirroring EnsureServer.
	certificates := map[string]interface{}{"load_files": loadFiles}

	if _, err := c.doRequest(ctx, http.MethodGet, "/config/apps/tls", nil); err == nil {
		// tls app exists — set just its certificates object.
		data, err := json.Marshal(certificates)
		if err != nil {
			return fmt.Errorf("marshaling tls certificates: %w", err)
		}
		if _, err := c.doRequest(ctx, http.MethodPut, "/config/apps/tls/certificates", data); err != nil {
			return fmt.Errorf("loading tls certificates: %w", err)
		}
		return nil
	}

	tlsApp := map[string]interface{}{"certificates": certificates}
	if _, err := c.doRequest(ctx, http.MethodGet, "/config/apps", nil); err == nil {
		// apps exists but tls doesn't — create just the tls app.
		data, err := json.Marshal(tlsApp)
		if err != nil {
			return fmt.Errorf("marshaling tls app: %w", err)
		}
		if _, err := c.doRequest(ctx, http.MethodPut, "/config/apps/tls", data); err != nil {
			return fmt.Errorf("creating tls app: %w", err)
		}
		return nil
	}

	// No apps object at all — create it with the tls app inside.
	data, err := json.Marshal(map[string]interface{}{"tls": tlsApp})
	if err != nil {
		return fmt.Errorf("marshaling apps: %w", err)
	}
	if _, err := c.doRequest(ctx, http.MethodPut, "/config/apps", data); err != nil {
		return fmt.Errorf("creating apps with tls: %w", err)
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

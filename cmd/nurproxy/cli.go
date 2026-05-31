package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

// The management CLI is a thin REST client over the orchestrator's /api/v1
// surface. It exists so the headless build (no embedded dashboard) is usable
// standalone: every operation the dashboard performs is reachable here.
//
// Auth resolves in this order:
//   - NP_API_KEY / --key  → Authorization: Bearer <key>
//   - NP_API_PASSWORD / --password → login first, then ride the session cookie
//
// The password path exists for bootstrapping a fresh headless install, where
// there is no dashboard to mint the first API key: `nurproxy auth setup` then
// `nurproxy apikey create` gets you a key with nothing but the binary.

// runCLI dispatches a management subcommand. It returns false if name is not a
// CLI subcommand, letting main() fall through to running the server.
func runCLI(name string, args []string) bool {
	switch name {
	case "provider":
		cmdProvider(args)
	case "zone":
		cmdZone(args)
	case "agent":
		cmdAgent(args)
	case "server":
		cmdServer(args)
	case "domain":
		cmdDomain(args)
	case "apikey":
		cmdAPIKey(args)
	case "auth":
		cmdAuth(args)
	default:
		return false
	}
	return true
}

// client talks to the orchestrator REST API.
type client struct {
	baseURL  string
	apiKey   string
	password string
	cookie   string // session cookie value, populated lazily via login
	asJSON   bool
	http     *http.Client
}

// registerClientFlags adds the auth/output flags shared by every subcommand to
// fs. Call newClient after fs.Parse to build the client from them.
func registerClientFlags(fs *flag.FlagSet) (*string, *string, *string, *bool) {
	url := fs.String("url", envOr("NP_API_URL", "http://localhost:8080"), "Orchestrator base URL")
	key := fs.String("key", os.Getenv("NP_API_KEY"), "Admin API key (or NP_API_KEY)")
	pass := fs.String("password", os.Getenv("NP_API_PASSWORD"), "Admin password for login-based auth (or NP_API_PASSWORD)")
	asJSON := fs.Bool("json", false, "Output raw JSON instead of a table")
	return url, key, pass, asJSON
}

func newClient(url, key, pass string, asJSON bool) *client {
	return &client{
		baseURL:  strings.TrimRight(url, "/"),
		apiKey:   key,
		password: pass,
		asJSON:   asJSON,
		http:     &http.Client{Timeout: 30 * time.Second},
	}
}

// ensureAuth makes sure the client has a usable credential. With an API key
// there is nothing to do; with only a password it logs in once and caches the
// session cookie for subsequent requests.
func (c *client) ensureAuth() error {
	if c.apiKey != "" || c.cookie != "" {
		return nil
	}
	if c.password == "" {
		return fmt.Errorf("no credentials: set NP_API_KEY (or --key), or NP_API_PASSWORD (or --password)")
	}
	return c.login(c.password)
}

// login exchanges the admin password for a session cookie.
func (c *client) login(password string) error {
	body, _ := json.Marshal(map[string]string{"password": password})
	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/api/v1/auth/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("login failed: %s", apiError(resp))
	}
	for _, ck := range resp.Cookies() {
		if ck.Name == "nurproxy_session" {
			c.cookie = ck.Value
			return nil
		}
	}
	return fmt.Errorf("login succeeded but no session cookie returned")
}

// do performs an authenticated request and returns the decoded response body.
// A non-2xx status is turned into an error carrying the API's message.
func (c *client) do(method, path string, body interface{}) ([]byte, error) {
	if err := c.ensureAuth(); err != nil {
		return nil, err
	}

	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	} else if c.cookie != "" {
		req.AddCookie(&http.Cookie{Name: "nurproxy_session", Value: c.cookie})
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s %s: %s", method, path, apiErrorBytes(resp.StatusCode, data))
	}
	return data, nil
}

func (c *client) get(path string) ([]byte, error) { return c.do(http.MethodGet, path, nil) }
func (c *client) del(path string) ([]byte, error) { return c.do(http.MethodDelete, path, nil) }

// getInto GETs path and unmarshals the JSON body into v.
func (c *client) getInto(path string, v interface{}) error {
	data, err := c.get(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// emit prints a successful response: raw JSON when --json is set, otherwise the
// caller-supplied human message.
func (c *client) emit(raw []byte, human string) {
	if c.asJSON {
		fmt.Println(strings.TrimSpace(string(raw)))
		return
	}
	fmt.Println(human)
}

// --- small helpers -------------------------------------------------------

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// apiError extracts the {"error": "..."} message from a response, falling back
// to the status text.
func apiError(resp *http.Response) string {
	data, _ := io.ReadAll(resp.Body)
	return apiErrorBytes(resp.StatusCode, data)
}

func apiErrorBytes(status int, data []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &e) == nil && e.Error != "" {
		return e.Error
	}
	if len(data) > 0 {
		return fmt.Sprintf("HTTP %d: %s", status, strings.TrimSpace(string(data)))
	}
	return fmt.Sprintf("HTTP %d", status)
}

// printTable renders rows under headers using aligned columns.
func printTable(headers []string, rows [][]string) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, strings.Join(headers, "\t"))
	for _, row := range rows {
		_, _ = fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	_ = tw.Flush()
}

// fatalf prints an error to stderr and exits non-zero.
func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

// dash renders empty strings as a placeholder for table cells.
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

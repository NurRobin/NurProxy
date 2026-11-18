package proxmox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// apiError is a non-2xx answer from the PVE API. PVE puts its message in the
// HTTP reason phrase (e.g. "500 QEMU guest agent is not running") and
// sometimes in a JSON "errors" object.
type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("proxmox API returned HTTP %d", e.Status)
	}
	return fmt.Sprintf("proxmox API returned HTTP %d: %s", e.Status, e.Message)
}

type client struct {
	base   *url.URL
	auth   string
	http   *http.Client
	maxErr int
}

func newClient(cfg *Config) (*client, error) {
	base, err := cfg.baseURL()
	if err != nil {
		return nil, err
	}
	hc, err := cfg.httpClient(requestTimeout)
	if err != nil {
		return nil, err
	}
	return &client{
		base:   base,
		auth:   "PVEAPIToken=" + cfg.TokenID + "=" + cfg.TokenSecret,
		http:   hc,
		maxErr: 200,
	}, nil
}

// close drops the client's idle connections so a finished run leaves no
// connection goroutines behind.
func (c *client) close() { c.http.CloseIdleConnections() }

// get fetches /api2/json/<path> and decodes the "data" member into out.
// Path segments must already be escaped.
func (c *client) get(ctx context.Context, path string, out any) error {
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + "/api2/json/" + strings.TrimPrefix(path, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.auth)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("proxmox: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return fmt.Errorf("proxmox: reading response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &apiError{Status: resp.StatusCode, Message: c.errorMessage(resp, body)}
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("proxmox: decoding %s: %w", path, err)
	}
	if out == nil || len(env.Data) == 0 || bytes.Equal(env.Data, []byte("null")) {
		return nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("proxmox: decoding %s: %w", path, err)
	}
	return nil
}

// errorMessage pulls PVE's message out of the reason phrase or the "errors"
// object, trimmed so a large body never ends up in a log line.
func (c *client) errorMessage(resp *http.Response, body []byte) string {
	msg := strings.TrimSpace(strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode)))
	if msg == http.StatusText(resp.StatusCode) {
		msg = ""
	}
	var env struct {
		Message string            `json:"message"`
		Errors  map[string]string `json:"errors"`
	}
	if json.Unmarshal(body, &env) == nil {
		if env.Message != "" && msg == "" {
			msg = strings.TrimSpace(env.Message)
		}
		for k, v := range env.Errors {
			msg = strings.TrimSpace(msg + " " + k + ": " + v)
		}
	}
	if len(msg) > c.maxErr {
		msg = msg[:c.maxErr] + "…"
	}
	return msg
}

// flexInt decodes a number that PVE sends either as a JSON number or as a
// string (the LXC list reports vmid as "101").
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("not an integer: %s", b)
	}
	*f = flexInt(n)
	return nil
}

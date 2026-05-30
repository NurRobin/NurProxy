package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/NurRobin/NurProxy/internal/provider"
)

const defaultBaseURL = "https://api.cloudflare.com/client/v4"

// CloudflareProvider implements provider.Provider for Cloudflare DNS.
type CloudflareProvider struct {
	// baseURL can be overridden for testing; defaults to defaultBaseURL.
	baseURL string
	// client can be overridden for testing; defaults to http.DefaultClient.
	client *http.Client
}

type cloudflareConfig struct {
	APIToken string `json:"api_token"`
	ZoneID   string `json:"zone_id"`
}

// cfResponse is the generic Cloudflare API response wrapper.
type cfResponse struct {
	Success bool            `json:"success"`
	Errors  []cfError       `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

// cfResultInfo contains pagination info from Cloudflare responses.
type cfResultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	TotalPages int `json:"total_pages"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
}

// cfPaginatedResponse is the Cloudflare API response with pagination info.
type cfPaginatedResponse struct {
	Success    bool            `json:"success"`
	Errors     []cfError       `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo cfResultInfo    `json:"result_info"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

func init() {
	provider.Register(&CloudflareProvider{})
}

func (p *CloudflareProvider) Info() provider.ProviderInfo {
	return provider.ProviderInfo{
		ID:          "cloudflare",
		Name:        "Cloudflare",
		Description: "Cloudflare DNS management via API v4",
		Website:     "https://www.cloudflare.com",
		RecordTypes: []string{"A", "AAAA", "CNAME", "TXT"},
	}
}

func (p *CloudflareProvider) ConfigSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"api_token": {
				"type": "string",
				"description": "Cloudflare API token with DNS edit permissions"
			},
			"zone_id": {
				"type": "string",
				"description": "Cloudflare zone ID, set after zone selection"
			}
		},
		"required": ["api_token"]
	}`)
}

func (p *CloudflareProvider) ValidateConfig(ctx context.Context, config json.RawMessage) error {
	cfg, err := parseConfig(config)
	if err != nil {
		return err
	}

	// Validate by listing zones — works for both user-owned and account-owned tokens,
	// and proves the token has the permissions we actually need (Zone:Read).
	_, err = p.doRequest(ctx, cfg.APIToken, http.MethodGet, "/zones?per_page=1", nil)
	if err != nil {
		return fmt.Errorf("cloudflare: token validation failed: %w", err)
	}
	return nil
}

func (p *CloudflareProvider) ListZones(ctx context.Context, config json.RawMessage) ([]provider.Zone, error) {
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, err
	}

	var allZones []provider.Zone
	page := 1

	for {
		path := fmt.Sprintf("/zones?per_page=50&page=%d", page)
		body, err := p.doRawRequest(ctx, cfg.APIToken, http.MethodGet, path, nil)
		if err != nil {
			return nil, fmt.Errorf("cloudflare: list zones request failed: %w", err)
		}

		var paginated cfPaginatedResponse
		if err := json.Unmarshal(body, &paginated); err != nil {
			return nil, fmt.Errorf("cloudflare: failed to parse zones response: %w", err)
		}
		if !paginated.Success {
			return nil, formatCFErrors(paginated.Errors)
		}

		var zones []cfZone
		if err := json.Unmarshal(paginated.Result, &zones); err != nil {
			return nil, fmt.Errorf("cloudflare: failed to parse zone list: %w", err)
		}

		for _, z := range zones {
			allZones = append(allZones, provider.Zone{ID: z.ID, Name: z.Name})
		}

		if page >= paginated.ResultInfo.TotalPages || paginated.ResultInfo.TotalPages == 0 {
			break
		}
		page++
	}

	return allZones, nil
}

func (p *CloudflareProvider) CreateRecord(ctx context.Context, config json.RawMessage, record provider.Record) (string, error) {
	cfg, err := parseConfig(config)
	if err != nil {
		return "", err
	}
	if cfg.ZoneID == "" {
		return "", fmt.Errorf("cloudflare: zone_id is required to create a record")
	}

	payload := cfDNSRecord{
		Type:    record.Type,
		Name:    record.Name,
		Content: record.Content,
		TTL:     record.TTL,
		Proxied: record.Proxied,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("cloudflare: failed to marshal record: %w", err)
	}

	path := fmt.Sprintf("/zones/%s/dns_records", cfg.ZoneID)
	resp, err := p.doRequest(ctx, cfg.APIToken, http.MethodPost, path, payloadBytes)
	if err != nil {
		return "", fmt.Errorf("cloudflare: create record request failed: %w", err)
	}

	var created cfDNSRecord
	if err := json.Unmarshal(resp.Result, &created); err != nil {
		return "", fmt.Errorf("cloudflare: failed to parse created record: %w", err)
	}
	return created.ID, nil
}

func (p *CloudflareProvider) GetRecord(ctx context.Context, config json.RawMessage, recordID string) (*provider.Record, error) {
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, err
	}
	if cfg.ZoneID == "" {
		return nil, fmt.Errorf("cloudflare: zone_id is required to get a record")
	}

	path := fmt.Sprintf("/zones/%s/dns_records/%s", cfg.ZoneID, recordID)
	resp, err := p.doRequest(ctx, cfg.APIToken, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: get record request failed: %w", err)
	}

	var rec cfDNSRecord
	if err := json.Unmarshal(resp.Result, &rec); err != nil {
		return nil, fmt.Errorf("cloudflare: failed to parse record: %w", err)
	}

	return &provider.Record{
		ID:      rec.ID,
		Type:    rec.Type,
		Name:    rec.Name,
		Content: rec.Content,
		TTL:     rec.TTL,
		Proxied: rec.Proxied,
	}, nil
}

// ListRecords returns the zone's records matching name (and type, if non-empty),
// each carrying its Cloudflare record ID so the caller can adopt or update it. It
// backs the reconciler's check-before-create: the CF list endpoint filters
// server-side by name/type (GET /zones/{zone}/dns_records?name=&type=).
func (p *CloudflareProvider) ListRecords(ctx context.Context, config json.RawMessage, name, recordType string) ([]provider.Record, error) {
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, err
	}
	if cfg.ZoneID == "" {
		return nil, fmt.Errorf("cloudflare: zone_id is required to list records")
	}

	q := url.Values{}
	if name != "" {
		q.Set("name", name)
	}
	if recordType != "" {
		q.Set("type", recordType)
	}
	q.Set("per_page", "100")
	path := fmt.Sprintf("/zones/%s/dns_records?%s", cfg.ZoneID, q.Encode())

	resp, err := p.doRequest(ctx, cfg.APIToken, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: list records request failed: %w", err)
	}

	var recs []cfDNSRecord
	if err := json.Unmarshal(resp.Result, &recs); err != nil {
		return nil, fmt.Errorf("cloudflare: failed to parse records: %w", err)
	}

	out := make([]provider.Record, 0, len(recs))
	for _, r := range recs {
		out = append(out, provider.Record{
			ID:      r.ID,
			Type:    r.Type,
			Name:    r.Name,
			Content: r.Content,
			TTL:     r.TTL,
			Proxied: r.Proxied,
		})
	}
	return out, nil
}

func (p *CloudflareProvider) UpdateRecord(ctx context.Context, config json.RawMessage, recordID string, record provider.Record) error {
	cfg, err := parseConfig(config)
	if err != nil {
		return err
	}
	if cfg.ZoneID == "" {
		return fmt.Errorf("cloudflare: zone_id is required to update a record")
	}

	payload := cfDNSRecord{
		Type:    record.Type,
		Name:    record.Name,
		Content: record.Content,
		TTL:     record.TTL,
		Proxied: record.Proxied,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("cloudflare: failed to marshal record: %w", err)
	}

	path := fmt.Sprintf("/zones/%s/dns_records/%s", cfg.ZoneID, recordID)
	_, err = p.doRequest(ctx, cfg.APIToken, http.MethodPut, path, payloadBytes)
	if err != nil {
		return fmt.Errorf("cloudflare: update record request failed: %w", err)
	}
	return nil
}

func (p *CloudflareProvider) DeleteRecord(ctx context.Context, config json.RawMessage, recordID string) error {
	cfg, err := parseConfig(config)
	if err != nil {
		return err
	}
	if cfg.ZoneID == "" {
		return fmt.Errorf("cloudflare: zone_id is required to delete a record")
	}

	path := fmt.Sprintf("/zones/%s/dns_records/%s", cfg.ZoneID, recordID)
	_, err = p.doRequest(ctx, cfg.APIToken, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("cloudflare: delete record request failed: %w", err)
	}
	return nil
}

// --- internal helpers ---

func parseConfig(config json.RawMessage) (*cloudflareConfig, error) {
	var cfg cloudflareConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, fmt.Errorf("cloudflare: invalid config JSON: %w", err)
	}
	if strings.TrimSpace(cfg.APIToken) == "" {
		return nil, fmt.Errorf("cloudflare: api_token is required")
	}
	return &cfg, nil
}

func (p *CloudflareProvider) getBaseURL() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return defaultBaseURL
}

func (p *CloudflareProvider) getClient() *http.Client {
	if p.client != nil {
		return p.client
	}
	return http.DefaultClient
}

// doRawRequest makes an HTTP request to the Cloudflare API and returns the raw response body.
func (p *CloudflareProvider) doRawRequest(ctx context.Context, token, method, path string, body []byte) ([]byte, error) {
	url := p.getBaseURL() + path

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.getClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return respBody, nil
}

// doRequest makes an HTTP request to the Cloudflare API and returns the parsed cfResponse.
func (p *CloudflareProvider) doRequest(ctx context.Context, token, method, path string, body []byte) (*cfResponse, error) {
	respBody, err := p.doRawRequest(ctx, token, method, path, body)
	if err != nil {
		return nil, err
	}

	var cfResp cfResponse
	if err := json.Unmarshal(respBody, &cfResp); err != nil {
		return nil, fmt.Errorf("failed to parse response JSON: %w", err)
	}
	if !cfResp.Success {
		return nil, formatCFErrors(cfResp.Errors)
	}

	return &cfResp, nil
}

func formatCFErrors(errors []cfError) error {
	if len(errors) == 0 {
		return fmt.Errorf("cloudflare: unknown API error")
	}
	msgs := make([]string, 0, len(errors))
	for _, e := range errors {
		msgs = append(msgs, fmt.Sprintf("[%d] %s", e.Code, e.Message))
	}
	return fmt.Errorf("cloudflare API error: %s", strings.Join(msgs, "; "))
}

package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/provider"
)

func newTestProvider(server *httptest.Server) *CloudflareProvider {
	return &CloudflareProvider{
		baseURL: server.URL,
		client:  server.Client(),
	}
}

func makeConfig(token, zoneID string) json.RawMessage {
	cfg := map[string]string{"api_token": token}
	if zoneID != "" {
		cfg["zone_id"] = zoneID
	}
	b, _ := json.Marshal(cfg)
	return b
}

// Deleting a record Cloudflare reports as nonexistent (HTTP 404, API code 81044)
// must surface as provider.ErrRecordNotFound so callers can treat it as an
// idempotent no-op — while other error codes stay plain errors.
func TestDeleteRecord_notFound_mapsToErrRecordNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"success":false,"errors":[{"code":81044,"message":"Record does not exist."}],"result":null}`))
	}))
	defer server.Close()

	p := newTestProvider(server)
	err := p.DeleteRecord(context.Background(), makeConfig("tok", "zone1"), "rec-123")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, provider.ErrRecordNotFound) {
		t.Fatalf("error should wrap provider.ErrRecordNotFound, got %v", err)
	}
}

func TestDeleteRecord_otherError_isNotNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"success":false,"errors":[{"code":9109,"message":"Unauthorized"}],"result":null}`))
	}))
	defer server.Close()

	p := newTestProvider(server)
	err := p.DeleteRecord(context.Background(), makeConfig("tok", "zone1"), "rec-123")
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, provider.ErrRecordNotFound) {
		t.Fatal("a non-81044 error must NOT be treated as record-not-found")
	}
}

func TestInfo(t *testing.T) {
	p := &CloudflareProvider{}
	info := p.Info()
	if info.ID != "cloudflare" {
		t.Fatalf("expected ID %q, got %q", "cloudflare", info.ID)
	}
	if info.Name != "Cloudflare" {
		t.Fatalf("expected Name %q, got %q", "Cloudflare", info.Name)
	}
}

func TestConfigSchema(t *testing.T) {
	p := &CloudflareProvider{}
	schema := p.ConfigSchema()
	if !json.Valid(schema) {
		t.Fatal("ConfigSchema returned invalid JSON")
	}
}

func TestValidateConfig_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/zones" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected auth header: %s", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success": true, "result": [{"id": "z1", "name": "example.com"}]}`))
	}))
	defer server.Close()

	p := newTestProvider(server)
	err := p.ValidateConfig(context.Background(), makeConfig("test-token", ""))
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidateConfig_InvalidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success": false, "errors": [{"code": 1000, "message": "Invalid API Token"}]}`))
	}))
	defer server.Close()

	p := newTestProvider(server)
	err := p.ValidateConfig(context.Background(), makeConfig("bad-token", ""))
	if err == nil {
		t.Fatal("expected error for invalid token, got nil")
	}
}

func TestValidateConfig_MissingToken(t *testing.T) {
	p := &CloudflareProvider{}
	err := p.ValidateConfig(context.Background(), json.RawMessage(`{"api_token": ""}`))
	if err == nil {
		t.Fatal("expected error for missing token, got nil")
	}
}

func TestListZones(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/zones" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"success": true,
			"result": [
				{"id": "zone-1", "name": "example.com"},
				{"id": "zone-2", "name": "example.org"}
			],
			"result_info": {"page": 1, "per_page": 50, "total_pages": 1, "count": 2, "total_count": 2}
		}`))
	}))
	defer server.Close()

	p := newTestProvider(server)
	zones, err := p.ListZones(context.Background(), makeConfig("test-token", ""))
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(zones) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(zones))
	}
	if zones[0].ID != "zone-1" || zones[0].Name != "example.com" {
		t.Errorf("unexpected first zone: %+v", zones[0])
	}
	if zones[1].ID != "zone-2" || zones[1].Name != "example.org" {
		t.Errorf("unexpected second zone: %+v", zones[1])
	}
}

func TestListZones_Pagination(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if callCount == 1 {
			w.Write([]byte(`{
				"success": true,
				"result": [{"id": "zone-1", "name": "example.com"}],
				"result_info": {"page": 1, "per_page": 50, "total_pages": 2, "count": 1, "total_count": 2}
			}`))
		} else {
			w.Write([]byte(`{
				"success": true,
				"result": [{"id": "zone-2", "name": "example.org"}],
				"result_info": {"page": 2, "per_page": 50, "total_pages": 2, "count": 1, "total_count": 2}
			}`))
		}
	}))
	defer server.Close()

	p := newTestProvider(server)
	zones, err := p.ListZones(context.Background(), makeConfig("test-token", ""))
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(zones) != 2 {
		t.Fatalf("expected 2 zones from pagination, got %d", len(zones))
	}
	if callCount != 2 {
		t.Fatalf("expected 2 API calls for pagination, got %d", callCount)
	}
}

func TestCreateRecord(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/zones/zone-1/dns_records" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var body cfDNSRecord
		json.NewDecoder(r.Body).Decode(&body)
		if body.Type != "A" || body.Name != "test.example.com" || body.Content != "1.2.3.4" {
			t.Errorf("unexpected request body: %+v", body)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success": true, "result": {"id": "record-123", "type": "A", "name": "test.example.com", "content": "1.2.3.4", "ttl": 300, "proxied": false}}`))
	}))
	defer server.Close()

	p := newTestProvider(server)
	record := provider.Record{
		Type:    "A",
		Name:    "test.example.com",
		Content: "1.2.3.4",
		TTL:     300,
		Proxied: false,
	}
	id, err := p.CreateRecord(context.Background(), makeConfig("test-token", "zone-1"), record)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if id != "record-123" {
		t.Fatalf("expected record ID %q, got %q", "record-123", id)
	}
}

func TestCreateRecord_MissingZoneID(t *testing.T) {
	p := &CloudflareProvider{}
	_, err := p.CreateRecord(context.Background(), makeConfig("test-token", ""), provider.Record{})
	if err == nil {
		t.Fatal("expected error for missing zone_id, got nil")
	}
}

func TestGetRecord(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/zones/zone-1/dns_records/record-123" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success": true, "result": {"id": "record-123", "type": "A", "name": "test.example.com", "content": "1.2.3.4", "ttl": 300, "proxied": true}}`))
	}))
	defer server.Close()

	p := newTestProvider(server)
	rec, err := p.GetRecord(context.Background(), makeConfig("test-token", "zone-1"), "record-123")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if rec.Type != "A" {
		t.Errorf("expected type A, got %s", rec.Type)
	}
	if rec.Name != "test.example.com" {
		t.Errorf("expected name test.example.com, got %s", rec.Name)
	}
	if rec.Content != "1.2.3.4" {
		t.Errorf("expected content 1.2.3.4, got %s", rec.Content)
	}
	if rec.TTL != 300 {
		t.Errorf("expected TTL 300, got %d", rec.TTL)
	}
	if !rec.Proxied {
		t.Error("expected proxied to be true")
	}
}

func TestUpdateRecord(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		if r.URL.Path != "/zones/zone-1/dns_records/record-123" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success": true, "result": {"id": "record-123", "type": "A", "name": "test.example.com", "content": "5.6.7.8", "ttl": 600, "proxied": false}}`))
	}))
	defer server.Close()

	p := newTestProvider(server)
	record := provider.Record{
		Type:    "A",
		Name:    "test.example.com",
		Content: "5.6.7.8",
		TTL:     600,
		Proxied: false,
	}
	err := p.UpdateRecord(context.Background(), makeConfig("test-token", "zone-1"), "record-123", record)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestDeleteRecord(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		if r.URL.Path != "/zones/zone-1/dns_records/record-123" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success": true, "result": {"id": "record-123"}}`))
	}))
	defer server.Close()

	p := newTestProvider(server)
	err := p.DeleteRecord(context.Background(), makeConfig("test-token", "zone-1"), "record-123")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAPIErrorHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"success": false, "errors": [{"code": 9109, "message": "Missing or invalid zone_id"}, {"code": 7003, "message": "Could not route to /zones"}]}`))
	}))
	defer server.Close()

	p := newTestProvider(server)
	_, err := p.ListZones(context.Background(), makeConfig("test-token", ""))
	if err == nil {
		t.Fatal("expected error for API error response, got nil")
	}
	errMsg := err.Error()
	if errMsg == "" {
		t.Fatal("expected non-empty error message")
	}
	// Check that multiple errors are included
	if !strings.Contains(errMsg, "9109") || !strings.Contains(errMsg, "7003") {
		t.Errorf("expected error to include both error codes, got: %s", errMsg)
	}
}

func TestInvalidConfigJSON(t *testing.T) {
	p := &CloudflareProvider{}
	err := p.ValidateConfig(context.Background(), json.RawMessage(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

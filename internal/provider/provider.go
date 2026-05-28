package provider

import (
	"context"
	"encoding/json"
)

type Provider interface {
	Info() ProviderInfo
	ConfigSchema() json.RawMessage
	ValidateConfig(ctx context.Context, config json.RawMessage) error
	ListZones(ctx context.Context, config json.RawMessage) ([]Zone, error)
	CreateRecord(ctx context.Context, config json.RawMessage, record Record) (string, error)
	UpdateRecord(ctx context.Context, config json.RawMessage, recordID string, record Record) error
	DeleteRecord(ctx context.Context, config json.RawMessage, recordID string) error
	GetRecord(ctx context.Context, config json.RawMessage, recordID string) (*Record, error)
}

type ProviderInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Website     string   `json:"website"`
	RecordTypes []string `json:"record_types"`
}

type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Record struct {
	Type    string `json:"type"`    // A, AAAA, CNAME
	Name    string `json:"name"`    // FQDN
	Content string `json:"content"` // IP or CNAME target
	TTL     int    `json:"ttl"`     // 0 = provider default
	Proxied bool   `json:"proxied"` // CF-specific
}

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
	// ListRecords returns the records in the zone matching name (the FQDN). When
	// recordType is non-empty it further filters by type (A, AAAA, CNAME, ...).
	// It lets the reconciler look a record up by name BEFORE creating one, so a
	// record left over from a prior run (or created by the operator) is adopted or
	// reported as a conflict instead of triggering the provider's "already exists"
	// error. Returned records carry their provider ID so the caller can adopt them.
	ListRecords(ctx context.Context, config json.RawMessage, name, recordType string) ([]Record, error)
}

type ProviderInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Website     string   `json:"website"`
	RecordTypes []string `json:"record_types"`
}

// SupportsTXT reports whether the provider can create TXT records, which is the
// prerequisite for DNS-01 ACME challenges (§7). A provider that cannot must fall
// back to HTTP-01 (Caddy) rather than failing silently.
func (i ProviderInfo) SupportsTXT() bool {
	for _, t := range i.RecordTypes {
		if t == "TXT" {
			return true
		}
	}
	return false
}

type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Record struct {
	// ID is the provider's record identifier. Empty on a record being created;
	// populated by GetRecord/ListRecords so a found record can be adopted/updated.
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`    // A, AAAA, CNAME
	Name    string `json:"name"`    // FQDN
	Content string `json:"content"` // IP or CNAME target
	TTL     int    `json:"ttl"`     // 0 = provider default
	Proxied bool   `json:"proxied"` // CF-specific
}

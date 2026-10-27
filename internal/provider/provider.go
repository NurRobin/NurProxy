package provider

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
)

// ErrRecordNotFound signals that a record a caller tried to read or delete does
// not exist at the provider. Providers should wrap it (errors.Is-detectable)
// only for the specific "record does not exist" API response — NOT for transient
// or auth errors — so callers can treat a delete of an already-absent record as
// success (idempotent teardown) without masking real failures. For Cloudflare
// this is HTTP 404 with API error code 81044.
var ErrRecordNotFound = errors.New("provider: dns record not found")

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
	// SupportsProxied reports whether Record.Proxied means anything for this
	// provider (Cloudflare's orange cloud). Providers without it must never be
	// asked to create a proxied record.
	SupportsProxied bool `json:"supports_proxied"`
}

// RecordPatch names the record fields NurProxy owns and wants changed. Nil
// fields are left alone, and so is everything the provider stores beyond them
// (Cloudflare comments, tags, per-record settings).
type RecordPatch struct {
	Content *string `json:"content,omitempty"`
	Proxied *bool   `json:"proxied,omitempty"`
}

// RecordPatcher is implemented by providers that can change selected fields of
// an existing record without overwriting the rest. Callers fall back to
// UpdateRecord for providers that don't implement it.
type RecordPatcher interface {
	PatchRecord(ctx context.Context, config json.RawMessage, recordID string, patch RecordPatch) error
}

// PatchOrUpdate applies patch through PatchRecord when p supports it, and
// otherwise overwrites the record with full via UpdateRecord.
func PatchOrUpdate(ctx context.Context, p Provider, config json.RawMessage, recordID string, patch RecordPatch, full Record) error {
	if rp, ok := p.(RecordPatcher); ok {
		return rp.PatchRecord(ctx, config, recordID, patch)
	}
	return p.UpdateRecord(ctx, config, recordID, full)
}

// SupportsProxied reports whether the registered provider with the given ID
// can proxy records. Unknown providers report false.
func SupportsProxied(id string) bool {
	p, err := Get(id)
	if err != nil {
		return false
	}
	return p.Info().SupportsProxied
}

// ProxiableType reports whether a record of this type can carry the proxied
// bit. Cloudflare only proxies address and alias records.
func ProxiableType(recordType string) bool {
	switch strings.ToUpper(recordType) {
	case "A", "AAAA", "CNAME":
		return true
	}
	return false
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

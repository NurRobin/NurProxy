// Package dryrun provides a sandbox decorator for a provider.Provider that
// validates and logs every record operation but never performs a real DNS API
// call. Mutations land in a process-global in-memory store instead, and reads
// (GetRecord/ListRecords) return what was previously "created" — so a full
// domain lifecycle (create CNAME -> present TXT challenge -> clean up TXT)
// exercises realistic sequencing without anything leaving the box (#93).
//
// The store is package-global on purpose: dry-run is a process-wide sandbox
// mode, and a record "created" in one reconcile cycle must be visible to the
// lookup in the next, and to the renewer resolving the same zone — all of which
// build their own wrapper instances. A single shared store is the only thing
// that makes those multi-step, multi-component flows consistent.
package dryrun

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/NurRobin/NurProxy/internal/provider"
)

// store is the shared in-memory record set backing every dry-run wrapper in the
// process. It is queryable so ListRecords/GetRecord reflect prior CreateRecord
// calls, which is what lets the reconciler's adopt-or-create state machine and
// the ACME challenge present/cleanup loop progress normally.
type store struct {
	mu      sync.Mutex
	records map[string]provider.Record // keyed by synthetic ID
	seq     atomic.Uint64
}

var shared = &store{records: make(map[string]provider.Record)}

// Reset clears the shared store. Intended for tests; harmless in production
// (dry-run is never on there).
func Reset() {
	shared.mu.Lock()
	defer shared.mu.Unlock()
	shared.records = make(map[string]provider.Record)
}

func (s *store) nextID() string {
	// A monotonic counter, not a random/time-based ID: dry-run IDs need only be
	// unique within the process, and a counter keeps logs and tests legible.
	return fmt.Sprintf("dryrun-%d", s.seq.Add(1))
}

// dryProvider wraps a real provider. It keeps the inner provider only for its
// static metadata (Info/ConfigSchema) — crucially Info().SupportsTXT(), which
// the TLS issuer checks before attempting DNS-01 — and never calls it for any
// network operation.
type dryProvider struct {
	inner  provider.Provider
	logger *slog.Logger
}

// Wrap returns a sandbox decorator over p. A nil logger defaults to
// slog.Default(). The returned provider satisfies provider.Provider and routes
// every record operation to the shared in-memory store.
func Wrap(p provider.Provider, logger *slog.Logger) provider.Provider {
	if logger == nil {
		logger = slog.Default()
	}
	return &dryProvider{inner: p, logger: logger}
}

func (d *dryProvider) Info() provider.ProviderInfo   { return d.inner.Info() }
func (d *dryProvider) ConfigSchema() json.RawMessage { return d.inner.ConfigSchema() }

// ValidateConfig accepts any syntactically valid JSON config without a network
// round trip — the point of dry-run is to need no live credentials.
func (d *dryProvider) ValidateConfig(_ context.Context, config json.RawMessage) error {
	if len(config) == 0 {
		return nil
	}
	if !json.Valid(config) {
		return fmt.Errorf("dryrun: provider config is not valid JSON")
	}
	return nil
}

// ListZones returns a single synthetic zone so dry-run setup paths have
// something to bind to without contacting the provider.
func (d *dryProvider) ListZones(_ context.Context, _ json.RawMessage) ([]provider.Zone, error) {
	return []provider.Zone{{ID: "dryrun-zone", Name: "dryrun.invalid"}}, nil
}

func (d *dryProvider) CreateRecord(ctx context.Context, _ json.RawMessage, record provider.Record) (string, error) {
	if err := validateRecord(record); err != nil {
		return "", err
	}
	id := shared.nextID()
	record.ID = id
	record.Name = canonicalName(record.Name)
	shared.mu.Lock()
	shared.records[id] = record
	shared.mu.Unlock()

	d.logger.InfoContext(ctx, "dryrun DNS: would create record",
		slog.String("op", "CreateRecord"),
		slog.String("id", id),
		slog.String("type", record.Type),
		slog.String("name", record.Name),
		slog.String("content", record.Content),
		slog.Int("ttl", record.TTL),
	)
	return id, nil
}

func (d *dryProvider) UpdateRecord(ctx context.Context, _ json.RawMessage, recordID string, record provider.Record) error {
	if recordID == "" {
		return fmt.Errorf("dryrun: UpdateRecord requires a record ID")
	}
	if err := validateRecord(record); err != nil {
		return err
	}
	shared.mu.Lock()
	_, ok := shared.records[recordID]
	if ok {
		record.ID = recordID
		record.Name = canonicalName(record.Name)
		shared.records[recordID] = record
	}
	shared.mu.Unlock()
	if !ok {
		return fmt.Errorf("dryrun: record %q not found", recordID)
	}

	d.logger.InfoContext(ctx, "dryrun DNS: would update record",
		slog.String("op", "UpdateRecord"),
		slog.String("id", recordID),
		slog.String("type", record.Type),
		slog.String("name", record.Name),
		slog.String("content", record.Content),
	)
	return nil
}

func (d *dryProvider) DeleteRecord(ctx context.Context, _ json.RawMessage, recordID string) error {
	if recordID == "" {
		return fmt.Errorf("dryrun: DeleteRecord requires a record ID")
	}
	shared.mu.Lock()
	_, ok := shared.records[recordID]
	delete(shared.records, recordID)
	shared.mu.Unlock()
	if !ok {
		// Match real providers' forgiving delete: removing an already-gone record
		// is not an error, so cleanup paths stay idempotent.
		d.logger.InfoContext(ctx, "dryrun DNS: delete of unknown record (no-op)",
			slog.String("op", "DeleteRecord"), slog.String("id", recordID))
		return nil
	}
	d.logger.InfoContext(ctx, "dryrun DNS: would delete record",
		slog.String("op", "DeleteRecord"), slog.String("id", recordID))
	return nil
}

func (d *dryProvider) GetRecord(ctx context.Context, _ json.RawMessage, recordID string) (*provider.Record, error) {
	shared.mu.Lock()
	rec, ok := shared.records[recordID]
	shared.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("dryrun: record %q not found", recordID)
	}
	d.logger.DebugContext(ctx, "dryrun DNS: get record", slog.String("id", recordID))
	out := rec
	return &out, nil
}

func (d *dryProvider) ListRecords(ctx context.Context, _ json.RawMessage, name, recordType string) ([]provider.Record, error) {
	want := canonicalName(name)
	shared.mu.Lock()
	var out []provider.Record
	for _, rec := range shared.records {
		if want != "" && rec.Name != want {
			continue
		}
		if recordType != "" && !strings.EqualFold(rec.Type, recordType) {
			continue
		}
		out = append(out, rec)
	}
	shared.mu.Unlock()
	d.logger.DebugContext(ctx, "dryrun DNS: list records",
		slog.String("name", want), slog.String("type", recordType), slog.Int("matches", len(out)))
	return out, nil
}

// validateRecord enforces the provider-interface contract on a record being
// written: a type, a name, and content are all required. This is the shape
// check the issue asks dry-run to perform in place of the real provider.
func validateRecord(r provider.Record) error {
	if strings.TrimSpace(r.Type) == "" {
		return fmt.Errorf("dryrun: record type is required")
	}
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("dryrun: record name is required")
	}
	if strings.TrimSpace(r.Content) == "" {
		return fmt.Errorf("dryrun: record content is required")
	}
	if r.TTL < 0 {
		return fmt.Errorf("dryrun: record TTL must be >= 0")
	}
	return nil
}

// canonicalName strips a single trailing dot so a lookup for "x.example.com"
// matches a record stored from an FQDN "x.example.com." (lego presents the
// challenge name with the dot).
func canonicalName(name string) string {
	return strings.TrimSuffix(name, ".")
}

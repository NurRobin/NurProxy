package dryrun

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/NurRobin/NurProxy/internal/provider"
)

// fakeInner is a minimal provider.Provider used only for its static metadata;
// the dry-run wrapper must never call its record operations.
type fakeInner struct{ recordTypes []string }

func (f fakeInner) Info() provider.ProviderInfo {
	return provider.ProviderInfo{ID: "fake", Name: "Fake", RecordTypes: f.recordTypes}
}
func (f fakeInner) ConfigSchema() json.RawMessage { return json.RawMessage(`{}`) }
func (f fakeInner) ValidateConfig(context.Context, json.RawMessage) error {
	panic("inner ValidateConfig must not be called in dry-run")
}
func (f fakeInner) ListZones(context.Context, json.RawMessage) ([]provider.Zone, error) {
	panic("inner ListZones must not be called in dry-run")
}
func (f fakeInner) CreateRecord(context.Context, json.RawMessage, provider.Record) (string, error) {
	panic("inner CreateRecord must not be called in dry-run")
}
func (f fakeInner) UpdateRecord(context.Context, json.RawMessage, string, provider.Record) error {
	panic("inner UpdateRecord must not be called in dry-run")
}
func (f fakeInner) DeleteRecord(context.Context, json.RawMessage, string) error {
	panic("inner DeleteRecord must not be called in dry-run")
}
func (f fakeInner) GetRecord(context.Context, json.RawMessage, string) (*provider.Record, error) {
	panic("inner GetRecord must not be called in dry-run")
}
func (f fakeInner) ListRecords(context.Context, json.RawMessage, string, string) ([]provider.Record, error) {
	panic("inner ListRecords must not be called in dry-run")
}

func newWrapped() provider.Provider {
	Reset()
	return Wrap(fakeInner{recordTypes: []string{"A", "AAAA", "CNAME", "TXT"}}, nil)
}

func TestInfoPassThrough(t *testing.T) {
	d := newWrapped()
	if !d.Info().SupportsTXT() {
		t.Fatal("expected wrapped provider to report TXT support from inner Info")
	}
}

func TestCreateGetListDeleteLifecycle(t *testing.T) {
	ctx := context.Background()
	d := newWrapped()
	cfg := json.RawMessage(`{}`)

	id, err := d.CreateRecord(ctx, cfg, provider.Record{Type: "CNAME", Name: "app.example.com", Content: "agent.example.com", TTL: 0})
	if err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}
	if id == "" {
		t.Fatal("CreateRecord returned empty ID")
	}

	got, err := d.GetRecord(ctx, cfg, id)
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if got.Content != "agent.example.com" || got.ID != id {
		t.Fatalf("GetRecord mismatch: %+v", got)
	}

	// ListRecords must surface what CreateRecord stored (queryable store).
	recs, err := d.ListRecords(ctx, cfg, "app.example.com", "CNAME")
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(recs) != 1 || recs[0].ID != id {
		t.Fatalf("ListRecords expected the created record, got %+v", recs)
	}

	// Type filter excludes non-matching types.
	if recs, _ := d.ListRecords(ctx, cfg, "app.example.com", "TXT"); len(recs) != 0 {
		t.Fatalf("ListRecords with TXT filter should be empty, got %+v", recs)
	}

	if err := d.DeleteRecord(ctx, cfg, id); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}
	if _, err := d.GetRecord(ctx, cfg, id); err == nil {
		t.Fatal("GetRecord after delete should fail")
	}
}

func TestChallengeRecordTrailingDot(t *testing.T) {
	ctx := context.Background()
	d := newWrapped()
	cfg := json.RawMessage(`{}`)

	// lego presents the challenge FQDN with a trailing dot; a later lookup uses
	// the dotless name. Both must resolve to the same record.
	if _, err := d.CreateRecord(ctx, cfg, provider.Record{Type: "TXT", Name: "_acme-challenge.app.example.com.", Content: "tokenvalue", TTL: 120}); err != nil {
		t.Fatalf("CreateRecord TXT: %v", err)
	}
	recs, err := d.ListRecords(ctx, cfg, "_acme-challenge.app.example.com", "TXT")
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(recs) != 1 || recs[0].Content != "tokenvalue" {
		t.Fatalf("expected the challenge record via dotless lookup, got %+v", recs)
	}
}

func TestDeleteUnknownIsNoOp(t *testing.T) {
	d := newWrapped()
	if err := d.DeleteRecord(context.Background(), json.RawMessage(`{}`), "nope"); err != nil {
		t.Fatalf("delete of unknown record should be a no-op, got %v", err)
	}
}

func TestValidateRecord(t *testing.T) {
	ctx := context.Background()
	d := newWrapped()
	cfg := json.RawMessage(`{}`)
	tests := []struct {
		name    string
		rec     provider.Record
		wantErr bool
	}{
		{"ok", provider.Record{Type: "A", Name: "x.example.com", Content: "1.2.3.4"}, false},
		{"missing type", provider.Record{Name: "x.example.com", Content: "1.2.3.4"}, true},
		{"missing name", provider.Record{Type: "A", Content: "1.2.3.4"}, true},
		{"missing content", provider.Record{Type: "A", Name: "x.example.com"}, true},
		{"negative ttl", provider.Record{Type: "A", Name: "x.example.com", Content: "1.2.3.4", TTL: -1}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := d.CreateRecord(ctx, cfg, tc.rec)
			if (err != nil) != tc.wantErr {
				t.Fatalf("CreateRecord err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestUpdateUnknownFails(t *testing.T) {
	d := newWrapped()
	err := d.UpdateRecord(context.Background(), json.RawMessage(`{}`), "missing", provider.Record{Type: "A", Name: "x", Content: "1.2.3.4"})
	if err == nil {
		t.Fatal("UpdateRecord on unknown ID should fail")
	}
}

func TestValidateConfig(t *testing.T) {
	d := newWrapped()
	if err := d.ValidateConfig(context.Background(), json.RawMessage(`{"api_token":"x"}`)); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if err := d.ValidateConfig(context.Background(), json.RawMessage(`{bad`)); err == nil {
		t.Fatal("invalid JSON config should be rejected")
	}
}

func TestZoneIsolation(t *testing.T) {
	ctx := context.Background()
	d := newWrapped()
	cfgA := json.RawMessage(`{"zone_id":"zoneA"}`)
	cfgB := json.RawMessage(`{"zone_id":"zoneB"}`)

	// Same record name created under two different zones (configs).
	idA, err := d.CreateRecord(ctx, cfgA, provider.Record{Type: "CNAME", Name: "app.example.com", Content: "a.edge", TTL: 0})
	if err != nil {
		t.Fatalf("create A: %v", err)
	}
	if _, err := d.CreateRecord(ctx, cfgB, provider.Record{Type: "CNAME", Name: "app.example.com", Content: "b.edge", TTL: 0}); err != nil {
		t.Fatalf("create B: %v", err)
	}

	// A lookup scoped to zone A must see only zone A's record, not zone B's.
	recsA, err := d.ListRecords(ctx, cfgA, "app.example.com", "CNAME")
	if err != nil {
		t.Fatalf("list A: %v", err)
	}
	if len(recsA) != 1 || recsA[0].ID != idA || recsA[0].Content != "a.edge" {
		t.Fatalf("zone A lookup leaked across zones: %+v", recsA)
	}

	recsB, _ := d.ListRecords(ctx, cfgB, "app.example.com", "CNAME")
	if len(recsB) != 1 || recsB[0].Content != "b.edge" {
		t.Fatalf("zone B lookup wrong: %+v", recsB)
	}
}

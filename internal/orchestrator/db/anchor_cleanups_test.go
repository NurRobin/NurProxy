package db

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/crypto"
)

// Rows that existed before migration 32 carry anchor record ids of unknown
// provenance. They must come out of the upgrade as NOT owned, and releasing
// them (rename or delete) must queue them as not owned, so the reconciler
// never deletes them.
func TestMigration32_ExistingAnchorsNotOwned(t *testing.T) {
	tests := []struct {
		name    string
		release func(t *testing.T, d *DB)
		reason  string
	}{
		{
			name: "rename",
			release: func(t *testing.T, d *DB) {
				a, err := d.GetAgent("agent1")
				if err != nil {
					t.Fatal(err)
				}
				a.FQDN = "edge2.example.com"
				if err := d.UpdateAgent(a); err != nil {
					t.Fatalf("UpdateAgent: %v", err)
				}
			},
			reason: "rename",
		},
		{
			name: "delete",
			release: func(t *testing.T, d *DB) {
				if err := d.DeleteAgent("agent1"); err != nil {
					t.Fatalf("DeleteAgent: %v", err)
				}
			},
			reason: "delete",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "anchor-upgrade.db")
			seedSchema31WithAnchors(t, dbPath)
			key, err := crypto.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			d, err := Open(dbPath, key)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			t.Cleanup(func() { d.Close() })

			a, err := d.GetAgent("agent1")
			if err != nil {
				t.Fatal(err)
			}
			if a.DNSRecordID != "rec-a" || a.DNSRecordID6 != "rec-aaaa" {
				t.Fatalf("record ids not preserved: A=%q AAAA=%q", a.DNSRecordID, a.DNSRecordID6)
			}
			if a.DNSRecordOwned || a.DNSRecordOwned6 {
				t.Fatalf("pre-existing anchors migrated as owned: A=%v AAAA=%v", a.DNSRecordOwned, a.DNSRecordOwned6)
			}

			tc.release(t, d)

			queued, err := d.ListAgentAnchorCleanups()
			if err != nil {
				t.Fatal(err)
			}
			if len(queued) != 2 {
				t.Fatalf("queued %d cleanups, want 2: %+v", len(queued), queued)
			}
			for _, c := range queued {
				if c.Owned {
					t.Errorf("%s record %s queued as owned", c.RecordType, c.RecordID)
				}
				if c.Reason != tc.reason || c.FQDN != "edge1.example.com" {
					t.Errorf("cleanup = %+v, want reason %q at edge1.example.com", c, tc.reason)
				}
			}
		})
	}
}

// seedSchema31WithAnchors builds a database at schema 31 with one agent whose
// A and AAAA anchor ids are already set, as an upgraded install would have.
func seedSchema31WithAnchors(t *testing.T, dbPath string) {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", dbPath)
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetMaxOpenConns(1)
	if _, err := raw.Exec(`CREATE TABLE schema_version (version INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 31; i++ {
		if _, err := raw.Exec(migrations[i]); err != nil {
			t.Fatalf("applying migration %d: %v", i+1, err)
		}
	}
	if _, err := raw.Exec(`INSERT INTO schema_version (version) VALUES (31)`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO agents (id, name, fqdn, dns_record_id, dns_record_id6)
		VALUES ('agent1', 'edge1', 'edge1.example.com', 'rec-a', 'rec-aaaa')`); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
}

func TestSetAgentAnchorRecord(t *testing.T) {
	tests := []struct {
		name       string
		recordType string
		owned      bool
		fqdn       string // fqdn the record was resolved for
		wantErr    error
		wantQueued int
	}{
		{name: "created A", recordType: "A", owned: true, fqdn: "agent1.example.com"},
		{name: "adopted AAAA", recordType: "AAAA", owned: false, fqdn: "agent1.example.com"},
		{name: "created for old name is queued", recordType: "A", owned: true, fqdn: "old.example.com", wantErr: ErrAnchorStale, wantQueued: 1},
		{name: "adopted for old name is dropped", recordType: "A", owned: false, fqdn: "old.example.com", wantErr: ErrAnchorStale},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := testDB(t)
			p := createTestProvider(t, d)
			z := createTestZone(t, d, p.ID)
			a := createTestAgent(t, d)

			stored, err := d.SetAgentAnchorRecord(a.ID, tc.fqdn, tc.recordType, "rec-1", z.ID, tc.owned)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if stored != tc.owned {
				t.Errorf("stored owned = %v, want %v", stored, tc.owned)
			}
			got, err := d.GetAgent(a.ID)
			if err != nil {
				t.Fatal(err)
			}
			id, owned, zone := got.DNSRecordID, got.DNSRecordOwned, got.DNSRecordZoneID
			if tc.recordType == "AAAA" {
				id, owned, zone = got.DNSRecordID6, got.DNSRecordOwned6, got.DNSRecordZoneID6
			}
			if tc.wantErr == nil {
				if id != "rec-1" || owned != tc.owned || zone != z.ID {
					t.Errorf("stored anchor = (%q, %v, %q), want (rec-1, %v, %s)", id, owned, zone, tc.owned, z.ID)
				}
			} else if id != "" {
				t.Errorf("stale anchor written to agent row: %q", id)
			}
			queued, err := d.ListAgentAnchorCleanups()
			if err != nil {
				t.Fatal(err)
			}
			if len(queued) != tc.wantQueued {
				t.Fatalf("queued %d cleanups, want %d", len(queued), tc.wantQueued)
			}
			if tc.wantQueued > 0 && (queued[0].ProviderID != p.ID || queued[0].ZoneExternalID != z.ExternalID) {
				t.Errorf("cleanup did not snapshot provider/zone: %+v", queued[0])
			}
		})
	}
}

// Renaming an agent away and back before the old record was deleted: the
// reconciler re-adopts the still-queued record by name. It must leave the
// queue and keep its owned flag, otherwise NurProxy would delete the record it
// is using, or forget it created it.
func TestSetAgentAnchorRecord_ReclaimsQueuedRecord(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	z := createTestZone(t, d, p.ID)
	a := createTestAgent(t, d)

	if _, err := d.SetAgentAnchorRecord(a.ID, a.FQDN, "A", "rec-1", z.ID, true); err != nil {
		t.Fatal(err)
	}
	a.FQDN = "agent2.example.com"
	if err := d.UpdateAgent(a); err != nil {
		t.Fatal(err)
	}
	a.FQDN = "agent1.example.com"
	if err := d.UpdateAgent(a); err != nil {
		t.Fatal(err)
	}
	if q, _ := d.ListAgentAnchorCleanups(); len(q) != 1 || !q[0].Owned {
		t.Fatalf("expected one owned queued record, got %+v", q)
	}

	stored, err := d.SetAgentAnchorRecord(a.ID, "agent1.example.com", "A", "rec-1", z.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if !stored {
		t.Error("reclaimed record lost its owned flag")
	}
	if q, _ := d.ListAgentAnchorCleanups(); len(q) != 0 {
		t.Errorf("reclaimed record still queued: %+v", q)
	}
}

// A plain UpdateAgent (no FQDN change) from a stale snapshot must not wipe
// anchor ids the reconciler stored in the meantime.
func TestUpdateAgent_KeepsAnchorWithoutRename(t *testing.T) {
	d := testDB(t)
	p := createTestProvider(t, d)
	z := createTestZone(t, d, p.ID)
	a := createTestAgent(t, d)
	stale, err := d.GetAgent(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SetAgentAnchorRecord(a.ID, a.FQDN, "A", "rec-1", z.ID, true); err != nil {
		t.Fatal(err)
	}
	stale.Name = "renamed display name only"
	if err := d.UpdateAgent(stale); err != nil {
		t.Fatal(err)
	}
	got, _ := d.GetAgent(a.ID)
	if got.DNSRecordID != "rec-1" || !got.DNSRecordOwned {
		t.Errorf("anchor clobbered by stale update: id=%q owned=%v", got.DNSRecordID, got.DNSRecordOwned)
	}
	if q, _ := d.ListAgentAnchorCleanups(); len(q) != 0 {
		t.Errorf("non-rename update queued cleanups: %+v", q)
	}
}

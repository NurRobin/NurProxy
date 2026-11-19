package reconciler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/provider"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// One Cloudflare zone can sit behind two provider/zone rows (nothing makes
// external_id unique). Moving a domain between them keeps its name and its
// record: the record must be taken back, never deleted as stale (#151 review).
func TestDomainZoneMoveBetweenRowsOfOneProviderZoneKeepsRecord(t *testing.T) {
	for _, adopt := range []bool{false, true} {
		name := "owned"
		if adopt {
			name = "adopted"
		}
		t.Run(name, func(t *testing.T) {
			d := testDB(t)
			mp := registerMockProvider(t)
			_, _, _, _, dom := setupScenario(t, d)
			if err := d.CreateProvider(&models.Provider{ID: "prov-2", Type: "mock", Name: "Same account again", Config: `{"api_token":"other"}`}); err != nil {
				t.Fatal(err)
			}
			if err := d.CreateZone(&models.Zone{ID: "zone-dup", ProviderID: "prov-2", ExternalID: "ext-zone-1", Name: "example.com"}); err != nil {
				t.Fatal(err)
			}
			if adopt {
				mp.seedRecord(provider.Record{Type: "CNAME", Name: "app.example.com", Content: "agent1.example.com"})
			}
			f := &renameFixture{d: d, mp: mp, r: New(d, newMockAgentClient(), time.Minute), dom: dom}
			f.cycle(t)
			before, _ := d.GetDomain(dom.ID)
			f.oldID = before.DNSRecordID

			f.update(t, moveToZone("zone-dup"))
			f.cycle(t)
			f.cycle(t)

			if _, ok := mp.getRecord(f.oldID); !ok {
				t.Fatal("the domain's live record was deleted")
			}
			after, _ := d.GetDomain(dom.ID)
			if after.DNSRecordID != f.oldID || after.DNSManaged != !adopt {
				t.Fatalf("domain = record %q managed %v, want %q managed %v", after.DNSRecordID, after.DNSManaged, f.oldID, !adopt)
			}
			if q := f.queued(t); len(q) != 0 {
				t.Fatalf("queue not drained: %+v", q)
			}
		})
	}
}

// The delete guards hold even when nothing took the record back: a record a
// domain holds, a name a domain serves, or a record whose content changed is
// never deleted.
func TestDomainDNSCleanupGuards(t *testing.T) {
	tests := []struct {
		name string
		// setup queues a cleanup for the domain's current record and arranges
		// the condition under test.
		setup      func(t *testing.T, f *renameFixture)
		wantAction string
	}{
		{
			name: "record held by a domain in another row of the same provider zone",
			setup: func(t *testing.T, f *renameFixture) {
				queueCurrent(t, f, "zone-other-row", "app.example.com")
			},
			wantAction: "dns_left_in_use",
		},
		{
			name: "name served by another domain in another provider",
			setup: func(t *testing.T, f *renameFixture) {
				// The queued record claims a name the domain serves, but lives
				// in an unrelated zone with a record id nobody holds.
				id := f.mp.seedRecord(provider.Record{Type: "CNAME", Name: "APP.example.com", Content: "agent1.example.com"})
				if err := f.d.QueueDomainDNSRecord(db.DomainDNSCleanup{
					DomainID: 999, FQDN: "APP.example.com", RecordID: id, Owned: true,
					Content: "agent1.example.com", ZoneID: "zone-elsewhere", ProviderID: "prov-1", ZoneExternalID: "ext-elsewhere",
				}); err != nil {
					t.Fatal(err)
				}
				f.oldID = id
			},
			wantAction: "dns_left_in_use",
		},
		{
			name: "content changed since it was released",
			setup: func(t *testing.T, f *renameFixture) {
				// Hold the delete back for one cycle (no record at the new
				// name yet), retarget the old record meanwhile, then let the
				// new record be created so the cleanup becomes due.
				f.update(t, renameTo("web"))
				f.set(errors.New("provider unavailable"), nil)
				f.cycle(t)
				f.mp.mu.Lock()
				rec := f.mp.records[f.oldID]
				rec.Content = "someone-else.example.net"
				f.mp.records[f.oldID] = rec
				f.mp.mu.Unlock()
				f.set(nil, nil)
				if err := f.r.reconcileDNS(context.Background()); err != nil {
					t.Fatal(err)
				}
			},
			wantAction: "dns_left_changed",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRenameFixture(t, false)
			if err := f.d.CreateZone(&models.Zone{ID: "zone-other-row", ProviderID: "prov-1", ExternalID: "ext-zone-1", Name: "example.com"}); err != nil {
				t.Fatal(err)
			}
			tc.setup(t, f)
			if err := f.r.reconcileDomainDNSCleanups(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, ok := f.mp.getRecord(f.oldID); !ok {
				t.Fatal("record deleted despite the guard")
			}
			if q := f.queued(t); len(q) != 0 {
				t.Fatalf("guarded row not dropped: %+v", q)
			}
			if countDomainAudit(t, f.d, tc.wantAction) == 0 {
				t.Errorf("missing audit entry %q", tc.wantAction)
			}
		})
	}
}

// queueCurrent queues the fixture domain's own live record under zoneID, as a
// rename from another zone row would have.
func queueCurrent(t *testing.T, f *renameFixture, zoneID, fqdn string) {
	t.Helper()
	if err := f.d.QueueDomainDNSRecord(db.DomainDNSCleanup{
		DomainID: 999, FQDN: fqdn, RecordID: f.oldID, Owned: true,
		Content: "agent1.example.com", ZoneID: zoneID,
	}); err != nil {
		t.Fatal(err)
	}
}

// A rename that lands while the reconciler creates or adopts the record for
// the old name: nothing is stored on the renamed domain, a created record is
// queued and cleaned up, and the new name converges.
func TestDomainRenameRacingRecordResolution(t *testing.T) {
	for _, adoptExisting := range []bool{false, true} {
		name := "create"
		if adoptExisting {
			name = "adopt"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			d := testDB(t)
			mp := registerMockProvider(t)
			_, _, _, _, dom := setupScenario(t, d)
			var seeded string
			if adoptExisting {
				seeded = mp.seedRecord(provider.Record{Type: "CNAME", Name: "app.example.com", Content: "agent1.example.com"})
			}
			r := New(d, newMockAgentClient(), time.Minute)
			stale, _ := d.GetDomain(dom.ID) // what the reconciler listed
			f := &renameFixture{d: d, mp: mp, r: r, dom: stale}
			f.update(t, renameTo("web")) // the rename lands meanwhile

			zone, prov, dnsProvider, ok := r.resolveDNS(stale.ZoneID)
			if !ok {
				t.Fatal("cannot resolve DNS")
			}
			r.ensureDomainCNAME(ctx, stale, "app.example.com", "agent1.example.com", dnsProvider, mergeZoneIDIntoConfig(prov.Config, zone.ExternalID))

			got, _ := d.GetDomain(dom.ID)
			if got.DNSRecordID != "" || got.Subdomain != "web" {
				t.Fatalf("renamed domain got the old name's record: %+v", got)
			}
			if adoptExisting {
				if q := f.queued(t); len(q) != 0 {
					t.Fatalf("adopt race queued something: %+v", q)
				}
				f.cycle(t)
				if _, ok := mp.getRecord(seeded); !ok {
					t.Fatal("operator record at the old name deleted")
				}
			} else {
				q := f.queued(t)
				if len(q) != 1 || !q[0].Owned || q[0].FQDN != "app.example.com" {
					t.Fatalf("created record not queued: %+v", q)
				}
				stray := q[0].RecordID
				f.cycle(t)
				if _, ok := mp.getRecord(stray); ok {
					t.Fatal("record created for the old name survived")
				}
			}
			final, _ := d.GetDomain(dom.ID)
			if rec, ok := f.recordAt("web.example.com"); !ok || final.DNSRecordID != rec.ID {
				t.Fatalf("new name did not converge: domain record %q", final.DNSRecordID)
			}
		})
	}
}

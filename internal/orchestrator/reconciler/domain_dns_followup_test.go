package reconciler

import (
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/provider"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// An update built from a row loaded before the reconciler stored a fresh
// record (a port change racing the immediate DNS pass) must not erase that
// record or its ownership; otherwise teardown would later treat it as foreign
// and leave it behind.
func TestUpdateDomainKeepsRecordStoredMeanwhile(t *testing.T) {
	d := testDB(t)
	mp := registerMockProvider(t)
	_, _, _, _, dom := setupScenario(t, d)
	stale, err := d.GetDomain(dom.ID) // loaded by the API handler, no record yet
	if err != nil {
		t.Fatal(err)
	}
	f := &renameFixture{d: d, mp: mp, r: New(d, newMockAgentClient(), time.Minute), dom: dom}
	f.cycle(t) // the reconciler creates and stores the record meanwhile
	fresh, _ := d.GetDomain(dom.ID)
	if fresh.DNSRecordID == "" || !fresh.DNSManaged {
		t.Fatalf("no record stored: %+v", fresh)
	}

	stale.Port = 9090
	if err := d.UpdateDomain(stale); err != nil {
		t.Fatal(err)
	}
	got, _ := d.GetDomain(dom.ID)
	if got.DNSRecordID != fresh.DNSRecordID || !got.DNSManaged || got.Port != 9090 {
		t.Fatalf("after stale update: record %q managed %v port %d, want %q managed port 9090", got.DNSRecordID, got.DNSManaged, got.Port, fresh.DNSRecordID)
	}
	if stale.DNSRecordID != fresh.DNSRecordID || !stale.DNSManaged {
		t.Fatalf("updated struct not refreshed from the row: %q %v", stale.DNSRecordID, stale.DNSManaged)
	}
}

// The immediate pass only touches the renamed domain, and does nothing while
// a cycle holds the DNS lock (the cycle covers it).
func TestReconcileDomainDNSNow(t *testing.T) {
	d := testDB(t)
	mp := registerMockProvider(t)
	_, zone, _, srv, dom := setupScenario(t, d)
	other := &models.Domain{Subdomain: "other", ZoneID: zone.ID, ServerID: srv.ID, Port: 8081, SSLMode: models.SSLModeAuto, Status: models.DomainStatusPending}
	if err := d.CreateDomain(other); err != nil {
		t.Fatal(err)
	}
	r := New(d, newMockAgentClient(), time.Minute)
	f := &renameFixture{d: d, mp: mp, r: r}

	r.dnsMu.Lock()
	r.ReconcileDomainDNSNow(dom.ID) // must return at once, not block
	r.dnsMu.Unlock()
	if _, ok := f.recordAt("app.example.com"); ok {
		t.Fatal("immediate pass ran while a cycle held the DNS lock")
	}

	r.ReconcileDomainDNSNow(dom.ID)
	if _, ok := f.recordAt("app.example.com"); !ok {
		t.Fatal("immediate pass created no record for the domain")
	}
	if _, ok := f.recordAt("other.example.com"); ok {
		t.Fatal("immediate pass touched another domain")
	}
	if got, _ := d.GetDomain(dom.ID); got.Status == models.DomainStatusError {
		t.Fatalf("immediate pass left the domain in error: %s", got.ErrorMsg)
	}
}

// A queued record at a name that a domain serves without ever getting a record
// does not wait forever: a cert-only domain (NurProxy manages no record for
// it) drops the row at once, any other domain after the wait bound. Both are
// audited and leave the record in place.
func TestDomainDNSCleanupNameGuardIsBounded(t *testing.T) {
	tests := []struct {
		name        string
		certOnly    bool
		maxWaitZero bool
		wantDropped bool
	}{
		{name: "cert-only domain at the name", certOnly: true, wantDropped: true},
		{name: "domain without a record, within the bound"},
		{name: "domain without a record, after the bound", maxWaitZero: true, wantDropped: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := testDB(t)
			mp := registerMockProvider(t)
			_, zone, _, srv, _ := setupScenario(t, d)
			holder := &models.Domain{Subdomain: "taken", ZoneID: zone.ID, ServerID: srv.ID, Port: 8081, SSLMode: models.SSLModeAuto, CertOnly: tc.certOnly, Status: models.DomainStatusPending}
			if err := d.CreateDomain(holder); err != nil {
				t.Fatal(err)
			}
			id := mp.seedRecord(provider.Record{Type: "CNAME", Name: "taken.example.com", Content: "agent1.example.com"})
			if err := d.QueueDomainDNSRecord(db.DomainDNSCleanup{
				DomainID: 999, FQDN: "taken.example.com", RecordID: id, Owned: true,
				Content: "agent1.example.com", ZoneID: "zone-gone", ProviderID: "prov-1", ZoneExternalID: "ext-gone",
			}); err != nil {
				t.Fatal(err)
			}
			r := New(d, newMockAgentClient(), time.Minute)
			if tc.maxWaitZero {
				r.domainDNSCleanupMaxWait = 0
			}
			if err := r.reconcileDomainDNSCleanups(t.Context()); err != nil {
				t.Fatal(err)
			}
			if _, ok := mp.getRecord(id); !ok {
				t.Fatal("record at a served name deleted")
			}
			rows, _ := d.ListDomainDNSCleanups()
			if dropped := len(rows) == 0; dropped != tc.wantDropped {
				t.Fatalf("row dropped = %v, want %v", dropped, tc.wantDropped)
			}
			if tc.wantDropped && countDomainAudit(t, d, "dns_left_in_use") == 0 {
				t.Error("missing audit entry dns_left_in_use")
			}
		})
	}
}

package reconciler

import (
	"errors"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/provider"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// After a rename or zone move between Cloudflare zones, the record at the new
// name keeps the old record's proxy (orange cloud) setting, unless the domain
// has an explicit setting of its own (#151, #126). The state is read once and
// kept with the queued record, so it survives a new record that is only
// created cycles later, after an adopted old record left the queue or an
// owned one was already deleted by the wait bound.
func TestDomainRenameInheritsCloudflareProxied(t *testing.T) {
	yes, no := true, false
	tests := []struct {
		name       string
		change     func(*models.Domain)
		oldProxied bool
		explicit   *bool // the domain's own proxied setting
		adopt      bool  // the old record was adopted, not created
		// first post-rename cycle only:
		getErr      error // reading the old record fails
		createErr   error // creating the new record fails
		conflict    bool  // a foreign record sits at the new name
		maxWaitZero bool
		newName     string
		cloudflare  bool // the new record lives at the cloudflare mock
		wantProxied bool
		wantOldGone bool
	}{
		{name: "rename in the same zone", change: renameTo("web"), oldProxied: true, newName: "web.example.net", cloudflare: true, wantProxied: true, wantOldGone: true},
		{name: "move to another Cloudflare zone", change: moveToZone("zone-cf2"), oldProxied: true, newName: "app.example.io", cloudflare: true, wantProxied: true, wantOldGone: true},
		{name: "grey cloud stays grey", change: renameTo("web"), newName: "web.example.net", cloudflare: true, wantOldGone: true},
		{name: "move to a non-Cloudflare provider", change: moveToZone("zone-1"), oldProxied: true, newName: "app.example.com", wantOldGone: true},
		{name: "explicit setting wins over inheritance", change: renameTo("web"), oldProxied: true, explicit: &no, newName: "web.example.net", cloudflare: true, wantOldGone: true},
		{name: "explicit proxied on a grey old record", change: renameTo("web"), explicit: &yes, newName: "web.example.net", cloudflare: true, wantProxied: true, wantOldGone: true},
		{name: "unreadable old record postpones the create", change: renameTo("web"), oldProxied: true, getErr: errors.New("rate limited"), newName: "web.example.net", cloudflare: true, wantProxied: true, wantOldGone: true},
		{name: "adopted old record, new name blocked for a cycle", change: renameTo("web"), oldProxied: true, adopt: true, conflict: true, newName: "web.example.net", cloudflare: true, wantProxied: true},
		{name: "old record deleted by the wait bound before the new one exists", change: renameTo("web"), oldProxied: true, createErr: errors.New("provider unavailable"), maxWaitZero: true, newName: "web.example.net", cloudflare: true, wantProxied: true, wantOldGone: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := testDB(t)
			plain := registerMockProvider(t)
			cf := newMockDNSProvider()
			cf.id = "cloudflare"
			provider.Register(cf)
			_, _, _, _, dom := setupScenario(t, d)
			for _, p := range []*models.Provider{
				{ID: "prov-cf1", Type: "cloudflare", Name: "CF one", Config: `{"api_token":"one"}`},
				{ID: "prov-cf2", Type: "cloudflare", Name: "CF two", Config: `{"api_token":"two"}`},
			} {
				if err := d.CreateProvider(p); err != nil {
					t.Fatal(err)
				}
			}
			for _, z := range []*models.Zone{
				{ID: "zone-cf1", ProviderID: "prov-cf1", ExternalID: "ext-cf1", Name: "example.net"},
				{ID: "zone-cf2", ProviderID: "prov-cf2", ExternalID: "ext-cf2", Name: "example.io"},
			} {
				if err := d.CreateZone(z); err != nil {
					t.Fatal(err)
				}
			}
			dom.ZoneID = "zone-cf1"
			if err := d.UpdateDomain(dom); err != nil {
				t.Fatal(err)
			}
			if tc.adopt {
				cf.seedRecord(provider.Record{Type: "CNAME", Name: "app.example.net", Content: "agent1.example.com", Proxied: tc.oldProxied})
			}
			r := New(d, newMockAgentClient(), time.Minute)
			f := &renameFixture{d: d, mp: cf, r: r, dom: dom}
			f.cycle(t)
			created, _ := d.GetDomain(dom.ID)
			oldID := created.DNSRecordID
			if created.DNSManaged == tc.adopt {
				t.Fatalf("initial record managed = %v, want %v", created.DNSManaged, !tc.adopt)
			}
			cf.mu.Lock()
			rec := cf.records[oldID]
			rec.Proxied = tc.oldProxied
			cf.records[oldID] = rec
			cf.mu.Unlock()

			f.dom = created
			f.update(t, func(dom *models.Domain) {
				tc.change(dom)
				if tc.explicit != nil {
					dom.Proxied = tc.explicit
				}
			})
			if tc.maxWaitZero {
				r.domainDNSCleanupMaxWait = 0
			}
			target := plain
			if tc.cloudflare {
				target = cf
			}
			newRecord := func() (provider.Record, bool) {
				return (&renameFixture{mp: target}).recordAt(tc.newName)
			}

			blocked := tc.getErr != nil || tc.createErr != nil || tc.conflict
			if blocked {
				var conflictID string
				if tc.conflict {
					conflictID = cf.seedRecord(provider.Record{Type: "A", Name: tc.newName, Content: "192.0.2.1"})
				}
				cf.mu.Lock()
				cf.getErr, cf.createErr = tc.getErr, tc.createErr
				cf.mu.Unlock()
				f.cycle(t)
				if rec, ok := newRecord(); ok && rec.Type == "CNAME" {
					t.Fatal("new record created in the blocked cycle")
				}
				if tc.getErr != nil {
					if _, ok := cf.getRecord(oldID); !ok {
						t.Fatal("old record deleted before the new one existed")
					}
					if got, _ := d.GetDomain(dom.ID); got.Status == models.DomainStatusError {
						t.Fatalf("unreadable old record put the domain into error: %s", got.ErrorMsg)
					}
				}
				cf.mu.Lock()
				cf.getErr, cf.createErr = nil, nil
				delete(cf.records, conflictID)
				cf.mu.Unlock()
			}
			f.cycle(t)
			got, ok := newRecord()
			if !ok {
				t.Fatalf("no record at %s", tc.newName)
			}
			if got.Proxied != tc.wantProxied {
				t.Fatalf("new record proxied = %v, want %v", got.Proxied, tc.wantProxied)
			}
			if _, ok := cf.getRecord(oldID); ok == tc.wantOldGone {
				t.Fatalf("old record present = %v, want %v", ok, !tc.wantOldGone)
			}
			if q := f.queued(t); len(q) != 0 {
				t.Fatalf("queue not drained: %+v", q)
			}
		})
	}
}

func moveToZone(zoneID string) func(*models.Domain) {
	return func(dom *models.Domain) { dom.ZoneID = zoneID }
}

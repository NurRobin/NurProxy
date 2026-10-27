package reconciler

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/provider"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// renameFixture is the domain app.example.com with a CNAME to agent1 made by
// one DNS pass, ready to be renamed or moved (#151).
type renameFixture struct {
	d        *db.DB
	mp       *mockDNSProvider
	r        *Reconciler
	dom      *models.Domain
	oldID    string
	oldOwned bool
}

func newRenameFixture(t *testing.T, adopt bool) *renameFixture {
	t.Helper()
	d := testDB(t)
	mp := registerMockProvider(t)
	_, _, _, _, dom := setupScenario(t, d)
	if adopt {
		mp.seedRecord(provider.Record{Type: "CNAME", Name: "app.example.com", Content: "agent1.example.com"})
	}
	r := New(d, newMockAgentClient(), time.Minute)
	if err := r.reconcileDNS(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetDomain(dom.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.DNSRecordID == "" || got.DNSManaged == adopt {
		t.Fatalf("initial record not set up: id=%q managed=%v", got.DNSRecordID, got.DNSManaged)
	}
	return &renameFixture{d: d, mp: mp, r: r, dom: got, oldID: got.DNSRecordID, oldOwned: got.DNSManaged}
}

// update applies change the way the REST and MCP handlers do.
func (f *renameFixture) update(t *testing.T, change func(*models.Domain)) {
	t.Helper()
	dom, err := f.d.GetDomain(f.dom.ID)
	if err != nil {
		t.Fatal(err)
	}
	before := *dom
	change(dom)
	rename, err := f.d.BeginDomainRename(&before, dom, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.d.UpdateDomain(dom); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.FinishDomainRename(rename); err != nil {
		t.Fatal(err)
	}
}

// cycle runs the domain DNS phases of one reconcile cycle.
func (f *renameFixture) cycle(t *testing.T) {
	t.Helper()
	f.r.runDomainDNSPhases(context.Background())
}

func (f *renameFixture) set(createErr, deleteErr error) {
	f.mp.mu.Lock()
	f.mp.createErr, f.mp.deleteErr = createErr, deleteErr
	f.mp.mu.Unlock()
}

func (f *renameFixture) queued(t *testing.T) []db.DomainDNSCleanup {
	t.Helper()
	rows, err := f.d.ListDomainDNSCleanups()
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func (f *renameFixture) recordAt(name string) (provider.Record, bool) {
	f.mp.mu.Lock()
	defer f.mp.mu.Unlock()
	for id, rec := range f.mp.records {
		if strings.EqualFold(rec.Name, name) {
			rec.ID = id
			return rec, true
		}
	}
	return provider.Record{}, false
}

func renameTo(sub string) func(*models.Domain) {
	return func(dom *models.Domain) { dom.Subdomain = sub }
}

func countDomainAudit(t *testing.T, d *db.DB, action string) int {
	t.Helper()
	entries, _, err := d.ListAuditLog(200, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if e.Action == action && e.EntityType == "domain" {
			n++
		}
	}
	return n
}

func TestDomainRenameDNSCleanup(t *testing.T) {
	transient := errors.New("provider unavailable")
	tests := []struct {
		name  string
		adopt bool
		// first-cycle provider failures; the second cycle runs without them.
		createErr, deleteErr error
		maxWaitZero          bool
		// wantOldAfterFirst: the old record still exists after the first cycle.
		wantOldAfterFirst bool
		wantOldFinal      bool
		wantNewAfterFirst bool
		wantAttempts      int // attempts on the queue row after the first cycle
		wantActions       []string
	}{
		{
			name:              "owned record is deleted once the new one exists",
			wantNewAfterFirst: true,
			wantActions:       []string{"dns_created", "dns_deleted"},
		},
		{
			name:              "adopted record is left untouched",
			adopt:             true,
			wantOldAfterFirst: true, wantOldFinal: true, wantNewAfterFirst: true,
			wantActions: []string{"dns_left_adopted"},
		},
		{
			name:              "provider delete failure keeps the row and retries",
			deleteErr:         transient,
			wantOldAfterFirst: true, wantNewAfterFirst: true, wantAttempts: 1,
			wantActions: []string{"dns_delete_failed", "dns_deleted"},
		},
		{
			name:              "record already gone counts as done",
			deleteErr:         provider.ErrRecordNotFound,
			wantOldAfterFirst: true, wantOldFinal: true, wantNewAfterFirst: true,
			wantActions: []string{"dns_delete_skipped"},
		},
		{
			name:              "old record waits while the new one cannot be created",
			createErr:         transient,
			wantOldAfterFirst: true,
			wantActions:       []string{"dns_create_failed", "dns_created", "dns_deleted"},
		},
		{
			name:        "old record goes after the wait bound even without a new one",
			createErr:   transient,
			maxWaitZero: true,
			wantActions: []string{"dns_create_failed", "dns_deleted"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRenameFixture(t, tc.adopt)
			if tc.maxWaitZero {
				f.r.domainDNSCleanupMaxWait = 0
			}
			f.update(t, renameTo("web"))

			stored, _ := f.d.GetDomain(f.dom.ID)
			if stored.DNSRecordID != "" || stored.DNSManaged {
				t.Fatalf("rename kept the old record on the row: id=%q managed=%v", stored.DNSRecordID, stored.DNSManaged)
			}
			if q := f.queued(t); len(q) != 1 || q[0].RecordID != f.oldID || q[0].Owned != f.oldOwned ||
				q[0].FQDN != "app.example.com" || q[0].ProviderID != "prov-1" || q[0].ZoneExternalID != "ext-zone-1" {
				t.Fatalf("queue after rename = %+v", q)
			}

			f.set(tc.createErr, tc.deleteErr)
			f.cycle(t)
			if _, ok := f.mp.getRecord(f.oldID); ok != tc.wantOldAfterFirst {
				t.Fatalf("old record present after first cycle = %v, want %v", ok, tc.wantOldAfterFirst)
			}
			if _, ok := f.recordAt("web.example.com"); ok != tc.wantNewAfterFirst {
				t.Fatalf("new record present after first cycle = %v, want %v", ok, tc.wantNewAfterFirst)
			}
			if tc.wantOldAfterFirst && !tc.adopt && tc.deleteErr != provider.ErrRecordNotFound {
				q := f.queued(t)
				if len(q) != 1 || q[0].Attempts != tc.wantAttempts {
					t.Fatalf("queue after first cycle = %+v, want one row with %d attempt(s)", q, tc.wantAttempts)
				}
			}

			f.set(nil, nil)
			f.cycle(t)
			if _, ok := f.mp.getRecord(f.oldID); ok != tc.wantOldFinal {
				t.Fatalf("old record present at the end = %v, want %v", ok, tc.wantOldFinal)
			}
			newRec, ok := f.recordAt("web.example.com")
			if !ok || newRec.Content != "agent1.example.com" {
				t.Fatalf("new name did not converge: %+v ok=%v", newRec, ok)
			}
			final, _ := f.d.GetDomain(f.dom.ID)
			if final.DNSRecordID != newRec.ID || !final.DNSManaged {
				t.Fatalf("domain row = id %q managed %v, want %q managed", final.DNSRecordID, final.DNSManaged, newRec.ID)
			}
			if q := f.queued(t); len(q) != 0 {
				t.Fatalf("queue not drained: %+v", q)
			}
			for _, action := range tc.wantActions {
				if countDomainAudit(t, f.d, action) == 0 {
					t.Errorf("missing audit entry %q", action)
				}
			}
		})
	}
}

// Renaming back before the old record was deleted takes the very record back:
// it is not deleted and stays NurProxy-managed.
func TestDomainRenameBackReclaimsQueuedRecord(t *testing.T) {
	f := newRenameFixture(t, false)
	f.update(t, renameTo("web"))
	f.set(errors.New("provider unavailable"), nil) // the new name never gets a record
	f.cycle(t)
	f.update(t, renameTo("app"))
	f.set(nil, nil)
	f.cycle(t)

	if _, ok := f.mp.getRecord(f.oldID); !ok {
		t.Fatal("record deleted although the domain is back at its name")
	}
	final, _ := f.d.GetDomain(f.dom.ID)
	if final.DNSRecordID != f.oldID || !final.DNSManaged {
		t.Fatalf("domain row = id %q managed %v, want the original %q managed", final.DNSRecordID, final.DNSManaged, f.oldID)
	}
	if q := f.queued(t); len(q) != 0 {
		t.Fatalf("queue not drained: %+v", q)
	}
	if countDomainAudit(t, f.d, "dns_reclaimed") == 0 {
		t.Error("missing audit entry dns_reclaimed")
	}
}

// A queued record that points somewhere else (the domain also moved agents)
// is still taken back rather than reported as a foreign conflict, and the
// content check then retargets it.
func TestDomainRenameBackReclaimsQueuedRecordWithOtherTarget(t *testing.T) {
	f := newRenameFixture(t, false)
	f.update(t, renameTo("web"))
	f.set(errors.New("provider unavailable"), nil)
	f.cycle(t)
	agent, err := f.d.GetAgent("agent-1")
	if err != nil {
		t.Fatal(err)
	}
	agent.FQDN = "edge9.example.com"
	if err := f.d.UpdateAgent(agent); err != nil {
		t.Fatal(err)
	}
	f.update(t, renameTo("app"))
	f.set(nil, nil)
	f.cycle(t)
	f.cycle(t)

	rec, ok := f.mp.getRecord(f.oldID)
	if !ok || rec.Content != "edge9.example.com" {
		t.Fatalf("record = %+v ok=%v, want the original record retargeted to edge9", rec, ok)
	}
	final, _ := f.d.GetDomain(f.dom.ID)
	if final.DNSRecordID != f.oldID || !final.DNSManaged || final.Status == models.DomainStatusError {
		t.Fatalf("domain = id %q managed %v status %s", final.DNSRecordID, final.DNSManaged, final.Status)
	}
}

// A zone move to another provider deletes the old record through the OLD
// provider and zone, even when the old zone row is gone by then, and creates
// the new record in the new zone.
func TestDomainZoneMoveAcrossProviders(t *testing.T) {
	f := newRenameFixture(t, false)
	if err := f.d.CreateProvider(&models.Provider{ID: "prov-2", Type: "mock", Name: "Other", Config: `{"api_token":"other"}`}); err != nil {
		t.Fatal(err)
	}
	if err := f.d.CreateZone(&models.Zone{ID: "zone-2", ProviderID: "prov-2", ExternalID: "ext-zone-2", Name: "example.org"}); err != nil {
		t.Fatal(err)
	}
	f.update(t, func(dom *models.Domain) { dom.ZoneID = "zone-2" })
	if err := f.d.DeleteZone("zone-1"); err != nil {
		t.Fatal(err)
	}
	f.mp.mu.Lock()
	f.mp.deleteConfigs = nil
	f.mp.mu.Unlock()
	f.cycle(t)

	if _, ok := f.mp.getRecord(f.oldID); ok {
		t.Fatal("old record survived the zone move")
	}
	if _, ok := f.recordAt("app.example.org"); !ok {
		t.Fatal("no record created in the new zone")
	}
	f.mp.mu.Lock()
	configs := append([]string(nil), f.mp.deleteConfigs...)
	f.mp.mu.Unlock()
	if len(configs) != 1 || !strings.Contains(configs[0], `"zone_id":"ext-zone-1"`) || !strings.Contains(configs[0], `"api_token":"secret"`) {
		t.Fatalf("delete went through %v, want the old provider and zone", configs)
	}
}

// A domain deleted while its old record is queued does not hold the cleanup.
func TestDomainRenameCleanupProceedsWhenDomainDeleted(t *testing.T) {
	f := newRenameFixture(t, false)
	f.update(t, renameTo("web"))
	f.set(errors.New("provider unavailable"), nil)
	f.cycle(t)
	if _, ok := f.mp.getRecord(f.oldID); !ok {
		t.Fatal("old record deleted before the new one existed")
	}
	if err := f.d.DeleteDomain(f.dom.ID); err != nil {
		t.Fatal(err)
	}
	f.set(nil, nil)
	if err := f.r.reconcileDomainDNSCleanups(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.mp.getRecord(f.oldID); ok {
		t.Fatal("old record kept although its domain is gone")
	}
}

// A rename combined with a port change on an nginx agent: the next signed
// apply carries the renamed route on the new port, retains the domain's
// resource, and deletes the old host's vhost through a tombstone with its own
// identity. The old host's certificate leaves the central store and is no
// longer retained on the agent.
func TestDomainRenameWithPortChangeManagedApply(t *testing.T) {
	d := testDB(t)
	registerMockProvider(t)
	_, _, agent, _, dom := setupScenario(t, d)
	agent.ProxyMode = "existing"
	agent.ProxyDetection = &models.ProxyDetection{Installed: true, Kind: "nginx"}
	if err := d.UpdateAgent(agent); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateAgentHealth(agent.ID, "", "", "", false, "existing"); err != nil {
		t.Fatal(err)
	}
	if err := d.UpsertCertificate(&models.Certificate{ID: "cert-app", Host: "app.example.com", Names: []string{"app.example.com"}, CertPEM: "LEAF", KeyPEM: "KEY"}); err != nil {
		t.Fatal(err)
	}
	f := &renameFixture{d: d, r: New(d, newMockAgentClient(), time.Minute), dom: dom}
	f.update(t, func(dom *models.Domain) {
		dom.Subdomain = "web"
		dom.Port = 9090
	})

	if _, err := d.GetCertificate("app.example.com"); !errors.Is(err, db.ErrCertNotFound) {
		t.Fatalf("old certificate still stored (err=%v)", err)
	}
	stored, err := d.GetAgent(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	desired, keep, err := f.r.buildDesiredRoutes(stored)
	if err != nil {
		t.Fatal(err)
	}
	set := f.r.intentSetFor(stored, desired, keep)
	tombstones, err := d.ListManagedRouteTombstones(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	deletions := deletionsOutsideDesired(tombstones, set.Intents)
	if len(deletions) != 1 || deletions[0].Host != "app.example.com" || deletions[0].ResourceID == artifactIDForDomain(dom.ID) {
		t.Fatalf("deletions = %#v, want one tombstone for app.example.com with its own id", deletions)
	}
	if len(set.Intents) != 1 || set.Intents[0].Route.Host != "web.example.com" || set.Intents[0].Route.Upstream.Port != 9090 ||
		set.Intents[0].ArtifactID != artifactIDForDomain(dom.ID) {
		t.Fatalf("intents = %#v, want the renamed route on port 9090", set.Intents)
	}
	for _, host := range set.CertKeep {
		if host == "app.example.com" {
			t.Fatalf("old host still retained on the agent: %v", set.CertKeep)
		}
	}
	intent, err := buildApplyIntent(agent.ID, "helper-1", set, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	intent.DeletionSet = deletions
	if err := intent.Validate(); err != nil {
		t.Fatalf("signed apply for the rename is invalid: %v", err)
	}

	// Renaming back claims the old host again: its tombstone is dropped so the
	// vhost the route writes is not deleted in the same apply, and the host the
	// domain just left gets one instead.
	f.update(t, renameTo("app"))
	back, _ := d.GetDomain(dom.ID)
	if err := d.ClaimDomainRoute(back); err != nil {
		t.Fatal(err)
	}
	if left, _ := d.ListManagedRouteTombstones(agent.ID); len(left) != 1 || left[0].Host != "web.example.com" {
		t.Fatalf("tombstones after renaming back = %#v, want only web.example.com", left)
	}
}

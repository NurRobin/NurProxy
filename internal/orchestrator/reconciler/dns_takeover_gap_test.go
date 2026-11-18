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

// startHeldTakeover starts a takeover of dom that replaces an A record and
// stops inside CreateRecord (the old record is already deleted). release lets
// it finish; the takeover's error arrives on the returned channel.
func startHeldTakeover(t *testing.T, r *Reconciler, hp *hookDNSProvider, domID int64) (release func(), result <-chan error) {
	t.Helper()
	hp.seedRecord(provider.Record{Type: "A", Name: "app.example.com", Content: "203.0.113.99"})
	hp.holdCreate = true
	hp.createEnter = make(chan struct{})
	hp.release = make(chan struct{})
	errc := make(chan error, 1)
	go func() {
		_, err := r.TakeoverDomainDNS(context.Background(), domID, nil)
		errc <- err
	}()
	<-hp.createEnter
	return func() { close(hp.release) }, errc
}

// TestTakeoverDomainDNS_renamedInGap: a rename that lands while the takeover
// sits between delete and create must not leave the takeover's record for the
// old name stored on the renamed domain (which would never get its own record
// and show no error); the record is queued for cleanup, the new name gets its
// own record and the old one is deleted.
func TestTakeoverDomainDNS_renamedInGap(t *testing.T) {
	hp := registerHookProvider(t)
	d := testDB(t)
	_, _, agent, _, dom := setupScenario(t, d)
	r := New(d, newMockAgentClient(), time.Minute)
	release, result := startHeldTakeover(t, r, hp, dom.ID)

	renamed, err := d.GetDomain(dom.ID)
	if err != nil {
		t.Fatal(err)
	}
	renamed.Subdomain = "app2"
	if err := d.UpdateDomain(renamed); err != nil {
		t.Fatalf("rename: %v", err)
	}
	release()
	err = <-result
	if err == nil || !strings.Contains(err.Error(), "renamed during the takeover") {
		t.Fatalf("takeover error = %v, want the rename reported", err)
	}
	got, _ := d.GetDomain(dom.ID)
	if got.DNSRecordID != "" {
		t.Fatalf("renamed domain holds record %q of the old name", got.DNSRecordID)
	}
	queued, err := d.ListDomainDNSCleanups()
	if err != nil || len(queued) != 1 || queued[0].FQDN != "app.example.com" || !queued[0].Owned {
		t.Fatalf("cleanup queue = %+v (err %v), want the old-name CNAME queued as owned", queued, err)
	}

	r.domainDNSCleanupMaxWait = 0
	r.runDomainDNSPhases(context.Background())
	if recs := recordsAt(t, hp, "app2.example.com"); len(recs) != 1 || recs[0].Content != agent.FQDN {
		t.Fatalf("records at the new name = %+v, want one CNAME -> %s", recs, agent.FQDN)
	}
	if recs := recordsAt(t, hp, "app.example.com"); len(recs) != 0 {
		t.Fatalf("records left at the old name = %+v, want none", recs)
	}
	got, _ = d.GetDomain(dom.ID)
	if got.DNSRecordID == "" || !got.DNSManaged || got.DNSError != "" {
		t.Fatalf("renamed domain record=%q managed=%v dns_error=%q", got.DNSRecordID, got.DNSManaged, got.DNSError)
	}
}

// TestTakeoverDomainDNS_deletedInGap: a domain marked for deletion while the
// takeover runs is torn down after the takeover, and the CNAME the takeover
// created is deleted with it rather than orphaned. The takeover does not
// reset the domain out of "deleting".
func TestTakeoverDomainDNS_deletedInGap(t *testing.T) {
	hp := registerHookProvider(t)
	d := testDB(t)
	_, _, _, _, dom := setupScenario(t, d)
	r := New(d, newMockAgentClient(), time.Minute)
	release, result := startHeldTakeover(t, r, hp, dom.ID)

	if err := d.UpdateDomainStatus(dom.ID, models.DomainStatusDeleting, ""); err != nil {
		t.Fatal(err)
	}
	tornDown := make(chan error, 1)
	go func() { tornDown <- r.reconcileDeletions(context.Background()) }()
	select {
	case <-tornDown:
		t.Fatal("teardown did not wait for the takeover")
	case <-time.After(200 * time.Millisecond):
	}
	release()
	if err := <-result; err != nil {
		t.Fatalf("takeover: %v", err)
	}
	if err := <-tornDown; err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if _, err := d.GetDomain(dom.ID); !errors.Is(err, db.ErrDomainNotFound) {
		t.Fatalf("domain still present after teardown: %v", err)
	}
	if recs := recordsAt(t, hp, "app.example.com"); len(recs) != 0 {
		t.Fatalf("records left at the name = %+v, want the takeover's CNAME deleted with the domain", recs)
	}
}

// TestTakeoverDomainDNS_lostNameDeletesForDeletedDomain: when the domain row
// is already gone when the takeover stores its record, the record it created
// is deleted at the provider.
func TestTakeoverDomainDNS_lostNameDeletesForDeletedDomain(t *testing.T) {
	hp := registerHookProvider(t)
	d := testDB(t)
	_, _, _, _, dom := setupScenario(t, d)
	r := New(d, newMockAgentClient(), time.Minute)
	tgt, err := r.resolveTakeover(context.Background(), dom.ID)
	if err != nil {
		t.Fatal(err)
	}
	id, err := hp.CreateRecord(context.Background(), nil, provider.Record{Type: "CNAME", Name: "app.example.com", Content: "agent1.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteDomain(dom.ID); err != nil {
		t.Fatal(err)
	}
	lErr := r.takeoverLostName(context.Background(), dom, tgt, id)
	if lErr == nil || !strings.Contains(lErr.Error(), "was deleted again") {
		t.Fatalf("error = %v, want the deleted record reported", lErr)
	}
	if _, ok := hp.getRecord(id); ok {
		t.Fatal("the record created for a deleted domain was left at the provider")
	}
}

// TestTakeoverDomainDNS_expectDelete: the takeover only deletes the records the
// caller saw in the preview.
func TestTakeoverDomainDNS_expectDelete(t *testing.T) {
	tests := []struct {
		name    string
		expect  func(previewed []string) []string
		wantErr bool
	}{
		{"same records", func(p []string) []string { return p }, false},
		{"no check", func([]string) []string { return nil }, false},
		{"record added after the preview", func(p []string) []string { return p[:1] }, true},
		{"previewed record gone", func(p []string) []string { return append(p, "gone") }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mp := registerMockProvider(t)
			d := testDB(t)
			_, _, _, _, dom := setupScenario(t, d)
			mp.seedRecord(provider.Record{Type: "A", Name: "app.example.com", Content: "203.0.113.99"})
			mp.seedRecord(provider.Record{Type: "TXT", Name: "app.example.com", Content: "v=spf1 -all"})
			r := New(d, newMockAgentClient(), time.Minute)
			plan, err := r.PreviewDomainDNSTakeover(context.Background(), dom.ID)
			if err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, rec := range plan.Delete {
				ids = append(ids, rec.ID)
			}

			_, err = r.TakeoverDomainDNS(context.Background(), dom.ID, tc.expect(ids))
			if tc.wantErr {
				if !errors.Is(err, models.ErrDNSTakeoverPlanChanged) {
					t.Fatalf("error = %v, want ErrDNSTakeoverPlanChanged", err)
				}
				if n := len(recordsAt(t, mp, "app.example.com")); n != 2 {
					t.Fatalf("a refused takeover changed the records: %d at the name, want 2", n)
				}
				return
			}
			if err != nil {
				t.Fatalf("takeover: %v", err)
			}
			if recs := recordsAt(t, mp, "app.example.com"); len(recs) != 1 || !strings.EqualFold(recs[0].Type, "CNAME") {
				t.Fatalf("records after takeover = %+v", recs)
			}
		})
	}
}

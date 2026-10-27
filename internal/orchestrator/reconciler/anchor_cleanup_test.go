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

// Provider-content tests for #152: what is actually left at the DNS provider
// after an agent's anchor moves or the agent is deleted.
func TestAgentAnchorCleanup(t *testing.T) {
	const (
		oldFQDN = "agent1.example.com"
		newFQDN = "edge9.example.com"
		ip4     = "203.0.113.10"
		ip6     = "2001:db8::10"
	)
	tests := []struct {
		name string
		// adopt seeds matching A/AAAA records at the old name before the first
		// cycle, so the agent adopts them instead of creating its own.
		adopt bool
		// deleteAgent deletes the agent instead of renaming it.
		deleteAgent bool
		// deleteErr makes the provider delete fail on the first cleanup pass.
		deleteErr error
		// wantOldGone: the old A/AAAA records are gone after cleanup.
		wantOldGone bool
		// wantRetry: the first cleanup pass must leave the queue intact.
		wantRetry   bool
		wantActions []string
	}{
		{
			name:        "rename owned deletes old and creates new",
			wantOldGone: true,
			wantActions: []string{"a_record_deleted", "aaaa_record_deleted"},
		},
		{
			name:        "rename adopted leaves old untouched",
			adopt:       true,
			wantActions: []string{"a_record_left_adopted", "aaaa_record_left_adopted"},
		},
		{
			name:        "delete owned removes records",
			deleteAgent: true,
			wantOldGone: true,
			wantActions: []string{"a_record_deleted", "aaaa_record_deleted"},
		},
		{
			name:        "delete adopted leaves records",
			deleteAgent: true,
			adopt:       true,
			wantActions: []string{"a_record_left_adopted", "aaaa_record_left_adopted"},
		},
		{
			name:        "provider delete failure is retried next tick",
			deleteErr:   errors.New("provider unavailable"),
			wantOldGone: true,
			wantRetry:   true,
			wantActions: []string{"a_record_delete_failed", "a_record_deleted"},
		},
		{
			name:        "record already gone counts as done",
			deleteErr:   provider.ErrRecordNotFound,
			wantActions: []string{"a_record_delete_skipped", "aaaa_record_delete_skipped"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			d := testDB(t)
			mp := registerMockProvider(t)
			_, zone, agent, _, _ := setupScenario(t, d)
			agent.PublicIP, agent.PublicIP6 = ip4, ip6
			if err := d.UpdateAgent(agent); err != nil {
				t.Fatal(err)
			}
			if err := d.AddAgentZone(agent.ID, zone.ID); err != nil {
				t.Fatal(err)
			}
			if tc.adopt {
				mp.seedRecord(provider.Record{Type: "A", Name: oldFQDN, Content: ip4})
				mp.seedRecord(provider.Record{Type: "AAAA", Name: oldFQDN, Content: ip6})
			}

			r := New(d, newMockAgentClient(), time.Minute)
			r.anchorRenameGrace = 0 // grace has its own test
			if err := r.reconcileAgentDNS(ctx); err != nil {
				t.Fatal(err)
			}
			before, err := d.GetAgent(agent.ID)
			if err != nil {
				t.Fatal(err)
			}
			oldA, oldAAAA := before.DNSRecordID, before.DNSRecordID6
			if oldA == "" || oldAAAA == "" {
				t.Fatalf("anchors not set up: A=%q AAAA=%q", oldA, oldAAAA)
			}
			if before.DNSRecordOwned == tc.adopt || before.DNSRecordOwned6 == tc.adopt {
				t.Fatalf("owned = (%v, %v), want %v", before.DNSRecordOwned, before.DNSRecordOwned6, !tc.adopt)
			}

			if tc.deleteAgent {
				if err := d.DeleteAgent(agent.ID); err != nil {
					t.Fatal(err)
				}
			} else {
				before.FQDN = newFQDN
				if err := d.UpdateAgent(before); err != nil {
					t.Fatal(err)
				}
			}

			mp.mu.Lock()
			mp.deleteErr = tc.deleteErr
			mp.mu.Unlock()
			if tc.wantRetry {
				if err := r.reconcileAgentDNS(ctx); err != nil {
					t.Fatal(err)
				}
				if err := r.reconcileAgentAnchorCleanups(ctx); err != nil {
					t.Fatal(err)
				}
				queued, _ := d.ListAgentAnchorCleanups()
				if len(queued) != 2 {
					t.Fatalf("failed deletes must stay queued, have %d rows", len(queued))
				}
				for _, c := range queued {
					if c.Attempts != 1 || c.LastError == "" {
						t.Errorf("failure not recorded on %+v", c)
					}
				}
				if _, ok := mp.getRecord(oldA); !ok {
					t.Fatal("record deleted although the provider failed")
				}
				mp.mu.Lock()
				mp.deleteErr = nil
				mp.mu.Unlock()
			}
			if tc.deleteErr != nil && errors.Is(tc.deleteErr, provider.ErrRecordNotFound) {
				// The provider says the record is gone; simulate that.
				mp.mu.Lock()
				delete(mp.records, oldA)
				delete(mp.records, oldAAAA)
				mp.mu.Unlock()
			}

			// Full tick: DNS for the (renamed) agent, then the cleanup queue.
			if err := r.reconcileAgentDNS(ctx); err != nil {
				t.Fatal(err)
			}
			if err := r.reconcileAgentAnchorCleanups(ctx); err != nil {
				t.Fatal(err)
			}

			for _, id := range []string{oldA, oldAAAA} {
				rec, ok := mp.getRecord(id)
				if tc.wantOldGone && ok {
					t.Errorf("old record %s still at provider: %+v", id, rec)
				}
				if tc.adopt && (!ok || rec.Name != oldFQDN) {
					t.Errorf("adopted record %s was touched (present=%v, %+v)", id, ok, rec)
				}
			}
			if queued, _ := d.ListAgentAnchorCleanups(); len(queued) != 0 {
				t.Errorf("cleanup queue not drained: %+v", queued)
			}

			if !tc.deleteAgent {
				after, err := d.GetAgent(agent.ID)
				if err != nil {
					t.Fatal(err)
				}
				for _, rt := range []struct{ typ, id string }{{"A", after.DNSRecordID}, {"AAAA", after.DNSRecordID6}} {
					rec, ok := mp.getRecord(rt.id)
					if !ok || rec.Name != newFQDN || rec.Type != rt.typ {
						t.Errorf("new %s record at %s missing: id=%q %+v", rt.typ, newFQDN, rt.id, rec)
					}
				}
				if !after.DNSRecordOwned || !after.DNSRecordOwned6 {
					t.Errorf("records created at the new name must be owned: A=%v AAAA=%v", after.DNSRecordOwned, after.DNSRecordOwned6)
				}
			}

			assertAuditActions(t, d, tc.wantActions)
		})
	}
}

// A provider delete failure is audited once, not on every cycle while the
// provider stays down.
func TestAgentAnchorCleanup_FailureAuditedOnce(t *testing.T) {
	ctx := context.Background()
	d := testDB(t)
	mp := registerMockProvider(t)
	_, zone, agent, _, _ := setupScenario(t, d)
	agent.PublicIP = "203.0.113.10"
	if err := d.UpdateAgent(agent); err != nil {
		t.Fatal(err)
	}
	if err := d.AddAgentZone(agent.ID, zone.ID); err != nil {
		t.Fatal(err)
	}
	r := New(d, newMockAgentClient(), time.Minute)
	if err := r.reconcileAgentDNS(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteAgent(agent.ID); err != nil {
		t.Fatal(err)
	}
	mp.mu.Lock()
	mp.deleteErr = errors.New("provider unavailable")
	mp.mu.Unlock()
	for range 3 {
		if err := r.reconcileAgentAnchorCleanups(ctx); err != nil {
			t.Fatal(err)
		}
	}
	queued, _ := d.ListAgentAnchorCleanups()
	if len(queued) != 1 || queued[0].Attempts != 3 {
		t.Fatalf("want one row with 3 attempts, got %+v", queued)
	}
	if n := countAuditAction(t, d, "a_record_delete_failed"); n != 1 {
		t.Errorf("a_record_delete_failed audited %d times, want 1", n)
	}
}

func assertAuditActions(t *testing.T, d *db.DB, want []string) {
	t.Helper()
	for _, action := range want {
		if countAuditAction(t, d, action) == 0 {
			t.Errorf("missing audit entry %q", action)
		}
	}
}

func countAuditAction(t *testing.T, d *db.DB, action string) int {
	t.Helper()
	entries, _, err := d.ListAuditLog(200, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if e.Action == action && e.EntityType == "agent" {
			n++
		}
	}
	return n
}

// anchorScenario is an adopted static-mode agent in zone example.com with an
// owned A record at agent1.example.com, created by one agent DNS cycle.
type anchorScenario struct {
	d     *db.DB
	mp    *mockDNSProvider
	r     *Reconciler
	agent *models.Agent
	zone  *models.Zone
	dom   *models.Domain
	oldA  string
}

func newAnchorScenario(t *testing.T) *anchorScenario {
	t.Helper()
	d := testDB(t)
	mp := registerMockProvider(t)
	_, zone, agent, _, dom := setupScenario(t, d)
	agent.PublicIP = "203.0.113.10"
	if err := d.UpdateAgent(agent); err != nil {
		t.Fatal(err)
	}
	if err := d.AddAgentZone(agent.ID, zone.ID); err != nil {
		t.Fatal(err)
	}
	r := New(d, newMockAgentClient(), time.Minute)
	r.anchorRenameGrace = 0
	if err := r.reconcileAgentDNS(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetAgent(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.DNSRecordID == "" || !got.DNSRecordOwned {
		t.Fatalf("setup: no owned A record (id=%q owned=%v)", got.DNSRecordID, got.DNSRecordOwned)
	}
	return &anchorScenario{d: d, mp: mp, r: r, agent: got, zone: zone, dom: dom, oldA: got.DNSRecordID}
}

// rename changes the agent FQDN through the same DB path the API uses.
func (s *anchorScenario) rename(t *testing.T, fqdn string) {
	t.Helper()
	a, err := s.d.GetAgent(s.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	a.FQDN = fqdn
	if err := s.d.UpdateAgent(a); err != nil {
		t.Fatal(err)
	}
}

// tick runs the agent DNS phase and then the cleanup phase, as RunOnce does.
func (s *anchorScenario) tick(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if err := s.r.reconcileAgentDNS(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.r.reconcileAgentAnchorCleanups(ctx); err != nil {
		t.Fatal(err)
	}
}

func (s *anchorScenario) setGetErr(err error) {
	s.mp.mu.Lock()
	s.mp.getErr = err
	s.mp.mu.Unlock()
}

// After a rename, the old anchor must survive until nothing visible depends
// on it any more; each case blocks the delete one way and then lifts the block.
func TestAgentAnchorCleanup_RenameWaitsUntilUnused(t *testing.T) {
	tests := []struct {
		name    string
		newFQDN string
		// block sets up the reason to wait; unblock removes it.
		block   func(t *testing.T, s *anchorScenario)
		unblock func(t *testing.T, s *anchorScenario)
	}{
		{
			name:    "grace period not over",
			newFQDN: "edge9.example.com",
			block:   func(_ *testing.T, s *anchorScenario) { s.r.anchorRenameGrace = time.Hour },
			unblock: func(_ *testing.T, s *anchorScenario) { s.r.anchorRenameGrace = 0 },
		},
		{
			name: "no anchor at the new name yet",
			// Outside every assigned zone: the agent can't get its new A record.
			newFQDN: "edge9.other.test",
			block:   func(*testing.T, *anchorScenario) {},
			unblock: func(t *testing.T, s *anchorScenario) { s.rename(t, "edge9.example.com") },
		},
		{
			name:    "domain CNAME still targets the old name",
			newFQDN: "edge9.example.com",
			block: func(t *testing.T, s *anchorScenario) {
				id := s.mp.seedRecord(provider.Record{Type: "CNAME", Name: "app.example.com", Content: "agent1.example.com"})
				if err := s.d.UpdateDomainDNSRecord(s.dom.ID, id, true); err != nil {
					t.Fatal(err)
				}
			},
			unblock: func(t *testing.T, s *anchorScenario) {
				// The domain DNS phase repoints the CNAME at the new name.
				if err := s.r.reconcileDNS(context.Background()); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:    "domain record cannot be read",
			newFQDN: "edge9.example.com",
			block: func(t *testing.T, s *anchorScenario) {
				id := s.mp.seedRecord(provider.Record{Type: "CNAME", Name: "app.example.com", Content: "edge9.example.com"})
				if err := s.d.UpdateDomainDNSRecord(s.dom.ID, id, true); err != nil {
					t.Fatal(err)
				}
				s.setGetErr(errors.New("dial tcp: i/o timeout"))
			},
			unblock: func(_ *testing.T, s *anchorScenario) { s.setGetErr(nil) },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newAnchorScenario(t)
			tc.block(t, s)
			s.rename(t, tc.newFQDN)
			s.tick(t)
			s.tick(t)
			if _, ok := s.mp.getRecord(s.oldA); !ok {
				t.Fatal("old anchor deleted while still needed")
			}
			if q, _ := s.d.ListAgentAnchorCleanups(); len(q) != 1 || q[0].Attempts != 0 {
				t.Fatalf("want one waiting row with no failed attempts, got %+v", q)
			}

			tc.unblock(t, s)
			s.tick(t)
			if _, ok := s.mp.getRecord(s.oldA); ok {
				t.Error("old anchor kept after the block was lifted")
			}
			if q, _ := s.d.ListAgentAnchorCleanups(); len(q) != 0 {
				t.Errorf("queue not drained: %+v", q)
			}
		})
	}
}

// Renaming away and back before the old record was deleted: the agent takes
// its original record back (still owned), and only the record it briefly had
// at the other name is deleted.
func TestAgentAnchorCleanup_RenameBackBeforeCleanup(t *testing.T) {
	s := newAnchorScenario(t)
	s.r.anchorRenameGrace = time.Hour // nothing is deleted while we move around

	s.rename(t, "edge9.example.com")
	s.tick(t)
	moved, _ := s.d.GetAgent(s.agent.ID)
	tempA := moved.DNSRecordID
	if tempA == "" || tempA == s.oldA {
		t.Fatalf("expected a new A record at edge9, got %q", tempA)
	}

	s.rename(t, "agent1.example.com")
	s.tick(t)
	back, _ := s.d.GetAgent(s.agent.ID)
	if back.DNSRecordID != s.oldA || !back.DNSRecordOwned {
		t.Fatalf("original record not reclaimed as owned: id=%q owned=%v (want %q)", back.DNSRecordID, back.DNSRecordOwned, s.oldA)
	}

	s.r.anchorRenameGrace = 0
	s.tick(t)
	if rec, ok := s.mp.getRecord(s.oldA); !ok || rec.Name != "agent1.example.com" {
		t.Errorf("reclaimed record was deleted or changed: %+v (present=%v)", rec, ok)
	}
	if _, ok := s.mp.getRecord(tempA); ok {
		t.Error("record at the abandoned name edge9 was not deleted")
	}
	if q, _ := s.d.ListAgentAnchorCleanups(); len(q) != 0 {
		t.Errorf("queue not drained: %+v", q)
	}
}

// If the zone or provider is removed while a record is queued: the provider
// snapshot still reaches the original zone when only the zone row is gone;
// with the provider gone too the delete can never succeed, so the row must stay
// (no silent drop), count as failing, and show up in the health counts.
func TestAgentAnchorCleanup_ZoneOrProviderGoneWhileQueued(t *testing.T) {
	tests := []struct {
		name           string
		deleteProvider bool
		wantDeleted    bool
	}{
		{name: "zone deleted, provider kept", wantDeleted: true},
		{name: "zone and provider deleted", deleteProvider: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s := newAnchorScenario(t)
			if err := s.d.DeleteAgent(s.agent.ID); err != nil {
				t.Fatal(err)
			}
			if err := s.d.DeleteZone(s.zone.ID); err != nil {
				t.Fatal(err)
			}
			if tc.deleteProvider {
				if err := s.d.DeleteProvider(s.zone.ProviderID); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.r.reconcileAgentAnchorCleanups(ctx); err != nil {
				t.Fatal(err)
			}

			_, present := s.mp.getRecord(s.oldA)
			q, _ := s.d.ListAgentAnchorCleanups()
			pending, failing, err := s.d.AgentAnchorCleanupCounts(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantDeleted {
				if present || len(q) != 0 || pending != 0 {
					t.Errorf("delete via provider snapshot failed: present=%v queue=%+v", present, q)
				}
				return
			}
			if !present {
				t.Error("record vanished although the provider is unknown")
			}
			if len(q) != 1 || q[0].Attempts != 1 || q[0].LastError == "" {
				t.Fatalf("row must stay with a recorded failure, got %+v", q)
			}
			if pending != 1 || failing != 1 {
				t.Errorf("counts = (%d pending, %d failing), want (1, 1)", pending, failing)
			}
			if countAuditAction(t, s.d, "a_record_delete_failed") != 1 {
				t.Error("missing a_record_delete_failed audit")
			}
		})
	}
}

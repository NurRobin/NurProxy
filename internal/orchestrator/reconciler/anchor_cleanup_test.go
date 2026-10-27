package reconciler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/provider"
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
	mp.deleteErr = errors.New("provider unavailable")
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

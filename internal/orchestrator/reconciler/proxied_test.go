package reconciler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/provider"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// proxiedCase is one combination of "what the live record has" and "what the
// operator set" for the Cloudflare proxy bit (#126).
type proxiedCase struct {
	name     string
	existing bool  // proxy state of the record already at the provider
	setting  *bool // domain.Proxied
	want     bool  // proxy state after the operation
	changed  bool  // whether a dns_proxied_updated audit entry is expected
}

func boolp(b bool) *bool { return &b }

// proxiedCases covers the rule: an unset setting keeps the live state, an
// explicit one wins.
var proxiedCases = []proxiedCase{
	{"unset keeps proxied", true, nil, true, false},
	{"unset keeps DNS only", false, nil, false, false},
	{"explicit on keeps proxied", true, boolp(true), true, false},
	{"explicit off flips proxied to DNS only", true, boolp(false), false, true},
	{"explicit on flips DNS only to proxied", false, boolp(true), true, true},
	{"explicit off keeps DNS only", false, boolp(false), false, false},
}

// proxiedScenario builds the standard scenario with the domain's proxied
// setting applied.
func proxiedScenario(t *testing.T, setting *bool) (*db.DB, *mockDNSProvider, *models.Agent, *models.Domain) {
	t.Helper()
	mp := registerMockProvider(t)
	d := testDB(t)
	_, _, agent, _, dom := setupScenario(t, d)
	dom.Proxied = setting
	if err := d.UpdateDomain(dom); err != nil {
		t.Fatalf("UpdateDomain: %v", err)
	}
	return d, mp, agent, dom
}

func countAudit(t *testing.T, d *db.DB, action string) int {
	t.Helper()
	entries, _, err := d.ListAuditLog(100, 0)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	n := 0
	for _, e := range entries {
		if e.Action == action {
			n++
		}
	}
	return n
}

func checkProxiedAudit(t *testing.T, d *db.DB, changed bool) {
	t.Helper()
	got := countAudit(t, d, "dns_proxied_updated")
	if changed && got != 1 {
		t.Errorf("dns_proxied_updated audit entries = %d, want 1", got)
	}
	if !changed && got != 0 {
		t.Errorf("dns_proxied_updated audit entries = %d, want 0 (record must not be touched)", got)
	}
}

// onlyRecord returns the single record the mock holds for app.example.com.
func onlyRecord(t *testing.T, mp *mockDNSProvider) provider.Record {
	t.Helper()
	recs, _ := mp.ListRecords(context.Background(), nil, "app.example.com", "")
	if len(recs) != 1 {
		t.Fatalf("expected exactly 1 record for app.example.com, got %d: %+v", len(recs), recs)
	}
	return recs[0]
}

// TestReconcileDNS_createUsesProxiedSetting: a fresh record is DNS only unless
// the operator asked for proxied.
func TestReconcileDNS_createUsesProxiedSetting(t *testing.T) {
	tests := []struct {
		name    string
		setting *bool
		want    bool
	}{
		{"unset creates DNS only", nil, false},
		{"explicit on creates proxied", boolp(true), true},
		{"explicit off creates DNS only", boolp(false), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, mp, agent, _ := proxiedScenario(t, tc.setting)
			r := New(d, newMockAgentClient(), time.Minute)
			if err := r.reconcileDNS(context.Background()); err != nil {
				t.Fatalf("reconcileDNS: %v", err)
			}
			rec := onlyRecord(t, mp)
			if rec.Content != agent.FQDN || rec.Proxied != tc.want {
				t.Errorf("created %s -> %s proxied=%t, want -> %s proxied=%t", rec.Type, rec.Content, rec.Proxied, agent.FQDN, tc.want)
			}
		})
	}
}

// TestReconcileDNS_adoptHonoursProxiedSetting: adopting an identical CNAME keeps
// its proxy state unless the operator set one.
func TestReconcileDNS_adoptHonoursProxiedSetting(t *testing.T) {
	for _, tc := range proxiedCases {
		t.Run(tc.name, func(t *testing.T) {
			d, mp, agent, dom := proxiedScenario(t, tc.setting)
			mp.seedRecord(provider.Record{Type: "CNAME", Name: "app.example.com", Content: agent.FQDN, Proxied: tc.existing})
			r := New(d, newMockAgentClient(), time.Minute)
			if err := r.reconcileDNS(context.Background()); err != nil {
				t.Fatalf("reconcileDNS: %v", err)
			}
			if rec := onlyRecord(t, mp); rec.Proxied != tc.want {
				t.Errorf("proxied = %t, want %t", rec.Proxied, tc.want)
			}
			got, _ := d.GetDomain(dom.ID)
			if got.DNSRecordID == "" || got.DNSManaged {
				t.Errorf("expected an adopted (unmanaged) record, got id=%q managed=%v", got.DNSRecordID, got.DNSManaged)
			}
			if got.Status == models.DomainStatusError {
				t.Errorf("unexpected error status: %s", got.ErrorMsg)
			}
			checkProxiedAudit(t, d, tc.changed)
		})
	}
}

// TestReconcileDNS_driftEnforcesProxiedSetting: a tracked record whose proxy
// state differs from an explicit setting is corrected; an unset setting never
// counts as drift. Running a second cycle must be a no-op.
func TestReconcileDNS_driftEnforcesProxiedSetting(t *testing.T) {
	for _, tc := range proxiedCases {
		t.Run(tc.name, func(t *testing.T) {
			d, mp, agent, dom := proxiedScenario(t, tc.setting)
			id := mp.seedRecord(provider.Record{Type: "CNAME", Name: "app.example.com", Content: agent.FQDN, Proxied: tc.existing})
			if err := d.UpdateDomainDNSRecord(dom.ID, id, true); err != nil {
				t.Fatalf("UpdateDomainDNSRecord: %v", err)
			}
			r := New(d, newMockAgentClient(), time.Minute)
			for i := 0; i < 2; i++ {
				if err := r.reconcileDNS(context.Background()); err != nil {
					t.Fatalf("reconcileDNS: %v", err)
				}
			}
			rec, ok := mp.getRecord(id)
			if !ok {
				t.Fatalf("record %s vanished", id)
			}
			if rec.Proxied != tc.want || rec.Content != agent.FQDN {
				t.Errorf("record = %s proxied=%t, want %s proxied=%t", rec.Content, rec.Proxied, agent.FQDN, tc.want)
			}
			checkProxiedAudit(t, d, tc.changed)
			if n := countAudit(t, d, "dns_updated"); n != 0 {
				t.Errorf("content did not drift, but got %d dns_updated entries", n)
			}
		})
	}
}

// TestReconcileDNS_contentDriftKeepsOrSetsProxied: fixing a wrong CNAME target
// carries the right proxy bit along.
func TestReconcileDNS_contentDriftKeepsOrSetsProxied(t *testing.T) {
	for _, tc := range proxiedCases {
		t.Run(tc.name, func(t *testing.T) {
			d, mp, agent, dom := proxiedScenario(t, tc.setting)
			id := mp.seedRecord(provider.Record{Type: "CNAME", Name: "app.example.com", Content: "old.example.net", Proxied: tc.existing})
			if err := d.UpdateDomainDNSRecord(dom.ID, id, true); err != nil {
				t.Fatalf("UpdateDomainDNSRecord: %v", err)
			}
			r := New(d, newMockAgentClient(), time.Minute)
			if err := r.reconcileDNS(context.Background()); err != nil {
				t.Fatalf("reconcileDNS: %v", err)
			}
			rec, _ := mp.getRecord(id)
			if rec.Proxied != tc.want || rec.Content != agent.FQDN {
				t.Errorf("record = %s proxied=%t, want %s proxied=%t", rec.Content, rec.Proxied, agent.FQDN, tc.want)
			}
			if n := countAudit(t, d, "dns_updated"); n != 1 {
				t.Errorf("dns_updated entries = %d, want 1", n)
			}
			checkProxiedAudit(t, d, tc.changed)
		})
	}
}

// TestTakeoverDomainDNS_proxiedSetting: replacing a conflicting record keeps the
// proxy state of what was there unless the operator set one; taking over a
// matching CNAME applies an explicit setting in place.
func TestTakeoverDomainDNS_proxiedSetting(t *testing.T) {
	for _, tc := range proxiedCases {
		t.Run("conflict/"+tc.name, func(t *testing.T) {
			d, mp, agent, dom := proxiedScenario(t, tc.setting)
			mp.seedRecord(provider.Record{Type: "A", Name: "app.example.com", Content: "203.0.113.99", Proxied: tc.existing})
			r := New(d, newMockAgentClient(), time.Minute)
			if err := r.TakeoverDomainDNS(context.Background(), dom.ID); err != nil {
				t.Fatalf("TakeoverDomainDNS: %v", err)
			}
			rec := onlyRecord(t, mp)
			if !strings.EqualFold(rec.Type, "CNAME") || rec.Content != agent.FQDN || rec.Proxied != tc.want {
				t.Errorf("after takeover %s -> %s proxied=%t, want CNAME -> %s proxied=%t", rec.Type, rec.Content, rec.Proxied, agent.FQDN, tc.want)
			}
			entries, _, _ := d.ListAuditLog(50, 0)
			for _, e := range entries {
				if e.Action == "dns_takeover" && tc.existing && !strings.Contains(e.Details, "(proxied)") {
					t.Errorf("takeover audit should show the replaced record was proxied: %q", e.Details)
				}
			}
		})
		t.Run("matching/"+tc.name, func(t *testing.T) {
			d, mp, agent, dom := proxiedScenario(t, tc.setting)
			mp.seedRecord(provider.Record{Type: "CNAME", Name: "app.example.com", Content: agent.FQDN, Proxied: tc.existing})
			r := New(d, newMockAgentClient(), time.Minute)
			if err := r.TakeoverDomainDNS(context.Background(), dom.ID); err != nil {
				t.Fatalf("TakeoverDomainDNS: %v", err)
			}
			if rec := onlyRecord(t, mp); rec.Proxied != tc.want {
				t.Errorf("proxied = %t, want %t", rec.Proxied, tc.want)
			}
			checkProxiedAudit(t, d, tc.changed)
		})
	}
}

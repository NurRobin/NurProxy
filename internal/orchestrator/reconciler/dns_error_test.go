package reconciler

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// TestDNSErrorSurvivesRouteApply: a failed DNS create used to be overwritten
// by the next route apply, leaving a domain "degraded" (no certificate yet) or
// "active" with no record and no word about DNS. The DNS reason now stays the
// domain's error until a DNS pass succeeds.
func TestDNSErrorSurvivesRouteApply(t *testing.T) {
	mp := registerMockProvider(t)
	d := testDB(t)
	_, _, agent, _, dom := setupScenario(t, d)
	r := New(d, newMockAgentClient(), time.Minute)
	mp.createErr = errors.New("cloudflare API error: [10000] Authentication error")

	if err := r.reconcileDNS(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := d.GetDomain(dom.ID)
	if got.Status != models.DomainStatusError || !strings.Contains(got.DNSError, "DNS create failed") || !strings.Contains(got.DNSError, "Authentication error") {
		t.Fatalf("after failed create: status=%q dns_error=%q", got.Status, got.DNSError)
	}

	// The agent applies the route (central TLS, no certificate yet): this is
	// what turned the domain "degraded" and hid the DNS failure.
	if err := d.MarkDomainApplied(dom.ID, "app.example.com", true); err != nil {
		t.Fatal(err)
	}
	got, _ = d.GetDomain(dom.ID)
	if got.Status != models.DomainStatusError || got.ErrorMsg != got.DNSError {
		t.Fatalf("route apply hid the DNS error: status=%q error_msg=%q dns_error=%q", got.Status, got.ErrorMsg, got.DNSError)
	}
	if err := d.MarkDomainSynced(dom.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ = d.GetDomain(dom.ID); got.Status != models.DomainStatusError || got.ErrorMsg != got.DNSError {
		t.Fatalf("sync hid the DNS error: status=%q error_msg=%q", got.Status, got.ErrorMsg)
	}

	mp.createErr = nil
	if err := r.reconcileDNS(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ = d.GetDomain(dom.ID)
	if got.DNSRecordID == "" || !got.DNSManaged {
		t.Fatalf("retry did not create a managed record: id=%q managed=%v", got.DNSRecordID, got.DNSManaged)
	}
	if got.DNSError != "" || got.ErrorMsg != "" || got.Status != models.DomainStatusPending {
		t.Fatalf("after successful create: status=%q error_msg=%q dns_error=%q, want pending and clear", got.Status, got.ErrorMsg, got.DNSError)
	}
	if rec, ok := mp.getRecord(got.DNSRecordID); !ok || rec.Content != agent.FQDN {
		t.Fatalf("record %s = %+v, want CNAME -> %s", got.DNSRecordID, rec, agent.FQDN)
	}
	if err := d.MarkDomainApplied(dom.ID, "app.example.com", true); err != nil {
		t.Fatal(err)
	}
	if got, _ = d.GetDomain(dom.ID); got.Status != models.DomainStatusDegraded || !strings.Contains(got.ErrorMsg, "plaintext") {
		t.Fatalf("without a DNS error the no-certificate state shows again: status=%q error_msg=%q", got.Status, got.ErrorMsg)
	}
}

// TestDNSErrorKeepsOtherErrors: clearing a DNS error leaves a route error in
// place.
func TestDNSErrorKeepsOtherErrors(t *testing.T) {
	d := testDB(t)
	_, _, _, _, dom := setupScenario(t, d)
	if err := d.SetDomainDNSError(dom.ID, "DNS create failed"); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateDomainStatus(dom.ID, models.DomainStatusError, "route push failed"); err != nil {
		t.Fatal(err)
	}
	if err := d.ClearDomainDNSError(dom.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := d.GetDomain(dom.ID)
	if got.DNSError != "" || got.Status != models.DomainStatusError || got.ErrorMsg != "route push failed" {
		t.Fatalf("status=%q error_msg=%q dns_error=%q, want the route error kept", got.Status, got.ErrorMsg, got.DNSError)
	}
}

// TestReconcileDNS_unresolvableNamesReason: the resolution steps before any
// provider call used to return with only a log line, so a domain could sit
// without a record and without a reason.
func TestReconcileDNS_unresolvableNamesReason(t *testing.T) {
	tests := []struct {
		name    string
		breakIt func(t *testing.T, r *Reconciler)
		want    string
	}{
		{"provider type not registered", func(t *testing.T, r *Reconciler) {
			if err := r.db.UpdateProvider(&models.Provider{ID: "prov-1", Type: "ghost-unregistered", Name: "Ghost", Config: `{}`}); err != nil {
				t.Fatal(err)
			}
		}, "ghost-unregistered"},
		{"agent without FQDN", func(t *testing.T, r *Reconciler) {
			a, err := r.db.GetAgent("agent-1")
			if err != nil {
				t.Fatal(err)
			}
			a.FQDN = ""
			if err := r.db.UpdateAgent(a); err != nil {
				t.Fatal(err)
			}
		}, "has no FQDN"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			registerMockProvider(t)
			d := testDB(t)
			_, _, _, _, dom := setupScenario(t, d)
			r := New(d, newMockAgentClient(), time.Minute)
			tc.breakIt(t, r)
			if err := r.reconcileDNS(context.Background()); err != nil {
				t.Fatal(err)
			}
			got, _ := d.GetDomain(dom.ID)
			if got.Status != models.DomainStatusError || !strings.Contains(got.ErrorMsg, tc.want) || got.DNSError != got.ErrorMsg {
				t.Fatalf("status=%q error_msg=%q dns_error=%q, want error naming %q", got.Status, got.ErrorMsg, got.DNSError, tc.want)
			}
		})
	}
}

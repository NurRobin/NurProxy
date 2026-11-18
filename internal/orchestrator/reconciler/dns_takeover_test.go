package reconciler

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/provider"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// hookDNSProvider wraps the mock provider so a test can fail the n-th
// delete or hold a CreateRecord until it is released.
type hookDNSProvider struct {
	*mockDNSProvider
	// failDeleteAt makes the n-th DeleteRecord call (1-based) return
	// failDeleteErr; 0 never fails.
	failDeleteAt  int
	failDeleteErr error
	deleteCalls   int

	mu          sync.Mutex
	holdCreate  bool
	createEnter chan struct{}
	release     chan struct{}
}

func (p *hookDNSProvider) DeleteRecord(ctx context.Context, cfg json.RawMessage, id string) error {
	p.deleteCalls++
	if p.failDeleteAt > 0 && p.deleteCalls == p.failDeleteAt {
		return p.failDeleteErr
	}
	return p.mockDNSProvider.DeleteRecord(ctx, cfg, id)
}

func (p *hookDNSProvider) CreateRecord(ctx context.Context, cfg json.RawMessage, rec provider.Record) (string, error) {
	p.mu.Lock()
	hold := p.holdCreate
	p.holdCreate = false
	p.mu.Unlock()
	if hold {
		close(p.createEnter)
		<-p.release
	}
	return p.mockDNSProvider.CreateRecord(ctx, cfg, rec)
}

func registerHookProvider(t *testing.T) *hookDNSProvider {
	t.Helper()
	hp := &hookDNSProvider{mockDNSProvider: newMockDNSProvider(), }
	provider.Register(hp)
	return hp
}

func recordsAt(t *testing.T, p provider.Provider, name string) []provider.Record {
	t.Helper()
	recs, err := p.ListRecords(context.Background(), nil, name, "")
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func TestTakeoverDomainDNS_refused(t *testing.T) {
	tests := []struct {
		name string
		// target returns the domain to take over; its name is certs.example.com.
		target func(t *testing.T, d *db.DB, scenario *models.Domain) int64
	}{
		{"cert-only", func(t *testing.T, d *db.DB, scenario *models.Domain) int64 {
			dom := &models.Domain{Subdomain: "certs", ZoneID: scenario.ZoneID, ServerID: scenario.ServerID,
				SSLMode: models.SSLModeAuto, CertOnly: true, Status: models.DomainStatusPending}
			if err := d.CreateDomain(dom); err != nil {
				t.Fatal(err)
			}
			return dom.ID
		}},
		{"being deleted", func(t *testing.T, d *db.DB, scenario *models.Domain) int64 {
			dom := &models.Domain{Subdomain: "certs", ZoneID: scenario.ZoneID, ServerID: scenario.ServerID,
				Port: 80, SSLMode: models.SSLModeAuto, Status: models.DomainStatusPending}
			if err := d.CreateDomain(dom); err != nil {
				t.Fatal(err)
			}
			if err := d.UpdateDomainStatus(dom.ID, models.DomainStatusDeleting, ""); err != nil {
				t.Fatal(err)
			}
			return dom.ID
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mp := registerMockProvider(t)
			d := testDB(t)
			_, _, _, _, scenario := setupScenario(t, d)
			id := tc.target(t, d, scenario)
			conflictID := mp.seedRecord(provider.Record{Type: "A", Name: "certs.example.com", Content: "203.0.113.99"})
			r := New(d, newMockAgentClient(), time.Minute)

			if _, err := r.PreviewDomainDNSTakeover(context.Background(), id); !errors.Is(err, ErrDNSTakeoverRefused) {
				t.Errorf("preview error = %v, want ErrDNSTakeoverRefused", err)
			}
			if _, err := r.TakeoverDomainDNS(context.Background(), id); !errors.Is(err, ErrDNSTakeoverRefused) {
				t.Errorf("takeover error = %v, want ErrDNSTakeoverRefused", err)
			}
			if _, ok := mp.getRecord(conflictID); !ok {
				t.Error("a refused takeover deleted the existing record")
			}
			if n := len(recordsAt(t, mp, "certs.example.com")); n != 1 {
				t.Errorf("records at the name = %d, want the 1 untouched record", n)
			}
		})
	}
}

// TestTakeoverDomainDNS_multipleRecords: every record at the name is listed by
// the preview (which changes nothing) and deleted by the takeover; records at
// other names stay.
func TestTakeoverDomainDNS_multipleRecords(t *testing.T) {
	mp := registerMockProvider(t)
	d := testDB(t)
	_, _, agent, _, dom := setupScenario(t, d)
	aID := mp.seedRecord(provider.Record{Type: "A", Name: "app.example.com", Content: "203.0.113.99"})
	mxID := mp.seedRecord(provider.Record{Type: "MX", Name: "app.example.com", Content: "mail.example.com"})
	txtID := mp.seedRecord(provider.Record{Type: "TXT", Name: "app.example.com", Content: "v=spf1 -all"})
	otherID := mp.seedRecord(provider.Record{Type: "A", Name: "other.example.com", Content: "203.0.113.1"})
	r := New(d, newMockAgentClient(), time.Minute)

	plan, err := r.PreviewDomainDNSTakeover(context.Background(), dom.ID)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if plan.Action != models.DNSTakeoverReplace || plan.Target != agent.FQDN || plan.FQDN != "app.example.com" {
		t.Errorf("preview plan = %+v", plan)
	}
	gotIDs := map[string]bool{}
	for _, rec := range plan.Delete {
		gotIDs[rec.ID] = true
	}
	for _, id := range []string{aID, mxID, txtID} {
		if !gotIDs[id] {
			t.Errorf("preview does not list record %s for deletion: %+v", id, plan.Delete)
		}
	}
	if len(plan.Delete) != 3 {
		t.Errorf("preview lists %d records, want 3", len(plan.Delete))
	}
	if n := len(recordsAt(t, mp, "app.example.com")); n != 3 {
		t.Fatalf("preview changed the provider: %d records at the name, want 3", n)
	}
	if got, _ := d.GetDomain(dom.ID); got.DNSRecordID != "" {
		t.Fatalf("preview stored a record id %q", got.DNSRecordID)
	}

	done, err := r.TakeoverDomainDNS(context.Background(), dom.ID)
	if err != nil {
		t.Fatalf("takeover: %v", err)
	}
	if len(done.Delete) != 3 {
		t.Errorf("takeover reports %d deleted records, want 3", len(done.Delete))
	}
	recs := recordsAt(t, mp, "app.example.com")
	if len(recs) != 1 || !strings.EqualFold(recs[0].Type, "CNAME") || recs[0].Content != agent.FQDN {
		t.Fatalf("records after takeover = %+v, want one CNAME -> %s", recs, agent.FQDN)
	}
	if _, ok := mp.getRecord(otherID); !ok {
		t.Error("takeover deleted a record at another name")
	}
	got, _ := d.GetDomain(dom.ID)
	if got.DNSRecordID != recs[0].ID || !got.DNSManaged {
		t.Errorf("domain record = %q managed=%v, want %q managed=true", got.DNSRecordID, got.DNSManaged, recs[0].ID)
	}
}

// TestTakeoverDomainDNS_adoptSetsManaged: taking over a matching CNAME that
// the reconciler had adopted as unmanaged makes it managed.
func TestTakeoverDomainDNS_adoptSetsManaged(t *testing.T) {
	mp := registerMockProvider(t)
	d := testDB(t)
	_, _, agent, _, dom := setupScenario(t, d)
	seedID := mp.seedRecord(provider.Record{Type: "CNAME", Name: "app.example.com", Content: agent.FQDN})
	r := New(d, newMockAgentClient(), time.Minute)

	if err := r.reconcileDNS(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.GetDomain(dom.ID); got.DNSRecordID != seedID || got.DNSManaged {
		t.Fatalf("reconcile should adopt %s unmanaged, got %q managed=%v", seedID, got.DNSRecordID, got.DNSManaged)
	}
	plan, err := r.TakeoverDomainDNS(context.Background(), dom.ID)
	if err != nil {
		t.Fatalf("takeover: %v", err)
	}
	if plan.Action != models.DNSTakeoverAdopt || len(plan.Delete) != 0 {
		t.Errorf("plan = %+v, want adopt without deletes", plan)
	}
	if got, _ := d.GetDomain(dom.ID); got.DNSRecordID != seedID || !got.DNSManaged {
		t.Errorf("after takeover record = %q managed=%v, want %q managed=true", got.DNSRecordID, got.DNSManaged, seedID)
	}
}

// TestTakeoverDomainDNS_incomplete: when a provider call fails after records
// were deleted, the error says which records are gone and that a retry heals
// it, the domain shows it, and a retry does.
func TestTakeoverDomainDNS_incomplete(t *testing.T) {
	tests := []struct {
		name     string
		fail     func(hp *hookDNSProvider)
		wantText []string
		wantLeft int
	}{
		{
			name: "create fails",
			fail: func(hp *hookDNSProvider) {
				hp.createErr = errors.New("provider says no")
			},
			wantText: []string{"were already deleted", "A → 203.0.113.99", "TXT → v=spf1 -all", "provider says no", "has no DNS record now", "Retry the takeover"},
		},
		{
			name: "second delete fails",
			fail: func(hp *hookDNSProvider) {
				hp.failDeleteAt, hp.failDeleteErr = 2, errors.New("delete refused")
			},
			wantText: []string{"were already deleted", "delete refused", "not restored", "Retry the takeover"},
			wantLeft: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hp := registerHookProvider(t)
			d := testDB(t)
			_, _, agent, _, dom := setupScenario(t, d)
			hp.seedRecord(provider.Record{Type: "A", Name: "app.example.com", Content: "203.0.113.99"})
			hp.seedRecord(provider.Record{Type: "TXT", Name: "app.example.com", Content: "v=spf1 -all"})
			r := New(d, newMockAgentClient(), time.Minute)
			tc.fail(hp)

			_, err := r.TakeoverDomainDNS(context.Background(), dom.ID)
			var inc *DNSTakeoverIncompleteError
			if !errors.As(err, &inc) {
				t.Fatalf("error = %v, want *DNSTakeoverIncompleteError", err)
			}
			for _, want := range tc.wantText {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err.Error(), want)
				}
			}
			if len(recordsAt(t, hp, "app.example.com")) != tc.wantLeft {
				t.Errorf("records left = %d, want %d", len(recordsAt(t, hp, "app.example.com")), tc.wantLeft)
			}
			got, _ := d.GetDomain(dom.ID)
			if got.Status != models.DomainStatusError || got.DNSError != err.Error() || got.ErrorMsg != err.Error() {
				t.Errorf("domain status=%q error_msg=%q dns_error=%q, want error with the takeover error", got.Status, got.ErrorMsg, got.DNSError)
			}

			hp.createErr = nil
			hp.failDeleteAt = 0
			if _, err := r.TakeoverDomainDNS(context.Background(), dom.ID); err != nil {
				t.Fatalf("retry: %v", err)
			}
			recs := recordsAt(t, hp, "app.example.com")
			if len(recs) != 1 || recs[0].Content != agent.FQDN {
				t.Fatalf("after retry records = %+v, want one CNAME -> %s", recs, agent.FQDN)
			}
			got, _ = d.GetDomain(dom.ID)
			if got.DNSError != "" || got.ErrorMsg != "" || !got.DNSManaged {
				t.Errorf("after retry dns_error=%q error_msg=%q managed=%v, want cleared and managed", got.DNSError, got.ErrorMsg, got.DNSManaged)
			}
		})
	}
}

// TestTakeoverDomainDNS_raceWithReconcile: a reconcile pass that runs while a
// takeover sits between its delete and its create must neither create a
// second record at the name nor adopt the takeover's record as unmanaged.
func TestTakeoverDomainDNS_raceWithReconcile(t *testing.T) {
	hp := registerHookProvider(t)
	d := testDB(t)
	_, _, agent, _, dom := setupScenario(t, d)
	hp.seedRecord(provider.Record{Type: "A", Name: "app.example.com", Content: "203.0.113.99"})
	r := New(d, newMockAgentClient(), time.Minute)

	hp.holdCreate = true
	hp.createEnter = make(chan struct{})
	hp.release = make(chan struct{})

	takeoverErr := make(chan error, 1)
	go func() {
		_, err := r.TakeoverDomainDNS(context.Background(), dom.ID)
		takeoverErr <- err
	}()
	<-hp.createEnter // the A record is deleted; the name is free at the provider

	reconciled := make(chan struct{})
	go func() {
		_ = r.reconcileDNS(context.Background())
		close(reconciled)
	}()
	select {
	case <-reconciled:
		t.Error("the reconcile pass did not wait for the takeover")
	case <-time.After(200 * time.Millisecond):
	}
	close(hp.release)
	if err := <-takeoverErr; err != nil {
		t.Fatalf("takeover: %v", err)
	}
	<-reconciled

	recs := recordsAt(t, hp, "app.example.com")
	if len(recs) != 1 || recs[0].Content != agent.FQDN {
		t.Fatalf("records at the name = %+v, want exactly one CNAME -> %s", recs, agent.FQDN)
	}
	got, _ := d.GetDomain(dom.ID)
	if got.DNSRecordID != recs[0].ID || !got.DNSManaged {
		t.Errorf("domain record = %q managed=%v, want %q managed=true", got.DNSRecordID, got.DNSManaged, recs[0].ID)
	}
}

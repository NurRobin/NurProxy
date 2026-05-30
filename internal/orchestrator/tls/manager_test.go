package tls

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fakeStore is a hand-written RenewalStore. due is what DueForRenewal returns;
// saved records every SaveRenewed call so tests can assert scope preservation.
type fakeStore struct {
	due       []RenewTarget
	dueErr    error
	forHost   map[string]*RenewTarget // TargetForHost lookups
	forHostEr error
	saved     []*CertResult
	savedWC   []bool
	saveErr   error
	gotWin    time.Duration
}

func (s *fakeStore) DueForRenewal(_ context.Context, window time.Duration) ([]RenewTarget, error) {
	s.gotWin = window
	return s.due, s.dueErr
}
func (s *fakeStore) TargetForHost(_ context.Context, host string) (*RenewTarget, error) {
	if s.forHostEr != nil {
		return nil, s.forHostEr
	}
	return s.forHost[host], nil
}
func (s *fakeStore) SaveRenewed(_ context.Context, res *CertResult, isWildcard bool) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.saved = append(s.saved, res)
	s.savedWC = append(s.savedWC, isWildcard)
	return nil
}

// fakeReloader records the hosts it was asked to re-push.
type fakeReloader struct {
	hosts []string
	err   error
}

func (r *fakeReloader) RepushCertForHost(_ context.Context, host string) error {
	r.hosts = append(r.hosts, host)
	return r.err
}

// fakeAudit records audited events.
type fakeAudit struct {
	events []string // "action:entityID"
}

func (a *fakeAudit) Audit(_, entityID, action, _ string) {
	a.events = append(a.events, action+":"+entityID)
}

func newRenewer(store RenewalStore, acme ACMEClient, rl Reloader, audit AuditSink) *Renewer {
	iss := NewIssuer(acme, nil)
	return NewRenewer(store, iss, RenewerConfig{Reloader: rl, Audit: audit})
}

func TestRenewer_RunOnce_renewsSavesAndRepushes(t *testing.T) {
	fp := newFakeProvider("TXT")
	store := &fakeStore{
		due: []RenewTarget{
			{Host: "a.example.com", Names: []string{"a.example.com"}, Provider: fp},
		},
	}
	acme := &fakeACME{result: &CertResult{CertPEM: []byte("NEWCERT"), KeyPEM: []byte("NEWKEY")}}
	rl := &fakeReloader{}
	audit := &fakeAudit{}

	r := newRenewer(store, acme, rl, audit)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if store.gotWin != DefaultRenewWindow {
		t.Errorf("window = %v, want default %v", store.gotWin, DefaultRenewWindow)
	}
	if len(store.saved) != 1 {
		t.Fatalf("saved %d certs, want 1", len(store.saved))
	}
	if string(store.saved[0].CertPEM) != "NEWCERT" {
		t.Errorf("saved cert = %q, want NEWCERT", store.saved[0].CertPEM)
	}
	if len(rl.hosts) != 1 || rl.hosts[0] != "a.example.com" {
		t.Errorf("repushed hosts = %v, want [a.example.com]", rl.hosts)
	}
	if !containsEvent(audit.events, "renewed:a.example.com") {
		t.Errorf("missing renewed audit event, got %v", audit.events)
	}
}

func TestRenewer_EnsureCertForHost_issuesSavesRepushes(t *testing.T) {
	fp := newFakeProvider("TXT")
	store := &fakeStore{
		forHost: map[string]*RenewTarget{
			"new.example.com": {Host: "new.example.com", Names: []string{"new.example.com"}, Provider: fp},
		},
	}
	acme := &fakeACME{result: &CertResult{CertPEM: []byte("FRESH"), KeyPEM: []byte("K")}}
	rl := &fakeReloader{}
	r := newRenewer(store, acme, rl, &fakeAudit{})

	if err := r.EnsureCertForHost(context.Background(), "new.example.com"); err != nil {
		t.Fatalf("EnsureCertForHost: %v", err)
	}
	if len(store.saved) != 1 || string(store.saved[0].CertPEM) != "FRESH" {
		t.Fatalf("first issuance did not save the cert: %+v", store.saved)
	}
	if len(rl.hosts) != 1 || rl.hosts[0] != "new.example.com" {
		t.Errorf("repushed hosts = %v, want [new.example.com]", rl.hosts)
	}
}

func TestRenewer_EnsureCertForHost_noTargetIsNoOp(t *testing.T) {
	store := &fakeStore{forHost: map[string]*RenewTarget{}} // host resolves to nothing
	acme := &fakeACME{result: &CertResult{CertPEM: []byte("X")}}
	r := newRenewer(store, acme, &fakeReloader{}, &fakeAudit{})

	if err := r.EnsureCertForHost(context.Background(), "unknown.example.com"); err != nil {
		t.Fatalf("EnsureCertForHost no-op should not error: %v", err)
	}
	if len(store.saved) != 0 {
		t.Errorf("nothing should be issued when no target resolves, saved=%v", store.saved)
	}
}

func TestRenewer_notConfigured_skipsQuietly(t *testing.T) {
	fp := newFakeProvider("TXT")
	acme := &fakeACME{err: ErrACMENotConfigured}
	audit := &fakeAudit{}

	// RunOnce: a target whose issuance reports "not configured" is not a failure —
	// the scan returns nil, nothing is saved, and no per-host failure is audited.
	store := &fakeStore{
		due:     []RenewTarget{{Host: "a.example.com", Names: []string{"a.example.com"}, Provider: fp}},
		forHost: map[string]*RenewTarget{"a.example.com": {Host: "a.example.com", Names: []string{"a.example.com"}, Provider: fp}},
	}
	r := newRenewer(store, acme, &fakeReloader{}, audit)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce should swallow not-configured: %v", err)
	}
	if len(store.saved) != 0 {
		t.Errorf("nothing should be saved when ACME is not configured: %v", store.saved)
	}
	for _, e := range audit.events {
		if strings.Contains(e, "renew_failed") || strings.Contains(e, "issue_failed") {
			t.Errorf("not-configured must not audit a failure, got %q", e)
		}
	}

	// EnsureCertForHost: likewise a quiet no-op (no error to the caller).
	if err := r.EnsureCertForHost(context.Background(), "a.example.com"); err != nil {
		t.Fatalf("EnsureCertForHost should swallow not-configured: %v", err)
	}
}

func TestRenewer_RunOnce_wildcardScopePreserved(t *testing.T) {
	fp := newFakeProvider("TXT")
	store := &fakeStore{
		due: []RenewTarget{
			{Host: "example.com", Names: []string{"*.example.com"}, IsWildcard: true, Provider: fp},
		},
	}
	acme := &fakeACME{result: &CertResult{CertPEM: []byte("C")}}
	r := newRenewer(store, acme, &fakeReloader{}, &fakeAudit{})

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	// The re-issue must request the wildcard name, not the bare host.
	want := []string{"*.example.com"}
	if !reflect.DeepEqual(acme.gotNames, want) {
		t.Errorf("re-issue names = %v, want %v", acme.gotNames, want)
	}
	if len(store.savedWC) != 1 || !store.savedWC[0] {
		t.Errorf("renewed cert lost its wildcard flag: %v", store.savedWC)
	}
}

func TestRenewer_RunOnce_sansPreserved(t *testing.T) {
	fp := newFakeProvider("TXT")
	store := &fakeStore{
		due: []RenewTarget{
			{Host: "a.example.com", Names: []string{"a.example.com", "b.example.com", "c.example.com"}, Provider: fp},
		},
	}
	acme := &fakeACME{result: &CertResult{CertPEM: []byte("C")}}
	r := newRenewer(store, acme, &fakeReloader{}, &fakeAudit{})

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	want := []string{"a.example.com", "b.example.com", "c.example.com"}
	if !reflect.DeepEqual(acme.gotNames, want) {
		t.Errorf("re-issue names = %v, want %v (SANs must survive renewal)", acme.gotNames, want)
	}
}

func TestRenewer_RunOnce_oneFailureDoesNotAbortRest(t *testing.T) {
	good := newFakeProvider("TXT")
	bad := newFakeProvider("A", "CNAME") // no TXT -> ErrNoTXTSupport on issue
	store := &fakeStore{
		due: []RenewTarget{
			{Host: "bad.example.com", Names: []string{"bad.example.com"}, Provider: bad},
			{Host: "good.example.com", Names: []string{"good.example.com"}, Provider: good},
		},
	}
	acme := &fakeACME{result: &CertResult{CertPEM: []byte("C")}}
	audit := &fakeAudit{}
	r := newRenewer(store, acme, &fakeReloader{}, audit)

	err := r.RunOnce(context.Background())
	if err == nil {
		t.Fatal("expected the first failure to be returned")
	}
	// The good host must still have been renewed despite the bad one failing.
	if len(store.saved) != 1 {
		t.Fatalf("saved %d certs, want 1 (good host)", len(store.saved))
	}
	if !containsEvent(audit.events, "renew_failed:bad.example.com") {
		t.Errorf("missing renew_failed audit for bad host, got %v", audit.events)
	}
	if !containsEvent(audit.events, "renewed:good.example.com") {
		t.Errorf("missing renewed audit for good host, got %v", audit.events)
	}
}

func TestRenewer_RunOnce_repushFailureIsNonFatal(t *testing.T) {
	fp := newFakeProvider("TXT")
	store := &fakeStore{
		due: []RenewTarget{{Host: "a.example.com", Names: []string{"a.example.com"}, Provider: fp}},
	}
	acme := &fakeACME{result: &CertResult{CertPEM: []byte("C")}}
	rl := &fakeReloader{err: errors.New("agent offline")}
	audit := &fakeAudit{}
	r := newRenewer(store, acme, rl, audit)

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("re-push failure must be non-fatal, got %v", err)
	}
	if len(store.saved) != 1 {
		t.Errorf("cert should still be stored, saved=%d", len(store.saved))
	}
	if !containsEvent(audit.events, "renew_repush_deferred:a.example.com") {
		t.Errorf("missing deferred-repush audit, got %v", audit.events)
	}
}

func TestRenewer_RunOnce_noWork_noop(t *testing.T) {
	store := &fakeStore{due: nil}
	r := newRenewer(store, &fakeACME{}, &fakeReloader{}, &fakeAudit{})
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce with no work: %v", err)
	}
	if len(store.saved) != 0 {
		t.Errorf("nothing should be saved, got %d", len(store.saved))
	}
}

func TestRenewer_RunOnce_dueErrorPropagates(t *testing.T) {
	store := &fakeStore{dueErr: errors.New("db down")}
	r := newRenewer(store, &fakeACME{}, &fakeReloader{}, &fakeAudit{})
	if err := r.RunOnce(context.Background()); err == nil {
		t.Fatal("expected DueForRenewal error to propagate")
	}
}

func TestRenewer_customWindow(t *testing.T) {
	store := &fakeStore{}
	iss := NewIssuer(&fakeACME{}, nil)
	r := NewRenewer(store, iss, RenewerConfig{Window: 10 * 24 * time.Hour})
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if store.gotWin != 10*24*time.Hour {
		t.Errorf("window = %v, want 240h", store.gotWin)
	}
}

func containsEvent(events []string, want string) bool {
	for _, e := range events {
		if e == want {
			return true
		}
	}
	return false
}

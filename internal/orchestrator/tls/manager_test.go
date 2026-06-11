package tls

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/provider"
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

// lockStore models the real DB seam closely enough to exercise the per-host
// issuance lock: TargetForHost re-checks for an already-issued cert (the same
// GetCertificate guard the orchestrator's store uses) and returns nil once one
// exists, so a second caller for the same host collapses to a no-op. SaveRenewed
// records the host. All access is mutex-guarded since callers hit it from
// goroutines.
type lockStore struct {
	mu        sync.Mutex
	provider  provider.Provider
	hasCert   map[string]bool // host -> already issued (TargetForHost returns nil)
	saveCount map[string]int  // host -> #SaveRenewed
	due       []RenewTarget   // what DueForRenewal returns (scan path)
}

func newLockStore(p provider.Provider) *lockStore {
	return &lockStore{provider: p, hasCert: map[string]bool{}, saveCount: map[string]int{}}
}

func (s *lockStore) DueForRenewal(context.Context, time.Duration) ([]RenewTarget, error) {
	return s.due, nil
}

func (s *lockStore) TargetForHost(_ context.Context, host string) (*RenewTarget, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hasCert[host] {
		return nil, nil // cert already on file — the winner already issued
	}
	return &RenewTarget{Host: host, Names: []string{host}, Provider: s.provider}, nil
}

func (s *lockStore) SaveRenewed(_ context.Context, res *CertResult, _ bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hasCert[res.Host] = true
	s.saveCount[res.Host]++
	return nil
}

// barrierACME counts Obtain calls and, when width > 1, holds every caller inside
// Obtain until the test releases them — so the different-hosts test can prove the
// issuance critical sections actually overlap (a global lock would never let the
// barrier fill). The `arrived` signal is sent non-blocking so an unexpected extra
// caller (e.g. the same-host test if the per-host lock regressed and let more than
// one through) never deadlocks the harness — the assertion on `calls` catches the
// regression instead. width <= 1 closes `release` up front so single-issuer paths
// never block at all.
type barrierACME struct {
	calls   int32
	arrived chan struct{}
	release chan struct{}
	result  *CertResult
}

func newBarrierACME(width int, res *CertResult) *barrierACME {
	if width < 1 {
		width = 1
	}
	b := &barrierACME{arrived: make(chan struct{}, width), release: make(chan struct{}), result: res}
	if width <= 1 {
		close(b.release) // never block single-issuer paths
	}
	return b
}

func (b *barrierACME) ObtainViaDNS01(_ context.Context, names []string, _ DNSSolver) (*CertResult, error) {
	atomic.AddInt32(&b.calls, 1)
	select {
	case b.arrived <- struct{}{}: // signal arrival; never block on a full buffer
	default:
	}
	<-b.release
	res := *b.result
	res.Names = names
	if len(names) > 0 {
		res.Host = strings.TrimPrefix(names[0], "*.")
	}
	return &res, nil
}

// TestRenewer_EnsureCertForHost_concurrentSameHost_issuesOnce verifies the
// per-host issuance guard: two concurrent EnsureCertForHost calls for the SAME
// host must drive ACME exactly once. The first to take the lock issues + saves;
// the second re-resolves TargetForHost inside the lock, sees the cert now exists,
// and no-ops. Without the lock both would issue, double-burning the CA quota.
func TestRenewer_EnsureCertForHost_concurrentSameHost_issuesOnce(t *testing.T) {
	store := newLockStore(newFakeProvider("TXT"))
	acme := newBarrierACME(1, &CertResult{CertPEM: []byte("C"), KeyPEM: []byte("K")})
	// nil reloader/audit: the test fakes are not concurrency-safe and the lock under
	// test serializes per host, not globally — the store's own mutex is the only
	// shared state the assertions read.
	r := newRenewer(store, acme, nil, nil)

	const host = "race.example.com"
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start // release all goroutines together to maximize contention
			errs[idx] = r.EnsureCertForHost(context.Background(), host)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("EnsureCertForHost[%d]: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&acme.calls); got != 1 {
		t.Errorf("ObtainViaDNS01 calls = %d, want 1 (per-host lock must collapse concurrent issuance)", got)
	}
	if got := store.saveCount[host]; got != 1 {
		t.Errorf("SaveRenewed for %s = %d, want 1", host, got)
	}
}

// TestRenewer_EnsureCertForHost_concurrentDifferentHosts_proceedConcurrently
// verifies the lock is per-host, not global: issuance for distinct hosts must run
// concurrently. The barrier forces all callers to sit inside Obtain at once; if
// the lock were global, only one could be in flight and the barrier would never
// fill, tripping the deadline.
func TestRenewer_EnsureCertForHost_concurrentDifferentHosts_proceedConcurrently(t *testing.T) {
	const n = 4
	store := newLockStore(newFakeProvider("TXT"))
	acme := newBarrierACME(n, &CertResult{CertPEM: []byte("C"), KeyPEM: []byte("K")})
	// nil reloader/audit: distinct hosts run truly concurrently here, and the test
	// fakes are not thread-safe; the store guards its own counters with a mutex.
	r := newRenewer(store, acme, nil, nil)

	hosts := []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"}
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i, h := range hosts {
		wg.Add(1)
		go func(idx int, host string) {
			defer wg.Done()
			errs[idx] = r.EnsureCertForHost(context.Background(), host)
		}(i, h)
	}

	// Wait until all n issuers are simultaneously inside Obtain (proving they run
	// concurrently), then release them. A global lock would stall here.
	deadline := time.After(2 * time.Second)
	for got := 0; got < n; {
		select {
		case <-acme.arrived:
			got++
		case <-deadline:
			t.Fatalf("only %d/%d issuers reached ACME concurrently — lock is not per-host", got, n)
		}
	}
	close(acme.release)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("EnsureCertForHost[%d]: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&acme.calls); got != n {
		t.Errorf("ObtainViaDNS01 calls = %d, want %d (one per distinct host)", got, n)
	}
	for _, h := range hosts {
		if store.saveCount[h] != 1 {
			t.Errorf("SaveRenewed for %s = %d, want 1", h, store.saveCount[h])
		}
	}
}

// TestRenewer_EnsureAndScan_concurrentSameHost_firstIssuanceOnce covers the race
// between the on-create fast path (EnsureCertForHost) and the periodic scan's
// first-issuance pass (RunOnce → renewOne) for the SAME host with no cert yet.
// The scan's target is resolved by DueForRenewal BEFORE any lock is taken; once
// the create path issues+saves+unlocks, renewOne takes the freed lock against a
// now-stale target. Without the under-lock re-check renewOne would re-drive ACME,
// double-burning the CA duplicate-cert quota. With FirstIssue set, renewOne
// re-resolves TargetForHost inside the lock, sees the cert now on file, and
// no-ops — so ACME is hit exactly once regardless of which path wins.
func TestRenewer_EnsureAndScan_concurrentSameHost_firstIssuanceOnce(t *testing.T) {
	const host = "first.example.com"
	store := newLockStore(newFakeProvider("TXT"))
	// The scan resolves a first-issuance target (no cert yet) — the pre-lock
	// snapshot that becomes stale the moment the create path issues.
	store.due = []RenewTarget{
		{Host: host, Names: []string{host}, Provider: store.provider, FirstIssue: true},
	}
	acme := newBarrierACME(1, &CertResult{CertPEM: []byte("C"), KeyPEM: []byte("K")})
	// nil reloader/audit: the lock under test serializes per host; the store's own
	// mutex guards the only shared state the assertions read.
	r := newRenewer(store, acme, nil, nil)

	var wg sync.WaitGroup
	start := make(chan struct{})
	var ensureErr, scanErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		ensureErr = r.EnsureCertForHost(context.Background(), host)
	}()
	go func() {
		defer wg.Done()
		<-start
		scanErr = r.RunOnce(context.Background())
	}()
	close(start) // release both together to maximize contention
	wg.Wait()

	if ensureErr != nil {
		t.Fatalf("EnsureCertForHost: %v", ensureErr)
	}
	if scanErr != nil {
		t.Fatalf("RunOnce: %v", scanErr)
	}
	if got := atomic.LoadInt32(&acme.calls); got != 1 {
		t.Errorf("ObtainViaDNS01 calls = %d, want 1 (create+scan must collapse to a single issuance)", got)
	}
	if got := store.saveCount[host]; got != 1 {
		t.Errorf("SaveRenewed for %s = %d, want 1", host, got)
	}
}

// TestRenewer_RunOnce_firstIssuance_skipsWhenCertAppears isolates the under-lock
// re-check: a first-issuance scan target whose cert already exists on file (a
// concurrent create path issued it before the scan reached this host) must NO-OP
// — TargetForHost returns nil and renewOne re-drives nothing.
func TestRenewer_RunOnce_firstIssuance_skipsWhenCertAppears(t *testing.T) {
	const host = "done.example.com"
	store := newLockStore(newFakeProvider("TXT"))
	store.hasCert[host] = true // cert already on file -> TargetForHost returns nil
	store.due = []RenewTarget{
		{Host: host, Names: []string{host}, Provider: store.provider, FirstIssue: true},
	}
	acme := newBarrierACME(1, &CertResult{CertPEM: []byte("C"), KeyPEM: []byte("K")})
	r := newRenewer(store, acme, nil, nil)

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if got := atomic.LoadInt32(&acme.calls); got != 0 {
		t.Errorf("ObtainViaDNS01 calls = %d, want 0 (first-issuance must skip when cert already on file)", got)
	}
	if got := store.saveCount[host]; got != 0 {
		t.Errorf("SaveRenewed for %s = %d, want 0", host, got)
	}
}

// TestRenewer_RunOnce_renewal_proceedsDespiteCertOnFile guards the safe default:
// a renewal target (FirstIssue=false) has an in-window cert on file by
// definition, and the scan exists precisely to re-issue it. The under-lock
// re-check must NOT collapse it — renewal must always drive ACME even though
// TargetForHost would report a cert present.
func TestRenewer_RunOnce_renewal_proceedsDespiteCertOnFile(t *testing.T) {
	const host = "renew.example.com"
	store := newLockStore(newFakeProvider("TXT"))
	store.hasCert[host] = true // an in-window cert is on file
	store.due = []RenewTarget{
		{Host: host, Names: []string{host}, Provider: store.provider}, // FirstIssue=false
	}
	acme := newBarrierACME(1, &CertResult{CertPEM: []byte("C"), KeyPEM: []byte("K")})
	r := newRenewer(store, acme, nil, nil)

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if got := atomic.LoadInt32(&acme.calls); got != 1 {
		t.Errorf("ObtainViaDNS01 calls = %d, want 1 (renewal must re-issue even with a cert on file)", got)
	}
	if got := store.saveCount[host]; got != 1 {
		t.Errorf("SaveRenewed for %s = %d, want 1", host, got)
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

// flakyACME fails its first failBefore Obtain calls with err, then returns result.
type flakyACME struct {
	failBefore int
	calls      int
	err        error
	result     *CertResult
}

func (f *flakyACME) ObtainViaDNS01(_ context.Context, _ []string, _ DNSSolver) (*CertResult, error) {
	f.calls++
	if f.calls <= f.failBefore {
		return nil, f.err
	}
	return f.result, nil
}

// withFastBackoff shrinks the issuance backoff for the duration of a test and
// restores it afterwards, so retry tests run in milliseconds.
func withFastBackoff(t *testing.T) {
	t.Helper()
	base, max := issueBaseBackoff, issueMaxBackoff
	issueBaseBackoff, issueMaxBackoff = time.Millisecond, 2*time.Millisecond
	t.Cleanup(func() { issueBaseBackoff, issueMaxBackoff = base, max })
}

func TestRenewer_issueWithRetry_succeedsAfterTransientFailures(t *testing.T) {
	withFastBackoff(t)
	fp := newFakeProvider("TXT")
	store := &fakeStore{forHost: map[string]*RenewTarget{
		"flaky.example.com": {Host: "flaky.example.com", Names: []string{"flaky.example.com"}, Provider: fp},
	}}
	acme := &flakyACME{failBefore: 2, err: errors.New("dial tcp 172.65.32.248:443: i/o timeout"),
		result: &CertResult{CertPEM: []byte("OK"), KeyPEM: []byte("K")}}
	r := newRenewer(store, acme, &fakeReloader{}, &fakeAudit{})

	if err := r.EnsureCertForHost(context.Background(), "flaky.example.com"); err != nil {
		t.Fatalf("expected success after transient retries, got %v", err)
	}
	if acme.calls != 3 {
		t.Errorf("ObtainViaDNS01 calls = %d, want 3 (2 transient failures + 1 success)", acme.calls)
	}
	if len(store.saved) != 1 || string(store.saved[0].CertPEM) != "OK" {
		t.Fatalf("cert not saved after retry: %+v", store.saved)
	}
}

func TestRenewer_issueWithRetry_doesNotRetryRateLimit(t *testing.T) {
	withFastBackoff(t)
	fp := newFakeProvider("TXT")
	store := &fakeStore{forHost: map[string]*RenewTarget{
		"rl.example.com": {Host: "rl.example.com", Names: []string{"rl.example.com"}, Provider: fp},
	}}
	acme := &flakyACME{failBefore: 99, err: &RateLimitError{Detail: "too many certificates"}}
	r := newRenewer(store, acme, &fakeReloader{}, &fakeAudit{})

	if err := r.EnsureCertForHost(context.Background(), "rl.example.com"); err == nil {
		t.Fatal("expected rate-limit error to surface")
	}
	if acme.calls != 1 {
		t.Errorf("ObtainViaDNS01 calls = %d, want 1 (rate limit must not be retried)", acme.calls)
	}
}

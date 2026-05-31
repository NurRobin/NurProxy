package tls

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/go-acme/lego/v4/acme"

	"github.com/NurRobin/NurProxy/internal/provider"
)

// fakeProvider is a hand-written provider.Provider that records the TXT records
// the solver creates/deletes. recordTypes drives SupportsTXT.
type fakeProvider struct {
	recordTypes []string

	created   map[string]provider.Record // recordID -> record
	deleted   []string
	createErr error
	nextID    int
}

func newFakeProvider(types ...string) *fakeProvider {
	return &fakeProvider{recordTypes: types, created: map[string]provider.Record{}}
}

func (f *fakeProvider) Info() provider.ProviderInfo {
	return provider.ProviderInfo{ID: "fake", Name: "Fake", RecordTypes: f.recordTypes}
}
func (f *fakeProvider) ConfigSchema() json.RawMessage                         { return nil }
func (f *fakeProvider) ValidateConfig(context.Context, json.RawMessage) error { return nil }
func (f *fakeProvider) ListZones(context.Context, json.RawMessage) ([]provider.Zone, error) {
	return nil, nil
}
func (f *fakeProvider) CreateRecord(_ context.Context, _ json.RawMessage, r provider.Record) (string, error) {
	if f.createErr != nil {
		return "", f.createErr
	}
	f.nextID++
	id := "rec-" + string(rune('0'+f.nextID))
	f.created[id] = r
	return id, nil
}
func (f *fakeProvider) UpdateRecord(context.Context, json.RawMessage, string, provider.Record) error {
	return nil
}
func (f *fakeProvider) DeleteRecord(_ context.Context, _ json.RawMessage, id string) error {
	f.deleted = append(f.deleted, id)
	delete(f.created, id)
	return nil
}
func (f *fakeProvider) GetRecord(context.Context, json.RawMessage, string) (*provider.Record, error) {
	return nil, nil
}
func (f *fakeProvider) ListRecords(context.Context, json.RawMessage, string, string) ([]provider.Record, error) {
	return nil, nil
}

// fakeACME is a hand-written ACMEClient seam. It drives the solver (to exercise
// TXT present/cleanup), then returns canned material or a canned error.
type fakeACME struct {
	result    *CertResult
	err       error
	exercise  bool // call solver.Present/CleanUp during the order
	gotNames  []string
	presented bool
	cleanedUp bool
}

func (f *fakeACME) ObtainViaDNS01(ctx context.Context, names []string, solver DNSSolver) (*CertResult, error) {
	f.gotNames = names
	if f.exercise {
		for _, n := range names {
			fqdn := "_acme-challenge." + strings.TrimPrefix(n, "*.") + "."
			if err := solver.Present(ctx, fqdn, "tok-"+n); err != nil {
				return nil, err
			}
			f.presented = true
		}
		for _, n := range names {
			fqdn := "_acme-challenge." + strings.TrimPrefix(n, "*.") + "."
			if err := solver.CleanUp(ctx, fqdn, "tok-"+n); err != nil {
				return nil, err
			}
			f.cleanedUp = true
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

func TestIssuer_Issue_dns01_success(t *testing.T) {
	fp := newFakeProvider("A", "AAAA", "CNAME", "TXT")
	fa := &fakeACME{
		exercise: true,
		result:   &CertResult{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")},
	}
	iss := NewIssuer(fa, nil)

	res, err := iss.Issue(context.Background(), IssueRequest{Host: "app.example.com"}, fp, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if res.Host != "app.example.com" {
		t.Errorf("host = %q, want app.example.com", res.Host)
	}
	if string(res.CertPEM) != "CERT" || string(res.KeyPEM) != "KEY" {
		t.Errorf("unexpected material: cert=%q key=%q", res.CertPEM, res.KeyPEM)
	}
	if len(res.Names) != 1 || res.Names[0] != "app.example.com" {
		t.Errorf("names = %v, want [app.example.com]", res.Names)
	}
	if !fa.presented || !fa.cleanedUp {
		t.Errorf("solver not driven: presented=%v cleanedUp=%v", fa.presented, fa.cleanedUp)
	}
	// The TXT record was created then deleted (no leftovers).
	if len(fp.created) != 0 {
		t.Errorf("leftover TXT records: %v", fp.created)
	}
	if len(fp.deleted) != 1 {
		t.Errorf("expected exactly 1 TXT cleanup, got %d", len(fp.deleted))
	}
}

func TestIssuer_Issue_noTXTSupport_fallsBack(t *testing.T) {
	fp := newFakeProvider("A", "AAAA", "CNAME") // no TXT
	fa := &fakeACME{result: &CertResult{CertPEM: []byte("X")}}
	iss := NewIssuer(fa, nil)

	_, err := iss.Issue(context.Background(), IssueRequest{Host: "app.example.com"}, fp, nil)
	if !errors.Is(err, ErrNoTXTSupport) {
		t.Fatalf("err = %v, want ErrNoTXTSupport", err)
	}
	if fa.gotNames != nil {
		t.Errorf("ACME client should not be called when TXT unsupported, got names=%v", fa.gotNames)
	}
}

func TestIssuer_Issue_rateLimited_surfacesUnblockLink(t *testing.T) {
	fp := newFakeProvider("TXT")
	fa := &fakeACME{
		err: &acme.ProblemDetails{
			HTTPStatus: 429,
			Type:       acme.RateLimitedErr,
			Detail:     "too many certificates already issued",
			Instance:   "https://letsencrypt.org/unblock/abc123",
		},
	}
	iss := NewIssuer(fa, nil)

	_, err := iss.Issue(context.Background(), IssueRequest{Host: "app.example.com"}, fp, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("err = %v, want *RateLimitError", err)
	}
	if rl.UnblockURL != "https://letsencrypt.org/unblock/abc123" {
		t.Errorf("unblock url = %q", rl.UnblockURL)
	}
	if !strings.Contains(rl.Error(), "unblock:") {
		t.Errorf("error string should include unblock link: %q", rl.Error())
	}
}

func TestIssuer_Issue_wildcard_namesPrefixed(t *testing.T) {
	fp := newFakeProvider("TXT")
	fa := &fakeACME{result: &CertResult{CertPEM: []byte("C")}}
	iss := NewIssuer(fa, nil)

	res, err := iss.Issue(context.Background(), IssueRequest{Host: "example.com", Wildcard: true}, fp, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(res.Names) != 1 || res.Names[0] != "*.example.com" {
		t.Errorf("names = %v, want [*.example.com]", res.Names)
	}
}

func TestIssuer_Issue_withSANs_batchesNames(t *testing.T) {
	fp := newFakeProvider("TXT")
	fa := &fakeACME{result: &CertResult{CertPEM: []byte("C")}}
	iss := NewIssuer(fa, nil)

	req := IssueRequest{Host: "a.example.com", SANs: []string{"b.example.com", "c.example.com"}}
	res, err := iss.Issue(context.Background(), req, fp, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	want := []string{"a.example.com", "b.example.com", "c.example.com"}
	if len(res.Names) != 3 {
		t.Fatalf("names = %v, want %v", res.Names, want)
	}
	for i := range want {
		if res.Names[i] != want[i] {
			t.Errorf("names[%d] = %q, want %q", i, res.Names[i], want[i])
		}
	}
}

func TestIssuer_Issue_emptyHost_errors(t *testing.T) {
	iss := NewIssuer(&fakeACME{}, nil)
	if _, err := iss.Issue(context.Background(), IssueRequest{}, newFakeProvider("TXT"), nil); err == nil {
		t.Fatal("expected error for empty host")
	}
}

// lightweightRateLimitErr exercises the non-lego rate-limit classification path
// (a fake that does not import lego's concrete problem type).
type lightweightRateLimitErr struct{}

func (lightweightRateLimitErr) Error() string           { return "rate limited" }
func (lightweightRateLimitErr) IsRateLimited() bool     { return true }
func (lightweightRateLimitErr) UnblockLink() string     { return "https://example.test/unblock" }
func (lightweightRateLimitErr) RateLimitDetail() string { return "slow down" }

func TestIssuer_Issue_rateLimited_lightweightInterface(t *testing.T) {
	fp := newFakeProvider("TXT")
	fa := &fakeACME{err: lightweightRateLimitErr{}}
	iss := NewIssuer(fa, nil)

	_, err := iss.Issue(context.Background(), IssueRequest{Host: "app.example.com"}, fp, nil)
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("err = %v, want *RateLimitError", err)
	}
	if rl.UnblockURL != "https://example.test/unblock" {
		t.Errorf("unblock url = %q", rl.UnblockURL)
	}
}

func TestClassifyACMEError_nonRateLimit_passthrough(t *testing.T) {
	orig := &acme.ProblemDetails{HTTPStatus: 400, Type: "urn:ietf:params:acme:error:malformed", Detail: "bad"}
	got := classifyACMEError(orig)
	var rl *RateLimitError
	if errors.As(got, &rl) {
		t.Fatalf("non-429 should not classify as rate limit")
	}
	if got != error(orig) {
		t.Errorf("expected original error passthrough")
	}
}

func TestClassifyACMEError_nil(t *testing.T) {
	if classifyACMEError(nil) != nil {
		t.Error("nil should classify to nil")
	}
}

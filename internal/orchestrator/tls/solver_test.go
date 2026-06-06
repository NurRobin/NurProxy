package tls

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/NurRobin/NurProxy/internal/provider"
)

// recordingProvider is a fake provider.Provider that keeps every record it is
// asked to create, so a test can assert the exact owner name and type of the
// DNS-01 challenge record (and that pre-existing records are left untouched).
type recordingProvider struct {
	records map[string]provider.Record // id -> record
	next    int
	// rejectIdenticalTXT makes CreateRecord fail with a duplicate error when a TXT
	// with the same name+content already exists, mimicking Cloudflare error 81058.
	rejectIdenticalTXT bool
}

func newRecordingProvider() *recordingProvider {
	return &recordingProvider{records: map[string]provider.Record{}}
}

// seed inserts a pre-existing record (e.g. the host's CNAME) so the test can
// prove the challenge does not collide with or overwrite it.
func (p *recordingProvider) seed(r provider.Record) string {
	p.next++
	id := "seed-" + string(rune('a'+p.next))
	p.records[id] = r
	return id
}

func (p *recordingProvider) Info() provider.ProviderInfo {
	return provider.ProviderInfo{ID: "rec", Name: "Recording", RecordTypes: []string{"A", "CNAME", "TXT"}}
}
func (p *recordingProvider) ConfigSchema() json.RawMessage                         { return nil }
func (p *recordingProvider) ValidateConfig(context.Context, json.RawMessage) error { return nil }
func (p *recordingProvider) ListZones(context.Context, json.RawMessage) ([]provider.Zone, error) {
	return nil, nil
}
func (p *recordingProvider) CreateRecord(_ context.Context, _ json.RawMessage, r provider.Record) (string, error) {
	if p.rejectIdenticalTXT && r.Type == "TXT" {
		for _, ex := range p.records {
			if ex.Type == "TXT" && strings.EqualFold(ex.Name, r.Name) && ex.Content == r.Content {
				return "", errors.New("provider: [81058] An identical record already exists")
			}
		}
	}
	p.next++
	id := "rec-" + string(rune('A'+p.next))
	p.records[id] = r
	return id, nil
}
func (p *recordingProvider) UpdateRecord(_ context.Context, _ json.RawMessage, id string, r provider.Record) error {
	p.records[id] = r
	return nil
}
func (p *recordingProvider) DeleteRecord(_ context.Context, _ json.RawMessage, id string) error {
	delete(p.records, id)
	return nil
}
func (p *recordingProvider) GetRecord(_ context.Context, _ json.RawMessage, id string) (*provider.Record, error) {
	r, ok := p.records[id]
	if !ok {
		return nil, nil
	}
	return &r, nil
}

func (p *recordingProvider) ListRecords(_ context.Context, _ json.RawMessage, name, recordType string) ([]provider.Record, error) {
	var out []provider.Record
	for id, r := range p.records {
		if name != "" && !strings.EqualFold(r.Name, name) {
			continue
		}
		if recordType != "" && !strings.EqualFold(r.Type, recordType) {
			continue
		}
		r.ID = id
		out = append(out, r)
	}
	return out, nil
}

// TestProviderSolver_dns01_challengeOwnerIsAcmeChallenge_notCNAME proves the
// CNAME interaction the spec (§7) requires us to verify:
//
//	api.example.com is a CNAME to the agent FQDN. The DNS-01 challenge does NOT
//	touch that CNAME — it creates a TXT at the DISTINCT owner name
//	_acme-challenge.api.example.com. Because owner names differ, the two records
//	coexist (there is no "CNAME and other data" conflict at api.example.com
//	itself). Let's Encrypt looks up _acme-challenge.api.example.com; if that name
//	is itself delegated via a challenge CNAME, LE follows it — but the owner name
//	we create the TXT under is always _acme-challenge.<host>, never <host>.
//
// The assertion is precisely that: the record the solver creates is a TXT whose
// owner is _acme-challenge.<host>, and the pre-existing <host> CNAME is left
// exactly as seeded.
func TestProviderSolver_dns01_challengeOwnerIsAcmeChallenge_notCNAME(t *testing.T) {
	const host = "api.example.com"
	const agentFQDN = "agent-1.nodes.example.net"

	p := newRecordingProvider()
	cnameID := p.seed(provider.Record{Type: "CNAME", Name: host, Content: agentFQDN, TTL: 0})

	s := &providerSolver{provider: p, createdID: map[string]string{}}

	// Drive the solver exactly as the real lego challenge.Provider path does:
	// compute the challenge FQDN/value with lego's helper, then Present it.
	info := dns01.GetChallengeInfo(host, "the-key-authorization-token")
	if err := s.legoPresent(host, "tok", "the-key-authorization-token"); err != nil {
		t.Fatalf("legoPresent: %v", err)
	}

	// The challenge owner name lego computes must be _acme-challenge.<host> — a
	// different owner than the CNAME at <host>.
	wantOwner := "_acme-challenge." + host + "."
	if info.FQDN != wantOwner {
		t.Fatalf("challenge FQDN = %q, want %q", info.FQDN, wantOwner)
	}

	// Find the record the solver created.
	var challenge *provider.Record
	for id, r := range p.records {
		if id == cnameID {
			continue
		}
		rec := r
		challenge = &rec
	}
	if challenge == nil {
		t.Fatal("solver created no challenge record")
	}

	if challenge.Type != "TXT" {
		t.Errorf("challenge record type = %q, want TXT", challenge.Type)
	}
	// The owner name must be _acme-challenge.<host> (lego returns it with a
	// trailing dot; the solver trims that for the provider call).
	if challenge.Name != "_acme-challenge."+host {
		t.Errorf("challenge owner = %q, want %q (must NOT be the host/CNAME owner %q)",
			challenge.Name, "_acme-challenge."+host, host)
	}
	if challenge.Name == host {
		t.Fatalf("challenge was created at the CNAME owner %q — would collide with the CNAME", host)
	}

	// The pre-existing CNAME at <host> is untouched: same owner, same target,
	// still a CNAME. The challenge coexists at the distinct _acme-challenge owner.
	cn, ok := p.records[cnameID]
	if !ok {
		t.Fatal("pre-existing CNAME was deleted by the challenge")
	}
	if cn.Type != "CNAME" || cn.Name != host || cn.Content != agentFQDN {
		t.Errorf("CNAME mutated: %+v", cn)
	}

	// CleanUp removes only the challenge TXT, leaving the CNAME intact.
	if err := s.legoCleanUp(host, "tok", "the-key-authorization-token"); err != nil {
		t.Fatalf("legoCleanUp: %v", err)
	}
	if _, ok := p.records[cnameID]; !ok {
		t.Error("CleanUp deleted the CNAME")
	}
	for id, r := range p.records {
		if id != cnameID && r.Type == "TXT" {
			t.Errorf("CleanUp left a challenge TXT behind: %+v", r)
		}
	}
}

// TestProviderSolver_Present_idempotentOnDuplicate proves the #82 fix: when a
// prior attempt left an identical _acme-challenge TXT behind (so the provider
// rejects the re-create as a duplicate), Present adopts the existing record
// instead of failing — and CleanUp then removes it, leaving no leak.
func TestProviderSolver_Present_idempotentOnDuplicate(t *testing.T) {
	p := newRecordingProvider()
	p.rejectIdenticalTXT = true
	const fqdn = "_acme-challenge.app.example.com."
	const value = "tok-abc123"
	// Seed a leftover identical challenge TXT from a "prior failed attempt".
	leakedID := p.seed(provider.Record{Type: "TXT", Name: strings.TrimSuffix(fqdn, "."), Content: value})

	s := &providerSolver{provider: p, createdID: map[string]string{}}

	if err := s.Present(context.Background(), fqdn, value); err != nil {
		t.Fatalf("Present should adopt the existing duplicate, got error: %v", err)
	}
	// The adopted record id must be tracked so CleanUp can remove it.
	if got := s.createdID[challengeKey(fqdn, value)]; got != leakedID {
		t.Fatalf("adopted record id = %q, want the leaked record %q", got, leakedID)
	}
	if err := s.CleanUp(context.Background(), fqdn, value); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	// No challenge TXT must remain.
	recs, _ := p.ListRecords(context.Background(), nil, strings.TrimSuffix(fqdn, "."), "TXT")
	if len(recs) != 0 {
		t.Fatalf("challenge TXT leaked after CleanUp: %+v", recs)
	}
}

// TestProviderSolver_Present_surfacesNonDuplicateErrors proves Present does not
// swallow a genuine create failure (no adoptable record exists).
func TestProviderSolver_Present_surfacesNonDuplicateErrors(t *testing.T) {
	p := newRecordingProvider()
	p.rejectIdenticalTXT = true // will only reject if an identical exists — none does here
	// Force a hard create error unrelated to duplicates by making the provider
	// reject everything via a wrapper.
	fp := &alwaysFailCreate{recordingProvider: p}
	s := &providerSolver{provider: fp, createdID: map[string]string{}}
	if err := s.Present(context.Background(), "_acme-challenge.x.example.com.", "v"); err == nil {
		t.Fatal("expected Present to surface a non-duplicate create error")
	}
}

type alwaysFailCreate struct{ *recordingProvider }

func (a *alwaysFailCreate) CreateRecord(context.Context, json.RawMessage, provider.Record) (string, error) {
	return "", errors.New("provider: boom")
}

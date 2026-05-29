package tls

import (
	"context"
	"encoding/json"
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

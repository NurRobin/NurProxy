package db

import (
	"errors"
	"testing"

	_ "github.com/NurRobin/NurProxy/internal/provider/cloudflare" // registers "cloudflare"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// TestValidateDomainProxied covers who may ask for a proxied record: only a
// served domain in a zone whose provider supports proxying.
func TestValidateDomainProxied(t *testing.T) {
	d := testDB(t)
	cf := createTestProvider(t, d) // type cloudflare
	cfZone := createTestZone(t, d, cf.ID)
	other := &models.Provider{ID: "prov-2", Type: "otherdns", Name: "Other", Config: `{}`}
	if err := d.CreateProvider(other); err != nil {
		t.Fatalf("CreateProvider: %v", err)
	}
	otherZone := &models.Zone{ID: "zone-2", ProviderID: other.ID, ExternalID: "ext-2", Name: "other.test"}
	if err := d.CreateZone(otherZone); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}

	yes, no := true, false
	tests := []struct {
		name     string
		zoneID   string
		certOnly bool
		proxied  *bool
		wantErr  bool
	}{
		{"unset on cloudflare", cfZone.ID, false, nil, false},
		{"true on cloudflare", cfZone.ID, false, &yes, false},
		{"false on cloudflare", cfZone.ID, false, &no, false},
		{"unset on other provider", otherZone.ID, false, nil, false},
		{"false on other provider", otherZone.ID, false, &no, false},
		{"true on other provider rejected", otherZone.ID, false, &yes, true},
		{"true on cert-only rejected", cfZone.ID, true, &yes, true},
		{"false on cert-only", cfZone.ID, true, &no, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := d.ValidateDomainProxied(tc.zoneID, tc.certOnly, tc.proxied)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, ErrProxiedUnsupported) {
				t.Fatalf("err = %v, want ErrProxiedUnsupported", err)
			}
		})
	}
}

// TestDomainProxiedRoundTrip asserts the tri-state proxied setting survives
// create, read, list and update, including going back to "not set" (#126).
func TestDomainProxiedRoundTrip(t *testing.T) {
	yes, no := true, false
	tests := []struct {
		name   string
		create *bool
		update *bool
	}{
		{"unset stays unset", nil, nil},
		{"true then false", &yes, &no},
		{"false then unset", &no, nil},
		{"unset then true", nil, &yes},
	}
	same := func(a, b *bool) bool {
		if a == nil || b == nil {
			return a == b
		}
		return *a == *b
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := testDB(t)
			p := createTestProvider(t, d)
			z := createTestZone(t, d, p.ID)
			a := createTestAgent(t, d)
			s := createTestServer(t, d, a.ID)
			dom := &models.Domain{
				Subdomain: "app", ZoneID: z.ID, ServerID: s.ID, Port: 8080,
				SSLMode: models.SSLModeAuto, Status: models.DomainStatusPending,
				Proxied: tc.create,
			}
			if err := d.CreateDomain(dom); err != nil {
				t.Fatalf("CreateDomain: %v", err)
			}
			got, err := d.GetDomain(dom.ID)
			if err != nil {
				t.Fatalf("GetDomain: %v", err)
			}
			if !same(got.Proxied, tc.create) {
				t.Fatalf("after create proxied = %v, want %v", got.Proxied, tc.create)
			}
			got.Proxied = tc.update
			if err := d.UpdateDomain(got); err != nil {
				t.Fatalf("UpdateDomain: %v", err)
			}
			list, err := d.ListDomainsByAgent(a.ID)
			if err != nil || len(list) != 1 {
				t.Fatalf("ListDomainsByAgent = %d rows, err %v", len(list), err)
			}
			if !same(list[0].Proxied, tc.update) {
				t.Fatalf("after update proxied = %v, want %v", list[0].Proxied, tc.update)
			}
		})
	}
}

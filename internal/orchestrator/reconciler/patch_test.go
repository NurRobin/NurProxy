package reconciler

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/provider"
)

// patchingDNSProvider is the mock provider plus PatchRecord, recording every
// patch and every full overwrite so tests can check which one was used.
type patchingDNSProvider struct {
	*mockDNSProvider
	pmu     sync.Mutex
	patches []provider.RecordPatch
	updates int
}

func (p *patchingDNSProvider) UpdateRecord(ctx context.Context, cfg json.RawMessage, id string, rec provider.Record) error {
	p.pmu.Lock()
	p.updates++
	p.pmu.Unlock()
	return p.mockDNSProvider.UpdateRecord(ctx, cfg, id, rec)
}

func (p *patchingDNSProvider) PatchRecord(_ context.Context, _ json.RawMessage, id string, patch provider.RecordPatch) error {
	p.pmu.Lock()
	p.patches = append(p.patches, patch)
	p.pmu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	rec := p.records[id]
	if patch.Content != nil {
		rec.Content = *patch.Content
	}
	if patch.Proxied != nil {
		rec.Proxied = *patch.Proxied
	}
	p.records[id] = rec
	return nil
}

// TestReconcileDNS_patchesOnlyDriftedFields: with a provider that can patch,
// the reconciler never overwrites the whole record and sends only the fields
// that drifted, so Cloudflare keeps comments, tags and settings.
func TestReconcileDNS_patchesOnlyDriftedFields(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		existing    bool
		setting     *bool
		wantContent bool // patch carries content
		wantProxied bool // patch carries proxied
	}{
		{"proxy only", "agent1.example.com", true, boolp(false), false, true},
		{"target only", "old.example.net", true, nil, true, false},
		{"target and proxy", "old.example.net", false, boolp(true), true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mp := &patchingDNSProvider{mockDNSProvider: newMockDNSProvider()}
			provider.Register(mp)
			d := testDB(t)
			_, _, _, _, dom := setupScenario(t, d)
			dom.Proxied = tc.setting
			if err := d.UpdateDomain(dom); err != nil {
				t.Fatal(err)
			}
			id := mp.seedRecord(provider.Record{Type: "CNAME", Name: "app.example.com", Content: tc.content, Proxied: tc.existing})
			if err := d.UpdateDomainDNSRecord(dom.ID, id, true); err != nil {
				t.Fatal(err)
			}
			r := New(d, newMockAgentClient(), time.Minute)
			if err := r.reconcileDNS(context.Background()); err != nil {
				t.Fatal(err)
			}
			if mp.updates != 0 {
				t.Errorf("UpdateRecord (full overwrite) called %d times, want 0", mp.updates)
			}
			if len(mp.patches) != 1 {
				t.Fatalf("PatchRecord called %d times, want 1", len(mp.patches))
			}
			p := mp.patches[0]
			if (p.Content != nil) != tc.wantContent || (p.Proxied != nil) != tc.wantProxied {
				t.Errorf("patch = content:%v proxied:%v, want content:%v proxied:%v", p.Content != nil, p.Proxied != nil, tc.wantContent, tc.wantProxied)
			}
			rec, _ := mp.getRecord(id)
			if rec.Content != "agent1.example.com" {
				t.Errorf("content = %s after patch", rec.Content)
			}
		})
	}
}

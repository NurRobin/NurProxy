package reconciler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/orchestrator/tls"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

const testWildcardHost = "*.example.com"

func TestSelectDomainCert(t *testing.T) {
	now := time.Now()
	acmeOwn := &models.Certificate{Host: "app.example.com", Source: models.CertSourceACME}
	importedFresh := &models.Certificate{Host: "app.example.com", Source: models.CertSourceImported, ExpiresAt: now.Add(60 * 24 * time.Hour)}
	importedDue := &models.Certificate{Host: "app.example.com", Source: models.CertSourceImported, ExpiresAt: now.Add(5 * 24 * time.Hour)}
	wild := &models.Certificate{Host: testWildcardHost, IsWildcard: true, Source: models.CertSourceACME}

	tests := []struct {
		name          string
		own, wildcard *models.Certificate
		want          *models.Certificate
	}{
		{"wildcard only", nil, wild, wild},
		{"wildcard beats a leftover per-host ACME cert", acmeOwn, wild, wild},
		{"leftover per-host cert bridges until the wildcard is issued", acmeOwn, nil, acmeOwn},
		{"imported cert overrides the wildcard", importedFresh, wild, importedFresh},
		{"imported cert inside the renew window yields to the wildcard", importedDue, wild, wild},
		{"imported cert inside the renew window kept without a wildcard", importedDue, nil, importedDue},
		{"nothing stored", nil, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := selectDomainCert(tt.own, tt.wildcard, now); got != tt.want {
				t.Fatalf("selectDomainCert = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// wildcardScenario is setupScenario plus a second domain, with app and api both
// opted into the zone wildcard cert and a third, per-host domain "plain".
func wildcardScenario(t *testing.T, d *db.DB) (agent *models.Agent, app, api, plain *models.Domain) {
	t.Helper()
	_, zone, agent, srv, app := setupScenario(t, d)
	app.ProxyConfig.TLSWildcard = true
	if err := d.UpdateDomain(app); err != nil {
		t.Fatalf("UpdateDomain: %v", err)
	}
	api = &models.Domain{Subdomain: "api", ZoneID: zone.ID, ServerID: srv.ID, Port: 8081, SSLMode: models.SSLModeAuto,
		Status: models.DomainStatusPending, ProxyConfig: models.ProxyConfig{TLSWildcard: true}}
	plain = &models.Domain{Subdomain: "plain", ZoneID: zone.ID, ServerID: srv.ID, Port: 8082, SSLMode: models.SSLModeAuto,
		Status: models.DomainStatusPending}
	for _, dom := range []*models.Domain{api, plain} {
		if err := d.CreateDomain(dom); err != nil {
			t.Fatalf("CreateDomain: %v", err)
		}
	}
	return agent, app, api, plain
}

func upsertCert(t *testing.T, d *db.DB, c models.Certificate) {
	t.Helper()
	if err := d.UpsertCertificate(&c); err != nil {
		t.Fatalf("UpsertCertificate %s: %v", c.Host, err)
	}
}

// TestGatherCertsWildcardFallback: both wildcard domains get the shared
// "*.example.com" cert, each bundle keyed by its own FQDN; the per-host domain
// keeps its own cert; an imported cert overrides the wildcard for its host.
func TestGatherCertsWildcardFallback(t *testing.T) {
	d := testDB(t)
	agent, _, _, _ := wildcardScenario(t, d)
	r := New(d, newMockAgentClient(), time.Minute)

	upsertCert(t, d, models.Certificate{ID: testWildcardHost, Host: testWildcardHost, Names: []string{testWildcardHost}, IsWildcard: true, CertPEM: "WILD", KeyPEM: "WK"})
	upsertCert(t, d, models.Certificate{ID: "plain.example.com", Host: "plain.example.com", Names: []string{"plain.example.com"}, CertPEM: "PLAIN", KeyPEM: "PK"})

	gather := func() map[string]string {
		t.Helper()
		desired, _, err := r.buildDesiredRoutes(agent)
		if err != nil {
			t.Fatalf("buildDesiredRoutes: %v", err)
		}
		set := r.intentSetFor(agent, desired, nil)
		got := make(map[string]string)
		for _, b := range set.Certs {
			got[b.Host] = b.CertPEM
		}
		return got
	}

	got := gather()
	want := map[string]string{"app.example.com": "WILD", "api.example.com": "WILD", "plain.example.com": "PLAIN"}
	if len(got) != len(want) {
		t.Fatalf("bundles = %v, want %v", got, want)
	}
	for host, pem := range want {
		if got[host] != pem {
			t.Fatalf("bundle %s = %q, want %q (all: %v)", host, got[host], pem, got)
		}
	}

	upsertCert(t, d, models.Certificate{ID: "api.example.com", Host: "api.example.com", Names: []string{"api.example.com"},
		CertPEM: "IMPORTED", KeyPEM: "IK", Source: models.CertSourceImported, ExpiresAt: time.Now().Add(80 * 24 * time.Hour)})
	if got := gather(); got["api.example.com"] != "IMPORTED" || got["app.example.com"] != "WILD" {
		t.Fatalf("after import: bundles = %v, want api IMPORTED and app WILD", got)
	}
}

// TestDueForRenewalWildcardDedup: two wildcard domains of a zone produce one
// "*.example.com" first-issuance target and no per-host targets; once the
// shared cert is due it is renewed once, and a per-host cert left over from a
// wildcard domain is not renewed.
func TestDueForRenewalWildcardDedup(t *testing.T) {
	registerMockProvider(t)
	d := testDB(t)
	wildcardScenario(t, d)
	upsertCert(t, d, models.Certificate{ID: "plain.example.com", Host: "plain.example.com", Names: []string{"plain.example.com"},
		CertPEM: "P", KeyPEM: "K", ExpiresAt: time.Now().Add(80 * 24 * time.Hour)})
	store := NewCertRenewalStore(d)

	targets, err := store.DueForRenewal(context.Background(), tls.DefaultRenewWindow)
	if err != nil {
		t.Fatalf("DueForRenewal: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("targets = %+v, want exactly one shared wildcard target", targets)
	}
	tg := targets[0]
	if tg.Host != testWildcardHost || !tg.IsWildcard || !tg.FirstIssue || len(tg.Names) != 1 || tg.Names[0] != testWildcardHost {
		t.Fatalf("target = %+v, want first issuance of %s", tg, testWildcardHost)
	}

	soon := time.Now().Add(24 * time.Hour)
	upsertCert(t, d, models.Certificate{ID: testWildcardHost, Host: testWildcardHost, Names: []string{testWildcardHost}, IsWildcard: true, CertPEM: "W", KeyPEM: "K", ExpiresAt: soon})
	upsertCert(t, d, models.Certificate{ID: "app.example.com", Host: "app.example.com", Names: []string{"app.example.com"}, CertPEM: "OLD", KeyPEM: "K", ExpiresAt: soon})
	targets, err = store.DueForRenewal(context.Background(), tls.DefaultRenewWindow)
	if err != nil {
		t.Fatalf("DueForRenewal: %v", err)
	}
	if len(targets) != 1 || targets[0].Host != testWildcardHost || targets[0].FirstIssue || targets[0].PriorCertPEM != "W" {
		t.Fatalf("targets = %+v, want one renewal of %s", targets, testWildcardHost)
	}
}

// TestDueForRenewalUnusedWildcardSkipped: a zone wildcard cert nobody opts into
// is not renewed even though central domains sit below the zone.
func TestDueForRenewalUnusedWildcardSkipped(t *testing.T) {
	registerMockProvider(t)
	d := testDB(t)
	setupScenario(t, d) // app.example.com, central, no opt-in
	upsertCert(t, d, models.Certificate{ID: "app.example.com", Host: "app.example.com", Names: []string{"app.example.com"}, CertPEM: "A", KeyPEM: "K", ExpiresAt: time.Now().Add(80 * 24 * time.Hour)})
	upsertCert(t, d, models.Certificate{ID: testWildcardHost, Host: testWildcardHost, Names: []string{testWildcardHost}, IsWildcard: true, CertPEM: "W", KeyPEM: "K", ExpiresAt: time.Now().Add(24 * time.Hour)})
	targets, err := NewCertRenewalStore(d).DueForRenewal(context.Background(), tls.DefaultRenewWindow)
	if err != nil {
		t.Fatalf("DueForRenewal: %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("targets = %+v, want none", targets)
	}
}

// TestTargetForHostWildcard: the on-demand path issues the shared cert for
// "*.<zone>" and refuses a per-host order for a host the wildcard serves.
func TestTargetForHostWildcard(t *testing.T) {
	registerMockProvider(t)
	d := testDB(t)
	wildcardScenario(t, d)
	store := NewCertRenewalStore(d)
	ctx := context.Background()

	tg, err := store.TargetForHost(ctx, testWildcardHost)
	if err != nil || tg == nil || !tg.IsWildcard || tg.Host != testWildcardHost {
		t.Fatalf("TargetForHost(%s) = %+v, %v; want a wildcard target", testWildcardHost, tg, err)
	}
	if tg, err := store.TargetForHost(ctx, "app.example.com"); err != nil || tg != nil {
		t.Fatalf("TargetForHost(app) = %+v, %v; want nil (served by the wildcard)", tg, err)
	}
	if tg, err := store.TargetForHost(ctx, "plain.example.com"); err != nil || tg == nil || tg.IsWildcard {
		t.Fatalf("TargetForHost(plain) = %+v, %v; want a per-host target", tg, err)
	}

	upsertCert(t, d, models.Certificate{ID: testWildcardHost, Host: testWildcardHost, Names: []string{testWildcardHost}, IsWildcard: true, CertPEM: "W", KeyPEM: "K"})
	if tg, err := store.TargetForHost(ctx, testWildcardHost); err != nil || tg != nil {
		t.Fatalf("TargetForHost(%s) with cert on file = %+v, %v; want nil", testWildcardHost, tg, err)
	}
}

// TestSaveRenewedWildcard stores the shared cert under "*.<zone>", flagged as a
// wildcard, so it never overwrites the apex domain's per-host cert.
func TestSaveRenewedWildcard(t *testing.T) {
	d := testDB(t)
	setupScenario(t, d)
	upsertCert(t, d, models.Certificate{ID: "example.com", Host: "example.com", Names: []string{"example.com"}, CertPEM: "APEX", KeyPEM: "K"})
	store := NewCertRenewalStore(d)
	res := &tls.CertResult{Host: testWildcardHost, Names: []string{testWildcardHost}, CertPEM: []byte("W"), KeyPEM: []byte("K")}
	if err := store.SaveRenewed(context.Background(), res, tls.RenewTarget{Host: testWildcardHost, IsWildcard: true}); err != nil {
		t.Fatalf("SaveRenewed: %v", err)
	}
	wild, err := d.GetCertificate(testWildcardHost)
	if err != nil || !wild.IsWildcard || wild.CertPEM != "W" {
		t.Fatalf("wildcard row = %+v, %v", wild, err)
	}
	if apex, err := d.GetCertificate("example.com"); err != nil || apex.CertPEM != "APEX" {
		t.Fatalf("apex row = %+v, %v; want it untouched", apex, err)
	}
}

// TestPruneUnusedWildcardCerts: the shared cert stays while any domain of the
// zone opts in and is deleted once the last one opts out or is being deleted.
// Per-host and imported certs are never touched by this sweep.
func TestPruneUnusedWildcardCerts(t *testing.T) {
	d := testDB(t)
	_, app, api, _ := wildcardScenario(t, d)
	r := New(d, newMockAgentClient(), time.Minute)
	upsertCert(t, d, models.Certificate{ID: testWildcardHost, Host: testWildcardHost, Names: []string{testWildcardHost}, IsWildcard: true, CertPEM: "W", KeyPEM: "K"})
	upsertCert(t, d, models.Certificate{ID: "plain.example.com", Host: "plain.example.com", Names: []string{"plain.example.com"}, CertPEM: "P", KeyPEM: "K"})

	exists := func() bool {
		t.Helper()
		_, err := d.GetCertificate(testWildcardHost)
		if err != nil && !errors.Is(err, db.ErrCertNotFound) {
			t.Fatalf("GetCertificate: %v", err)
		}
		return err == nil
	}

	r.pruneUnusedWildcardCerts()
	if !exists() {
		t.Fatal("wildcard cert pruned while two domains use it")
	}

	app.ProxyConfig.TLSWildcard = false
	if err := d.UpdateDomain(app); err != nil {
		t.Fatalf("UpdateDomain: %v", err)
	}
	r.pruneUnusedWildcardCerts()
	if !exists() {
		t.Fatal("wildcard cert pruned while api still uses it")
	}

	if err := d.UpdateDomainStatus(api.ID, models.DomainStatusDeleting, ""); err != nil {
		t.Fatalf("UpdateDomainStatus: %v", err)
	}
	r.pruneUnusedWildcardCerts()
	if exists() {
		t.Fatal("wildcard cert kept after its last consumer went away")
	}
	if _, err := d.GetCertificate("plain.example.com"); err != nil {
		t.Fatalf("per-host cert touched by the wildcard sweep: %v", err)
	}
}

// TestAgentsUsingWildcard resolves the agents a renewed wildcard is re-pushed to.
func TestAgentsUsingWildcard(t *testing.T) {
	d := testDB(t)
	agent, _, _, _ := wildcardScenario(t, d)
	r := New(d, newMockAgentClient(), time.Minute)
	got, err := r.agentsUsingWildcard(testWildcardHost)
	if err != nil || len(got) != 1 || got[0] != agent.ID {
		t.Fatalf("agentsUsingWildcard = %v, %v; want [%s]", got, err, agent.ID)
	}
	if got, err := r.agentsUsingWildcard("*.other.com"); err != nil || len(got) != 0 {
		t.Fatalf("agentsUsingWildcard(other) = %v, %v; want none", got, err)
	}
}

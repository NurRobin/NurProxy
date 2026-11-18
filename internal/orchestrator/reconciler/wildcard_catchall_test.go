package reconciler

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/orchestrator/tls"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// A catch-all domain (subdomain "*") has the FQDN "*.<zone>", the same store key
// as the zone wildcard cert of opted-in domains. These tests pin that both kinds
// of domains share that one cert and that neither side's cleanup removes it from
// under the other.

func createCatchAll(t *testing.T, d *db.DB, zoneID, serverID string) *models.Domain {
	t.Helper()
	dom := &models.Domain{Subdomain: "*", ZoneID: zoneID, ServerID: serverID, Port: 8090,
		SSLMode: models.SSLModeAuto, Status: models.DomainStatusPending}
	if err := d.CreateDomain(dom); err != nil {
		t.Fatalf("CreateDomain(*): %v", err)
	}
	return dom
}

func certExists(t *testing.T, d *db.DB, host string) bool {
	t.Helper()
	_, err := d.GetCertificate(host)
	if err != nil && !errors.Is(err, db.ErrCertNotFound) {
		t.Fatalf("GetCertificate(%s): %v", host, err)
	}
	return err == nil
}

func storeIssued(t *testing.T, d *db.DB, host string, expires time.Time) {
	t.Helper()
	store := NewCertRenewalStore(d)
	res := &tls.CertResult{Host: host, Names: []string{host}, CertPEM: []byte("W"), KeyPEM: []byte("K")}
	if err := store.SaveRenewed(context.Background(), res, tls.RenewTarget{Host: host, IsWildcard: true}); err != nil {
		t.Fatalf("SaveRenewed: %v", err)
	}
	cert, err := d.GetCertificate(host)
	if err != nil {
		t.Fatal(err)
	}
	cert.ExpiresAt = expires
	if err := d.UpsertCertificate(cert); err != nil {
		t.Fatal(err)
	}
}

// TestCatchAllOnlyKeepsItsCert: a catch-all domain's own cert is a wildcard row
// under "*.<zone>"; the wildcard sweep must keep it and renewal must renew it.
func TestCatchAllOnlyKeepsItsCert(t *testing.T) {
	registerMockProvider(t)
	d := testDB(t)
	_, zone, _, srv, _ := setupScenario(t, d)
	createCatchAll(t, d, zone.ID, srv.ID)
	r := New(d, newMockAgentClient(), time.Minute)
	store := NewCertRenewalStore(d)

	tg, err := store.TargetForHost(context.Background(), testWildcardHost)
	if err != nil || tg == nil || !tg.IsWildcard {
		t.Fatalf("TargetForHost(*) = %+v, %v; want a wildcard target", tg, err)
	}
	storeIssued(t, d, testWildcardHost, time.Now().Add(24*time.Hour))

	r.pruneUnusedWildcardCerts()
	if !certExists(t, d, testWildcardHost) {
		t.Fatal("catch-all domain's cert deleted by the wildcard sweep")
	}
	targets, err := store.DueForRenewal(context.Background(), tls.DefaultRenewWindow)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(targets, func(t tls.RenewTarget) bool { return t.Host == testWildcardHost && !t.FirstIssue }) {
		t.Fatalf("targets = %+v, want a renewal of the catch-all cert", targets)
	}
}

// TestCatchAllFirstIssueIsWildcard: the scan's first issuance flags the
// catch-all row as a wildcard too, matching the on-demand path.
func TestCatchAllFirstIssueIsWildcard(t *testing.T) {
	registerMockProvider(t)
	d := testDB(t)
	_, zone, _, srv, app := setupScenario(t, d)
	upsertCert(t, d, models.Certificate{ID: "app.example.com", Host: "app.example.com", Names: []string{"app.example.com"},
		CertPEM: "A", KeyPEM: "K", ExpiresAt: time.Now().Add(80 * 24 * time.Hour)})
	_ = app
	createCatchAll(t, d, zone.ID, srv.ID)
	targets, err := NewCertRenewalStore(d).DueForRenewal(context.Background(), tls.DefaultRenewWindow)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Host != testWildcardHost || !targets[0].IsWildcard || !targets[0].FirstIssue {
		t.Fatalf("targets = %+v, want one wildcard first issuance of %s", targets, testWildcardHost)
	}
}

// TestCatchAllAndOptInShareCert covers both teardown orders: deleting the
// catch-all keeps the cert while opted-in domains use it; opting all of them
// out keeps it while the catch-all exists; it goes once neither is left.
func TestCatchAllAndOptInShareCert(t *testing.T) {
	t.Run("delete catch-all first", func(t *testing.T) {
		d := testDB(t)
		_, app, api, _ := wildcardScenario(t, d)
		catchAll := createCatchAll(t, d, app.ZoneID, app.ServerID)
		r := New(d, newMockAgentClient(), time.Minute)
		storeIssued(t, d, testWildcardHost, time.Now().Add(80*24*time.Hour))

		if err := d.DeleteDomain(catchAll.ID); err != nil {
			t.Fatal(err)
		}
		r.cleanupCertForDomain(catchAll)
		r.pruneUnusedWildcardCerts()
		if !certExists(t, d, testWildcardHost) {
			t.Fatal("shared cert deleted with the catch-all while opted-in domains use it")
		}

		for _, dom := range []*models.Domain{app, api} {
			dom.ProxyConfig.TLSWildcard = false
			if err := d.UpdateDomain(dom); err != nil {
				t.Fatal(err)
			}
		}
		r.pruneUnusedWildcardCerts()
		if certExists(t, d, testWildcardHost) {
			t.Fatal("shared cert kept after its last user went away")
		}
	})

	t.Run("opt-in side leaves first", func(t *testing.T) {
		d := testDB(t)
		_, app, api, _ := wildcardScenario(t, d)
		catchAll := createCatchAll(t, d, app.ZoneID, app.ServerID)
		r := New(d, newMockAgentClient(), time.Minute)
		storeIssued(t, d, testWildcardHost, time.Now().Add(80*24*time.Hour))

		for _, dom := range []*models.Domain{app, api} {
			if err := d.UpdateDomainStatus(dom.ID, models.DomainStatusDeleting, ""); err != nil {
				t.Fatal(err)
			}
		}
		r.pruneUnusedWildcardCerts()
		if !certExists(t, d, testWildcardHost) {
			t.Fatal("catch-all's cert deleted after the opted-in domains left")
		}

		if err := d.DeleteDomain(catchAll.ID); err != nil {
			t.Fatal(err)
		}
		r.cleanupCertForDomain(catchAll)
		if certExists(t, d, testWildcardHost) {
			t.Fatal("cert kept after the catch-all, its last user, was deleted")
		}
	})
}

// TestAgentsUsingWildcardIncludesCatchAll: a renewed "*.<zone>" cert is pushed
// to the union of the agents serving opted-in domains and the catch-all.
func TestAgentsUsingWildcardIncludesCatchAll(t *testing.T) {
	d := testDB(t)
	agent, app, _, _ := wildcardScenario(t, d)
	seen := time.Now().UTC()
	other := &models.Agent{ID: "agent-2", Name: "Agent Two", FQDN: "agent2.example.com", APIURL: "https://agent2.example.com:8443",
		TokenHash: "token-hash-2", DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted, LastSeen: &seen}
	if err := d.CreateAgent(other); err != nil {
		t.Fatal(err)
	}
	srv2 := &models.Server{ID: "srv-2", AgentID: other.ID, Name: "Catch-all", Address: "10.0.0.2"}
	if err := d.CreateServer(srv2); err != nil {
		t.Fatal(err)
	}
	createCatchAll(t, d, app.ZoneID, srv2.ID)
	r := New(d, newMockAgentClient(), time.Minute)

	got, err := r.agentsUsingWildcard(testWildcardHost)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	if want := []string{agent.ID, other.ID}; !slices.Equal(got, want) {
		t.Fatalf("agentsUsingWildcard = %v, want %v", got, want)
	}
}

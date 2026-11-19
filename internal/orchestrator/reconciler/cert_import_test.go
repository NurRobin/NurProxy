package reconciler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/tls"
	"github.com/NurRobin/NurProxy/internal/provider"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// gatedACME hands out a fixed cert, optionally holding every order until
// release is closed so a test can act while the order is in flight.
type gatedACME struct {
	arrived chan struct{}
	release chan struct{}
}

func (g *gatedACME) ObtainViaDNS01(_ context.Context, names []string, _ tls.DNSSolver) (*tls.CertResult, error) {
	select {
	case g.arrived <- struct{}{}:
	default:
	}
	<-g.release
	return &tls.CertResult{Host: strings.TrimPrefix(names[0], "*."), Names: names, CertPEM: []byte("ACME"), KeyPEM: []byte("K")}, nil
}

// txtProvider lets the mock DNS provider pass the issuer's TXT capability check;
// gatedACME never calls the solver.
type txtProvider struct{ *mockDNSProvider }

func (p txtProvider) Info() provider.ProviderInfo {
	info := p.mockDNSProvider.Info()
	info.RecordTypes = append(info.RecordTypes, "TXT")
	return info
}

// staleScanStore replays targets resolved before the test changed the store,
// like a scan whose DueForRenewal ran before an import landed.
type staleScanStore struct {
	*CertRenewalStore
	due []tls.RenewTarget
}

func (s staleScanStore) DueForRenewal(context.Context, time.Duration) ([]tls.RenewTarget, error) {
	return s.due, nil
}

type auditRecorder struct {
	mu      sync.Mutex
	actions []string
}

func (a *auditRecorder) Audit(_, entityID, action, _ string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.actions = append(a.actions, action+":"+entityID)
}

// TestImportRacesRenewal covers both halves of the import/renewal race (#80):
// an import that lands after the scan resolved its target survives the ACME
// result, and while an order runs the host lock the import handler takes is
// held, so the handler answers 409 instead of writing.
func TestImportRacesRenewal(t *testing.T) {
	mp := registerMockProvider(t)
	const host = "app.example.com"
	imported := &models.Certificate{ID: host, Host: host, Names: []string{host}, CertPEM: "IMPORTED", KeyPEM: "K", Source: models.CertSourceImported}

	setup := func(t *testing.T) (*CertRenewalStore, []tls.RenewTarget, *models.Domain, func(*models.Certificate) error) {
		t.Helper()
		d := testDB(t)
		_, _, _, _, dom := setupScenario(t, d)
		if err := d.UpsertCertificate(&models.Certificate{ID: host, Host: host, Names: []string{host}, CertPEM: "OLD", KeyPEM: "K", ExpiresAt: time.Now().Add(24 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
		store := NewCertRenewalStore(d)
		due, err := store.DueForRenewal(context.Background(), tls.DefaultRenewWindow)
		if err != nil || len(due) != 1 || due[0].PriorCertPEM != "OLD" {
			t.Fatalf("DueForRenewal = %+v, %v; want one target remembering the OLD cert", due, err)
		}
		due[0].Provider = txtProvider{mp}
		importFn := func(c *models.Certificate) error { return d.ImportCertificateForDomain(dom.ID, c) }
		return store, due, dom, importFn
	}

	t.Run("import between scan and order is kept", func(t *testing.T) {
		store, due, _, importCert := setup(t)
		if err := importCert(imported); err != nil {
			t.Fatal(err)
		}
		acme := &gatedACME{arrived: make(chan struct{}, 1), release: make(chan struct{})}
		close(acme.release)
		audit := &auditRecorder{}
		r := tls.NewRenewer(staleScanStore{store, due}, tls.NewIssuer(acme, nil), tls.RenewerConfig{Audit: audit})
		if err := r.RunOnce(context.Background()); err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
		got, err := store.db.GetCertificate(host)
		if err != nil || got.CertPEM != "IMPORTED" || got.Source != models.CertSourceImported {
			t.Fatalf("stored cert after the order = %+v (%v), want the import kept", got, err)
		}
		if !slices.Contains(audit.actions, "renew_superseded:"+host) {
			t.Errorf("audit = %v, want renew_superseded", audit.actions)
		}
	})

	t.Run("import during order is locked out", func(t *testing.T) {
		store, due, _, _ := setup(t)
		acme := &gatedACME{arrived: make(chan struct{}, 1), release: make(chan struct{})}
		r := tls.NewRenewer(staleScanStore{store, due}, tls.NewIssuer(acme, nil), tls.RenewerConfig{})
		done := make(chan error, 1)
		go func() { done <- r.RunOnce(context.Background()) }()
		select {
		case <-acme.arrived:
		case <-time.After(5 * time.Second):
			t.Fatal("order never reached ACME")
		}
		if _, ok := r.TryLockHost(host); ok {
			t.Fatal("host lock was free while the order ran; an import could be overwritten")
		}
		close(acme.release)
		if err := <-done; err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
		unlock, ok := r.TryLockHost(host)
		if !ok {
			t.Fatal("host lock still held after the order finished")
		}
		unlock()
		got, err := store.db.GetCertificate(host)
		if err != nil || got.CertPEM != "ACME" || got.Source != models.CertSourceACME {
			t.Errorf("stored cert = %+v (%v), want the renewed ACME cert", got, err)
		}
	})
}

// TestImportedCertReachesManagedApplyIntent checks that an imported cert (#80)
// takes the same road to the agent as an issued one: it rides the intent set,
// stays in the prune keep set, and becomes certificate + source_key artifacts in
// the signed helper intent.
func TestImportedCertReachesManagedApplyIntent(t *testing.T) {
	tests := []struct {
		name     string
		certOnly bool
	}{
		{name: "served domain"},
		{name: "cert-only domain", certOnly: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := testDB(t)
			_, zone, agent, srv, _ := setupScenario(t, d)
			host := "app.example.com"
			if tt.certOnly {
				co := &models.Domain{
					Subdomain: "certonly", ZoneID: zone.ID, ServerID: srv.ID,
					SSLMode: models.SSLModeAuto, CertOnly: true, Status: models.DomainStatusPending,
				}
				if err := d.CreateDomain(co); err != nil {
					t.Fatalf("CreateDomain: %v", err)
				}
				host = co.FQDN(zone.Name)
			}
			const certPEM = "-----BEGIN CERTIFICATE-----\nimported\n-----END CERTIFICATE-----\n"
			if err := d.UpsertCertificate(&models.Certificate{
				ID: host, Host: host, Names: []string{"*.example.com"},
				CertPEM: certPEM, KeyPEM: "-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----\n",
				ExpiresAt: time.Now().Add(60 * 24 * time.Hour), Source: models.CertSourceImported,
			}); err != nil {
				t.Fatalf("UpsertCertificate: %v", err)
			}

			r := New(d, newMockAgentClient(), time.Minute)
			desired, keep, err := r.buildDesiredRoutes(agent)
			if err != nil {
				t.Fatalf("buildDesiredRoutes: %v", err)
			}
			set := r.intentSetFor(agent, desired, keep)

			idx := slices.IndexFunc(set.Certs, func(c proxymodel.CertBundle) bool { return c.Host == host })
			if idx < 0 || set.Certs[idx].CertPEM != certPEM {
				t.Fatalf("intent set certs = %+v, want the imported bundle for %s", set.Certs, host)
			}
			if tt.certOnly && !set.Certs[idx].MaterializeKey {
				t.Error("cert-only bundle must materialize its key for the operator's own config")
			}
			if !set.PruneCerts || !slices.Contains(set.CertKeep, host) {
				t.Fatalf("imported cert not protected from prune: prune=%v keep=%v", set.PruneCerts, set.CertKeep)
			}

			intent, err := buildApplyIntent(agent.ID, "helper-1", set, time.Now().UTC())
			if err != nil {
				t.Fatalf("buildApplyIntent: %v", err)
			}
			sum := sha256.Sum256([]byte(certPEM))
			kinds := map[string]bool{}
			for _, a := range intent.Artifacts {
				if a.Name != host {
					continue
				}
				kinds[a.Kind] = true
				if a.Kind == "certificate" && a.SHA256 != hex.EncodeToString(sum[:]) {
					t.Errorf("certificate artifact digest does not match the imported PEM")
				}
			}
			if !kinds["certificate"] || !kinds["source_key"] {
				t.Fatalf("apply intent artifacts = %+v, want certificate and source_key for %s", intent.Artifacts, host)
			}
			if !slices.Contains(intent.CertificateKeep, host) {
				t.Errorf("apply intent certificate_keep = %v, want %s", intent.CertificateKeep, host)
			}
		})
	}
}

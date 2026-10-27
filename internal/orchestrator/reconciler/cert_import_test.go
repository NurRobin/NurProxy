package reconciler

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

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

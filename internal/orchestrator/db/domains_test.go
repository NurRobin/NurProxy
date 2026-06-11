package db

import (
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// markDomainAppliedFixture builds a fresh DB with a single pending domain and
// returns the DB plus the domain's id. The fqdn used for central-TLS lookups is
// "app.example.com" (matching the createTestDomain subdomain "app").
func markDomainAppliedFixture(t *testing.T) (*DB, int64) {
	t.Helper()
	d := testDB(t)
	p := createTestProvider(t, d)
	z := createTestZone(t, d, p.ID)
	a := createTestAgent(t, d)
	s := createTestServer(t, d, a.ID)
	dom := createTestDomain(t, d, z.ID, s.ID)
	return d, dom.ID
}

func domainStatus(t *testing.T, d *DB, id int64) models.DomainStatus {
	t.Helper()
	got, err := d.GetDomain(id)
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	return got.Status
}

// TestMarkDomainApplied covers the three central-TLS outcomes: a present
// certificate marks the domain active; a genuinely absent certificate degrades
// it to plaintext; and a transient DB read error must NOT mislabel a domain as
// degraded — it propagates the error and leaves the status untouched.
func TestMarkDomainApplied(t *testing.T) {
	const fqdn = "app.example.com"

	t.Run("present cert => active, not degraded", func(t *testing.T) {
		d, id := markDomainAppliedFixture(t)
		if err := d.UpsertCertificate(&models.Certificate{
			ID: "cert-1", Host: fqdn, CertPEM: "CERT", KeyPEM: "KEY",
		}); err != nil {
			t.Fatalf("UpsertCertificate: %v", err)
		}

		if err := d.MarkDomainApplied(id, fqdn, true); err != nil {
			t.Fatalf("MarkDomainApplied: %v", err)
		}
		if got := domainStatus(t, d, id); got != models.DomainStatusActive {
			t.Errorf("status: got %q, want %q", got, models.DomainStatusActive)
		}
	})

	t.Run("missing cert => degraded plaintext", func(t *testing.T) {
		d, id := markDomainAppliedFixture(t)

		if err := d.MarkDomainApplied(id, fqdn, true); err != nil {
			t.Fatalf("MarkDomainApplied: %v", err)
		}
		got, err := d.GetDomain(id)
		if err != nil {
			t.Fatalf("GetDomain: %v", err)
		}
		if got.Status != models.DomainStatusDegraded {
			t.Errorf("status: got %q, want %q", got.Status, models.DomainStatusDegraded)
		}
		if !strings.Contains(got.ErrorMsg, "plaintext") {
			t.Errorf("error_msg: got %q, want it to mention plaintext", got.ErrorMsg)
		}
	})

	t.Run("transient read error => not mislabeled", func(t *testing.T) {
		d, id := markDomainAppliedFixture(t)
		// Induce a non-not-found read error on the certificate lookup by
		// removing the table the probe queries. The domains table stays intact,
		// so a mislabel-as-degraded would still succeed — proving the guard.
		if _, err := d.sql.Exec("DROP TABLE certificates"); err != nil {
			t.Fatalf("DROP TABLE certificates: %v", err)
		}

		err := d.MarkDomainApplied(id, fqdn, true)
		if err == nil {
			t.Fatal("expected an error from the transient certificate read, got nil")
		}
		// The domain must NOT have been degraded; it stays at its prior status.
		if got := domainStatus(t, d, id); got == models.DomainStatusDegraded {
			t.Errorf("domain mislabeled degraded on a transient read error; status=%q", got)
		}
	})

	t.Run("not central-TLS => active regardless of cert", func(t *testing.T) {
		d, id := markDomainAppliedFixture(t)

		if err := d.MarkDomainApplied(id, fqdn, false); err != nil {
			t.Fatalf("MarkDomainApplied: %v", err)
		}
		if got := domainStatus(t, d, id); got != models.DomainStatusActive {
			t.Errorf("status: got %q, want %q", got, models.DomainStatusActive)
		}
	})
}

package db

import (
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

func TestUpsertCertificate_roundtrip_decryptsKey(t *testing.T) {
	d := testDB(t)

	cert := &models.Certificate{
		ID:        "cert-1",
		Host:      "app.example.com",
		Names:     []string{"app.example.com", "www.app.example.com"},
		CertPEM:   "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
		KeyPEM:    "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
		ExpiresAt: time.Now().Add(60 * 24 * time.Hour).UTC().Truncate(time.Second),
	}
	if err := d.UpsertCertificate(cert); err != nil {
		t.Fatalf("UpsertCertificate: %v", err)
	}

	got, err := d.GetCertificate("app.example.com")
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got.KeyPEM != cert.KeyPEM {
		t.Errorf("key roundtrip failed: got %q", got.KeyPEM)
	}
	if got.CertPEM != cert.CertPEM {
		t.Errorf("cert roundtrip failed")
	}
	if len(got.Names) != 2 || got.Names[1] != "www.app.example.com" {
		t.Errorf("names = %v", got.Names)
	}
}

func TestUpsertCertificate_keyEncryptedAtRest(t *testing.T) {
	d := testDB(t)

	secret := "VERY-SECRET-PRIVATE-KEY-MATERIAL"
	cert := &models.Certificate{ID: "c", Host: "h.example.com", CertPEM: "C", KeyPEM: secret}
	if err := d.UpsertCertificate(cert); err != nil {
		t.Fatal(err)
	}

	var stored string
	if err := d.sql.QueryRow("SELECT key_pem_enc FROM certificates WHERE host = ?", "h.example.com").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == secret {
		t.Fatal("private key stored in plaintext")
	}
	if stored == "" {
		t.Fatal("encrypted key empty")
	}
}

func TestUpsertCertificate_reissueOverwrites(t *testing.T) {
	d := testDB(t)

	c1 := &models.Certificate{ID: "c1", Host: "h.example.com", CertPEM: "OLD", KeyPEM: "K1"}
	if err := d.UpsertCertificate(c1); err != nil {
		t.Fatal(err)
	}
	c2 := &models.Certificate{ID: "c1", Host: "h.example.com", CertPEM: "NEW", KeyPEM: "K2"}
	if err := d.UpsertCertificate(c2); err != nil {
		t.Fatal(err)
	}

	got, err := d.GetCertificate("h.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.CertPEM != "NEW" || got.KeyPEM != "K2" {
		t.Errorf("reissue did not overwrite: cert=%q key=%q", got.CertPEM, got.KeyPEM)
	}

	certs, err := d.ListCertificates()
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 cert after reissue, got %d", len(certs))
	}
}

// TestUpsertCertificate_source covers the import provenance (#80): an imported
// bundle keeps its source until a later upsert (an ACME renewal) replaces it,
// and an unset source is stored as acme.
func TestUpsertCertificate_source(t *testing.T) {
	tests := []struct {
		name   string
		writes []string
		want   string
	}{
		{name: "unset defaults to acme", writes: []string{""}, want: models.CertSourceACME},
		{name: "imported", writes: []string{models.CertSourceImported}, want: models.CertSourceImported},
		{name: "renewal replaces import", writes: []string{models.CertSourceImported, models.CertSourceACME}, want: models.CertSourceACME},
		{name: "re-import over acme", writes: []string{models.CertSourceACME, models.CertSourceImported}, want: models.CertSourceImported},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := testDB(t)
			for _, source := range tc.writes {
				c := &models.Certificate{ID: "h.example.com", Host: "h.example.com", CertPEM: "C", KeyPEM: "K", Source: source}
				if err := d.UpsertCertificate(c); err != nil {
					t.Fatalf("UpsertCertificate(%q): %v", source, err)
				}
			}
			got, err := d.GetCertificate("h.example.com")
			if err != nil {
				t.Fatal(err)
			}
			if got.Source != tc.want {
				t.Errorf("source = %q, want %q", got.Source, tc.want)
			}
		})
	}
}

func TestCertificatesDueForRenewal_window(t *testing.T) {
	d := testDB(t)

	soon := &models.Certificate{ID: "s", Host: "soon.example.com", CertPEM: "C", KeyPEM: "K",
		ExpiresAt: time.Now().Add(10 * 24 * time.Hour)}
	later := &models.Certificate{ID: "l", Host: "later.example.com", CertPEM: "C", KeyPEM: "K",
		ExpiresAt: time.Now().Add(90 * 24 * time.Hour)}
	if err := d.UpsertCertificate(soon); err != nil {
		t.Fatal(err)
	}
	if err := d.UpsertCertificate(later); err != nil {
		t.Fatal(err)
	}

	due, err := d.CertificatesDueForRenewal(30 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 || due[0].Host != "soon.example.com" {
		t.Errorf("due = %v, want [soon.example.com]", hosts(due))
	}
}

func TestDeleteCertificate(t *testing.T) {
	d := testDB(t)
	if err := d.UpsertCertificate(&models.Certificate{ID: "c", Host: "h.example.com", CertPEM: "C", KeyPEM: "K"}); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteCertificate("h.example.com"); err != nil {
		t.Fatalf("DeleteCertificate: %v", err)
	}
	if err := d.DeleteCertificate("h.example.com"); err == nil {
		t.Error("expected error deleting non-existent certificate")
	}
}

func hosts(certs []models.Certificate) []string {
	out := make([]string, len(certs))
	for i, c := range certs {
		out[i] = c.Host
	}
	return out
}

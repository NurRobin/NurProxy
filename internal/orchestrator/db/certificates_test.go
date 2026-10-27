package db

import (
	"errors"
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

// TestReplaceCertificateIfUnchanged is the store half of the import race
// (#80): an ACME result is only written while the row still holds the cert the
// order started from.
func TestReplaceCertificateIfUnchanged(t *testing.T) {
	tests := []struct {
		name     string
		stored   string // "" = no row
		prior    string
		wantSave bool
	}{
		{name: "first issuance, still no row", prior: "", wantSave: true},
		{name: "first issuance, import landed", stored: "IMPORTED", prior: "", wantSave: false},
		{name: "renewal, row unchanged", stored: "OLD", prior: "OLD", wantSave: true},
		{name: "renewal, import replaced the row", stored: "IMPORTED", prior: "OLD", wantSave: false},
		{name: "renewal, row deleted meanwhile", prior: "OLD", wantSave: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := testDB(t)
			if tc.stored != "" {
				if err := d.UpsertCertificate(&models.Certificate{ID: "h.example.com", Host: "h.example.com", CertPEM: tc.stored, KeyPEM: "K", Source: models.CertSourceImported}); err != nil {
					t.Fatal(err)
				}
			}
			saved, err := d.ReplaceCertificateIfUnchanged(&models.Certificate{ID: "h.example.com", Host: "h.example.com", CertPEM: "ACME", KeyPEM: "K2"}, tc.prior)
			if err != nil {
				t.Fatalf("ReplaceCertificateIfUnchanged: %v", err)
			}
			if saved != tc.wantSave {
				t.Fatalf("saved = %v, want %v", saved, tc.wantSave)
			}
			got, err := d.GetCertificate("h.example.com")
			switch {
			case tc.wantSave:
				if err != nil || got.CertPEM != "ACME" {
					t.Errorf("after save: cert=%v err=%v, want ACME", got, err)
				}
			case tc.stored != "":
				if err != nil || got.CertPEM != tc.stored || got.Source != models.CertSourceImported {
					t.Errorf("refused save changed the stored cert: %+v err=%v", got, err)
				}
			default:
				if err == nil {
					t.Errorf("refused save created a row: %+v", got)
				}
			}
		})
	}
}

// TestImportCertificateForDomain checks that the import write is refused for a
// domain that is gone or being deleted, so teardown cannot miss the new row.
func TestImportCertificateForDomain(t *testing.T) {
	tests := []struct {
		name    string
		status  models.DomainStatus
		missing bool
		wantErr error
	}{
		{name: "active domain", status: models.DomainStatusActive},
		{name: "deleting domain", status: models.DomainStatusDeleting, wantErr: ErrDomainDeleting},
		{name: "domain row gone", status: models.DomainStatusActive, missing: true, wantErr: ErrDomainDeleting},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := testDB(t)
			mustNoErr(t, d.CreateProvider(&models.Provider{ID: "p", Type: "cloudflare", Name: "CF", Config: `{}`}))
			mustNoErr(t, d.CreateZone(&models.Zone{ID: "z", ProviderID: "p", ExternalID: "e", Name: "example.com"}))
			mustNoErr(t, d.CreateAgent(&models.Agent{ID: "a", Name: "A", FQDN: "a.example.com"}))
			mustNoErr(t, d.CreateServer(&models.Server{ID: "s", AgentID: "a", Name: "S", Address: "10.0.0.1"}))
			dom := &models.Domain{Subdomain: "app", ZoneID: "z", ServerID: "s", Port: 80, Status: tc.status}
			mustNoErr(t, d.CreateDomain(dom))
			id := dom.ID
			if tc.missing {
				id += 100
			}

			err := d.ImportCertificateForDomain(id, &models.Certificate{ID: "app.example.com", Host: "app.example.com", CertPEM: "C", KeyPEM: "K", Source: models.CertSourceImported})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			_, gErr := d.GetCertificate("app.example.com")
			if stored := gErr == nil; stored != (tc.wantErr == nil) {
				t.Errorf("certificate stored = %v, want %v", stored, tc.wantErr == nil)
			}
		})
	}
}

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func hosts(certs []models.Certificate) []string {
	out := make([]string, len(certs))
	for i, c := range certs {
		out[i] = c.Host
	}
	return out
}

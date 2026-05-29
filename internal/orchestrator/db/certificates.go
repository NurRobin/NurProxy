package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/crypto"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// UpsertCertificate inserts or replaces the certificate for a host. The private
// key (KeyPEM) is encrypted with the existing AES-256-GCM key before storage;
// the leaf certificate is public and stored as-is. One certificate per host
// (UNIQUE(host)); re-issuance overwrites in place and bumps updated_at.
func (d *DB) UpsertCertificate(c *models.Certificate) error {
	encKey, err := crypto.EncryptString(d.cryptoKey, c.KeyPEM)
	if err != nil {
		return fmt.Errorf("encrypting certificate key: %w", err)
	}

	names, err := json.Marshal(c.Names)
	if err != nil {
		return fmt.Errorf("marshaling certificate names: %w", err)
	}

	now := time.Now().UTC()
	c.UpdatedAt = now
	if c.IssuedAt.IsZero() {
		c.IssuedAt = now
	}

	isWildcard := 0
	if c.IsWildcard {
		isWildcard = 1
	}
	expires := ""
	if !c.ExpiresAt.IsZero() {
		expires = c.ExpiresAt.UTC().Format(time.RFC3339)
	}

	_, err = d.sql.Exec(`
		INSERT INTO certificates (id, host, names, is_wildcard, cert_pem, key_pem_enc, issued_at, expires_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(host) DO UPDATE SET
			names = excluded.names,
			is_wildcard = excluded.is_wildcard,
			cert_pem = excluded.cert_pem,
			key_pem_enc = excluded.key_pem_enc,
			issued_at = excluded.issued_at,
			expires_at = excluded.expires_at,
			updated_at = excluded.updated_at`,
		c.ID, c.Host, string(names), isWildcard, c.CertPEM, encKey,
		c.IssuedAt.UTC().Format(time.RFC3339), expires, now.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("upserting certificate: %w", err)
	}
	return nil
}

// GetCertificate retrieves the certificate for a host and decrypts its private
// key. Returns an error if not found.
func (d *DB) GetCertificate(host string) (*models.Certificate, error) {
	row := d.sql.QueryRow(`
		SELECT id, host, names, is_wildcard, cert_pem, key_pem_enc, issued_at, expires_at, updated_at
		FROM certificates WHERE host = ?`, host)
	c, err := d.scanCertificate(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("certificate not found: %s", host)
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ListCertificates returns all stored certificates with private keys decrypted.
func (d *DB) ListCertificates() ([]models.Certificate, error) {
	rows, err := d.sql.Query(`
		SELECT id, host, names, is_wildcard, cert_pem, key_pem_enc, issued_at, expires_at, updated_at
		FROM certificates ORDER BY host`)
	if err != nil {
		return nil, fmt.Errorf("listing certificates: %w", err)
	}
	defer rows.Close()

	var certs []models.Certificate
	for rows.Next() {
		c, err := d.scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		certs = append(certs, *c)
	}
	return certs, rows.Err()
}

// CertificatesDueForRenewal returns certificates whose expiry is within the
// given window (e.g. 30 days), driving central renewal (§7). Certificates with
// no recorded expiry are skipped (nothing to compute against).
func (d *DB) CertificatesDueForRenewal(window time.Duration) ([]models.Certificate, error) {
	cutoff := time.Now().UTC().Add(window).Format(time.RFC3339)
	rows, err := d.sql.Query(`
		SELECT id, host, names, is_wildcard, cert_pem, key_pem_enc, issued_at, expires_at, updated_at
		FROM certificates
		WHERE expires_at != '' AND expires_at <= ?
		ORDER BY expires_at`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("querying certificates due for renewal: %w", err)
	}
	defer rows.Close()

	var certs []models.Certificate
	for rows.Next() {
		c, err := d.scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		certs = append(certs, *c)
	}
	return certs, rows.Err()
}

// DeleteCertificate removes the certificate for a host.
func (d *DB) DeleteCertificate(host string) error {
	res, err := d.sql.Exec("DELETE FROM certificates WHERE host = ?", host)
	if err != nil {
		return fmt.Errorf("deleting certificate: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("certificate not found: %s", host)
	}
	return nil
}

// scanner abstracts *sql.Row and *sql.Rows for shared scanning.
type scanner interface {
	Scan(dest ...any) error
}

func (d *DB) scanCertificate(s scanner) (*models.Certificate, error) {
	var (
		c          models.Certificate
		namesJSON  string
		isWildcard int
		encKey     string
		issuedAt   string
		expiresAt  string
		updatedAt  string
	)
	if err := s.Scan(&c.ID, &c.Host, &namesJSON, &isWildcard, &c.CertPEM, &encKey, &issuedAt, &expiresAt, &updatedAt); err != nil {
		return nil, err
	}

	c.IsWildcard = isWildcard != 0
	if err := json.Unmarshal([]byte(namesJSON), &c.Names); err != nil {
		return nil, fmt.Errorf("unmarshaling certificate names: %w", err)
	}

	key, err := crypto.DecryptString(d.cryptoKey, encKey)
	if err != nil {
		return nil, fmt.Errorf("decrypting certificate key: %w", err)
	}
	c.KeyPEM = key

	c.IssuedAt, _ = time.Parse(time.RFC3339, issuedAt)
	if expiresAt != "" {
		c.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	}
	c.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)

	return &c, nil
}

package db

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// CertBackoff is the per-host issuance hold after an ACME rate limit (#70): no
// issuance is attempted for Host before NextAttemptAt. Attempts counts the
// consecutive rate-limited attempts and drives the exponential step; LastError
// keeps the CA's detail for operators. Rows are host-keyed (not certificate-
// keyed) so first-issuance hosts without a certificates row are covered too,
// and are deleted on successful issuance.
type CertBackoff struct {
	Host          string
	Attempts      int
	NextAttemptAt time.Time
	LastError     string
}

// GetCertBackoff returns the backoff row for host, or (nil, nil) when none is
// recorded (the host may be issued immediately).
func (d *DB) GetCertBackoff(host string) (*CertBackoff, error) {
	row := d.read.QueryRow(`
		SELECT host, attempts, next_attempt_at, last_error
		FROM cert_backoff WHERE host = ?`, host)
	var b CertBackoff
	var next string
	if err := row.Scan(&b.Host, &b.Attempts, &next, &b.LastError); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("querying cert backoff for %q: %w", host, err)
	}
	t, err := time.Parse(time.RFC3339, next)
	if err != nil {
		return nil, fmt.Errorf("parsing cert backoff next_attempt_at for %q: %w", host, err)
	}
	b.NextAttemptAt = t
	return &b, nil
}

// UpsertCertBackoff records (or replaces) the backoff for a host.
func (d *DB) UpsertCertBackoff(b *CertBackoff) error {
	if b == nil || b.Host == "" {
		return fmt.Errorf("cert backoff needs a host")
	}
	_, err := d.sql.Exec(`
		INSERT INTO cert_backoff (host, attempts, next_attempt_at, last_error, updated_at)
		VALUES (?, ?, ?, ?, datetime('now'))
		ON CONFLICT(host) DO UPDATE SET
			attempts = excluded.attempts,
			next_attempt_at = excluded.next_attempt_at,
			last_error = excluded.last_error,
			updated_at = excluded.updated_at`,
		b.Host, b.Attempts, b.NextAttemptAt.UTC().Format(time.RFC3339), b.LastError)
	if err != nil {
		return fmt.Errorf("upserting cert backoff for %q: %w", b.Host, err)
	}
	return nil
}

// DeleteCertBackoff removes the backoff row for host. Missing rows are a no-op
// (idempotent — called after every successful issuance).
func (d *DB) DeleteCertBackoff(host string) error {
	if _, err := d.sql.Exec("DELETE FROM cert_backoff WHERE host = ?", host); err != nil {
		return fmt.Errorf("deleting cert backoff for %q: %w", host, err)
	}
	return nil
}

// ActiveCertBackoffs returns the hosts whose backoff has not elapsed at "now",
// mapped to their next-attempt instant. The renewal/first-issuance scans skip
// these hosts; elapsed rows are simply not returned (they are cleared on the
// next successful issuance).
func (d *DB) ActiveCertBackoffs(now time.Time) (map[string]time.Time, error) {
	rows, err := d.read.Query(`
		SELECT host, next_attempt_at FROM cert_backoff WHERE next_attempt_at > ?`,
		now.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("querying active cert backoffs: %w", err)
	}
	defer rows.Close()
	active := make(map[string]time.Time)
	for rows.Next() {
		var host, next string
		if err := rows.Scan(&host, &next); err != nil {
			return nil, fmt.Errorf("scanning cert backoff: %w", err)
		}
		t, err := time.Parse(time.RFC3339, next)
		if err != nil {
			return nil, fmt.Errorf("parsing cert backoff next_attempt_at for %q: %w", host, err)
		}
		active[host] = t
	}
	return active, rows.Err()
}

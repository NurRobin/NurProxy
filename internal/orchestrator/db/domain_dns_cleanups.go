package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

var (
	// ErrDomainNotFound is wrapped by GetDomain when no row has the id.
	ErrDomainNotFound = errors.New("domain not found")
	// ErrZoneNotFound is wrapped by GetZone when no row has the id.
	ErrZoneNotFound = errors.New("zone not found")
	// ErrDomainRenamed is returned by the record-id writes below when the
	// domain's name changed while the reconciler was resolving its record.
	ErrDomainRenamed = errors.New("domain name changed while its DNS record was being resolved")
)

// DomainDNSCleanup is a domain CNAME record released by a rename or zone move,
// waiting for the reconciler. Owned records are deleted through the provider
// and zone they were created in; adopted ones are never deleted.
type DomainDNSCleanup struct {
	ID       int64
	DomainID int64
	FQDN     string // the name the record was made for
	RecordID string
	Owned    bool
	// Content is the target the record had when it was released ("" when
	// unknown); a record whose content changed since is left alone.
	Content string
	// Proxied is the record's Cloudflare proxy state, read once from the
	// provider; nil until read.
	Proxied *bool
	// Deleted: the record is already gone at the provider (deleted by the
	// wait bound); the row only keeps Proxied until the new record exists.
	Deleted        bool
	ZoneID         string
	ProviderID     string
	ZoneExternalID string
	Attempts       int
	LastError      string
	CreatedAt      time.Time
}

// releaseRenamedDomainRecordTx compares dom's name with the stored row. When
// the subdomain or zone changes it queues the stored DNS record for cleanup and
// returns true: the caller must then store the domain without a record id, so
// the reconciler creates or adopts one for the new name. A missing row returns
// false; the caller's UPDATE reports it.
func releaseRenamedDomainRecordTx(tx *sql.Tx, dom *models.Domain) (bool, error) {
	var subdomain, zoneID, recordID, zoneName, providerID, zoneExternalID, target string
	var managed int
	err := tx.QueryRow(`
		SELECT d.subdomain, d.zone_id, d.dns_record_id, d.dns_managed,
			COALESCE(z.name, ''), COALESCE(z.provider_id, ''), COALESCE(z.external_id, ''),
			COALESCE(a.fqdn, '')
		FROM domains d
		LEFT JOIN zones z ON z.id = d.zone_id
		LEFT JOIN servers s ON s.id = d.server_id
		LEFT JOIN agents a ON a.id = s.agent_id
		WHERE d.id = ?`, dom.ID).
		Scan(&subdomain, &zoneID, &recordID, &managed, &zoneName, &providerID, &zoneExternalID, &target)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading stored domain %d: %w", dom.ID, err)
	}
	if subdomain == dom.Subdomain && zoneID == dom.ZoneID {
		return false, nil
	}
	if recordID == "" {
		return true, nil
	}
	err = queueDomainRecordTx(tx, DomainDNSCleanup{
		DomainID: dom.ID, FQDN: models.Domain{Subdomain: subdomain}.FQDN(zoneName),
		RecordID: recordID, Owned: managed != 0, Content: target,
		ZoneID: zoneID, ProviderID: providerID, ZoneExternalID: zoneExternalID,
	})
	return err == nil, err
}

// queueDomainRecordTx inserts a cleanup row. A row already queued for the same
// zone and record is replaced by the new values: ownership and content are
// what the domain knew last, and the proxied snapshot is read again.
func queueDomainRecordTx(tx *sql.Tx, c DomainDNSCleanup) error {
	if _, err := tx.Exec(`
		INSERT INTO domain_dns_cleanups
			(domain_id, fqdn, record_id, owned, content, proxied, zone_id, provider_id, zone_external_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(zone_id, record_id) DO UPDATE SET
			domain_id = excluded.domain_id, fqdn = excluded.fqdn, owned = excluded.owned,
			content = excluded.content, proxied = excluded.proxied, deleted = 0,
			provider_id = excluded.provider_id, zone_external_id = excluded.zone_external_id,
			attempts = 0, last_error = ''`,
		c.DomainID, c.FQDN, c.RecordID, boolToInt(c.Owned), c.Content, nullableBool(c.Proxied),
		c.ZoneID, c.ProviderID, c.ZoneExternalID,
	); err != nil {
		return fmt.Errorf("queueing DNS cleanup for domain %d: %w", c.DomainID, err)
	}
	return nil
}

// QueueDomainDNSRecord queues a record the reconciler created for a name the
// domain no longer has (it was renamed while the record was being created).
// The provider and external zone are taken from the zone row.
func (d *DB) QueueDomainDNSRecord(c DomainDNSCleanup) error {
	tx, err := d.sql.Begin()
	if err != nil {
		return fmt.Errorf("beginning DNS cleanup queue: %w", err)
	}
	defer tx.Rollback()
	if c.ProviderID == "" {
		zErr := tx.QueryRow(`SELECT provider_id, external_id FROM zones WHERE id = ?`, c.ZoneID).
			Scan(&c.ProviderID, &c.ZoneExternalID)
		if zErr != nil && !errors.Is(zErr, sql.ErrNoRows) {
			return fmt.Errorf("reading zone %s: %w", c.ZoneID, zErr)
		}
	}
	if err := queueDomainRecordTx(tx, c); err != nil {
		return err
	}
	return tx.Commit()
}

// SetDomainDNSRecordIfNamed stores the record the reconciler created or found
// for the domain, but only while the domain still has the subdomain and zone
// the record was resolved for. Otherwise nothing is written and
// ErrDomainRenamed is returned.
func (d *DB) SetDomainDNSRecordIfNamed(domainID int64, subdomain, zoneID, recordID string, managed bool) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.sql.Exec(`
		UPDATE domains SET dns_record_id = ?, dns_managed = ?, updated_at = ?
		WHERE id = ? AND subdomain = ? AND zone_id = ?`,
		recordID, boolToInt(managed), now, domainID, subdomain, zoneID)
	if err != nil {
		return fmt.Errorf("updating domain DNS record: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrDomainRenamed
	}
	return nil
}

// AdoptDomainDNSRecord stores an existing record the reconciler found at the
// domain's name (subdomain in zoneID) as the domain's record. When that record
// is still queued for cleanup (the domain came back to the name before the old
// record was deleted, or moved between two zone rows for the same provider
// zone), it is taken back out of the queue and keeps its original ownership,
// so NurProxy never deletes a record it is using and does not forget that it
// created it. It returns the ownership stored, or ErrDomainRenamed (with
// nothing changed) when the domain's name changed meanwhile.
func (d *DB) AdoptDomainDNSRecord(domainID int64, subdomain, recordID, zoneID string) (bool, error) {
	tx, err := d.sql.Begin()
	if err != nil {
		return false, fmt.Errorf("beginning DNS adopt: %w", err)
	}
	defer tx.Rollback()

	queuedID, owned, queued, err := queuedDomainRecord(tx, recordID, zoneID)
	if err != nil {
		return false, err
	}
	if queued {
		if _, err := tx.Exec(`DELETE FROM domain_dns_cleanups WHERE id = ?`, queuedID); err != nil {
			return false, fmt.Errorf("reclaiming queued DNS record: %w", err)
		}
	}

	now := time.Now().UTC().Format(time.RFC3339)
	res, err := tx.Exec(`
		UPDATE domains SET dns_record_id = ?, dns_managed = ?, updated_at = ?
		WHERE id = ? AND subdomain = ? AND zone_id = ?`,
		recordID, boolToInt(owned), now, domainID, subdomain, zoneID)
	if err != nil {
		return false, fmt.Errorf("updating domain DNS record: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, ErrDomainRenamed
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("committing DNS adopt: %w", err)
	}
	return owned, nil
}

// QueuedDomainDNSRecord reports whether recordID, found in zoneID, is queued for
// cleanup and whether NurProxy created it.
func (d *DB) QueuedDomainDNSRecord(recordID, zoneID string) (owned, queued bool, err error) {
	_, owned, queued, err = queuedDomainRecord(d.read, recordID, zoneID)
	return owned, queued, err
}

type queryRower interface {
	QueryRow(query string, args ...any) *sql.Row
}

// queuedDomainRecord finds the cleanup row for a record seen in zoneID. Record
// ids belong to the provider zone, not to NurProxy's zone row, so a row queued
// under another zone row (even of another provider row) for the same external
// zone matches too.
func queuedDomainRecord(q queryRower, recordID, zoneID string) (id int64, owned, queued bool, err error) {
	var zoneExternalID string
	zErr := q.QueryRow(`SELECT external_id FROM zones WHERE id = ?`, zoneID).Scan(&zoneExternalID)
	if zErr != nil && !errors.Is(zErr, sql.ErrNoRows) {
		return 0, false, false, fmt.Errorf("reading zone %s: %w", zoneID, zErr)
	}
	var ownedInt int
	qErr := q.QueryRow(`
		SELECT id, owned FROM domain_dns_cleanups
		WHERE deleted = 0 AND record_id = ? AND (zone_id = ? OR (zone_external_id != '' AND zone_external_id = ?))
		ORDER BY id LIMIT 1`,
		recordID, zoneID, zoneExternalID).Scan(&id, &ownedInt)
	switch {
	case qErr == nil:
		return id, ownedInt != 0, true, nil
	case errors.Is(qErr, sql.ErrNoRows):
		return 0, false, false, nil
	default:
		return 0, false, false, fmt.Errorf("checking DNS cleanup queue: %w", qErr)
	}
}

// MarkDomainDNSCleanupDeleted records that the queued record is gone at the
// provider while the row is kept for its proxied snapshot.
func (d *DB) MarkDomainDNSCleanupDeleted(id int64) error {
	if _, err := d.sql.Exec(`UPDATE domain_dns_cleanups SET deleted = 1, attempts = 0, last_error = '' WHERE id = ?`, id); err != nil {
		return fmt.Errorf("marking DNS cleanup %d deleted: %w", id, err)
	}
	return nil
}

// SetDomainDNSCleanupProxied stores the proxied snapshot read from the provider.
func (d *DB) SetDomainDNSCleanupProxied(id int64, proxied bool) error {
	if _, err := d.sql.Exec(`UPDATE domain_dns_cleanups SET proxied = ? WHERE id = ?`, boolToInt(proxied), id); err != nil {
		return fmt.Errorf("storing proxied snapshot for DNS cleanup %d: %w", id, err)
	}
	return nil
}

// LatestDomainDNSCleanup returns the record the domain released most recently,
// or nil when none is queued. The reconciler takes the proxied snapshot of the
// old record from it before creating the new one.
func (d *DB) LatestDomainDNSCleanup(domainID int64) (*DomainDNSCleanup, error) {
	rows, err := d.listDomainDNSCleanups(`WHERE domain_id = ? ORDER BY id DESC LIMIT 1`, domainID)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &rows[0], nil
}

// ListDomainDNSCleanups returns every queued domain DNS cleanup, oldest first.
func (d *DB) ListDomainDNSCleanups() ([]DomainDNSCleanup, error) {
	return d.listDomainDNSCleanups(`ORDER BY id`)
}

func (d *DB) listDomainDNSCleanups(tail string, args ...any) ([]DomainDNSCleanup, error) {
	rows, err := d.read.Query(`
		SELECT id, domain_id, fqdn, record_id, owned, content, proxied, deleted, zone_id, provider_id,
			zone_external_id, attempts, last_error, created_at
		FROM domain_dns_cleanups `+tail, args...)
	if err != nil {
		return nil, fmt.Errorf("listing domain DNS cleanups: %w", err)
	}
	defer rows.Close()
	var out []DomainDNSCleanup
	for rows.Next() {
		var c DomainDNSCleanup
		var owned, deleted int
		var proxied sql.NullInt64
		var createdAt string
		if err := rows.Scan(&c.ID, &c.DomainID, &c.FQDN, &c.RecordID, &owned, &c.Content, &proxied, &deleted,
			&c.ZoneID, &c.ProviderID, &c.ZoneExternalID, &c.Attempts, &c.LastError, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning domain DNS cleanup: %w", err)
		}
		c.Owned, c.Deleted = owned != 0, deleted != 0
		if proxied.Valid {
			p := proxied.Int64 != 0
			c.Proxied = &p
		}
		c.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
		out = append(out, c)
	}
	return out, rows.Err()
}

// DomainDNSCleanupCounts returns how many old domain records still wait for
// deletion and how many of those have failed at least once.
func (d *DB) DomainDNSCleanupCounts(ctx context.Context) (pending, failing int, err error) {
	err = d.read.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(SUM(CASE WHEN attempts > 0 THEN 1 ELSE 0 END), 0)
		FROM domain_dns_cleanups WHERE deleted = 0`).Scan(&pending, &failing)
	if err != nil {
		return 0, 0, fmt.Errorf("counting domain DNS cleanups: %w", err)
	}
	return pending, failing, nil
}

// RemoveDomainDNSCleanup drops a queued cleanup once it is done.
func (d *DB) RemoveDomainDNSCleanup(id int64) error {
	if _, err := d.sql.Exec(`DELETE FROM domain_dns_cleanups WHERE id = ?`, id); err != nil {
		return fmt.Errorf("removing domain DNS cleanup %d: %w", id, err)
	}
	return nil
}

// RecordDomainDNSCleanupFailure counts a failed attempt and stores its error,
// keeping the row for the next reconcile cycle.
func (d *DB) RecordDomainDNSCleanupFailure(id int64, msg string) error {
	if _, err := d.sql.Exec(`
		UPDATE domain_dns_cleanups SET attempts = attempts + 1, last_error = ? WHERE id = ?`,
		msg, id); err != nil {
		return fmt.Errorf("recording domain DNS cleanup failure %d: %w", id, err)
	}
	return nil
}

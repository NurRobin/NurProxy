package db

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/crypto"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// ErrDiscoverySourceNotFound is returned when no source has the given ID.
var ErrDiscoverySourceNotFound = errors.New("discovery source not found")

const discoverySourceColumns = `id, type, name, config, sync_interval, last_run_at, last_error, created_at`

// CreateDiscoverySource inserts a source. Config is encrypted before it is
// stored.
func (d *DB) CreateDiscoverySource(s *models.DiscoverySource) error {
	enc, err := crypto.EncryptString(d.cryptoKey, s.Config)
	if err != nil {
		return fmt.Errorf("encrypting discovery config: %w", err)
	}
	s.CreatedAt = time.Now().UTC()
	_, err = d.sql.Exec(`
		INSERT INTO discovery_sources (id, type, name, config, sync_interval, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		s.ID, s.Type, s.Name, enc, s.SyncInterval, s.CreatedAt.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("inserting discovery source: %w", err)
	}
	return nil
}

func (d *DB) scanDiscoverySource(sc interface{ Scan(...any) error }) (*models.DiscoverySource, error) {
	var s models.DiscoverySource
	var enc, lastRun, createdAt string
	if err := sc.Scan(&s.ID, &s.Type, &s.Name, &enc, &s.SyncInterval, &lastRun, &s.LastError, &createdAt); err != nil {
		return nil, err
	}
	s.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if lastRun != "" {
		if t, err := time.Parse(time.RFC3339, lastRun); err == nil {
			s.LastRunAt = &t
		}
	}
	cfg, err := crypto.DecryptString(d.cryptoKey, enc)
	if err != nil {
		return nil, fmt.Errorf("decrypting discovery config: %w", err)
	}
	s.Config = cfg
	return &s, nil
}

// GetDiscoverySource returns a source with its config decrypted.
func (d *DB) GetDiscoverySource(id string) (*models.DiscoverySource, error) {
	row := d.read.QueryRow(`SELECT `+discoverySourceColumns+` FROM discovery_sources WHERE id = ?`, id)
	s, err := d.scanDiscoverySource(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDiscoverySourceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying discovery source: %w", err)
	}
	return s, nil
}

// ListDiscoverySources returns every source with its config decrypted.
func (d *DB) ListDiscoverySources() ([]models.DiscoverySource, error) {
	rows, err := d.read.Query(`SELECT ` + discoverySourceColumns + ` FROM discovery_sources ORDER BY created_at, name`)
	if err != nil {
		return nil, fmt.Errorf("listing discovery sources: %w", err)
	}
	defer rows.Close()
	var out []models.DiscoverySource
	for rows.Next() {
		s, err := d.scanDiscoverySource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// UpdateDiscoverySource stores name, config (re-encrypted) and sync interval.
func (d *DB) UpdateDiscoverySource(s *models.DiscoverySource) error {
	enc, err := crypto.EncryptString(d.cryptoKey, s.Config)
	if err != nil {
		return fmt.Errorf("encrypting discovery config: %w", err)
	}
	res, err := d.sql.Exec(`UPDATE discovery_sources SET name = ?, config = ?, sync_interval = ? WHERE id = ?`,
		s.Name, enc, s.SyncInterval, s.ID)
	if err != nil {
		return fmt.Errorf("updating discovery source: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrDiscoverySourceNotFound
	}
	return nil
}

// DeleteDiscoverySource removes a source. Servers imported from it stay, but
// lose the link, so they become ordinary servers.
func (d *DB) DeleteDiscoverySource(id string) error {
	tx, err := d.sql.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE servers SET discovery_source_id = '', external_id = '', discovery_missing_since = ''
		WHERE discovery_source_id = ?`, id); err != nil {
		return fmt.Errorf("unlinking imported servers: %w", err)
	}
	res, err := tx.Exec(`DELETE FROM discovery_sources WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting discovery source: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrDiscoverySourceNotFound
	}
	return tx.Commit()
}

// RecordDiscoveryFailure stores a failed run. The last successful result is
// kept.
func (d *DB) RecordDiscoveryFailure(id string, at time.Time, msg string) error {
	_, err := d.sql.Exec(`UPDATE discovery_sources SET last_run_at = ?, last_error = ? WHERE id = ?`,
		at.UTC().Format(time.RFC3339), msg, id)
	return err
}

// DiscoveryServerUpdate is the per-server outcome of a successful run.
type DiscoveryServerUpdate struct {
	ServerID   string
	ExternalID string
	// MissingSince is nil when the machine was found.
	MissingSince *time.Time
}

// RecordDiscoveryRun stores a successful run's result and, in the same
// transaction, the link state of the servers imported from the source.
func (d *DB) RecordDiscoveryRun(id string, at time.Time, resultJSON string, updates []DiscoveryServerUpdate) error {
	tx, err := d.sql.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE discovery_sources SET last_run_at = ?, last_error = '', last_result = ? WHERE id = ?`,
		at.UTC().Format(time.RFC3339), resultJSON, id)
	if err != nil {
		return fmt.Errorf("storing discovery result: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrDiscoverySourceNotFound
	}
	for _, u := range updates {
		missing := ""
		if u.MissingSince != nil {
			missing = u.MissingSince.UTC().Format(time.RFC3339)
		}
		if _, err := tx.Exec(`UPDATE servers SET external_id = ?, discovery_missing_since = ?
			WHERE id = ? AND discovery_source_id = ?`, u.ExternalID, missing, u.ServerID, id); err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("server %s: %w", u.ServerID, ErrServerAlreadyImported)
			}
			return fmt.Errorf("updating server %s: %w", u.ServerID, err)
		}
	}
	return tx.Commit()
}

// GetDiscoveryResult returns the JSON result of the source's last successful
// run, or "" if it never ran successfully.
func (d *DB) GetDiscoveryResult(id string) (string, error) {
	var out string
	err := d.read.QueryRow(`SELECT last_result FROM discovery_sources WHERE id = ?`, id).Scan(&out)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrDiscoverySourceNotFound
	}
	return out, err
}

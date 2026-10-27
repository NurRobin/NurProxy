package db

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// GetSetting retrieves a single setting value by key.
func (d *DB) GetSetting(key string) (string, error) {
	var value string
	err := d.read.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("setting not found: %s", key)
	}
	if err != nil {
		return "", fmt.Errorf("querying setting: %w", err)
	}
	return value, nil
}

// SetSetting upserts a setting value.
func (d *DB) SetSetting(key, value string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := d.sql.Exec(`
		INSERT INTO settings (key, value, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, now,
	)
	if err != nil {
		return fmt.Errorf("setting value for %s: %w", key, err)
	}
	return nil
}

// InitializeAdminPassword atomically claims first-time setup. It writes hash
// only when the setting is absent or contains the empty legacy value and
// reports whether this caller won. The conditional upsert is one SQLite
// statement, so concurrent orchestrator requests or connections cannot both
// initialize the password.
func (d *DB) InitializeAdminPassword(hash string) (bool, error) {
	if hash == "" {
		return false, fmt.Errorf("initializing admin password: hash is required")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.sql.Exec(`
		INSERT INTO settings (key, value, updated_at)
		VALUES ('admin_password_hash', ?, ?)
		ON CONFLICT(key) DO UPDATE SET
			value = excluded.value,
			updated_at = excluded.updated_at
		WHERE settings.value = ''`,
		hash, now,
	)
	if err != nil {
		return false, fmt.Errorf("initializing admin password: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("reading admin password initialization result: %w", err)
	}
	return n == 1, nil
}

// CompareAndSwapSetting stores newValue only when the setting is absent or its
// current value equals expected, then returns the authoritative stored value.
// The write and read-back share one transaction, so callers on different
// database handles cannot retain different locally generated values.
func (d *DB) CompareAndSwapSetting(key, expected, newValue string) (actual string, swapped bool, err error) {
	tx, err := d.sql.Begin()
	if err != nil {
		return "", false, fmt.Errorf("beginning setting compare-and-swap: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC().Format(time.RFC3339)
	res, err := tx.Exec(`
		INSERT INTO settings (key, value, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET
			value = excluded.value,
			updated_at = excluded.updated_at
		WHERE settings.value = ?`,
		key, newValue, now, expected,
	)
	if err != nil {
		return "", false, fmt.Errorf("comparing and swapping setting %s: %w", key, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", false, fmt.Errorf("reading setting compare-and-swap result: %w", err)
	}
	if err := tx.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&actual); err != nil {
		return "", false, fmt.Errorf("reading setting %s after compare-and-swap: %w", key, err)
	}
	if err := tx.Commit(); err != nil {
		return "", false, fmt.Errorf("committing setting compare-and-swap: %w", err)
	}
	return actual, n == 1, nil
}

// ListSettings returns all stored settings.
func (d *DB) ListSettings() ([]models.Setting, error) {
	rows, err := d.read.Query("SELECT key, value, updated_at FROM settings ORDER BY key")
	if err != nil {
		return nil, fmt.Errorf("listing settings: %w", err)
	}
	defer rows.Close()

	var settings []models.Setting
	for rows.Next() {
		var s models.Setting
		var updatedAt string

		if err := rows.Scan(&s.Key, &s.Value, &updatedAt); err != nil {
			return nil, fmt.Errorf("scanning setting: %w", err)
		}

		s.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		settings = append(settings, s)
	}
	return settings, rows.Err()
}

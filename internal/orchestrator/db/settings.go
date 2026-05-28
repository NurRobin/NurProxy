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
	err := d.sql.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&value)
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

// ListSettings returns all stored settings.
func (d *DB) ListSettings() ([]models.Setting, error) {
	rows, err := d.sql.Query("SELECT key, value, updated_at FROM settings ORDER BY key")
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

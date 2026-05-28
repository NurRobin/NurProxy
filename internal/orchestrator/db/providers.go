package db

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/crypto"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// CreateProvider inserts a new provider. The Config field is encrypted before
// being stored.
func (d *DB) CreateProvider(p *models.Provider) error {
	enc, err := crypto.EncryptString(d.cryptoKey, p.Config)
	if err != nil {
		return fmt.Errorf("encrypting provider config: %w", err)
	}

	now := time.Now().UTC()
	p.CreatedAt = now

	isDefault := 0
	if p.IsDefault {
		isDefault = 1
	}

	_, err = d.sql.Exec(`
		INSERT INTO providers (id, type, name, config, zone_id, zone_name, is_default, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Type, p.Name, enc, p.ZoneID, p.ZoneName, isDefault, now.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("inserting provider: %w", err)
	}
	return nil
}

// GetProvider retrieves a provider by ID and decrypts its config.
func (d *DB) GetProvider(id string) (*models.Provider, error) {
	var p models.Provider
	var encConfig string
	var isDefault int
	var createdAt string

	err := d.sql.QueryRow(`
		SELECT id, type, name, config, zone_id, zone_name, is_default, created_at
		FROM providers WHERE id = ?`, id,
	).Scan(&p.ID, &p.Type, &p.Name, &encConfig, &p.ZoneID, &p.ZoneName, &isDefault, &createdAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("provider not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("querying provider: %w", err)
	}

	p.IsDefault = isDefault != 0
	p.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)

	p.Config, err = crypto.DecryptString(d.cryptoKey, encConfig)
	if err != nil {
		return nil, fmt.Errorf("decrypting provider config: %w", err)
	}

	return &p, nil
}

// ListProviders returns all providers with their configs decrypted.
func (d *DB) ListProviders() ([]models.Provider, error) {
	rows, err := d.sql.Query(`
		SELECT id, type, name, config, zone_id, zone_name, is_default, created_at
		FROM providers ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("listing providers: %w", err)
	}
	defer rows.Close()

	var providers []models.Provider
	for rows.Next() {
		var p models.Provider
		var encConfig string
		var isDefault int
		var createdAt string

		if err := rows.Scan(&p.ID, &p.Type, &p.Name, &encConfig, &p.ZoneID, &p.ZoneName, &isDefault, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning provider: %w", err)
		}

		p.IsDefault = isDefault != 0
		p.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)

		p.Config, err = crypto.DecryptString(d.cryptoKey, encConfig)
		if err != nil {
			return nil, fmt.Errorf("decrypting provider config: %w", err)
		}

		providers = append(providers, p)
	}

	return providers, rows.Err()
}

// UpdateProvider updates an existing provider. The Config field is re-encrypted.
func (d *DB) UpdateProvider(p *models.Provider) error {
	enc, err := crypto.EncryptString(d.cryptoKey, p.Config)
	if err != nil {
		return fmt.Errorf("encrypting provider config: %w", err)
	}

	isDefault := 0
	if p.IsDefault {
		isDefault = 1
	}

	res, err := d.sql.Exec(`
		UPDATE providers
		SET type = ?, name = ?, config = ?, zone_id = ?, zone_name = ?, is_default = ?
		WHERE id = ?`,
		p.Type, p.Name, enc, p.ZoneID, p.ZoneName, isDefault, p.ID,
	)
	if err != nil {
		return fmt.Errorf("updating provider: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("provider not found: %s", p.ID)
	}
	return nil
}

// DeleteProvider removes a provider by ID.
func (d *DB) DeleteProvider(id string) error {
	res, err := d.sql.Exec("DELETE FROM providers WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("deleting provider: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("provider not found: %s", id)
	}
	return nil
}

// SetDefaultProvider clears the is_default flag on all providers and sets it on
// the one identified by id.
func (d *DB) SetDefaultProvider(id string) error {
	tx, err := d.sql.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}

	if _, err := tx.Exec("UPDATE providers SET is_default = 0"); err != nil {
		tx.Rollback()
		return fmt.Errorf("clearing default flag: %w", err)
	}

	res, err := tx.Exec("UPDATE providers SET is_default = 1 WHERE id = ?", id)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("setting default provider: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		tx.Rollback()
		return fmt.Errorf("provider not found: %s", id)
	}

	return tx.Commit()
}

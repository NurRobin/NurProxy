package db

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// CreateZone inserts a new zone record.
func (d *DB) CreateZone(z *models.Zone) error {
	now := time.Now().UTC()
	z.CreatedAt = now

	_, err := d.sql.Exec(`
		INSERT INTO zones (id, provider_id, external_id, name, created_at)
		VALUES (?, ?, ?, ?, ?)`,
		z.ID, z.ProviderID, z.ExternalID, z.Name, now.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("inserting zone: %w", err)
	}
	return nil
}

// GetZone retrieves a zone by ID.
func (d *DB) GetZone(id string) (*models.Zone, error) {
	var z models.Zone
	var createdAt string

	err := d.sql.QueryRow(`
		SELECT id, provider_id, external_id, name, created_at
		FROM zones WHERE id = ?`, id,
	).Scan(&z.ID, &z.ProviderID, &z.ExternalID, &z.Name, &createdAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("zone not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("querying zone: %w", err)
	}

	z.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &z, nil
}

// ListZones returns all zones ordered by creation time.
func (d *DB) ListZones() ([]models.Zone, error) {
	rows, err := d.sql.Query(`
		SELECT id, provider_id, external_id, name, created_at
		FROM zones ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("listing zones: %w", err)
	}
	defer rows.Close()

	var zones []models.Zone
	for rows.Next() {
		var z models.Zone
		var createdAt string
		if err := rows.Scan(&z.ID, &z.ProviderID, &z.ExternalID, &z.Name, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning zone: %w", err)
		}
		z.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		zones = append(zones, z)
	}
	return zones, rows.Err()
}

// ListZonesByProvider returns all zones belonging to a provider.
func (d *DB) ListZonesByProvider(providerID string) ([]models.Zone, error) {
	rows, err := d.sql.Query(`
		SELECT id, provider_id, external_id, name, created_at
		FROM zones WHERE provider_id = ? ORDER BY created_at`, providerID)
	if err != nil {
		return nil, fmt.Errorf("listing zones by provider: %w", err)
	}
	defer rows.Close()

	var zones []models.Zone
	for rows.Next() {
		var z models.Zone
		var createdAt string
		if err := rows.Scan(&z.ID, &z.ProviderID, &z.ExternalID, &z.Name, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning zone: %w", err)
		}
		z.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		zones = append(zones, z)
	}
	return zones, rows.Err()
}

// DeleteZone removes a zone by ID.
func (d *DB) DeleteZone(id string) error {
	res, err := d.sql.Exec("DELETE FROM zones WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("deleting zone: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("zone not found: %s", id)
	}
	return nil
}

// AddAgentZone adds a zone assignment for an agent.
func (d *DB) AddAgentZone(agentID, zoneID string) error {
	_, err := d.sql.Exec(`
		INSERT OR IGNORE INTO agent_zones (agent_id, zone_id) VALUES (?, ?)`,
		agentID, zoneID,
	)
	if err != nil {
		return fmt.Errorf("adding agent zone: %w", err)
	}
	return nil
}

// RemoveAgentZone removes a zone assignment from an agent.
func (d *DB) RemoveAgentZone(agentID, zoneID string) error {
	res, err := d.sql.Exec(`
		DELETE FROM agent_zones WHERE agent_id = ? AND zone_id = ?`,
		agentID, zoneID,
	)
	if err != nil {
		return fmt.Errorf("removing agent zone: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("agent zone not found: %s/%s", agentID, zoneID)
	}
	return nil
}

// ListAgentZones returns all zones assigned to an agent.
func (d *DB) ListAgentZones(agentID string) ([]models.Zone, error) {
	rows, err := d.sql.Query(`
		SELECT z.id, z.provider_id, z.external_id, z.name, z.created_at
		FROM zones z
		JOIN agent_zones az ON z.id = az.zone_id
		WHERE az.agent_id = ?
		ORDER BY z.created_at`, agentID)
	if err != nil {
		return nil, fmt.Errorf("listing agent zones: %w", err)
	}
	defer rows.Close()

	var zones []models.Zone
	for rows.Next() {
		var z models.Zone
		var createdAt string
		if err := rows.Scan(&z.ID, &z.ProviderID, &z.ExternalID, &z.Name, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning zone: %w", err)
		}
		z.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		zones = append(zones, z)
	}
	return zones, rows.Err()
}

// SetAgentZones replaces all zone assignments for an agent in a transaction.
func (d *DB) SetAgentZones(agentID string, zoneIDs []string) error {
	tx, err := d.sql.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}

	if _, err := tx.Exec("DELETE FROM agent_zones WHERE agent_id = ?", agentID); err != nil {
		tx.Rollback()
		return fmt.Errorf("clearing agent zones: %w", err)
	}

	for _, zoneID := range zoneIDs {
		if _, err := tx.Exec("INSERT INTO agent_zones (agent_id, zone_id) VALUES (?, ?)", agentID, zoneID); err != nil {
			tx.Rollback()
			return fmt.Errorf("inserting agent zone: %w", err)
		}
	}

	return tx.Commit()
}

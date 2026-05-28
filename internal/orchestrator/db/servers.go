package db

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// CreateServer inserts a new server record.
func (d *DB) CreateServer(s *models.Server) error {
	now := time.Now().UTC()
	s.CreatedAt = now

	_, err := d.sql.Exec(`
		INSERT INTO servers (id, agent_id, name, address, notes, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		s.ID, s.AgentID, s.Name, s.Address, s.Notes, now.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("inserting server: %w", err)
	}
	return nil
}

func scanServer(sc interface {
	Scan(dest ...any) error
}) (*models.Server, error) {
	var s models.Server
	var createdAt string

	err := sc.Scan(&s.ID, &s.AgentID, &s.Name, &s.Address, &s.Notes, &createdAt)
	if err != nil {
		return nil, err
	}

	s.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &s, nil
}

// GetServer retrieves a server by ID.
func (d *DB) GetServer(id string) (*models.Server, error) {
	row := d.sql.QueryRow(`
		SELECT id, agent_id, name, address, notes, created_at
		FROM servers WHERE id = ?`, id)

	s, err := scanServer(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("server not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("querying server: %w", err)
	}
	return s, nil
}

// ListServersByAgent returns all servers belonging to the given agent.
func (d *DB) ListServersByAgent(agentID string) ([]models.Server, error) {
	rows, err := d.sql.Query(`
		SELECT id, agent_id, name, address, notes, created_at
		FROM servers WHERE agent_id = ? ORDER BY created_at`, agentID)
	if err != nil {
		return nil, fmt.Errorf("listing servers: %w", err)
	}
	defer rows.Close()

	var servers []models.Server
	for rows.Next() {
		s, err := scanServer(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning server: %w", err)
		}
		servers = append(servers, *s)
	}
	return servers, rows.Err()
}

// UpdateServer updates a server's mutable fields.
func (d *DB) UpdateServer(s *models.Server) error {
	res, err := d.sql.Exec(`
		UPDATE servers SET name = ?, address = ?, notes = ? WHERE id = ?`,
		s.Name, s.Address, s.Notes, s.ID,
	)
	if err != nil {
		return fmt.Errorf("updating server: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("server not found: %s", s.ID)
	}
	return nil
}

// DeleteServer removes a server by ID.
func (d *DB) DeleteServer(id string) error {
	res, err := d.sql.Exec("DELETE FROM servers WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("deleting server: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("server not found: %s", id)
	}
	return nil
}

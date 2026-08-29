package db

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

func (d *DB) UpsertManagedRouteTombstone(agentID string, deletion helperprotocol.ManagedDeletion, at time.Time) error {
	if !validRecoverySemanticID(agentID) || deletion.Validate() != nil || at.IsZero() {
		return fmt.Errorf("invalid managed route tombstone")
	}
	atNanos, err := recoveryUnixNano(at)
	if err != nil {
		return err
	}
	_, err = d.sql.Exec(`INSERT INTO managed_route_tombstones (agent_id, resource_id, host, backend, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(agent_id, resource_id) DO UPDATE SET
			host = excluded.host, backend = excluded.backend`,
		agentID, deletion.ResourceID, deletion.Host, deletion.Backend, atNanos)
	if err != nil {
		return fmt.Errorf("store managed route tombstone: %w", err)
	}
	return nil
}

func (d *DB) ListManagedRouteTombstones(agentID string) ([]helperprotocol.ManagedDeletion, error) {
	if !validRecoverySemanticID(agentID) {
		return nil, fmt.Errorf("managed route tombstone agent identity is required")
	}
	rows, err := d.read.Query(`SELECT resource_id, host, backend FROM managed_route_tombstones
		WHERE agent_id = ? ORDER BY created_at, resource_id`, agentID)
	if err != nil {
		return nil, fmt.Errorf("list managed route tombstones: %w", err)
	}
	defer rows.Close()
	deletions := make([]helperprotocol.ManagedDeletion, 0)
	for rows.Next() {
		var deletion helperprotocol.ManagedDeletion
		if err := rows.Scan(&deletion.ResourceID, &deletion.Host, &deletion.Backend); err != nil || deletion.Validate() != nil {
			return nil, fmt.Errorf("invalid stored managed route tombstone")
		}
		deletions = append(deletions, deletion)
	}
	return deletions, rows.Err()
}

func (d *DB) DeleteManagedRouteTombstones(agentID string, deletions []helperprotocol.ManagedDeletion) error {
	if !validRecoverySemanticID(agentID) || deletions == nil {
		return fmt.Errorf("invalid managed route tombstone deletion")
	}
	if len(deletions) == 0 {
		return nil
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, deletion := range deletions {
		if deletion.Validate() != nil {
			return fmt.Errorf("invalid managed route tombstone identity")
		}
		result, err := tx.Exec(`DELETE FROM managed_route_tombstones
			WHERE agent_id = ? AND resource_id = ? AND host = ? AND backend = ?`,
			agentID, deletion.ResourceID, deletion.Host, deletion.Backend)
		if err != nil {
			return fmt.Errorf("delete managed route tombstone: %w", err)
		}
		if rows, _ := result.RowsAffected(); rows > 1 {
			return sql.ErrNoRows
		}
	}
	return tx.Commit()
}

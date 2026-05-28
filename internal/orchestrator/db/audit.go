package db

import (
	"fmt"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// InsertAuditLog records a new audit log entry.
func (d *DB) InsertAuditLog(entry *models.AuditLogEntry) error {
	now := time.Now().UTC()
	entry.CreatedAt = now

	res, err := d.sql.Exec(`
		INSERT INTO audit_log (entity_type, entity_id, action, actor, details, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		entry.EntityType, entry.EntityID, entry.Action, entry.Actor, entry.Details,
		now.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("inserting audit log: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("getting audit log id: %w", err)
	}
	entry.ID = id

	return nil
}

// ListAuditLog returns a page of audit log entries (newest first) along with
// the total count of all entries for pagination.
func (d *DB) ListAuditLog(limit, offset int) ([]models.AuditLogEntry, int, error) {
	var total int
	if err := d.sql.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting audit log: %w", err)
	}

	rows, err := d.sql.Query(`
		SELECT id, entity_type, entity_id, action, actor, details, created_at
		FROM audit_log ORDER BY created_at DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("listing audit log: %w", err)
	}
	defer rows.Close()

	var entries []models.AuditLogEntry
	for rows.Next() {
		var e models.AuditLogEntry
		var createdAt string

		if err := rows.Scan(&e.ID, &e.EntityType, &e.EntityID, &e.Action, &e.Actor, &e.Details, &createdAt); err != nil {
			return nil, 0, fmt.Errorf("scanning audit log entry: %w", err)
		}

		e.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		entries = append(entries, e)
	}

	return entries, total, rows.Err()
}

package db

import "fmt"

// PendingParentDeletion is a recorded cascade-delete intent (#104): the parent
// (server/agent/zone) is removed by the reconciler once every domain that
// referenced it has finished its reconciler teardown — never by a raw DB
// cascade, which would orphan managed DNS records and certs at the provider.
type PendingParentDeletion struct {
	// EntityType is "server", "agent" or "zone".
	EntityType string
	// EntityID is the parent's id.
	EntityID string
	// Actor is who requested the cascade (carried into the finalize audit).
	Actor string
}

// AddPendingParentDeletion records (or refreshes) a cascade intent.
func (d *DB) AddPendingParentDeletion(p PendingParentDeletion) error {
	if p.EntityType == "" || p.EntityID == "" {
		return fmt.Errorf("pending parent deletion needs entity type + id")
	}
	_, err := d.sql.Exec(`
		INSERT INTO pending_parent_deletions (entity_type, entity_id, actor)
		VALUES (?, ?, ?)
		ON CONFLICT(entity_type, entity_id) DO UPDATE SET actor = excluded.actor`,
		p.EntityType, p.EntityID, p.Actor)
	if err != nil {
		return fmt.Errorf("recording pending %s deletion for %q: %w", p.EntityType, p.EntityID, err)
	}
	return nil
}

// ListPendingParentDeletions returns every recorded cascade intent.
func (d *DB) ListPendingParentDeletions() ([]PendingParentDeletion, error) {
	rows, err := d.read.Query(`SELECT entity_type, entity_id, actor FROM pending_parent_deletions`)
	if err != nil {
		return nil, fmt.Errorf("listing pending parent deletions: %w", err)
	}
	defer rows.Close()
	var out []PendingParentDeletion
	for rows.Next() {
		var p PendingParentDeletion
		if err := rows.Scan(&p.EntityType, &p.EntityID, &p.Actor); err != nil {
			return nil, fmt.Errorf("scanning pending parent deletion: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RemovePendingParentDeletion drops a cascade intent (after finalization, or
// when the parent turned out to be already gone). Idempotent.
func (d *DB) RemovePendingParentDeletion(entityType, entityID string) error {
	if _, err := d.sql.Exec(`DELETE FROM pending_parent_deletions WHERE entity_type = ? AND entity_id = ?`,
		entityType, entityID); err != nil {
		return fmt.Errorf("removing pending %s deletion for %q: %w", entityType, entityID, err)
	}
	return nil
}

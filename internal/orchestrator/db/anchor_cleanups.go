package db

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrAnchorStale is returned by SetAgentAnchorRecord when the agent was renamed
// or deleted while the reconciler was creating/adopting its anchor record, so
// the record no longer belongs on the agent row.
var ErrAnchorStale = errors.New("agent anchor changed while the record was being resolved")

// AgentAnchorCleanup is an agent anchor record (A or AAAA) released by a rename
// or delete, waiting for the reconciler. Owned records are deleted at the
// provider; adopted ones are only audited and dropped from the queue.
type AgentAnchorCleanup struct {
	ID             int64
	AgentID        string
	FQDN           string
	RecordType     string // "A" or "AAAA"
	RecordID       string
	Owned          bool
	ZoneID         string
	ProviderID     string
	ZoneExternalID string
	Reason         string // "rename", "delete" or "stale"
	Attempts       int
	LastError      string
	CreatedAt      time.Time
}

// anchorColumns maps an address record type to its agent columns.
func anchorColumns(recordType string) (idCol, ownedCol, zoneCol string, err error) {
	switch recordType {
	case "A":
		return "dns_record_id", "dns_record_owned", "dns_record_zone_id", nil
	case "AAAA":
		return "dns_record_id6", "dns_record_owned6", "dns_record_zone_id6", nil
	default:
		return "", "", "", fmt.Errorf("unsupported anchor record type %q", recordType)
	}
}

// SetAgentAnchorRecord stores the A or AAAA anchor record the reconciler just
// created (owned=true) or adopted (owned=false) for the agent, together with
// the zone it lives in. It is a narrow update, so it does not clobber fields
// that concurrent heartbeats write.
//
// fqdn is the name the record was resolved for. If the agent has been renamed
// or deleted since, nothing is written to the agent row: an owned record is
// queued for cleanup instead and ErrAnchorStale is returned.
//
// Adopting a record that is still queued for cleanup (the agent was renamed
// back before the old record was deleted) takes it back out of the queue and
// keeps its original ownership, so NurProxy never deletes a record it is using
// and does not forget that it created it.
//
// The returned bool is the ownership actually stored.
func (d *DB) SetAgentAnchorRecord(agentID, fqdn, recordType, recordID, zoneID string, owned bool) (bool, error) {
	idCol, ownedCol, zoneCol, err := anchorColumns(recordType)
	if err != nil {
		return false, err
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return false, fmt.Errorf("beginning anchor update: %w", err)
	}
	defer tx.Rollback()

	if !owned {
		var queuedID int64
		var queuedOwned int
		qErr := tx.QueryRow(`
			SELECT id, owned FROM agent_anchor_cleanups
			WHERE record_id = ? AND zone_id = ? AND record_type = ?`,
			recordID, zoneID, recordType).Scan(&queuedID, &queuedOwned)
		switch {
		case qErr == nil:
			if _, err := tx.Exec(`DELETE FROM agent_anchor_cleanups WHERE id = ?`, queuedID); err != nil {
				return false, fmt.Errorf("reclaiming queued anchor record: %w", err)
			}
			owned = queuedOwned != 0
		case !errors.Is(qErr, sql.ErrNoRows):
			return false, fmt.Errorf("checking anchor cleanup queue: %w", qErr)
		}
	}

	var currentFQDN string
	fErr := tx.QueryRow(`SELECT fqdn FROM agents WHERE id = ?`, agentID).Scan(&currentFQDN)
	if fErr != nil && !errors.Is(fErr, sql.ErrNoRows) {
		return false, fmt.Errorf("reading agent fqdn: %w", fErr)
	}
	if errors.Is(fErr, sql.ErrNoRows) || currentFQDN != fqdn {
		if owned {
			if err := queueAnchorCleanupTx(tx, AgentAnchorCleanup{
				AgentID: agentID, FQDN: fqdn, RecordType: recordType, RecordID: recordID,
				Owned: true, ZoneID: zoneID, Reason: "stale",
			}); err != nil {
				return false, err
			}
		}
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("committing stale anchor: %w", err)
		}
		return owned, ErrAnchorStale
	}

	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := tx.Exec(
		`UPDATE agents SET `+idCol+` = ?, `+ownedCol+` = ?, `+zoneCol+` = ?, updated_at = ? WHERE id = ?`,
		recordID, boolToInt(owned), zoneID, now, agentID,
	); err != nil {
		return false, fmt.Errorf("updating agent %s record: %w", recordType, err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("committing anchor update: %w", err)
	}
	return owned, nil
}

// releaseAgentAnchorsTx moves the agent's current A/AAAA anchor records into
// agent_anchor_cleanups and clears the anchor columns. Owned and adopted
// records are both queued so the reconciler can audit what it keeps as well as
// what it deletes. A missing agent row is not an error here; the caller reports
// it.
func releaseAgentAnchorsTx(tx *sql.Tx, agentID, reason string) error {
	var fqdn, id4, zone4, id6, zone6 string
	var owned4, owned6 int
	err := tx.QueryRow(`
		SELECT fqdn, dns_record_id, dns_record_owned, dns_record_zone_id,
			dns_record_id6, dns_record_owned6, dns_record_zone_id6
		FROM agents WHERE id = ?`, agentID).
		Scan(&fqdn, &id4, &owned4, &zone4, &id6, &owned6, &zone6)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading agent anchors: %w", err)
	}
	for _, c := range []AgentAnchorCleanup{
		{RecordType: "A", RecordID: id4, Owned: owned4 != 0, ZoneID: zone4},
		{RecordType: "AAAA", RecordID: id6, Owned: owned6 != 0, ZoneID: zone6},
	} {
		if c.RecordID == "" {
			continue
		}
		c.AgentID, c.FQDN, c.Reason = agentID, fqdn, reason
		if err := queueAnchorCleanupTx(tx, c); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`
		UPDATE agents SET dns_record_id = '', dns_record_owned = 0, dns_record_zone_id = '',
			dns_record_id6 = '', dns_record_owned6 = 0, dns_record_zone_id6 = ''
		WHERE id = ?`, agentID); err != nil {
		return fmt.Errorf("clearing agent anchors: %w", err)
	}
	return nil
}

// queueAnchorCleanupTx inserts one cleanup row, snapshotting the zone's
// provider and external zone id so the delete later goes to the original
// provider/zone even if the zone row changes or disappears. A record already
// queued (same zone + record id) is left as it is.
func queueAnchorCleanupTx(tx *sql.Tx, c AgentAnchorCleanup) error {
	if c.ZoneID != "" && c.ProviderID == "" {
		zErr := tx.QueryRow(`SELECT provider_id, external_id FROM zones WHERE id = ?`, c.ZoneID).
			Scan(&c.ProviderID, &c.ZoneExternalID)
		if zErr != nil && !errors.Is(zErr, sql.ErrNoRows) {
			return fmt.Errorf("reading zone %s for anchor cleanup: %w", c.ZoneID, zErr)
		}
	}
	if _, err := tx.Exec(`
		INSERT INTO agent_anchor_cleanups
			(agent_id, fqdn, record_type, record_id, owned, zone_id, provider_id, zone_external_id, reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(zone_id, record_id) DO NOTHING`,
		c.AgentID, c.FQDN, c.RecordType, c.RecordID, boolToInt(c.Owned),
		c.ZoneID, c.ProviderID, c.ZoneExternalID, c.Reason,
	); err != nil {
		return fmt.Errorf("queueing %s anchor cleanup for agent %s: %w", c.RecordType, c.AgentID, err)
	}
	return nil
}

// ListAgentAnchorCleanups returns every queued anchor cleanup, oldest first.
func (d *DB) ListAgentAnchorCleanups() ([]AgentAnchorCleanup, error) {
	rows, err := d.read.Query(`
		SELECT id, agent_id, fqdn, record_type, record_id, owned, zone_id,
			provider_id, zone_external_id, reason, attempts, last_error, created_at
		FROM agent_anchor_cleanups ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("listing anchor cleanups: %w", err)
	}
	defer rows.Close()
	var out []AgentAnchorCleanup
	for rows.Next() {
		var c AgentAnchorCleanup
		var owned int
		var createdAt string
		if err := rows.Scan(&c.ID, &c.AgentID, &c.FQDN, &c.RecordType, &c.RecordID, &owned,
			&c.ZoneID, &c.ProviderID, &c.ZoneExternalID, &c.Reason, &c.Attempts, &c.LastError,
			&createdAt); err != nil {
			return nil, fmt.Errorf("scanning anchor cleanup: %w", err)
		}
		c.Owned = owned != 0
		c.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
		out = append(out, c)
	}
	return out, rows.Err()
}

// RemoveAgentAnchorCleanup drops a queued cleanup once it is done.
func (d *DB) RemoveAgentAnchorCleanup(id int64) error {
	if _, err := d.sql.Exec(`DELETE FROM agent_anchor_cleanups WHERE id = ?`, id); err != nil {
		return fmt.Errorf("removing anchor cleanup %d: %w", id, err)
	}
	return nil
}

// RecordAgentAnchorCleanupFailure counts a failed attempt and stores its error,
// keeping the row for the next reconcile cycle.
func (d *DB) RecordAgentAnchorCleanupFailure(id int64, msg string) error {
	if _, err := d.sql.Exec(`
		UPDATE agent_anchor_cleanups SET attempts = attempts + 1, last_error = ? WHERE id = ?`,
		msg, id); err != nil {
		return fmt.Errorf("recording anchor cleanup failure %d: %w", id, err)
	}
	return nil
}

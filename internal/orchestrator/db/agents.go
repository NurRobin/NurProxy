package db

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// CreateAgent inserts a new agent record.
func (d *DB) CreateAgent(a *models.Agent) error {
	now := time.Now().UTC()
	a.CreatedAt = now
	a.UpdatedAt = now

	var lastSeen *string
	if a.LastSeen != nil {
		s := a.LastSeen.UTC().Format(time.RFC3339)
		lastSeen = &s
	}

	_, err := d.sql.Exec(`
		INSERT INTO agents (id, name, fqdn, api_url, token_hash, dns_mode,
			ddns_interval, public_ip, dns_record_id, status, last_seen, version, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Name, a.FQDN, a.APIURL, a.TokenHash,
		string(a.DNSMode), a.DDNSInterval, a.PublicIP, a.DNSRecordID,
		string(a.Status), lastSeen, a.Version,
		now.Format(time.RFC3339), now.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("inserting agent: %w", err)
	}
	return nil
}

// scanAgent reads a single agent row from a *sql.Row or *sql.Rows scanner.
func scanAgent(sc interface {
	Scan(dest ...any) error
}) (*models.Agent, error) {
	var a models.Agent
	var lastSeen sql.NullString
	var createdAt, updatedAt string

	err := sc.Scan(
		&a.ID, &a.Name, &a.FQDN, &a.APIURL, &a.TokenHash,
		&a.DNSMode, &a.DDNSInterval, &a.PublicIP, &a.DNSRecordID,
		&a.Status, &lastSeen, &a.Version, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	a.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	a.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	if lastSeen.Valid {
		t, _ := time.Parse(time.RFC3339, lastSeen.String)
		a.LastSeen = &t
	}

	return &a, nil
}

const agentColumns = `id, name, fqdn, api_url, token_hash, dns_mode,
	ddns_interval, public_ip, dns_record_id, status, last_seen, version,
	created_at, updated_at`

// GetAgent retrieves an agent by ID.
func (d *DB) GetAgent(id string) (*models.Agent, error) {
	row := d.sql.QueryRow(
		"SELECT "+agentColumns+" FROM agents WHERE id = ?", id)

	a, err := scanAgent(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("agent not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("querying agent: %w", err)
	}
	return a, nil
}

// GetAgentByFQDN retrieves an agent by its unique FQDN.
func (d *DB) GetAgentByFQDN(fqdn string) (*models.Agent, error) {
	row := d.sql.QueryRow(
		"SELECT "+agentColumns+" FROM agents WHERE fqdn = ?", fqdn)

	a, err := scanAgent(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("agent not found with fqdn: %s", fqdn)
	}
	if err != nil {
		return nil, fmt.Errorf("querying agent by fqdn: %w", err)
	}
	return a, nil
}

// ListAgents returns all agents ordered by creation time.
func (d *DB) ListAgents() ([]models.Agent, error) {
	rows, err := d.sql.Query(
		"SELECT " + agentColumns + " FROM agents ORDER BY created_at")
	if err != nil {
		return nil, fmt.Errorf("listing agents: %w", err)
	}
	defer rows.Close()

	var agents []models.Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning agent: %w", err)
		}
		agents = append(agents, *a)
	}
	return agents, rows.Err()
}

// UpdateAgent updates all mutable fields of an existing agent.
func (d *DB) UpdateAgent(a *models.Agent) error {
	a.UpdatedAt = time.Now().UTC()

	var lastSeen *string
	if a.LastSeen != nil {
		s := a.LastSeen.UTC().Format(time.RFC3339)
		lastSeen = &s
	}

	res, err := d.sql.Exec(`
		UPDATE agents
		SET name = ?, fqdn = ?, api_url = ?, token_hash = ?,
			dns_mode = ?, ddns_interval = ?, public_ip = ?, dns_record_id = ?,
			status = ?, last_seen = ?, version = ?, updated_at = ?
		WHERE id = ?`,
		a.Name, a.FQDN, a.APIURL, a.TokenHash,
		string(a.DNSMode), a.DDNSInterval, a.PublicIP, a.DNSRecordID,
		string(a.Status), lastSeen, a.Version, a.UpdatedAt.Format(time.RFC3339),
		a.ID,
	)
	if err != nil {
		return fmt.Errorf("updating agent: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("agent not found: %s", a.ID)
	}
	return nil
}

// DeleteAgent removes an agent by ID. Cascades to servers and their domains.
func (d *DB) DeleteAgent(id string) error {
	res, err := d.sql.Exec("DELETE FROM agents WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("deleting agent: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("agent not found: %s", id)
	}
	return nil
}

// UpdateAgentStatus sets the status field and touches updated_at.
func (d *DB) UpdateAgentStatus(id string, status models.AgentStatus) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.sql.Exec(`
		UPDATE agents SET status = ?, updated_at = ? WHERE id = ?`,
		string(status), now, id,
	)
	if err != nil {
		return fmt.Errorf("updating agent status: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("agent not found: %s", id)
	}
	return nil
}

// UpdateAgentDNSRecord sets only the dns_record_id for an agent. Using a narrow
// update (rather than a full-row UpdateAgent) avoids clobbering fields like
// public_ip/last_seen that concurrent heartbeats write.
func (d *DB) UpdateAgentDNSRecord(id string, recordID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.sql.Exec(`
		UPDATE agents SET dns_record_id = ?, updated_at = ? WHERE id = ?`,
		recordID, now, id,
	)
	if err != nil {
		return fmt.Errorf("updating agent DNS record: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("agent not found: %s", id)
	}
	return nil
}

// UpdateAgentHeartbeat updates the last_seen timestamp and public IP.
func (d *DB) UpdateAgentHeartbeat(id string, ip string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.sql.Exec(`
		UPDATE agents SET last_seen = ?, public_ip = ?, updated_at = ? WHERE id = ?`,
		now, ip, now, id,
	)
	if err != nil {
		return fmt.Errorf("updating agent heartbeat: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("agent not found: %s", id)
	}
	return nil
}

// ListPendingAgents returns all agents with status "pending".
func (d *DB) ListPendingAgents() ([]models.Agent, error) {
	rows, err := d.sql.Query(
		"SELECT "+agentColumns+" FROM agents WHERE status = ? ORDER BY created_at",
		string(models.AgentStatusPending))
	if err != nil {
		return nil, fmt.Errorf("listing pending agents: %w", err)
	}
	defer rows.Close()

	var agents []models.Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning agent: %w", err)
		}
		agents = append(agents, *a)
	}
	return agents, rows.Err()
}

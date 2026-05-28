package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// DomainFilter controls which domains are returned by ListDomains.
type DomainFilter struct {
	AgentID  string
	ServerID string
	Status   string
}

// CreateDomain inserts a new domain record. ProxyConfig is marshaled to JSON.
func (d *DB) CreateDomain(dom *models.Domain) error {
	now := time.Now().UTC()
	dom.CreatedAt = now
	dom.UpdatedAt = now

	pcJSON, err := json.Marshal(dom.ProxyConfig)
	if err != nil {
		return fmt.Errorf("marshaling proxy config: %w", err)
	}

	var lastSynced *string
	if dom.LastSynced != nil {
		s := dom.LastSynced.UTC().Format(time.RFC3339)
		lastSynced = &s
	}

	boolToInt := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}

	res, err := d.sql.Exec(`
		INSERT INTO domains (subdomain, zone_id, server_id, port, proxy_config,
			manual_config, websocket, force_https, ssl_mode, dns_record_id,
			status, error_msg, last_synced, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		dom.Subdomain, dom.ZoneID, dom.ServerID, dom.Port, string(pcJSON),
		boolToInt(dom.ManualConfig), boolToInt(dom.WebSocket), boolToInt(dom.ForceHTTPS),
		string(dom.SSLMode), dom.DNSRecordID,
		string(dom.Status), dom.ErrorMsg, lastSynced,
		now.Format(time.RFC3339), now.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("inserting domain: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("getting domain id: %w", err)
	}
	dom.ID = id

	return nil
}

func scanDomain(sc interface {
	Scan(dest ...any) error
}) (*models.Domain, error) {
	var dom models.Domain
	var pcJSON string
	var manualConfig, websocket, forceHTTPS int
	var lastSynced sql.NullString
	var createdAt, updatedAt string

	err := sc.Scan(
		&dom.ID, &dom.Subdomain, &dom.ZoneID, &dom.ServerID, &dom.Port,
		&pcJSON, &manualConfig, &websocket, &forceHTTPS,
		&dom.SSLMode, &dom.DNSRecordID, &dom.Status, &dom.ErrorMsg,
		&lastSynced, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	dom.ManualConfig = manualConfig != 0
	dom.WebSocket = websocket != 0
	dom.ForceHTTPS = forceHTTPS != 0
	dom.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	dom.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	if lastSynced.Valid {
		t, _ := time.Parse(time.RFC3339, lastSynced.String)
		dom.LastSynced = &t
	}

	if err := json.Unmarshal([]byte(pcJSON), &dom.ProxyConfig); err != nil {
		return nil, fmt.Errorf("unmarshaling proxy config: %w", err)
	}

	return &dom, nil
}

const domainColumns = `id, subdomain, zone_id, server_id, port, proxy_config,
	manual_config, websocket, force_https, ssl_mode, dns_record_id, status,
	error_msg, last_synced, created_at, updated_at`

// GetDomain retrieves a domain by its auto-incremented ID.
func (d *DB) GetDomain(id int64) (*models.Domain, error) {
	row := d.sql.QueryRow(
		"SELECT "+domainColumns+" FROM domains WHERE id = ?", id,
	)

	dom, err := scanDomain(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("domain not found: %d", id)
	}
	if err != nil {
		return nil, fmt.Errorf("querying domain: %w", err)
	}
	return dom, nil
}

// ListDomains returns domains matching the given filter. An empty filter field
// means "no constraint" for that dimension.
func (d *DB) ListDomains(filter DomainFilter) ([]models.Domain, error) {
	query := "SELECT " + domainColumns + " FROM domains"
	var conditions []string
	var args []any

	if filter.ServerID != "" {
		conditions = append(conditions, "server_id = ?")
		args = append(args, filter.ServerID)
	}
	if filter.Status != "" {
		conditions = append(conditions, "status = ?")
		args = append(args, filter.Status)
	}
	if filter.AgentID != "" {
		conditions = append(conditions, "server_id IN (SELECT id FROM servers WHERE agent_id = ?)")
		args = append(args, filter.AgentID)
	}

	if len(conditions) > 0 {
		query += " WHERE "
		for i, c := range conditions {
			if i > 0 {
				query += " AND "
			}
			query += c
		}
	}
	query += " ORDER BY created_at"

	rows, err := d.sql.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing domains: %w", err)
	}
	defer rows.Close()

	var domains []models.Domain
	for rows.Next() {
		dom, err := scanDomain(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning domain: %w", err)
		}
		domains = append(domains, *dom)
	}
	return domains, rows.Err()
}

// UpdateDomain updates all mutable fields of a domain.
func (d *DB) UpdateDomain(dom *models.Domain) error {
	dom.UpdatedAt = time.Now().UTC()

	pcJSON, err := json.Marshal(dom.ProxyConfig)
	if err != nil {
		return fmt.Errorf("marshaling proxy config: %w", err)
	}

	var lastSynced *string
	if dom.LastSynced != nil {
		s := dom.LastSynced.UTC().Format(time.RFC3339)
		lastSynced = &s
	}

	boolToInt := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}

	res, err := d.sql.Exec(`
		UPDATE domains
		SET subdomain = ?, zone_id = ?, server_id = ?, port = ?, proxy_config = ?,
			manual_config = ?, websocket = ?, force_https = ?, ssl_mode = ?,
			dns_record_id = ?, status = ?, error_msg = ?, last_synced = ?, updated_at = ?
		WHERE id = ?`,
		dom.Subdomain, dom.ZoneID, dom.ServerID, dom.Port, string(pcJSON),
		boolToInt(dom.ManualConfig), boolToInt(dom.WebSocket), boolToInt(dom.ForceHTTPS),
		string(dom.SSLMode), dom.DNSRecordID, string(dom.Status), dom.ErrorMsg,
		lastSynced, dom.UpdatedAt.Format(time.RFC3339), dom.ID,
	)
	if err != nil {
		return fmt.Errorf("updating domain: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("domain not found: %d", dom.ID)
	}
	return nil
}

// DeleteDomain removes a domain by ID.
func (d *DB) DeleteDomain(id int64) error {
	res, err := d.sql.Exec("DELETE FROM domains WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("deleting domain: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("domain not found: %d", id)
	}
	return nil
}

// UpdateDomainStatus sets the status and optional error message.
func (d *DB) UpdateDomainStatus(id int64, status models.DomainStatus, errMsg string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.sql.Exec(`
		UPDATE domains SET status = ?, error_msg = ?, updated_at = ? WHERE id = ?`,
		string(status), errMsg, now, id,
	)
	if err != nil {
		return fmt.Errorf("updating domain status: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("domain not found: %d", id)
	}
	return nil
}

// MarkDomainSynced marks a domain as active, clears any error message, and
// stamps last_synced with the current time. Used by the reconciler after a
// successful sync cycle.
func (d *DB) MarkDomainSynced(id int64) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.sql.Exec(`
		UPDATE domains SET status = ?, error_msg = '', last_synced = ?, updated_at = ? WHERE id = ?`,
		string(models.DomainStatusActive), now, now, id,
	)
	if err != nil {
		return fmt.Errorf("marking domain synced: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("domain not found: %d", id)
	}
	return nil
}

// UpdateDomainDNSRecord sets the dns_record_id for a domain.
func (d *DB) UpdateDomainDNSRecord(id int64, recordID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.sql.Exec(`
		UPDATE domains SET dns_record_id = ?, updated_at = ? WHERE id = ?`,
		recordID, now, id,
	)
	if err != nil {
		return fmt.Errorf("updating domain DNS record: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("domain not found: %d", id)
	}
	return nil
}

// ListDomainsByAgent returns all domains whose server belongs to the given agent.
func (d *DB) ListDomainsByAgent(agentID string) ([]models.Domain, error) {
	// Qualify all column references with d. to avoid ambiguity with the servers join.
	qualifiedColumns := `d.id, d.subdomain, d.zone_id, d.server_id, d.port, d.proxy_config,
		d.manual_config, d.websocket, d.force_https, d.ssl_mode, d.dns_record_id, d.status,
		d.error_msg, d.last_synced, d.created_at, d.updated_at`

	rows, err := d.sql.Query(`
		SELECT `+qualifiedColumns+`
		FROM domains d
		JOIN servers s ON d.server_id = s.id
		WHERE s.agent_id = ?
		ORDER BY d.created_at`, agentID)
	if err != nil {
		return nil, fmt.Errorf("listing domains by agent: %w", err)
	}
	defer rows.Close()

	var domains []models.Domain
	for rows.Next() {
		dom, err := scanDomain(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning domain: %w", err)
		}
		domains = append(domains, *dom)
	}
	return domains, rows.Err()
}

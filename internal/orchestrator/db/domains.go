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
	ZoneID   string
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
			status, error_msg, last_synced, created_at, updated_at, dns_managed,
			cert_only, proxied)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		dom.Subdomain, dom.ZoneID, dom.ServerID, dom.Port, string(pcJSON),
		boolToInt(dom.ManualConfig), boolToInt(dom.WebSocket), boolToInt(dom.ForceHTTPS),
		string(dom.SSLMode), dom.DNSRecordID,
		string(dom.Status), dom.ErrorMsg, lastSynced,
		now.Format(time.RFC3339), now.Format(time.RFC3339), boolToInt(dom.DNSManaged),
		boolToInt(dom.CertOnly), nullableBool(dom.Proxied),
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
	var manualConfig, websocket, forceHTTPS, dnsManaged, certOnly int
	var proxied sql.NullInt64
	var lastSynced sql.NullString
	var createdAt, updatedAt string

	err := sc.Scan(
		&dom.ID, &dom.Subdomain, &dom.ZoneID, &dom.ServerID, &dom.Port,
		&pcJSON, &manualConfig, &websocket, &forceHTTPS,
		&dom.SSLMode, &dom.DNSRecordID, &dom.Status, &dom.ErrorMsg,
		&lastSynced, &createdAt, &updatedAt, &dnsManaged, &certOnly, &proxied,
	)
	if err != nil {
		return nil, err
	}

	dom.ManualConfig = manualConfig != 0
	dom.WebSocket = websocket != 0
	dom.ForceHTTPS = forceHTTPS != 0
	dom.DNSManaged = dnsManaged != 0
	dom.CertOnly = certOnly != 0
	if proxied.Valid {
		p := proxied.Int64 != 0
		dom.Proxied = &p
	}
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
	error_msg, last_synced, created_at, updated_at, dns_managed, cert_only, proxied`

// GetDomain retrieves a domain by its auto-incremented ID.
func (d *DB) GetDomain(id int64) (*models.Domain, error) {
	row := d.read.QueryRow(
		"SELECT "+domainColumns+" FROM domains WHERE id = ?", id,
	)

	dom, err := scanDomain(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: %d", ErrDomainNotFound, id)
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
	if filter.ZoneID != "" {
		conditions = append(conditions, "zone_id = ?")
		args = append(args, filter.ZoneID)
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

	rows, err := d.read.Query(query, args...)
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
//
// When the update changes the domain's name (subdomain or zone), the DNS record
// stored for the old name is released in the same transaction: it is queued in
// domain_dns_cleanups (snapshotting the old zone's provider) and the domain's
// dns_record_id / dns_managed are cleared, so the reconciler resolves the new
// name from scratch and deletes the old record only if NurProxy created it
// (#151). Otherwise dns_record_id / dns_managed are never written here; dom's
// copies are refreshed from the row.
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

	tx, err := d.sql.Begin()
	if err != nil {
		return fmt.Errorf("beginning domain update: %w", err)
	}
	defer tx.Rollback()
	released, err := releaseRenamedDomainRecordTx(tx, dom)
	if err != nil {
		return err
	}

	// dns_record_id / dns_managed belong to the reconciler (UpdateDomainDNSRecord,
	// SetDomainDNSRecordIfNamed, AdoptDomainDNSRecord). An update only clears
	// them when it releases the record on a rename; otherwise it keeps what is
	// stored, so an update built from a row loaded before the reconciler stored
	// a fresh record cannot erase that record (or its ownership).
	res, err := tx.Exec(`
		UPDATE domains
		SET subdomain = ?, zone_id = ?, server_id = ?, port = ?, proxy_config = ?,
			manual_config = ?, websocket = ?, force_https = ?, ssl_mode = ?,
			dns_record_id = CASE WHEN ? THEN '' ELSE dns_record_id END,
			status = ?, error_msg = ?, last_synced = ?, updated_at = ?,
			dns_managed = CASE WHEN ? THEN 0 ELSE dns_managed END, proxied = ?
		WHERE id = ?`,
		dom.Subdomain, dom.ZoneID, dom.ServerID, dom.Port, string(pcJSON),
		boolToInt(dom.ManualConfig), boolToInt(dom.WebSocket), boolToInt(dom.ForceHTTPS),
		string(dom.SSLMode), boolToInt(released), string(dom.Status), dom.ErrorMsg,
		lastSynced, dom.UpdatedAt.Format(time.RFC3339), boolToInt(released),
		nullableBool(dom.Proxied), dom.ID,
	)
	if err != nil {
		return fmt.Errorf("updating domain: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("domain not found: %d", dom.ID)
	}
	var managed int
	if err := tx.QueryRow(`SELECT dns_record_id, dns_managed FROM domains WHERE id = ?`, dom.ID).
		Scan(&dom.DNSRecordID, &managed); err != nil {
		return fmt.Errorf("reading stored DNS record of domain %d: %w", dom.ID, err)
	}
	dom.DNSManaged = managed != 0
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing domain update: %w", err)
	}
	return nil
}

// nullableBool maps a tri-state bool to SQL: nil -> NULL, else 0/1.
func nullableBool(b *bool) any {
	if b == nil {
		return nil
	}
	if *b {
		return 1
	}
	return 0
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

// MarkDomainApplied records a successful route apply. For a domain that wants a
// central-TLS certificate (wantsCentralTLS), it first checks whether one has
// actually been issued for fqdn: if not, the agent is serving the route over
// plaintext HTTP (TLS and any force_https redirect were dropped), so the domain
// is marked "degraded" with an explanatory error rather than a bare "active"
// that would hide the downgrade (§78). Otherwise the domain is marked active.
func (d *DB) MarkDomainApplied(id int64, fqdn string, wantsCentralTLS bool) error {
	if wantsCentralTLS {
		// Distinguish a genuinely absent certificate (degrade — the route is
		// served plaintext) from a transient DB read error (propagate — do not
		// mislabel a healthy domain as degraded). A bare existence probe avoids
		// the key decryption that GetCertificate performs and lets sql.ErrNoRows
		// cleanly signal not-found.
		var dummy int
		err := d.read.QueryRow(
			"SELECT 1 FROM certificates WHERE host = ?", fqdn,
		).Scan(&dummy)
		switch {
		case err == sql.ErrNoRows:
			now := time.Now().UTC().Format(time.RFC3339)
			res, xErr := d.sql.Exec(`
				UPDATE domains SET status = ?, error_msg = ?, last_synced = ?, updated_at = ? WHERE id = ?`,
				string(models.DomainStatusDegraded),
				"served over plaintext HTTP — no TLS certificate issued yet; force_https not enforced",
				now, now, id,
			)
			if xErr != nil {
				return fmt.Errorf("marking domain degraded: %w", xErr)
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return fmt.Errorf("domain not found: %d", id)
			}
			return nil
		case err != nil:
			return fmt.Errorf("checking central-TLS certificate for %s: %w", fqdn, err)
		}
	}
	return d.MarkDomainSynced(id)
}

// UpdateDomainDNSRecord stores the provider record id for a domain and records
// whether NurProxy created that record (managed=true) or adopted a pre-existing
// matching one (managed=false). Only created records are deleted on teardown.
func (d *DB) UpdateDomainDNSRecord(id int64, recordID string, managed bool) error {
	now := time.Now().UTC().Format(time.RFC3339)
	managedInt := 0
	if managed {
		managedInt = 1
	}
	res, err := d.sql.Exec(`
		UPDATE domains SET dns_record_id = ?, dns_managed = ?, updated_at = ? WHERE id = ?`,
		recordID, managedInt, now, id,
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
		d.error_msg, d.last_synced, d.created_at, d.updated_at, d.dns_managed, d.cert_only, d.proxied`

	rows, err := d.read.Query(`
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

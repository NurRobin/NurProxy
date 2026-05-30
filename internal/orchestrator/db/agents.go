package db

import (
	"database/sql"
	"encoding/json"
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

	det := encodeDetection(a.ProxyDetection)
	var detectedAt *string
	if a.ProxyDetectedAt != nil {
		s := a.ProxyDetectedAt.UTC().Format(time.RFC3339)
		detectedAt = &s
	}
	caps := encodeCapabilities(a.ProxyCapabilities)

	_, err := d.sql.Exec(`
		INSERT INTO agents (id, name, fqdn, api_url, token_hash, dns_mode,
			ddns_interval, public_ip, dns_record_id, status, last_seen, version,
			caddy_running, last_error, dns_error,
			detected_proxy_kind, detected_proxy_version, detected_binary_path,
			detected_config_dir, detected_log_paths, detected_port_conflicts,
			detected_installed, detected_at, detected_capabilities,
			auto_reconcile_config,
			created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Name, a.FQDN, a.APIURL, a.TokenHash,
		string(a.DNSMode), a.DDNSInterval, a.PublicIP, a.DNSRecordID,
		string(a.Status), lastSeen, a.Version,
		boolToInt(a.CaddyRunning), a.LastError, a.DNSError,
		det.kind, det.version, det.binaryPath, det.configDir,
		det.logPaths, det.portConflicts, det.installed, detectedAt, caps,
		boolToInt(a.AutoReconcileConfig),
		now.Format(time.RFC3339), now.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("inserting agent: %w", err)
	}
	return nil
}

// detectionCols holds a ProxyDetection flattened to its stored column values.
type detectionCols struct {
	kind          string
	version       string
	binaryPath    string
	configDir     string
	logPaths      string // JSON array
	portConflicts string // JSON array
	installed     int
}

// encodeDetection flattens a ProxyDetection into its stored column values. A nil
// detection encodes to all-empty columns (installed=0, empty JSON), so a row
// that never reported detection round-trips back to a nil ProxyDetection.
func encodeDetection(d *models.ProxyDetection) detectionCols {
	if d == nil {
		return detectionCols{}
	}
	logs := ""
	if len(d.LogPaths) > 0 {
		if b, err := json.Marshal(d.LogPaths); err == nil {
			logs = string(b)
		}
	}
	conflicts := ""
	if len(d.PortConflicts) > 0 {
		if b, err := json.Marshal(d.PortConflicts); err == nil {
			conflicts = string(b)
		}
	}
	return detectionCols{
		kind:          d.Kind,
		version:       d.Version,
		binaryPath:    d.BinaryPath,
		configDir:     d.ConfigDir,
		logPaths:      logs,
		portConflicts: conflicts,
		installed:     boolToInt(d.Installed),
	}
}

// decodeDetection rebuilds a ProxyDetection from its stored columns. It returns
// nil when no detection has ever been reported (the all-empty zero state), so
// callers can distinguish "never reported" from "reported nothing installed".
func decodeDetection(c detectionCols, detectedAt sql.NullString) (*models.ProxyDetection, *time.Time) {
	var at *time.Time
	if detectedAt.Valid && detectedAt.String != "" {
		if t, err := time.Parse(time.RFC3339, detectedAt.String); err == nil {
			at = &t
		}
	}
	// Nothing was ever reported: leave detection nil.
	if at == nil && c.installed == 0 && c.kind == "" && c.version == "" &&
		c.binaryPath == "" && c.configDir == "" && c.logPaths == "" && c.portConflicts == "" {
		return nil, nil
	}
	d := &models.ProxyDetection{
		Installed:  c.installed != 0,
		Kind:       c.kind,
		Version:    c.version,
		BinaryPath: c.binaryPath,
		ConfigDir:  c.configDir,
	}
	if c.logPaths != "" {
		_ = json.Unmarshal([]byte(c.logPaths), &d.LogPaths)
	}
	if c.portConflicts != "" {
		_ = json.Unmarshal([]byte(c.portConflicts), &d.PortConflicts)
	}
	return d, at
}

// encodeCapabilities flattens a ProxyCapabilities into the JSON stored in the
// detected_capabilities column. A nil matrix encodes to a NULL (untyped nil), so
// an agent that never reported capabilities round-trips back to a nil matrix
// (distinguishable from "reported nothing supported").
func encodeCapabilities(c *models.ProxyCapabilities) any {
	if c == nil {
		return nil
	}
	b, err := json.Marshal(c)
	if err != nil {
		return nil
	}
	return string(b)
}

// decodeCapabilities rebuilds a ProxyCapabilities from the stored JSON. A NULL or
// empty column decodes to nil ("never reported"), letting callers distinguish it
// from a reported all-false matrix.
func decodeCapabilities(s sql.NullString) *models.ProxyCapabilities {
	if !s.Valid || s.String == "" {
		return nil
	}
	var c models.ProxyCapabilities
	if err := json.Unmarshal([]byte(s.String), &c); err != nil {
		return nil
	}
	return &c
}

// encodePermissions flattens the agent's §12 permission self-test to a JSON
// string column value, or nil (SQL NULL) when there is nothing to store (built-in
// mode). decodePermissions is its inverse.
func encodePermissions(p *models.ProxyPermissions) any {
	if p == nil {
		return nil
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil
	}
	return string(b)
}
func decodePermissions(s sql.NullString) *models.ProxyPermissions {
	if !s.Valid || s.String == "" {
		return nil
	}
	var p models.ProxyPermissions
	if err := json.Unmarshal([]byte(s.String), &p); err != nil {
		return nil
	}
	return &p
}

// scanAgent reads a single agent row from a *sql.Row or *sql.Rows scanner.
func scanAgent(sc interface {
	Scan(dest ...any) error
}) (*models.Agent, error) {
	var a models.Agent
	var lastSeen sql.NullString
	var createdAt, updatedAt string
	var caddyRunning int
	var det detectionCols
	var detectedAt sql.NullString
	var capabilities sql.NullString
	var autoReconcile int
	var permissions sql.NullString

	err := sc.Scan(
		&a.ID, &a.Name, &a.FQDN, &a.APIURL, &a.TokenHash,
		&a.DNSMode, &a.DDNSInterval, &a.PublicIP, &a.DNSRecordID,
		&a.Status, &lastSeen, &a.Version, &caddyRunning, &a.LastError,
		&a.DNSError,
		&det.kind, &det.version, &det.binaryPath, &det.configDir,
		&det.logPaths, &det.portConflicts, &det.installed, &detectedAt,
		&capabilities,
		&autoReconcile,
		&a.ProxyMode, &permissions,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	a.CaddyRunning = caddyRunning != 0
	a.AutoReconcileConfig = autoReconcile != 0
	a.ProxyDetection, a.ProxyDetectedAt = decodeDetection(det, detectedAt)
	a.ProxyCapabilities = decodeCapabilities(capabilities)
	a.ProxyPermissions = decodePermissions(permissions)

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
	caddy_running, last_error, dns_error,
	detected_proxy_kind, detected_proxy_version, detected_binary_path,
	detected_config_dir, detected_log_paths, detected_port_conflicts,
	detected_installed, detected_at, detected_capabilities,
	auto_reconcile_config,
	proxy_mode, proxy_permissions,
	created_at, updated_at`

// boolToInt maps a bool to SQLite's integer boolean representation.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

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

	det := encodeDetection(a.ProxyDetection)
	var detectedAt *string
	if a.ProxyDetectedAt != nil {
		s := a.ProxyDetectedAt.UTC().Format(time.RFC3339)
		detectedAt = &s
	}
	caps := encodeCapabilities(a.ProxyCapabilities)

	res, err := d.sql.Exec(`
		UPDATE agents
		SET name = ?, fqdn = ?, api_url = ?, token_hash = ?,
			dns_mode = ?, ddns_interval = ?, public_ip = ?, dns_record_id = ?,
			status = ?, last_seen = ?, version = ?, caddy_running = ?,
			last_error = ?, dns_error = ?,
			detected_proxy_kind = ?, detected_proxy_version = ?,
			detected_binary_path = ?, detected_config_dir = ?,
			detected_log_paths = ?, detected_port_conflicts = ?,
			detected_installed = ?, detected_at = ?, detected_capabilities = ?,
			auto_reconcile_config = ?,
			updated_at = ?
		WHERE id = ?`,
		a.Name, a.FQDN, a.APIURL, a.TokenHash,
		string(a.DNSMode), a.DDNSInterval, a.PublicIP, a.DNSRecordID,
		string(a.Status), lastSeen, a.Version, boolToInt(a.CaddyRunning),
		a.LastError, a.DNSError,
		det.kind, det.version, det.binaryPath, det.configDir,
		det.logPaths, det.portConflicts, det.installed, detectedAt, caps,
		boolToInt(a.AutoReconcileConfig),
		a.UpdatedAt.Format(time.RFC3339),
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

// UpdateAgentHeartbeat updates the last_seen timestamp and public IP. A blank
// IP leaves the stored value untouched (so a transient detection failure on the
// agent doesn't erase a known-good address).
func (d *DB) UpdateAgentHeartbeat(id string, ip string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.sql.Exec(`
		UPDATE agents
		SET last_seen = ?, public_ip = CASE WHEN ? != '' THEN ? ELSE public_ip END,
			updated_at = ?
		WHERE id = ?`,
		now, ip, ip, now, id,
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

// UpdateAgentHealth records a full heartbeat from the agent: it refreshes
// last_seen, the public IP, and the agent's self-reported Caddy state, last
// error, and current live proxy mode (§19). It is a narrow update so it doesn't
// clobber fields (name, fqdn, zones, dns_record_id) owned by the orchestrator. A
// blank IP is ignored; a blank proxyMode leaves the stored mode untouched (so an
// older agent that doesn't report it doesn't reset the row to built-in).
func (d *DB) UpdateAgentHealth(id, ip, lastError string, caddyRunning bool, proxyMode string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.sql.Exec(`
		UPDATE agents
		SET last_seen = ?, public_ip = CASE WHEN ? != '' THEN ? ELSE public_ip END,
			caddy_running = ?, last_error = ?,
			proxy_mode = CASE WHEN ? != '' THEN ? ELSE proxy_mode END,
			updated_at = ?
		WHERE id = ?`,
		now, ip, ip, boolToInt(caddyRunning), lastError, proxyMode, proxyMode, now, id,
	)
	if err != nil {
		return fmt.Errorf("updating agent health: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("agent not found: %s", id)
	}
	return nil
}

// UpdateAgentDetection records the agent's read-only Phase-0 proxy detection
// (§13.0, §2.1, §9): installed proxy kind + version, config dir / binary / log
// paths, and the :80/:443 bind-conflict holders. It is a narrow update (touches
// only the detected_* columns + updated_at) so it never clobbers operator-owned
// fields (name, fqdn, zones) or the agent's own liveness/health self-report. A
// nil detection clears the stored values. detected_at is stamped to now so the
// dashboard can show staleness.
func (d *DB) UpdateAgentDetection(id string, det *models.ProxyDetection) error {
	now := time.Now().UTC().Format(time.RFC3339)
	c := encodeDetection(det)
	res, err := d.sql.Exec(`
		UPDATE agents
		SET detected_proxy_kind = ?, detected_proxy_version = ?,
			detected_binary_path = ?, detected_config_dir = ?,
			detected_log_paths = ?, detected_port_conflicts = ?,
			detected_installed = ?, detected_at = ?, updated_at = ?
		WHERE id = ?`,
		c.kind, c.version, c.binaryPath, c.configDir,
		c.logPaths, c.portConflicts, c.installed, now, now, id,
	)
	if err != nil {
		return fmt.Errorf("updating agent detection: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("agent not found: %s", id)
	}
	return nil
}

// UpdateAgentCapabilities records the agent's reported capability matrix (§8) for
// its selected backend, including module-probed options (e.g. caddy-ratelimit).
// It is a narrow update (touches only detected_capabilities + updated_at) so it
// never clobbers operator-owned fields or the agent's liveness/health self-report
// written by the same heartbeat. A nil matrix clears the stored value.
func (d *DB) UpdateAgentCapabilities(id string, caps *models.ProxyCapabilities) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.sql.Exec(`
		UPDATE agents SET detected_capabilities = ?, updated_at = ? WHERE id = ?`,
		encodeCapabilities(caps), now, id,
	)
	if err != nil {
		return fmt.Errorf("updating agent capabilities: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("agent not found: %s", id)
	}
	return nil
}

// UpdateAgentPermissions records the agent's §12 permission self-test (config-dir
// writable? service reloadable? + remediation) reported each heartbeat in
// existing mode. It is a narrow update (touches only proxy_permissions +
// updated_at) so it never clobbers operator-owned fields or the liveness/health
// self-report written by the same beat. A nil report stores SQL NULL, which is
// the correct "no permission state" for built-in mode.
func (d *DB) UpdateAgentPermissions(id string, perms *models.ProxyPermissions) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.sql.Exec(`
		UPDATE agents SET proxy_permissions = ?, updated_at = ? WHERE id = ?`,
		encodePermissions(perms), now, id,
	)
	if err != nil {
		return fmt.Errorf("updating agent permissions: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("agent not found: %s", id)
	}
	return nil
}

// SetAgentAutoReconcileConfig toggles the opt-in per-agent "auto-reconcile
// config" policy (§11). When enabled the reconciler re-applies generated
// artifacts over on-disk drift instead of flagging it for review (hands-off
// mode). It is a narrow update so it never clobbers the agent's liveness/health
// self-report. DNS reconciliation is unaffected (always automatic).
func (d *DB) SetAgentAutoReconcileConfig(id string, enabled bool) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.sql.Exec(`
		UPDATE agents SET auto_reconcile_config = ?, updated_at = ? WHERE id = ?`,
		boolToInt(enabled), now, id,
	)
	if err != nil {
		return fmt.Errorf("updating agent auto-reconcile policy: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("agent not found: %s", id)
	}
	return nil
}

// SetAgentDNSError records an orchestrator-side DNS/config error about an agent
// (e.g. its FQDN is outside every assigned zone). Passing an empty string
// clears it. It touches only dns_error (not last_seen or last_error), so it
// won't affect liveness or stomp the agent's own self-report.
func (d *DB) SetAgentDNSError(id, dnsError string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.sql.Exec(`
		UPDATE agents SET dns_error = ?, updated_at = ? WHERE id = ?`,
		dnsError, now, id,
	)
	if err != nil {
		return fmt.Errorf("updating agent dns error: %w", err)
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

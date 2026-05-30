package db

import "fmt"

// migrations is an ordered list of SQL statements. Each entry corresponds to a
// schema version (1-indexed). They are executed inside a transaction when the
// current schema_version is lower than the list length.
var migrations = []string{
	// Migration 001: initial schema
	`
	CREATE TABLE IF NOT EXISTS providers (
		id         TEXT PRIMARY KEY,
		type       TEXT NOT NULL,
		name       TEXT NOT NULL,
		config     TEXT NOT NULL,
		zone_id    TEXT NOT NULL DEFAULT '',
		zone_name  TEXT NOT NULL DEFAULT '',
		is_default INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL DEFAULT (datetime('now'))
	);

	CREATE TABLE IF NOT EXISTS agents (
		id            TEXT PRIMARY KEY,
		name          TEXT NOT NULL,
		fqdn          TEXT NOT NULL UNIQUE,
		api_url       TEXT NOT NULL DEFAULT '',
		token_hash    TEXT NOT NULL DEFAULT '',
		provider_id   TEXT NOT NULL DEFAULT '' REFERENCES providers(id),
		dns_mode      TEXT NOT NULL DEFAULT 'static',
		ddns_interval INTEGER NOT NULL DEFAULT 300,
		public_ip     TEXT NOT NULL DEFAULT '',
		dns_record_id TEXT NOT NULL DEFAULT '',
		status        TEXT NOT NULL DEFAULT 'pending',
		last_seen     TEXT,
		version       TEXT NOT NULL DEFAULT '',
		created_at    TEXT NOT NULL DEFAULT (datetime('now')),
		updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
	);

	CREATE TABLE IF NOT EXISTS servers (
		id         TEXT PRIMARY KEY,
		agent_id   TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
		name       TEXT NOT NULL,
		address    TEXT NOT NULL,
		notes      TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL DEFAULT (datetime('now'))
	);

	CREATE TABLE IF NOT EXISTS domains (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		subdomain     TEXT NOT NULL,
		provider_id   TEXT NOT NULL REFERENCES providers(id),
		server_id     TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
		port          INTEGER NOT NULL DEFAULT 80,
		proxy_config  TEXT NOT NULL DEFAULT '{}',
		manual_config INTEGER NOT NULL DEFAULT 0,
		websocket     INTEGER NOT NULL DEFAULT 0,
		force_https   INTEGER NOT NULL DEFAULT 0,
		ssl_mode      TEXT NOT NULL DEFAULT 'auto',
		dns_record_id TEXT NOT NULL DEFAULT '',
		status        TEXT NOT NULL DEFAULT 'pending',
		error_msg     TEXT NOT NULL DEFAULT '',
		last_synced   TEXT,
		created_at    TEXT NOT NULL DEFAULT (datetime('now')),
		updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
		UNIQUE(subdomain, provider_id)
	);

	CREATE TABLE IF NOT EXISTS notifiers (
		id         TEXT PRIMARY KEY,
		type       TEXT NOT NULL,
		name       TEXT NOT NULL,
		config     TEXT NOT NULL DEFAULT '{}',
		events     TEXT NOT NULL DEFAULT '[]',
		enabled    INTEGER NOT NULL DEFAULT 1,
		created_at TEXT NOT NULL DEFAULT (datetime('now'))
	);

	CREATE TABLE IF NOT EXISTS audit_log (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		entity_type TEXT NOT NULL,
		entity_id   TEXT NOT NULL,
		action      TEXT NOT NULL,
		actor       TEXT NOT NULL DEFAULT '',
		details     TEXT NOT NULL DEFAULT '',
		created_at  TEXT NOT NULL DEFAULT (datetime('now'))
	);

	CREATE TABLE IF NOT EXISTS settings (
		key        TEXT PRIMARY KEY,
		value      TEXT NOT NULL DEFAULT '',
		updated_at TEXT NOT NULL DEFAULT (datetime('now'))
	);

	-- Seed default settings
	INSERT OR IGNORE INTO settings (key, value) VALUES ('mcp_enabled', 'false');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('reconciler_interval', '60');
	`,

	// Migration 002: allow NULL provider_id on agents (pre-adoption agents have no provider)
	`
	CREATE TABLE agents_new (
		id            TEXT PRIMARY KEY,
		name          TEXT NOT NULL,
		fqdn          TEXT NOT NULL UNIQUE,
		api_url       TEXT NOT NULL DEFAULT '',
		token_hash    TEXT NOT NULL DEFAULT '',
		provider_id   TEXT DEFAULT '' REFERENCES providers(id),
		dns_mode      TEXT NOT NULL DEFAULT 'static',
		ddns_interval INTEGER NOT NULL DEFAULT 300,
		public_ip     TEXT NOT NULL DEFAULT '',
		dns_record_id TEXT NOT NULL DEFAULT '',
		status        TEXT NOT NULL DEFAULT 'pending',
		last_seen     TEXT,
		version       TEXT NOT NULL DEFAULT '',
		created_at    TEXT NOT NULL DEFAULT (datetime('now')),
		updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
	);

	INSERT INTO agents_new SELECT * FROM agents;
	DROP TABLE agents;
	ALTER TABLE agents_new RENAME TO agents;
	`,

	// Migration 003: separate zones from providers, agent-zone many-to-many
	`
	-- 1. Create zones table. Use provider.id as zone.id for seamless data migration
	--    (since old model was 1:1 provider-to-zone).
	CREATE TABLE IF NOT EXISTS zones (
		id          TEXT PRIMARY KEY,
		provider_id TEXT NOT NULL REFERENCES providers(id),
		external_id TEXT NOT NULL DEFAULT '',
		name        TEXT NOT NULL DEFAULT '',
		created_at  TEXT NOT NULL DEFAULT (datetime('now'))
	);

	-- 2. Create agent_zones junction table for many-to-many.
	CREATE TABLE IF NOT EXISTS agent_zones (
		agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
		zone_id  TEXT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
		PRIMARY KEY (agent_id, zone_id)
	);

	-- 3. Migrate existing provider zone data into zones table.
	--    Use provider.id as zone.id so existing domain.provider_id values
	--    will remain valid as zone_id references.
	INSERT OR IGNORE INTO zones (id, provider_id, external_id, name, created_at)
	SELECT id, id, zone_id, zone_name, created_at FROM providers
	WHERE zone_id != '' OR zone_name != '';

	-- 4. Migrate agent.provider_id into agent_zones entries.
	INSERT OR IGNORE INTO agent_zones (agent_id, zone_id)
	SELECT id, provider_id FROM agents
	WHERE provider_id IS NOT NULL AND provider_id != ''
	AND provider_id IN (SELECT id FROM zones);

	-- 5. Recreate domains table with zone_id instead of provider_id.
	CREATE TABLE domains_new (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		subdomain     TEXT NOT NULL,
		zone_id       TEXT NOT NULL DEFAULT '' REFERENCES zones(id),
		server_id     TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
		port          INTEGER NOT NULL DEFAULT 80,
		proxy_config  TEXT NOT NULL DEFAULT '{}',
		manual_config INTEGER NOT NULL DEFAULT 0,
		websocket     INTEGER NOT NULL DEFAULT 0,
		force_https   INTEGER NOT NULL DEFAULT 0,
		ssl_mode      TEXT NOT NULL DEFAULT 'auto',
		dns_record_id TEXT NOT NULL DEFAULT '',
		status        TEXT NOT NULL DEFAULT 'pending',
		error_msg     TEXT NOT NULL DEFAULT '',
		last_synced   TEXT,
		created_at    TEXT NOT NULL DEFAULT (datetime('now')),
		updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
		UNIQUE(subdomain, zone_id)
	);
	INSERT INTO domains_new (id, subdomain, zone_id, server_id, port, proxy_config,
		manual_config, websocket, force_https, ssl_mode, dns_record_id, status,
		error_msg, last_synced, created_at, updated_at)
	SELECT id, subdomain, provider_id, server_id, port, proxy_config,
		manual_config, websocket, force_https, ssl_mode, dns_record_id, status,
		error_msg, last_synced, created_at, updated_at
	FROM domains;
	DROP TABLE domains;
	ALTER TABLE domains_new RENAME TO domains;

	-- 6. Recreate agents table without provider_id.
	CREATE TABLE agents_new (
		id            TEXT PRIMARY KEY,
		name          TEXT NOT NULL,
		fqdn          TEXT NOT NULL UNIQUE,
		api_url       TEXT NOT NULL DEFAULT '',
		token_hash    TEXT NOT NULL DEFAULT '',
		dns_mode      TEXT NOT NULL DEFAULT 'static',
		ddns_interval INTEGER NOT NULL DEFAULT 300,
		public_ip     TEXT NOT NULL DEFAULT '',
		dns_record_id TEXT NOT NULL DEFAULT '',
		status        TEXT NOT NULL DEFAULT 'pending',
		last_seen     TEXT,
		version       TEXT NOT NULL DEFAULT '',
		created_at    TEXT NOT NULL DEFAULT (datetime('now')),
		updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
	);
	INSERT INTO agents_new (id, name, fqdn, api_url, token_hash,
		dns_mode, ddns_interval, public_ip, dns_record_id, status,
		last_seen, version, created_at, updated_at)
	SELECT id, name, fqdn, api_url, token_hash,
		dns_mode, ddns_interval, public_ip, dns_record_id, status,
		last_seen, version, created_at, updated_at
	FROM agents;
	DROP TABLE agents;
	ALTER TABLE agents_new RENAME TO agents;

	-- 7. Recreate providers table without zone_id/zone_name.
	CREATE TABLE providers_new (
		id         TEXT PRIMARY KEY,
		type       TEXT NOT NULL,
		name       TEXT NOT NULL,
		config     TEXT NOT NULL,
		is_default INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL DEFAULT (datetime('now'))
	);
	INSERT INTO providers_new (id, type, name, config, is_default, created_at)
	SELECT id, type, name, config, is_default, created_at FROM providers;
	DROP TABLE providers;
	ALTER TABLE providers_new RENAME TO providers;
	`,

	// Migration 004: agent self-reported health (caddy state + last error), an
	// orchestrator-side DNS/config error channel, and a heartbeat-staleness
	// timeout that drives offline detection.
	//
	// last_error and dns_error are kept separate so the two writers never clobber
	// each other: the agent owns last_error (via heartbeat), the orchestrator
	// owns dns_error (via the reconciler).
	`
	ALTER TABLE agents ADD COLUMN caddy_running INTEGER NOT NULL DEFAULT 1;
	ALTER TABLE agents ADD COLUMN last_error TEXT NOT NULL DEFAULT '';
	ALTER TABLE agents ADD COLUMN dns_error TEXT NOT NULL DEFAULT '';

	INSERT OR IGNORE INTO settings (key, value) VALUES ('agent_offline_timeout', '90');
	`,

	// Migration 005: categorize audit-log entries by source channel
	// (ui/api/mcp/agent/system) so the log distinguishes where each action
	// originated.
	`
	ALTER TABLE audit_log ADD COLUMN source TEXT NOT NULL DEFAULT '';
	`,

	// Migration 006: store the agent's Phase-0 read-only proxy detection (§13.0,
	// §2.1, §9) on the agent row. The agent dials out and reports which proxy is
	// installed (kind + version), the discovered config dir / binary / log paths,
	// and which process holds :80/:443; the orchestrator persists it here and
	// exposes it read-only so the dashboard can show "nginx 1.24 at /etc/nginx".
	//
	// Scalars get their own columns (queryable); the list-valued fields
	// (log_paths, port_conflicts) are stored as JSON. detected_at records when the
	// last detection report arrived (NULL until the first one).
	`
	ALTER TABLE agents ADD COLUMN detected_proxy_kind     TEXT NOT NULL DEFAULT '';
	ALTER TABLE agents ADD COLUMN detected_proxy_version  TEXT NOT NULL DEFAULT '';
	ALTER TABLE agents ADD COLUMN detected_binary_path    TEXT NOT NULL DEFAULT '';
	ALTER TABLE agents ADD COLUMN detected_config_dir     TEXT NOT NULL DEFAULT '';
	ALTER TABLE agents ADD COLUMN detected_log_paths      TEXT NOT NULL DEFAULT '';
	ALTER TABLE agents ADD COLUMN detected_port_conflicts TEXT NOT NULL DEFAULT '';
	ALTER TABLE agents ADD COLUMN detected_installed      INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE agents ADD COLUMN detected_at             TEXT;
	`,

	// Migration 007: store the agent's reported capability matrix (§8) on the
	// agent row. The agent reports which proxy options its selected backend
	// supports — including module-probed ones (e.g. is caddy-ratelimit compiled
	// in?) — at adoption and on every heartbeat. The orchestrator persists it here
	// (a single JSON blob, since it is read as a unit by the dashboard) and exposes
	// it read-only so unsupported options are greyed out per the selected backend.
	// NULL until the first capability report arrives.
	`
	ALTER TABLE agents ADD COLUMN detected_capabilities TEXT;
	`,

	// Migration 008: the central managed-config store (§4, §11, Phase 3). The
	// agent renders native config and round-trips the rendered artifact back here
	// (B1, §3); the orchestrator versions, diffs, backs up, rolls back, and
	// drift-reviews it. Built-in Caddy participates with target_kind ==
	// "caddy-route" and content == route JSON.
	//
	// config_artifacts holds the live/accepted state of each artifact (one row
	// per managed config); config_artifact_versions is the append-only full
	// content history (a new row only on semantic change, §4 — no pruning).
	// domain_id is nullable: set for generated (model-backed) artifacts, NULL for
	// manual/adopted ones. live_version references the version currently on disk.
	`
	CREATE TABLE IF NOT EXISTS config_artifacts (
		id            TEXT PRIMARY KEY,
		agent_id      TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
		backend       TEXT NOT NULL,
		target_kind   TEXT NOT NULL,
		target_path   TEXT NOT NULL,
		source        TEXT NOT NULL DEFAULT 'generated',
		domain_id     INTEGER REFERENCES domains(id) ON DELETE SET NULL,
		content       TEXT NOT NULL DEFAULT '',
		checksum      TEXT NOT NULL DEFAULT '',
		live_version  INTEGER NOT NULL DEFAULT 0,
		enabled       INTEGER NOT NULL DEFAULT 1,
		drifted       INTEGER NOT NULL DEFAULT 0,
		apply_state   TEXT NOT NULL DEFAULT 'live',
		last_error    TEXT NOT NULL DEFAULT '',
		updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
		UNIQUE(agent_id, target_kind, target_path)
	);

	CREATE INDEX IF NOT EXISTS idx_config_artifacts_agent  ON config_artifacts(agent_id);
	CREATE INDEX IF NOT EXISTS idx_config_artifacts_domain ON config_artifacts(domain_id);

	CREATE TABLE IF NOT EXISTS config_artifact_versions (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		artifact_id TEXT NOT NULL REFERENCES config_artifacts(id) ON DELETE CASCADE,
		version     INTEGER NOT NULL,
		content     TEXT NOT NULL DEFAULT '',
		checksum    TEXT NOT NULL DEFAULT '',
		source      TEXT NOT NULL DEFAULT 'generated',
		actor       TEXT NOT NULL DEFAULT '',
		note        TEXT NOT NULL DEFAULT '',
		created_at  TEXT NOT NULL DEFAULT (datetime('now')),
		UNIQUE(artifact_id, version)
	);

	CREATE INDEX IF NOT EXISTS idx_config_artifact_versions_artifact
		ON config_artifact_versions(artifact_id);
	`,

	// Migration 009: opt-in per-agent "auto-reconcile config" policy (§11). By
	// default drift is a review, not a bulldoze: NurProxy never overwrites an
	// artifact the operator changed on-disk without an explicit Accept. An operator
	// who wants the old hands-off behavior sets this flag on the agent, restoring
	// automatic re-apply of generated artifacts over drift. DNS reconciliation is
	// unaffected (it stays automatic regardless).
	`
	ALTER TABLE agents ADD COLUMN auto_reconcile_config INTEGER NOT NULL DEFAULT 0;
	`,

	// Migration 010: central TLS cert store (§7). The orchestrator issues certs
	// centrally via DNS-01 and stores cert+key here. The private key is encrypted
	// at rest with the existing AES-256-GCM key (cert_pem is public, stored plain;
	// key_pem_enc is the base64 AES-256-GCM ciphertext). Per-host certs by default;
	// is_wildcard flags the opt-in shared-key case. names is a JSON array of all
	// SANs covered. expires_at drives ≥30-day-early renewal.
	`
	CREATE TABLE IF NOT EXISTS certificates (
		id          TEXT PRIMARY KEY,
		host        TEXT NOT NULL,
		names       TEXT NOT NULL DEFAULT '[]',
		is_wildcard INTEGER NOT NULL DEFAULT 0,
		cert_pem    TEXT NOT NULL,
		key_pem_enc TEXT NOT NULL,
		issued_at   TEXT NOT NULL DEFAULT (datetime('now')),
		expires_at  TEXT NOT NULL DEFAULT '',
		updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
		UNIQUE(host)
	);

	CREATE INDEX IF NOT EXISTS idx_certificates_expires ON certificates(expires_at);
	`,

	// Migration 11: agent admin-change channel (§19). A generic "pending agent
	// admin op" gated by a short-lived, single-use confirmation code. Only the
	// hash of the code is ever stored; the plaintext is shown once at mint time.
	// op_type drives the payload schema (e.g. set_proxy_mode). status walks
	// pending -> applied | expired | canceled.
	`
	CREATE TABLE IF NOT EXISTS agent_admin_ops (
		id         TEXT PRIMARY KEY,
		agent_id   TEXT NOT NULL,
		op_type    TEXT NOT NULL,
		payload    TEXT NOT NULL DEFAULT '{}',
		code_hash  TEXT NOT NULL,
		status     TEXT NOT NULL DEFAULT 'pending',
		result     TEXT NOT NULL DEFAULT '',
		created_by TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		applied_at TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_agent_admin_ops_agent_status
		ON agent_admin_ops(agent_id, status);
	`,

	// Migration 12: store the agent's CURRENT live reverse-proxy mode (§19) on the
	// agent row. After a hot-switch to Existing mode the agent reports its mode via
	// heartbeat; the orchestrator persists it here and exposes it so the dashboard
	// reflects reality (existing vs built-in) instead of always assuming built-in.
	// Defaults to 'built-in' for every existing row.
	`
	ALTER TABLE agents ADD COLUMN proxy_mode TEXT NOT NULL DEFAULT 'built-in';
	`,

	// Migration 13: store the agent's §12 permission self-test (config-dir writable?
	// service reloadable?) + targeted remediation as a JSON blob on the agent row.
	// The agent re-probes each heartbeat in existing mode; the orchestrator persists
	// the latest so the dashboard can show exactly which grant is missing and the
	// fix. NULL means built-in mode / not yet reported.
	`
	ALTER TABLE agents ADD COLUMN proxy_permissions TEXT;
	`,

	// Migration 14: capture the drifted on-disk content (§11). The heartbeat now
	// ships the on-disk bytes when they diverge from the accepted state; we store
	// them here (separate from content, which stays the accepted state) so the
	// dashboard can show a real accepted-vs-on-disk diff and Accept can persist the
	// operator's edit. Empty when the artifact is in agreement.
	`
	ALTER TABLE config_artifacts ADD COLUMN drift_content TEXT NOT NULL DEFAULT '';
	`,
}

// migrate applies any outstanding migrations. It uses a simple
// schema_version table to track which migrations have already run.
func (d *DB) migrate() error {
	// Ensure the version tracking table exists.
	if _, err := d.sql.Exec(`
		CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("creating schema_version table: %w", err)
	}

	var current int
	row := d.sql.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version")
	if err := row.Scan(&current); err != nil {
		return fmt.Errorf("reading schema version: %w", err)
	}

	for i := current; i < len(migrations); i++ {
		tx, err := d.sql.Begin()
		if err != nil {
			return fmt.Errorf("beginning migration %d: %w", i+1, err)
		}

		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("executing migration %d: %w", i+1, err)
		}

		if _, err := tx.Exec("INSERT INTO schema_version (version) VALUES (?)", i+1); err != nil {
			tx.Rollback()
			return fmt.Errorf("recording migration %d: %w", i+1, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing migration %d: %w", i+1, err)
		}
	}

	return nil
}

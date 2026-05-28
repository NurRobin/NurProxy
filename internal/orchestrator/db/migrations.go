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

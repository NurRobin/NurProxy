// Package db provides the SQLite persistence layer for the orchestrator.
package db

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// DB wraps a SQLite connection and an encryption key for provider configs.
type DB struct {
	sql       *sql.DB
	cryptoKey []byte
}

// Open opens (or creates) a SQLite database at dbPath, enables recommended
// pragmas, and runs any pending schema migrations. cryptoKey is the AES-256
// key used to encrypt/decrypt provider configurations at rest.
func Open(dbPath string, cryptoKey []byte) (*DB, error) {
	sqlDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Enable WAL mode for better concurrent read performance.
	if _, err := sqlDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("enabling WAL: %w", err)
	}

	// Enforce foreign key constraints.
	if _, err := sqlDB.Exec("PRAGMA foreign_keys=ON"); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("enabling foreign keys: %w", err)
	}

	// Set a busy timeout to avoid "database is locked" under contention.
	if _, err := sqlDB.Exec("PRAGMA busy_timeout=5000"); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("setting busy timeout: %w", err)
	}

	d := &DB{
		sql:       sqlDB,
		cryptoKey: cryptoKey,
	}

	if err := d.migrate(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return d, nil
}

// Close closes the underlying database connection.
func (d *DB) Close() error {
	return d.sql.Close()
}

// SnapshotTo opens the database at srcPath and writes a consistent, standalone
// snapshot to destPath via SQLite's VACUUM INTO. It runs no migrations and needs
// no encryption key — it copies the (already-encrypted) bytes verbatim — and is
// safe to run against a live WAL database from a separate process: the result is
// a fully checkpointed single file with no -wal/-shm sidecars. destPath must not
// already exist (VACUUM INTO refuses to overwrite).
func SnapshotTo(srcPath, destPath string) error {
	conn, err := sql.Open("sqlite", srcPath)
	if err != nil {
		return fmt.Errorf("opening source database: %w", err)
	}
	defer conn.Close()

	if _, err := conn.Exec("VACUUM INTO ?", destPath); err != nil {
		return fmt.Errorf("snapshotting database: %w", err)
	}
	return nil
}

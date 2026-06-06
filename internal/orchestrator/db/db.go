// Package db provides the SQLite persistence layer for the orchestrator.
package db

import (
	"context"
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
	// Pragmas must ride the DSN so EVERY pooled connection gets them. busy_timeout
	// and foreign_keys are per-connection settings: running them once via Exec only
	// configures whichever connection happened to serve that statement, leaving the
	// rest of the pool with busy_timeout=0 — so any concurrent writer that doesn't
	// win the lock immediately returns SQLITE_BUSY ("database is locked") instead of
	// waiting. That surfaced as spurious 500s on domain create under load.
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", dbPath)
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// SQLite allows only one writer at a time. Capping the pool at a single
	// connection serializes all access through it, which (combined with the DSN
	// pragmas above) removes write contention entirely — the orchestrator's load is
	// modest and correctness/latency-stability matters more than read parallelism
	// here. Without this, concurrent writers (API insert + reconciler status updates
	// + N cert-issuance goroutines) race on the WAL writer lock and intermittently
	// fail.
	sqlDB.SetMaxOpenConns(1)

	// Belt-and-suspenders: re-assert WAL on the (single) connection. journal_mode is
	// a persistent database property, so this is effectively idempotent.
	if _, err := sqlDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("enabling WAL: %w", err)
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

// Ping verifies the database is reachable and responsive by running a trivial
// query (not just a pool check), so a wedged or corrupted database surfaces in
// the health endpoint instead of being reported healthy.
func (d *DB) Ping(ctx context.Context) error {
	var n int
	return d.sql.QueryRowContext(ctx, "SELECT 1").Scan(&n)
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

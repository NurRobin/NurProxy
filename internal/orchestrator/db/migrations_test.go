package db

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/crypto"
)

func TestMigration24BackfillsRecoveryOperationTotals(t *testing.T) {
	if len(migrations) < 24 {
		t.Fatalf("expected recovery total rollup migration, have %d migrations", len(migrations))
	}
	dbPath := filepath.Join(t.TempDir(), "recovery-total-upgrade.db")
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", dbPath)
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	raw.SetMaxOpenConns(1)
	if _, err := raw.Exec(`CREATE TABLE schema_version (version INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 23; i++ {
		if _, err := raw.Exec(migrations[i]); err != nil {
			t.Fatalf("applying migration %d: %v", i+1, err)
		}
	}
	if _, err := raw.Exec(`INSERT INTO schema_version (version) VALUES (23)`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO agents (id, name, fqdn) VALUES ('agent-backfill', 'Backfill', 'backfill.example.com')`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO recovery_diagnostics (
		id, agent_id, code, subsystem, severity, ownership, summary, evidence,
		affected_paths, resource_fingerprint, proposed_action, auto_repair_eligible,
		hard_change, first_seen_at, last_seen_at, occurrences
	) VALUES (
		'diagnostic-backfill', 'agent-backfill', 'managed_stale_temp', 'nginx', 'warning',
		'nurproxy', 'stale temp', 'owned marker', '[]', 'fp-backfill',
		'remove_managed_temp', 1, 0, 1, 1, 1
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO recovery_operations (
		id, agent_id, diagnostic_id, action, resource_fingerprint, risk,
		request_source, state, step_summaries, snapshot_reference,
		validation_outcome, rollback_outcome, error, started_at, created_at,
		received_at, finished_at
	) VALUES (
		'op-backfill', 'agent-backfill', 'diagnostic-backfill', 'remove_managed_temp',
		'fp-backfill', 'safe', 'user', 'succeeded', '[]', 'recovery/op-backfill',
		'valid', '', '', 1, 1, 1, 2
	)`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	d, err := Open(dbPath, key)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var count int
	if err := d.sql.QueryRow(`SELECT count FROM recovery_operation_totals
		WHERE action = 'remove_managed_temp' AND outcome = 'succeeded' AND request_source = 'user'`).Scan(&count); err != nil {
		t.Fatalf("reading backfilled recovery operation total: %v", err)
	}
	if count != 1 {
		t.Fatalf("backfilled recovery operation total = %d, want 1", count)
	}
}

// seedSchema14 opens a raw SQLite connection at dbPath, applies the first 14
// migrations verbatim, records schema_version=14, and inserts one fully-linked
// row chain (provider → zone → agent → server → domain) so the upgrade test can
// assert that pre-existing data survives the 15→18 migrations and that the new
// columns appear with their declared defaults. It deliberately does NOT call
// Open() — it stops at exactly the post-migration-14 schema.
func seedSchema14(t *testing.T, dbPath string) {
	t.Helper()
	// Same DSN shape as Open(): foreign_keys ON so the seed chain is validated.
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", dbPath)
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer raw.Close()
	raw.SetMaxOpenConns(1)

	if _, err := raw.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		t.Fatalf("create schema_version: %v", err)
	}
	// Guard: this test pins the pre-0.3.0 baseline at 14. If migrations are ever
	// renumbered below 14 the seed is meaningless, so fail loudly.
	if len(migrations) < 14 {
		t.Fatalf("expected at least 14 migrations, have %d", len(migrations))
	}
	for i := 0; i < 14; i++ {
		if _, err := raw.Exec(migrations[i]); err != nil {
			t.Fatalf("applying migration %d: %v", i+1, err)
		}
	}
	if _, err := raw.Exec(`INSERT INTO schema_version (version) VALUES (14)`); err != nil {
		t.Fatalf("recording version 14: %v", err)
	}

	// Seed a linked chain. Column lists are pinned to the post-migration-14
	// shape so we never depend on later-added columns having defaults.
	if _, err := raw.Exec(`INSERT INTO providers (id, type, name, config) VALUES ('prov1', 'cloudflare', 'CF', '{}')`); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO zones (id, provider_id, external_id, name) VALUES ('zone1', 'prov1', 'ext1', 'example.com')`); err != nil {
		t.Fatalf("seed zone: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO agents (id, name, fqdn) VALUES ('agent1', 'edge1', 'edge1.example.com')`); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO servers (id, agent_id, name, address) VALUES ('srv1', 'agent1', 'app', '10.0.0.5:8080')`); err != nil {
		t.Fatalf("seed server: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO domains (id, subdomain, zone_id, server_id, port) VALUES (1, 'app', 'zone1', 'srv1', 8080)`); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
}

// schemaVersion reads the recorded max schema version.
func schemaVersion(t *testing.T, d *DB) int {
	t.Helper()
	var v int
	if err := d.sql.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&v); err != nil {
		t.Fatalf("read schema version: %v", err)
	}
	return v
}

// TestMigration_UpgradeFrom14 is the permanent regression for the 0.3.0
// migrations (15–18): opening a real on-disk database seeded at the
// post-migration-14 schema must advance it to 18, add the new columns with
// their declared defaults on the pre-existing rows, preserve all seeded data,
// and be a no-op on a second Open().
func TestMigration_UpgradeFrom14(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "upgrade.db")
	seedSchema14(t, dbPath)

	// --- real Open() runs the outstanding migrations ------------------------
	d, err := Open(dbPath, key)
	if err != nil {
		t.Fatalf("Open (first): %v", err)
	}

	if got := schemaVersion(t, d); got != len(migrations) {
		t.Fatalf("schema_version = %d, want %d after upgrade", got, len(migrations))
	}
	if len(migrations) != 24 {
		t.Fatalf("this test pins the schema target at 24 migrations; have %d — update the test", len(migrations))
	}

	// --- new columns exist with the declared defaults on pre-existing rows ---
	// Each entry: a query that selects the new column for the seeded row, the
	// scan destination, and the expected default.
	agentStr := []struct {
		col  string
		want string
	}{
		{"detected_upstreams", ""}, // migration 15
		{"detected_networks", ""},  // migration 16
		{"public_ip6", ""},         // migration 18
		{"dns_record_id6", ""},     // migration 18
		{"token_enc", ""},          // migration 19
	}
	for _, tc := range agentStr {
		t.Run("agent_col_"+tc.col, func(t *testing.T) {
			var got string
			q := fmt.Sprintf("SELECT %s FROM agents WHERE id='agent1'", tc.col)
			if err := d.sql.QueryRow(q).Scan(&got); err != nil {
				t.Fatalf("select %s: %v", tc.col, err)
			}
			if got != tc.want {
				t.Errorf("agents.%s = %q, want %q (default on pre-existing row)", tc.col, got, tc.want)
			}
		})
	}

	// migration 17: domains.dns_managed INTEGER default 0.
	t.Run("domain_dns_managed_default", func(t *testing.T) {
		var dnsManaged int
		if err := d.sql.QueryRow("SELECT dns_managed FROM domains WHERE id=1").Scan(&dnsManaged); err != nil {
			t.Fatalf("select dns_managed: %v", err)
		}
		if dnsManaged != 0 {
			t.Errorf("domains.dns_managed = %d, want 0 (default on pre-existing row)", dnsManaged)
		}
	})

	// migration 20: domains.cert_only INTEGER default 0.
	t.Run("domain_cert_only_default", func(t *testing.T) {
		var certOnly int
		if err := d.sql.QueryRow("SELECT cert_only FROM domains WHERE id=1").Scan(&certOnly); err != nil {
			t.Fatalf("select cert_only: %v", err)
		}
		if certOnly != 0 {
			t.Errorf("domains.cert_only = %d, want 0 (default on pre-existing row)", certOnly)
		}
	})

	// migration 21: cert_backoff table exists and is empty.
	t.Run("cert_backoff_table", func(t *testing.T) {
		var n int
		if err := d.sql.QueryRow("SELECT COUNT(*) FROM cert_backoff").Scan(&n); err != nil {
			t.Fatalf("select from cert_backoff: %v", err)
		}
		if n != 0 {
			t.Errorf("cert_backoff should start empty, has %d rows", n)
		}
	})

	// migration 22: pending_parent_deletions table exists and is empty.
	t.Run("pending_parent_deletions_table", func(t *testing.T) {
		var n int
		if err := d.sql.QueryRow("SELECT COUNT(*) FROM pending_parent_deletions").Scan(&n); err != nil {
			t.Fatalf("select from pending_parent_deletions: %v", err)
		}
		if n != 0 {
			t.Errorf("pending_parent_deletions should start empty, has %d rows", n)
		}
	})

	// migration 23: recovery policy defaults to enabled globally while the
	// per-agent override remains NULL (inherit), and recovery history starts empty.
	t.Run("recovery_defaults", func(t *testing.T) {
		var global string
		if err := d.sql.QueryRow("SELECT value FROM settings WHERE key='safe_auto_repair'").Scan(&global); err != nil {
			t.Fatalf("select safe_auto_repair: %v", err)
		}
		if global != "true" {
			t.Errorf("safe_auto_repair = %q, want true", global)
		}
		var override, capability sql.NullString
		if err := d.sql.QueryRow(`SELECT safe_auto_repair_override, recovery_capability FROM agents WHERE id='agent1'`).
			Scan(&override, &capability); err != nil {
			t.Fatalf("select recovery agent columns: %v", err)
		}
		if override.Valid || capability.Valid {
			t.Errorf("legacy agent recovery columns = (%v, %v), want (NULL, NULL)", override, capability)
		}
		for _, table := range []string{"recovery_diagnostics", "recovery_operations"} {
			var n int
			if err := d.sql.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
				t.Fatalf("select from %s: %v", table, err)
			}
			if n != 0 {
				t.Errorf("%s should start empty, has %d rows", table, n)
			}
		}
	})

	// --- seeded data is preserved -------------------------------------------
	t.Run("data_preserved", func(t *testing.T) {
		var fqdn string
		if err := d.sql.QueryRow("SELECT fqdn FROM agents WHERE id='agent1'").Scan(&fqdn); err != nil {
			t.Fatalf("select agent fqdn: %v", err)
		}
		if fqdn != "edge1.example.com" {
			t.Errorf("agent fqdn = %q, want edge1.example.com", fqdn)
		}
		var sub, zoneID, srvID string
		var port int
		if err := d.sql.QueryRow("SELECT subdomain, zone_id, server_id, port FROM domains WHERE id=1").
			Scan(&sub, &zoneID, &srvID, &port); err != nil {
			t.Fatalf("select domain: %v", err)
		}
		if sub != "app" || zoneID != "zone1" || srvID != "srv1" || port != 8080 {
			t.Errorf("domain row corrupted: sub=%q zone=%q srv=%q port=%d", sub, zoneID, srvID, port)
		}
	})

	if err := d.Close(); err != nil {
		t.Fatalf("close (first): %v", err)
	}

	// --- second Open() is a no-op -------------------------------------------
	d2, err := Open(dbPath, key)
	if err != nil {
		t.Fatalf("Open (second): %v", err)
	}
	defer d2.Close()
	if got := schemaVersion(t, d2); got != len(migrations) {
		t.Fatalf("schema_version = %d after second Open, want %d (must be no-op)", got, len(migrations))
	}
	// The seeded row must still be the only agent — the no-op Open touched nothing.
	var agentCount int
	if err := d2.sql.QueryRow("SELECT COUNT(*) FROM agents").Scan(&agentCount); err != nil {
		t.Fatalf("count agents: %v", err)
	}
	if agentCount != 1 {
		t.Errorf("agent count = %d after second Open, want 1", agentCount)
	}
}

func TestSchemaVersion_readOnly(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "v.db")
	d, err := Open(dbPath, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	current, target, err := SchemaVersion(dbPath)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if current != len(migrations) || target != len(migrations) {
		t.Errorf("SchemaVersion = (%d, %d), want (%d, %d)", current, target, len(migrations), len(migrations))
	}
}

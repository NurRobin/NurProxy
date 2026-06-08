package db

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/crypto"
)

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
	if len(migrations) != 18 {
		t.Fatalf("this test pins the 0.3.0 target at 18 migrations; have %d — update the test", len(migrations))
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

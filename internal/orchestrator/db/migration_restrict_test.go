package db

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/crypto"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// restrictMigrationIndex is the 0-based position of the RESTRICT rebuild, so
// the tests seed exactly the schema before it however migrations get
// renumbered.
func restrictMigrationIndex(t *testing.T) int {
	t.Helper()
	for i, m := range migrations {
		if m == migrationRestrictParentFKs {
			return i
		}
	}
	t.Fatal("RESTRICT rebuild migration not found")
	return 0
}

// seedBeforeRestrict applies every migration before the RESTRICT rebuild to
// a raw database at dbPath, then runs the seed statements. Returns the raw
// handle, still open.
func seedBeforeRestrict(t *testing.T, dbPath string, seed []string) *sql.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", dbPath)
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	raw.SetMaxOpenConns(1)
	if _, err := raw.Exec(`CREATE TABLE schema_version (version INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	n := restrictMigrationIndex(t)
	for i := 0; i < n; i++ {
		if _, err := raw.Exec(migrations[i]); err != nil {
			t.Fatalf("applying migration %d: %v", i+1, err)
		}
	}
	if _, err := raw.Exec(`INSERT INTO schema_version (version) VALUES (?)`, n); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range seed {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	return raw
}

var restrictSeed = []string{
	`INSERT INTO providers (id, type, name, config) VALUES ('prov1', 'cloudflare', 'CF', '{}')`,
	`INSERT INTO zones (id, provider_id, external_id, name) VALUES ('zone1', 'prov1', 'ext1', 'example.com')`,
	`INSERT INTO zones (id, provider_id, external_id, name) VALUES ('zone2', 'prov1', 'ext2', 'example.org')`,
	`INSERT INTO agents (id, name, fqdn, dns_record_owned, dns_record_zone_id) VALUES ('agent1', 'edge1', 'edge1.example.com', 1, 'zone1')`,
	`INSERT INTO agents (id, name, fqdn) VALUES ('agent2', 'edge2', 'edge2.example.com')`,
	`INSERT INTO agents (id, name, fqdn) VALUES ('agent3', 'edge3', 'edge3.example.com')`,
	`INSERT INTO agent_zones (agent_id, zone_id) VALUES ('agent1', 'zone1'), ('agent1', 'zone2'), ('agent2', 'zone1')`,
	`INSERT INTO servers (id, agent_id, name, address, notes, created_at) VALUES ('srv1', 'agent1', 'app', '10.0.0.5:8080', 'main', '2025-01-01 10:00:00')`,
	`INSERT INTO servers (id, agent_id, name, address) VALUES ('srv2', 'agent1', 'api', '10.0.0.6:9000')`,
	`INSERT INTO servers (id, agent_id, name, address) VALUES ('srv3', 'agent2', 'web', '10.0.0.7:80')`,
	`INSERT INTO domains (id, subdomain, zone_id, server_id, port, proxy_config, websocket, ssl_mode, dns_record_id, status, dns_managed, proxied)
		VALUES (1, 'app', 'zone1', 'srv1', 8080, '{"headers":{"X-A":"1"}}', 1, 'auto', 'rec1', 'active', 1, 1)`,
	`INSERT INTO domains (id, subdomain, zone_id, server_id, port, cert_only, status) VALUES (2, 'api', 'zone2', 'srv2', 9000, 1, 'active')`,
	`INSERT INTO domains (id, subdomain, zone_id, server_id, port, status, error_msg) VALUES (3, 'web', 'zone1', 'srv3', 80, 'error', 'boom')`,
	// A deleted domain with the highest id: the rebuild must not hand it out again.
	`INSERT INTO domains (id, subdomain, zone_id, server_id) VALUES (9, 'gone', 'zone1', 'srv1')`,
	`DELETE FROM domains WHERE id = 9`,
	`INSERT INTO certificates (id, host, names, cert_pem, key_pem_enc, source) VALUES ('app.example.com', 'app.example.com', '["app.example.com"]', 'cert', 'key', 'imported')`,
	`INSERT INTO config_artifacts (id, agent_id, backend, target_kind, target_path, domain_id, content, checksum)
		VALUES ('dom-1', 'agent1', 'caddy', 'route', 'app.example.com', 1, 'route', 'sum1')`,
	`INSERT INTO config_artifact_versions (artifact_id, version, content, checksum) VALUES ('dom-1', 1, 'route', 'sum1')`,
	`INSERT INTO managed_route_tombstones (agent_id, resource_id, host, backend, created_at) VALUES ('agent1', 'dom-9', 'gone.example.com', 'nginx', 1700000000)`,
	`INSERT INTO domain_dns_cleanups (domain_id, fqdn, record_id, owned, zone_id, provider_id, zone_external_id) VALUES (9, 'gone.example.com', 'rec9', 1, 'zone1', 'prov1', 'ext1')`,
	`INSERT INTO agent_anchor_cleanups (agent_id, fqdn, record_type, record_id, owned, zone_id) VALUES ('agent-old', 'old.example.com', 'A', 'rec-old', 1, 'zone1')`,
	`INSERT INTO pending_parent_deletions (entity_type, entity_id, actor) VALUES ('server', 'srv2', 'admin')`,
	// An index and a trigger on the rebuilt tables must survive the rebuild.
	`CREATE INDEX idx_test_domains_status ON domains(status)`,
	`CREATE INDEX idx_test_servers_agent ON servers(agent_id)`,
	`CREATE TRIGGER trg_test_domains_port AFTER UPDATE OF port ON domains BEGIN UPDATE domains SET error_msg = 'port changed' WHERE id = NEW.id; END`,
}

var restrictCheckedTables = []string{
	"agents", "agent_zones", "servers", "domains", "zones", "providers",
	"certificates", "config_artifacts", "config_artifact_versions",
	"managed_route_tombstones", "domain_dns_cleanups", "agent_anchor_cleanups",
	"pending_parent_deletions",
}

// dumpTable returns every row of table, in rowid order, as strings.
func dumpTable(t *testing.T, q interface {
	Query(string, ...any) (*sql.Rows, error)
}, table string) [][]string {
	t.Helper()
	return dumpColumns(t, q, table, nil)
}

// dumpColumns is dumpTable limited to cols (all columns when nil), so a
// comparison across an upgrade ignores columns later migrations add.
func dumpColumns(t *testing.T, q interface {
	Query(string, ...any) (*sql.Rows, error)
}, table string, cols []string) [][]string {
	t.Helper()
	sel := "*"
	if len(cols) > 0 {
		sel = `"` + strings.Join(cols, `", "`) + `"`
	}
	order := "rowid"
	if table == "managed_route_tombstones" || table == "agent_zones" || table == "pending_parent_deletions" {
		order = "1, 2"
	}
	rows, err := q.Query(fmt.Sprintf(`SELECT %s FROM %s ORDER BY %s`, sel, table, order))
	if err != nil {
		t.Fatalf("dump %s: %v", table, err)
	}
	defer rows.Close()
	names, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var out [][]string
	for rows.Next() {
		vals := make([]sql.NullString, len(names))
		ptrs := make([]any, len(names))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		row := make([]string, 0, len(names)+1)
		row = append(row, strings.Join(names, ","))
		for _, v := range vals {
			if v.Valid {
				row = append(row, v.String)
			} else {
				row = append(row, "<NULL>")
			}
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func schemaObjects(t *testing.T, q interface {
	Query(string, ...any) (*sql.Rows, error)
}, table string) map[string]string {
	t.Helper()
	rows, err := q.Query(`SELECT type || ':' || name, COALESCE(sql, '') FROM sqlite_master
		WHERE tbl_name = ? AND type IN ('index', 'trigger')`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, s string
		if err := rows.Scan(&name, &s); err != nil {
			t.Fatal(err)
		}
		out[name] = s
	}
	return out
}

func onDeleteActions(t *testing.T, d *DB, table string) map[string]string {
	t.Helper()
	rows, err := d.sql.Query(fmt.Sprintf(`PRAGMA foreign_key_list(%s)`, table))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, seq int
		var parent, from, onUpdate, onDelete, match string
		var to sql.NullString
		if err := rows.Scan(&id, &seq, &parent, &from, &to, &onUpdate, &onDelete, &match); err != nil {
			t.Fatal(err)
		}
		out[from+"->"+parent] = onDelete
	}
	return out
}

// TestMigrationRestrictParentFKs upgrades a database seeded at the schema
// before the rebuild and checks that every row, index and trigger survives,
// the parent references are RESTRICT, and a parent with children can no
// longer be deleted.
func TestMigrationRestrictParentFKs(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "restrict.db")
	raw := seedBeforeRestrict(t, dbPath, restrictSeed)

	before := map[string][][]string{}
	beforeCols := map[string][]string{}
	for _, table := range restrictCheckedTables {
		before[table] = dumpTable(t, raw, table)
		beforeCols[table] = columnNames(t, raw, table)
	}
	objectsBefore := map[string]map[string]string{
		"servers": schemaObjects(t, raw, "servers"),
		"domains": schemaObjects(t, raw, "domains"),
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
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()

	if got := schemaVersion(t, d); got != len(migrations) {
		t.Fatalf("schema_version = %d, want %d", got, len(migrations))
	}

	for _, table := range restrictCheckedTables {
		if got := dumpColumns(t, d.sql, table, beforeCols[table]); !reflect.DeepEqual(got, before[table]) {
			t.Errorf("%s rows changed by the rebuild:\nbefore %v\nafter  %v", table, before[table], got)
		}
	}
	for table, want := range objectsBefore {
		if got := schemaObjects(t, d.sql, table); !reflect.DeepEqual(got, want) {
			t.Errorf("%s indexes/triggers changed:\nbefore %v\nafter  %v", table, want, got)
		}
	}

	wantFKs := map[string]map[string]string{
		"servers": {"agent_id->agents": "RESTRICT"},
		"domains": {"zone_id->zones": "RESTRICT", "server_id->servers": "RESTRICT"},
		// Untouched by the rebuild.
		"config_artifacts": {"agent_id->agents": "CASCADE", "domain_id->domains": "SET NULL"},
		"agent_zones":      {"agent_id->agents": "CASCADE", "zone_id->zones": "CASCADE"},
	}
	for table, want := range wantFKs {
		if got := onDeleteActions(t, d, table); !reflect.DeepEqual(got, want) {
			t.Errorf("%s ON DELETE actions = %v, want %v", table, got, want)
		}
	}

	var fkOn int
	if err := d.sql.QueryRow(`PRAGMA foreign_keys`).Scan(&fkOn); err != nil || fkOn != 1 {
		t.Fatalf("foreign_keys after migration = %d (%v), want 1", fkOn, err)
	}
	violations, err := d.sql.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	if violations.Next() {
		var table, parent string
		var rowid sql.NullInt64
		var fkid int
		_ = violations.Scan(&table, &rowid, &parent, &fkid)
		t.Errorf("foreign_key_check reports %s rowid %v -> %s", table, rowid, parent)
	}
	violations.Close()

	// Parents with children are refused and stay intact.
	if err := d.DeleteServer("srv1"); !errors.Is(err, ErrParentInUse) {
		t.Errorf("DeleteServer with a domain = %v, want ErrParentInUse", err)
	}
	if err := d.DeleteZone("zone1"); !errors.Is(err, ErrParentInUse) {
		t.Errorf("DeleteZone with domains = %v, want ErrParentInUse", err)
	}
	if err := d.DeleteAgent("agent1"); !errors.Is(err, ErrParentInUse) {
		t.Errorf("DeleteAgent with domains = %v, want ErrParentInUse", err)
	}
	if _, err := d.sql.Exec(`DELETE FROM servers WHERE id = 'srv3'`); err == nil {
		t.Error("raw DELETE of a server with a domain succeeded; RESTRICT not enforced")
	}
	for _, table := range []string{"agents", "servers", "domains", "config_artifacts"} {
		if got := dumpColumns(t, d.sql, table, beforeCols[table]); !reflect.DeepEqual(got, before[table]) {
			t.Errorf("%s changed by refused deletes", table)
		}
	}

	// The trigger carried over still fires.
	if _, err := d.sql.Exec(`UPDATE domains SET port = 8081 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	var msg string
	if err := d.sql.QueryRow(`SELECT error_msg FROM domains WHERE id = 1`).Scan(&msg); err != nil || msg != "port changed" {
		t.Errorf("trigger after rebuild: error_msg = %q (%v)", msg, err)
	}

	// AUTOINCREMENT keeps its high-water mark: id 9 was used before.
	dom := &models.Domain{Subdomain: "new", ZoneID: "zone1", ServerID: "srv1", Port: 80, SSLMode: models.SSLModeAuto, Status: models.DomainStatusPending}
	if err := d.CreateDomain(dom); err != nil {
		t.Fatal(err)
	}
	if dom.ID <= 9 {
		t.Errorf("new domain id = %d, want > 9 (sequence reset by the rebuild)", dom.ID)
	}

	// Children first, then the parent: the agent goes with its servers.
	for _, id := range []int64{1, 2, dom.ID} {
		if err := d.DeleteDomain(id); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.DeleteAgent("agent1"); err != nil {
		t.Fatalf("DeleteAgent without domains: %v", err)
	}
	var servers int
	if err := d.sql.QueryRow(`SELECT COUNT(*) FROM servers WHERE agent_id = 'agent1'`).Scan(&servers); err != nil || servers != 0 {
		t.Errorf("agent1 servers after delete = %d (%v), want 0", servers, err)
	}
	var artifactDomain sql.NullInt64
	if err := d.sql.QueryRow(`SELECT COUNT(*) FROM config_artifacts WHERE id = 'dom-1'`).Scan(&artifactDomain); err != nil || artifactDomain.Int64 != 0 {
		t.Errorf("agent1 artifacts should cascade with the agent, have %v (%v)", artifactDomain, err)
	}

	// A second Open has nothing to do.
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d2, err := Open(dbPath, key)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer d2.Close()
	if got := schemaVersion(t, d2); got != len(migrations) {
		t.Fatalf("schema_version after second Open = %d", got)
	}
}

// A violation that already existed before the upgrade (here an orphaned
// agent_zones row written with enforcement off) must not block it; the check
// only refuses violations the migrations add.
func TestMigrationRestrictToleratesExistingViolations(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy.db")
	raw := seedBeforeRestrict(t, dbPath, restrictSeed)
	if _, err := raw.Exec(`PRAGMA foreign_keys = OFF`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO agent_zones (agent_id, zone_id) VALUES ('agent-missing', 'zone1')`); err != nil {
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
		t.Fatalf("Open with a pre-existing violation: %v", err)
	}
	defer d.Close()
	if got := schemaVersion(t, d); got != len(migrations) {
		t.Fatalf("schema_version = %d, want %d", got, len(migrations))
	}
}

func TestRewriteCreateTableRejectsUnexpectedSchema(t *testing.T) {
	_, err := rewriteCreateTable(`CREATE TABLE servers (id TEXT PRIMARY KEY, agent_id TEXT)`, "servers", "servers_new",
		[]restrictFK{{column: "agent_id", parent: "agents"}})
	if err == nil {
		t.Fatal("rewrite without a REFERENCES clause succeeded")
	}
	got, err := rewriteCreateTable(`CREATE TABLE "domains" (id INTEGER, zone_id TEXT NOT NULL DEFAULT '' REFERENCES zones(id), UNIQUE(subdomain, zone_id))`,
		"domains", "domains_new", []restrictFK{{column: "zone_id", parent: "zones"}})
	if err != nil {
		t.Fatal(err)
	}
	want := `CREATE TABLE "domains_new" (id INTEGER, zone_id TEXT NOT NULL DEFAULT '' REFERENCES zones(id) ON DELETE RESTRICT, UNIQUE(subdomain, zone_id))`
	if got != want {
		t.Fatalf("rewrite = %s\nwant      %s", got, want)
	}
}

// columnNames lists a table's columns in declaration order.
func columnNames(t *testing.T, q interface {
	Query(string, ...any) (*sql.Rows, error)
}, table string) []string {
	t.Helper()
	rows, err := q.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var cid, notNull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		out = append(out, name)
	}
	return out
}

package db

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
)

// restrictFK names a foreign key column whose ON DELETE action a rebuild
// replaces with RESTRICT.
type restrictFK struct {
	column string
	parent string
}

// rebuildParentFKsRestrict switches servers.agent_id, domains.server_id and
// domains.zone_id to ON DELETE RESTRICT. Must run with foreign key
// enforcement off (see migrate).
func rebuildParentFKsRestrict(ctx context.Context, tx *sql.Tx) error {
	if err := rebuildWithRestrictFKs(ctx, tx, "servers", []restrictFK{
		{column: "agent_id", parent: "agents"},
	}); err != nil {
		return err
	}
	return rebuildWithRestrictFKs(ctx, tx, "domains", []restrictFK{
		{column: "zone_id", parent: "zones"},
		{column: "server_id", parent: "servers"},
	})
}

// rebuildWithRestrictFKs rebuilds table from its live CREATE statement with
// the given column references rewritten to ON DELETE RESTRICT. Working from
// sqlite_master instead of a hard-coded definition keeps every column,
// default, CHECK and UNIQUE constraint the table has at this point. Rowids,
// the AUTOINCREMENT high-water mark, indexes and triggers are carried over.
func rebuildWithRestrictFKs(ctx context.Context, tx *sql.Tx, table string, fks []restrictFK) error {
	tmp := table + "_restrict_new"

	var createSQL string
	if err := tx.QueryRowContext(ctx,
		`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`, table,
	).Scan(&createSQL); err != nil {
		return fmt.Errorf("reading %s schema: %w", table, err)
	}

	newSQL, err := rewriteCreateTable(createSQL, table, tmp, fks)
	if err != nil {
		return err
	}

	extras, err := indexesAndTriggers(ctx, tx, table)
	if err != nil {
		return err
	}

	cols, err := tableColumns(ctx, tx, table)
	if err != nil {
		return err
	}
	colList := strings.Join(cols, ", ")

	exec := func(stmt string, args ...any) error {
		if _, err := tx.ExecContext(ctx, stmt, args...); err != nil {
			return fmt.Errorf("rebuilding %s: %w", table, err)
		}
		return nil
	}

	if err := exec(newSQL); err != nil {
		return err
	}
	if err := exec(fmt.Sprintf(`INSERT INTO %s (rowid, %s) SELECT rowid, %s FROM %s`,
		quoteIdent(tmp), colList, colList, quoteIdent(table))); err != nil {
		return err
	}

	// An AUTOINCREMENT table must not hand out ids again that were used by
	// rows deleted before the rebuild; other tables keep such ids without a
	// foreign key (cleanups, audit log). RENAME carries the row over.
	hasSequence, err := tableExists(ctx, tx, "sqlite_sequence")
	if err != nil {
		return err
	}
	if hasSequence {
		if err := exec(`UPDATE sqlite_sequence
			SET seq = (SELECT MAX(seq) FROM sqlite_sequence WHERE name IN (?1, ?2))
			WHERE name = ?2`, table, tmp); err != nil {
			return err
		}
		if err := exec(`INSERT INTO sqlite_sequence (name, seq)
			SELECT ?2, seq FROM sqlite_sequence
			WHERE name = ?1 AND NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = ?2)`, table, tmp); err != nil {
			return err
		}
	}

	if err := exec(fmt.Sprintf(`DROP TABLE %s`, quoteIdent(table))); err != nil {
		return err
	}
	if err := exec(fmt.Sprintf(`ALTER TABLE %s RENAME TO %s`, quoteIdent(tmp), quoteIdent(table))); err != nil {
		return err
	}
	for _, stmt := range extras {
		if err := exec(stmt); err != nil {
			return err
		}
	}

	return verifyRestrictFKs(ctx, tx, table, fks)
}

// rewriteCreateTable renames the table in a CREATE TABLE statement and sets
// ON DELETE RESTRICT on each listed column reference. Every listed column
// must match exactly once, so an unexpected schema fails the migration
// instead of silently keeping the old action.
func rewriteCreateTable(createSQL, table, newName string, fks []restrictFK) (string, error) {
	head := regexp.MustCompile(`(?is)^\s*CREATE\s+TABLE\s+(?:"` + regexp.QuoteMeta(table) + `"|` + regexp.QuoteMeta(table) + `)\s*\(`)
	if !head.MatchString(createSQL) {
		return "", fmt.Errorf("rebuilding %s: unexpected CREATE TABLE statement", table)
	}
	out := head.ReplaceAllLiteralString(createSQL, "CREATE TABLE "+quoteIdent(newName)+" (")

	for _, fk := range fks {
		// <column> <type and constraints> REFERENCES <parent>(id) [ON DELETE <action>]
		re := regexp.MustCompile(`(?is)(\b` + regexp.QuoteMeta(fk.column) + `\b[^,]*?\bREFERENCES\s+"?` +
			regexp.QuoteMeta(fk.parent) + `"?\s*\(\s*id\s*\))(\s+ON\s+DELETE\s+(?:CASCADE|RESTRICT|NO\s+ACTION|SET\s+NULL|SET\s+DEFAULT))?`)
		if n := len(re.FindAllStringIndex(out, -1)); n != 1 {
			return "", fmt.Errorf("rebuilding %s: found %d references for %s -> %s, want 1", table, n, fk.column, fk.parent)
		}
		out = re.ReplaceAllString(out, "${1} ON DELETE RESTRICT")
	}
	return out, nil
}

// verifyRestrictFKs confirms the rebuilt table carries RESTRICT on each
// listed reference.
func verifyRestrictFKs(ctx context.Context, tx *sql.Tx, table string, fks []restrictFK) error {
	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`PRAGMA foreign_key_list(%s)`, quoteIdent(table)))
	if err != nil {
		return fmt.Errorf("reading %s foreign keys: %w", table, err)
	}
	defer rows.Close()
	actions := map[string]string{}
	for rows.Next() {
		var id, seq int
		var parent, from, onUpdate, onDelete, match string
		var to sql.NullString
		if err := rows.Scan(&id, &seq, &parent, &from, &to, &onUpdate, &onDelete, &match); err != nil {
			return fmt.Errorf("scanning %s foreign keys: %w", table, err)
		}
		actions[from+" -> "+parent] = onDelete
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("reading %s foreign keys: %w", table, err)
	}
	for _, fk := range fks {
		if got := actions[fk.column+" -> "+fk.parent]; got != "RESTRICT" {
			return fmt.Errorf("rebuilding %s: %s -> %s has ON DELETE %q, want RESTRICT", table, fk.column, fk.parent, got)
		}
	}
	return nil
}

// indexesAndTriggers returns the CREATE statements of table's indexes and
// triggers, which DROP TABLE removes with it. Automatic indexes (UNIQUE,
// PRIMARY KEY) have no statement and come back with the table definition.
func indexesAndTriggers(ctx context.Context, tx *sql.Tx, table string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT sql FROM sqlite_master
		WHERE tbl_name = ? AND type IN ('index', 'trigger') AND sql IS NOT NULL
		ORDER BY CASE type WHEN 'index' THEN 0 ELSE 1 END, name`, table)
	if err != nil {
		return nil, fmt.Errorf("reading %s indexes and triggers: %w", table, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scanning %s index or trigger: %w", table, err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading %s indexes and triggers: %w", table, err)
	}
	return out, nil
}

// tableColumns returns the quoted names of table's stored columns in
// declaration order.
func tableColumns(ctx context.Context, tx *sql.Tx, table string) ([]string, error) {
	// table_xinfo also lists generated columns (hidden 2 and 3), which cannot be
	// inserted into and are recomputed by the new table.
	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`PRAGMA table_xinfo(%s)`, quoteIdent(table)))
	if err != nil {
		return nil, fmt.Errorf("reading %s columns: %w", table, err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var cid, notNull, pk, hidden int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk, &hidden); err != nil {
			return nil, fmt.Errorf("scanning %s columns: %w", table, err)
		}
		if hidden == 2 || hidden == 3 {
			continue
		}
		cols = append(cols, quoteIdent(name))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading %s columns: %w", table, err)
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("rebuilding %s: table has no columns", table)
	}
	return cols, nil
}

func tableExists(ctx context.Context, tx *sql.Tx, name string) (bool, error) {
	var n int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name,
	).Scan(&n); err != nil {
		return false, fmt.Errorf("looking up table %s: %w", name, err)
	}
	return n > 0, nil
}

func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

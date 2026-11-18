package db

import (
	"errors"
	"fmt"
	"strings"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// ErrParentInUse is returned when an agent, server or zone cannot be deleted
// because domains still reference it. The foreign keys are ON DELETE
// RESTRICT, so a parent only goes once the reconciler has torn its domains
// down.
var ErrParentInUse = errors.New("still referenced by domains")

// parentDeleteError maps a foreign key failure from deleting a parent row to
// ErrParentInUse and wraps everything else with what.
func parentDeleteError(what, id string, err error) error {
	if isForeignKeyViolation(err) {
		return fmt.Errorf("deleting %s %s: %w", what, id, ErrParentInUse)
	}
	return fmt.Errorf("deleting %s: %w", what, err)
}

// isForeignKeyViolation reports whether err is SQLite refusing a write
// because of a foreign key. An immediate RESTRICT action reports
// SQLITE_CONSTRAINT_TRIGGER rather than SQLITE_CONSTRAINT_FOREIGNKEY, so the
// message tells it apart from a RAISE() in a user trigger.
func isForeignKeyViolation(err error) bool {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code() {
	case sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY:
		return true
	case sqlite3.SQLITE_CONSTRAINT_TRIGGER:
		return strings.Contains(se.Error(), "FOREIGN KEY constraint failed")
	}
	return false
}

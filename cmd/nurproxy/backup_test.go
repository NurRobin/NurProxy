package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/crypto"
)

// seedDataDir creates a data dir with a real DB (carrying a marker setting) plus
// the two key files, mirroring a live install.
func seedDataDir(t *testing.T) (dir, marker string) {
	t.Helper()
	dir = t.TempDir()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(filepath.Join(dir, dbFileName), key)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	marker = "marker-value-123"
	if err := database.SetSetting("backup_marker", marker); err != nil {
		t.Fatalf("set setting: %v", err)
	}
	database.Close()

	if err := os.WriteFile(filepath.Join(dir, encryptionKeyName), key, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, acmeAccountKeyName), []byte("acme-key-bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	return dir, marker
}

func TestBackupRestore_roundTripPreservesDBAndKeys(t *testing.T) {
	src, marker := seedDataDir(t)
	archive := filepath.Join(t.TempDir(), "backup.tar.gz")

	if err := backupDataDir(src, archive); err != nil {
		t.Fatalf("backupDataDir: %v", err)
	}

	dst := t.TempDir()
	n, err := restoreArchive(archive, dst, false)
	if err != nil {
		t.Fatalf("restoreArchive: %v", err)
	}
	if n != 3 {
		t.Errorf("restored %d files, want 3 (db + 2 keys)", n)
	}

	// The restored DB must reopen and still carry the marker — and crucially with
	// the SAME encryption key (restored from the archive), so encrypted secrets
	// would still decrypt.
	restoredKey, err := os.ReadFile(filepath.Join(dst, encryptionKeyName))
	if err != nil {
		t.Fatalf("read restored key: %v", err)
	}
	database, err := db.Open(filepath.Join(dst, dbFileName), restoredKey)
	if err != nil {
		t.Fatalf("reopen restored db: %v", err)
	}
	defer database.Close()
	got, err := database.GetSetting("backup_marker")
	if err != nil || got != marker {
		t.Fatalf("marker after restore = %q (err %v), want %q", got, err, marker)
	}

	acme, _ := os.ReadFile(filepath.Join(dst, acmeAccountKeyName))
	if string(acme) != "acme-key-bytes" {
		t.Errorf("acme key not restored verbatim: %q", acme)
	}
}

func TestRestore_refusesToClobberWithoutForce(t *testing.T) {
	src, _ := seedDataDir(t)
	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := backupDataDir(src, archive); err != nil {
		t.Fatalf("backup: %v", err)
	}

	// Restoring into a dir that already has a DB must fail without --force...
	if _, err := restoreArchive(archive, src, false); err == nil {
		t.Fatal("expected refusal to overwrite existing DB without force")
	}
	// ...and succeed with it.
	if _, err := restoreArchive(archive, src, true); err != nil {
		t.Fatalf("restore with force: %v", err)
	}
}

func TestBackup_missingDB_errors(t *testing.T) {
	empty := t.TempDir()
	if err := backupDataDir(empty, filepath.Join(t.TempDir(), "x.tar.gz")); err == nil {
		t.Fatal("expected error backing up a data dir with no database")
	}
}

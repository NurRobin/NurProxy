package main

import (
	"os"
	"os/exec"
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

// TestRestore_truncatedArchive_leavesExistingDBIntact is the H2 regression: a
// corrupt/truncated archive must NOT clobber the existing DB. Restore stages to
// temp files and only commits after the whole archive verifies, so a truncated
// archive leaves the on-disk DB byte-for-byte identical.
func TestRestore_truncatedArchive_leavesExistingDBIntact(t *testing.T) {
	src, _ := seedDataDir(t)
	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := backupDataDir(src, archive); err != nil {
		t.Fatalf("backup: %v", err)
	}

	full, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	// Lop off the tail so the gzip stream can't be read to completion (CRC/size
	// trailer gone). Keep enough that gzip.NewReader still succeeds on the header.
	truncated := filepath.Join(t.TempDir(), "truncated.tar.gz")
	if err := os.WriteFile(truncated, full[:len(full)/2], 0600); err != nil {
		t.Fatal(err)
	}

	// Capture the live DB bytes before the doomed restore.
	dbPath := filepath.Join(src, dbFileName)
	before, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := restoreArchive(truncated, src, true); err == nil {
		t.Fatal("expected restore of a truncated archive to fail")
	}

	after, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("existing DB gone after failed restore: %v", err)
	}
	if !bytesEqual(before, after) {
		t.Fatalf("existing %s was modified by a failed restore (%d -> %d bytes); restore is not atomic", dbFileName, len(before), len(after))
	}

	// No staged temp files should be left behind in the data dir.
	leftovers := globRestoreTemps(t, src)
	if len(leftovers) != 0 {
		t.Errorf("failed restore left staged temp files: %v", leftovers)
	}
}

// TestRestore_removesStaleWALSHM verifies a --force restore clears -wal/-shm
// sidecars that belonged to the previous database.
func TestRestore_removesStaleWALSHM(t *testing.T) {
	src, marker := seedDataDir(t)
	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := backupDataDir(src, archive); err != nil {
		t.Fatalf("backup: %v", err)
	}

	// Plant stale journal sidecars from a "previous" DB.
	wal := filepath.Join(src, dbFileName+"-wal")
	shm := filepath.Join(src, dbFileName+"-shm")
	if err := os.WriteFile(wal, []byte("stale-wal"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shm, []byte("stale-shm"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := restoreArchive(archive, src, true); err != nil {
		t.Fatalf("force restore: %v", err)
	}
	if _, err := os.Stat(wal); !os.IsNotExist(err) {
		t.Errorf("stale -wal not removed (stat err: %v)", err)
	}
	if _, err := os.Stat(shm); !os.IsNotExist(err) {
		t.Errorf("stale -shm not removed (stat err: %v)", err)
	}

	// And the restored DB still opens and carries the marker.
	key, _ := os.ReadFile(filepath.Join(src, encryptionKeyName))
	database, err := db.Open(filepath.Join(src, dbFileName), key)
	if err != nil {
		t.Fatalf("reopen after restore: %v", err)
	}
	defer database.Close()
	if got, _ := database.GetSetting("backup_marker"); got != marker {
		t.Errorf("marker after restore = %q, want %q", got, marker)
	}
}

// TestRestore_keylessArchiveOntoDifferingKey_refuses verifies that restoring a
// keyless archive (DB only) into a dir that already holds an encryption.key is
// refused, since the existing key likely cannot decrypt the restored DB.
func TestRestore_keylessArchiveOntoDifferingKey_refuses(t *testing.T) {
	src, _ := seedDataDir(t)

	// Build a DB-only archive (no key files) by removing the keys before backup.
	keyless := t.TempDir()
	if err := copyFile(filepath.Join(src, dbFileName), filepath.Join(keyless, dbFileName)); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "keyless.tar.gz")
	if err := backupDataDir(keyless, archive); err != nil {
		t.Fatalf("backup keyless: %v", err)
	}

	// Target dir already has a (differing) encryption.key.
	dst := t.TempDir()
	if err := os.WriteFile(filepath.Join(dst, encryptionKeyName), []byte("a-different-existing-key"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := restoreArchive(archive, dst, true); err == nil {
		t.Fatal("expected refusal restoring a keyless archive over an existing differing key")
	}
	// The pre-existing key must be untouched and no DB installed.
	if _, err := os.Stat(filepath.Join(dst, dbFileName)); !os.IsNotExist(err) {
		t.Errorf("DB was installed despite the key-mismatch refusal (stat err: %v)", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dst, encryptionKeyName)); string(got) != "a-different-existing-key" {
		t.Errorf("existing key was modified: %q", got)
	}
}

func TestResolveDataDir(t *testing.T) {
	tests := []struct {
		name    string
		flagVal string
		env     string
		setEnv  bool
		want    string
	}{
		{name: "flag wins", flagVal: "/from/flag", env: "/from/env", setEnv: true, want: "/from/flag"},
		{name: "env fallback", flagVal: "", env: "/from/env", setEnv: true, want: "/from/env"},
		{name: "default", flagVal: "", setEnv: false, want: "./data"},
		{name: "empty env ignored", flagVal: "", env: "", setEnv: true, want: "./data"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv("NP_DATA_DIR", tt.env)
			} else {
				// t.Setenv with "" still sets it; ensure unset for the default case.
				os.Unsetenv("NP_DATA_DIR")
			}
			if got := resolveDataDir(tt.flagVal); got != tt.want {
				t.Errorf("resolveDataDir(%q) = %q, want %q", tt.flagVal, got, tt.want)
			}
		})
	}
}

// TestCmdBackupRestore_roundTrip drives the []string command wrappers end to end:
// cmdBackup writes an archive via -o, cmdRestore reads it back with --force.
func TestCmdBackupRestore_roundTrip(t *testing.T) {
	// Subprocess branch: re-running restore without --force over an existing DB
	// must call fatalf -> os.Exit(1). Short-circuit before the normal flow.
	if os.Getenv("NP_TEST_RESTORE_NOFORCE") == "1" {
		cmdRestore([]string{"--data-dir", os.Getenv("NP_TEST_RESTORE_DIR"), os.Getenv("NP_TEST_RESTORE_ARCHIVE")})
		return // unreachable: fatalf exits
	}

	src, marker := seedDataDir(t)
	archive := filepath.Join(t.TempDir(), "wrapped.tar.gz")

	cmdBackup([]string{"--data-dir", src, "-o", archive})
	if _, err := os.Stat(archive); err != nil {
		t.Fatalf("cmdBackup did not write the archive: %v", err)
	}

	dst := t.TempDir()
	// dst is empty, so no --force needed.
	cmdRestore([]string{"--data-dir", dst, archive})

	key, _ := os.ReadFile(filepath.Join(dst, encryptionKeyName))
	database, err := db.Open(filepath.Join(dst, dbFileName), key)
	if err != nil {
		t.Fatalf("reopen restored db: %v", err)
	}
	defer database.Close()
	if got, _ := database.GetSetting("backup_marker"); got != marker {
		t.Errorf("marker after wrapped restore = %q, want %q", got, marker)
	}

	// Re-running restore into the now-populated dst without --force must abort.
	// cmdRestore calls fatalf -> os.Exit on refusal, so exercise that in a
	// subprocess (guarded branch at the top of this test) and assert non-zero exit.
	cmd := exec.Command(os.Args[0], "-test.run", "^TestCmdBackupRestore_roundTrip$")
	cmd.Env = append(os.Environ(),
		"NP_TEST_RESTORE_NOFORCE=1",
		"NP_TEST_RESTORE_DIR="+dst,
		"NP_TEST_RESTORE_ARCHIVE="+archive,
	)
	err = cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.Success() {
		t.Fatalf("cmdRestore without --force over an existing DB should exit non-zero, got err=%v", err)
	}
}

// TestCmdRestore_missingArchive_exits asserts the missing-archive path exits
// non-zero. cmdRestore calls fatalf -> os.Exit, so run it in a subprocess.
func TestCmdRestore_missingArchive_exits(t *testing.T) {
	if os.Getenv("NP_TEST_RESTORE_MISSING") == "1" {
		cmdRestore([]string{"--data-dir", t.TempDir(), "/no/such/archive.tar.gz"})
		return // unreachable
	}
	cmd := exec.Command(os.Args[0], "-test.run", "TestCmdRestore_missingArchive_exits")
	cmd.Env = append(os.Environ(), "NP_TEST_RESTORE_MISSING=1")
	err := cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.Success() {
		t.Fatalf("cmdRestore on a missing archive should exit non-zero, got err=%v", err)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func globRestoreTemps(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, ".*.restore-*"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0600)
}

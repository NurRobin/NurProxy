//go:build unix

package dataperms

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/crypto"
	"golang.org/x/sys/unix"
)

func TestHardenRestrictsOnlyAllowedRegularEntries(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.Mkdir(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	allowed := []string{"nurproxy.db", "nurproxy.db-wal", "nurproxy.db-shm", "encryption.key", "acme-account.key"}
	for _, name := range allowed {
		if err := os.WriteFile(filepath.Join(dataDir, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	unknown := filepath.Join(dataDir, "operator-notes.txt")
	if err := os.WriteFile(unknown, []byte("leave me alone"), 0o644); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(dataDir, "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	nestedFile := filepath.Join(nested, "nurproxy.db")
	if err := os.WriteFile(nestedFile, []byte("not the database"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dataDir, "acme-account.key")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dataDir, "acme-account.key")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dataDir, ".nurproxy.db.restore-foreign"), 0o644); err != nil {
		t.Fatal(err)
	}
	foreignStage := filepath.Join(dataDir, ".encryption.key.restore-attacker")
	if err := os.WriteFile(foreignStage, []byte("foreign"), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := Harden(dataDir)
	if err == nil {
		t.Fatal("Harden must report managed symlink/non-regular entries as unsafe")
	}
	if len(report.Skipped) < 4 {
		t.Fatalf("skipped = %v, want unknown file, directory, symlink, and fifo", report.Skipped)
	}
	assertMode(t, dataDir, 0o700)
	for _, name := range allowed[:4] {
		assertMode(t, filepath.Join(dataDir, name), 0o600)
	}
	assertMode(t, unknown, 0o644)
	assertMode(t, nested, 0o755)
	assertMode(t, nestedFile, 0o644)
	assertMode(t, outside, 0o644)
	assertMode(t, foreignStage, 0o644)
	if err := os.Remove(filepath.Join(dataDir, "acme-account.key")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dataDir, ".nurproxy.db.restore-foreign")); err != nil {
		t.Fatal(err)
	}
	if _, err := Harden(dataDir); err != nil {
		t.Fatalf("second Harden: %v", err)
	}
}

func TestHardenRejectsLinkedDataDirectory(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(realDir, "nurproxy.db")
	if err := os.WriteFile(dbPath, []byte("unchanged"), 0o644); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(root, "linked")
	if err := os.Symlink(realDir, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := Harden(linked); err == nil {
		t.Fatal("Harden accepted a symlink data directory")
	}
	assertMode(t, realDir, 0o755)
	assertMode(t, dbPath, 0o644)
}

func TestEnsureRejectsIntermediateAndTrailingSlashSymlinks(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(root, "link", "child"), filepath.Join(root, "link") + string(os.PathSeparator)} {
		if _, err := Ensure(path); err == nil {
			t.Errorf("Ensure accepted symlink component %q", path)
		}
	}
	if _, err := os.Stat(filepath.Join(target, "child")); !os.IsNotExist(err) {
		t.Fatalf("created through intermediate symlink: %v", err)
	}
	assertMode(t, target, 0o755)
}

func TestHardenRejectsManagedHardlinkWithoutChangingExternalInode(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("external"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(dataDir, "encryption.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := Harden(dataDir); err == nil {
		t.Fatal("Harden accepted managed hardlink")
	}
	assertMode(t, outside, 0o644)
}

func TestBoundDirSurvivesPathReplacement(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dir, err := OpenDir(dataDir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	original := filepath.Join(root, "original")
	if err := os.Rename(dataDir, original); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, dataDir); err != nil {
		t.Fatal(err)
	}
	f, tempName, err := dir.CreateTemp("restore")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("bound"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := dir.Rename(tempName, "nurproxy.db"); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(original, "nurproxy.db")); err != nil || string(got) != "bound" {
		t.Fatalf("original got %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(outside, "nurproxy.db")); !os.IsNotExist(err) {
		t.Fatalf("replacement target changed: %v", err)
	}
}

func TestBoundFilePathSurvivesFinalNameReplacement(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, "encryption.key")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir, err := OpenDir(dataDir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	held, err := dir.OpenRegular("encryption.key")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "external")
	if err := os.WriteFile(external, []byte("external"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, path); err != nil {
		t.Fatal(err)
	}
	bound, err := BoundFilePath(held)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(bound)
	if err != nil || string(got) != "original" {
		t.Fatalf("bound file = %q, %v", got, err)
	}
}

func TestPrivateUmaskRestrictsNewFiles(t *testing.T) {
	old := unix.Umask(0)
	defer unix.Umask(old)
	SetPrivateUmask()
	path := filepath.Join(t.TempDir(), "created")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o666)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	assertMode(t, path, 0o600)
}

func TestAllowedNameAcceptsOnlyExplicitSafeDatabaseBackupBasenames(t *testing.T) {
	for _, name := range []string{
		"nurproxy.db.backup-20260828-b66a15f",
		"nurproxy.db.backup-20260827",
		"nurproxy.db.bak-llmfix-20260806",
	} {
		if !allowedName(name) {
			t.Errorf("allowedName(%q) = false", name)
		}
	}
	for _, name := range []string{
		"nurproxy.db.backup-",
		"nurproxy.db.bak-",
		"nurproxy.db.backup-../../outside",
		"nurproxy.db.backup-bad\nname",
		"other.db.backup-20260828",
		".nurproxy.db.restore-attacker",
	} {
		if allowedName(name) {
			t.Errorf("allowedName(%q) = true", name)
		}
	}
}

func TestHardenRestrictsTimestampedDatabaseBackups(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nurproxy.db.backup-20260828-b66a15f", "nurproxy.db.bak-llmfix-20260806"} {
		if err := os.WriteFile(filepath.Join(dataDir, name), []byte("backup"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Harden(dataDir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nurproxy.db.backup-20260828-b66a15f", "nurproxy.db.bak-llmfix-20260806"} {
		assertMode(t, filepath.Join(dataDir, name), 0o600)
	}
}

func TestSQLiteDatabaseAndLiveSidecarsConvergeToPrivateModes(t *testing.T) {
	old := unix.Umask(0)
	defer unix.Umask(old)
	SetPrivateUmask()

	dataDir := filepath.Join(t.TempDir(), "data")
	if _, err := Ensure(dataDir); err != nil {
		t.Fatal(err)
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.SaveKey(key, filepath.Join(dataDir, "encryption.key")); err != nil {
		t.Fatal(err)
	}
	dir, err := OpenDir(dataDir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	dbFile, created, err := dir.OpenOrCreateRegular("nurproxy.db")
	if err != nil {
		t.Fatal(err)
	}
	defer dbFile.Close()
	if !created {
		t.Fatal("new database was not reported created")
	}
	dbPath, err := BoundFilePath(dbFile)
	if err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(dbPath, key)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.SetSetting("permission_test", "value"); err != nil {
		t.Fatal(err)
	}
	if _, err := Harden(dataDir); err != nil {
		t.Fatal(err)
	}

	assertMode(t, dataDir, 0o700)
	for _, name := range []string{"encryption.key", "nurproxy.db", "nurproxy.db-wal", "nurproxy.db-shm"} {
		assertMode(t, filepath.Join(dataDir, name), 0o600)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("mode %s = %04o, want %04o", path, got, want)
	}
}

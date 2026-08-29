package recovery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

func TestSnapshotAndRollbackPreserveRegularAbsentAndSymlinkState(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	managed := filepath.Join(root, "managed")
	mustMkdir(t, managed, 0o750)
	regular := filepath.Join(managed, "regular.conf")
	absent := filepath.Join(managed, "absent.conf")
	target := filepath.Join(managed, "target.conf")
	link := filepath.Join(managed, "enabled.conf")
	mustWrite(t, regular, []byte("before\n"), 0o640)
	mustWrite(t, target, []byte("target\n"), 0o600)
	if err := os.Symlink("target.conf", link); err != nil {
		t.Fatal(err)
	}

	guard, err := NewPathGuard(managed)
	if err != nil {
		t.Fatal(err)
	}
	paths := resolveAll(t, guard, regular, absent, link)
	store, err := NewSnapshotStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 29, 1, 2, 3, 0, time.UTC)
	manifest, err := store.Create("op-1", recoverymodel.ActionPruneManagedOrphan, "fingerprint", paths, now)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.State != recoverymodel.OperationStateSnapshotted || len(manifest.Entries) != 3 {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	assertMode(t, filepath.Join(dataDir, "recovery", "operations", "op-1"), 0o700)
	assertMode(t, filepath.Join(dataDir, "recovery", "operations", "op-1", manifest.Entries[0].SnapshotFile), 0o600)

	mustWrite(t, regular, []byte("after\n"), 0o600)
	mustWrite(t, absent, []byte("created\n"), 0o600)
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("absent.conf", link); err != nil {
		t.Fatal(err)
	}
	if err := store.Rollback("op-1"); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(regular)
	if err != nil || string(got) != "before\n" {
		t.Fatalf("regular restore = %q, %v", got, err)
	}
	assertMode(t, regular, 0o640)
	if _, err := os.Lstat(absent); !os.IsNotExist(err) {
		t.Fatalf("absent path restored as %v", err)
	}
	gotTarget, err := os.Readlink(link)
	if err != nil || gotTarget != "target.conf" {
		t.Fatalf("symlink target = %q, %v", gotTarget, err)
	}
}

func TestSnapshotManifestIsTypedSecretFreeAndAtomicallyPersisted(t *testing.T) {
	root := t.TempDir()
	managed := filepath.Join(root, "managed")
	mustMkdir(t, managed, 0o700)
	path := filepath.Join(managed, "secret.pem")
	mustWrite(t, path, []byte("TOP-SECRET-KEY-MATERIAL"), 0o600)
	guard, _ := NewPathGuard(managed)
	checked := resolveAll(t, guard, path)
	store, err := NewSnapshotStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := store.Create("op-atomic", recoverymodel.ActionRematerializeCertBundle, "fp", checked, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(store.OperationDir("op-atomic"), manifestFilename))
	if err != nil {
		t.Fatal(err)
	}
	if containsBytes(raw, []byte("TOP-SECRET")) {
		t.Fatal("manifest leaked snapshot contents")
	}
	if manifest.Entries[0].SHA256 == "" || manifest.Entries[0].Path != path || manifest.Entries[0].Mode != 0o600 {
		t.Fatalf("incomplete metadata: %#v", manifest.Entries[0])
	}
	assertMode(t, filepath.Join(store.OperationDir("op-atomic"), manifestFilename), 0o600)
	matches, err := filepath.Glob(filepath.Join(store.OperationDir("op-atomic"), ".manifest-*.tmp"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary manifests remain: %v, %v", matches, err)
	}
	loaded, err := store.Load("op-atomic")
	if err != nil || loaded.OperationID != manifest.OperationID {
		t.Fatalf("load = %#v, %v", loaded, err)
	}
}

func TestSnapshotRejectsAnEmptyMutationSet(t *testing.T) {
	store, err := NewSnapshotStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create("op-empty", recoverymodel.ActionRemoveManagedTemp, "fp", nil, testTime()); err == nil {
		t.Fatal("empty snapshot accepted")
	}
}

func TestRollbackRejectsSnapshotBlobSymlink(t *testing.T) {
	root := t.TempDir()
	managed := filepath.Join(root, "managed")
	mustMkdir(t, managed, 0o700)
	path := filepath.Join(managed, "config")
	mustWrite(t, path, []byte("before"), 0o600)
	guard, _ := NewPathGuard(managed)
	store, err := NewSnapshotStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := store.Create("op-blob", recoverymodel.ActionRemoveManagedTemp, "fp", resolveAll(t, guard, path), testTime())
	if err != nil {
		t.Fatal(err)
	}
	blob := filepath.Join(store.OperationDir("op-blob"), manifest.Entries[0].SnapshotFile)
	external := filepath.Join(root, "external")
	mustWrite(t, external, []byte("before"), 0o600)
	if err := os.Remove(blob); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, blob); err != nil {
		t.Fatal(err)
	}
	if err := store.Rollback("op-blob"); err == nil {
		t.Fatal("rollback followed a symlinked snapshot blob")
	}
}

func TestRollbackRejectsTamperedSymlinkTarget(t *testing.T) {
	root := t.TempDir()
	managed := filepath.Join(root, "managed")
	mustMkdir(t, managed, 0o700)
	target := filepath.Join(managed, "target")
	link := filepath.Join(managed, "link")
	mustWrite(t, target, []byte("target"), 0o600)
	if err := os.Symlink("target", link); err != nil {
		t.Fatal(err)
	}
	guard, _ := NewPathGuard(managed)
	store, err := NewSnapshotStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := store.Create("op-link", recoverymodel.ActionRemoveManagedTemp, "fp", resolveAll(t, guard, link), testTime())
	if err != nil {
		t.Fatal(err)
	}
	manifest.Entries[0].SymlinkTarget = filepath.Join(root, "outside")
	manifest.Entries[0].SHA256 = digest([]byte(manifest.Entries[0].SymlinkTarget))
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.OperationDir("op-link"), manifestFilename), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := store.Rollback("op-link"); err == nil {
		t.Fatal("rollback accepted a symlink target outside the captured identity")
	}
}

func TestRetentionKeepsNewestTwentyRecentAndActiveWithoutFollowingSymlinks(t *testing.T) {
	root := t.TempDir()
	store, err := NewSnapshotStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 25; i++ {
		id := operationID(i)
		created := now.Add(-time.Duration(i) * time.Minute)
		state := recoverymodel.OperationStateSucceeded
		if i == 0 {
			state = recoverymodel.OperationStateApplying
			created = now.Add(-30 * 24 * time.Hour)
		}
		if err := persistTestManifest(store, id, state, created); err != nil {
			t.Fatal(err)
		}
	}
	if err := persistTestManifest(store, "op-old", recoverymodel.OperationStateSucceeded, now.Add(-8*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(root, "must-survive")
	mustMkdir(t, external, 0o700)
	mustWrite(t, filepath.Join(external, "sentinel"), []byte("ok"), 0o600)
	if err := os.Symlink(external, filepath.Join(store.operationsDir, "evil-link")); err != nil {
		t.Fatal(err)
	}
	if err := store.Prune(now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(external, "sentinel")); err != nil {
		t.Fatalf("retention followed symlink: %v", err)
	}
	if _, err := os.Stat(store.OperationDir("op-00")); err != nil {
		t.Fatalf("active operation pruned: %v", err)
	}
	entries, err := os.ReadDir(store.operationsDir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			count++
		}
	}
	if count != 21 {
		t.Fatalf("kept %d operation directories, want newest 20 plus active", count)
	}
}

func resolveAll(t *testing.T, guard *PathGuard, paths ...string) []GuardedPath {
	t.Helper()
	result := make([]GuardedPath, 0, len(paths))
	for _, path := range paths {
		checked, err := guard.Resolve(path)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, checked)
	}
	return result
}

func mustMkdir(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, mode); err != nil {
		t.Fatal(err)
	}
}
func mustWrite(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}
func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("%s mode = %o, want %o", path, info.Mode().Perm(), want)
	}
}
func containsBytes(haystack, needle []byte) bool {
	return string(haystack) != "" && string(needle) != "" && len(haystack) >= len(needle) && stringContains(string(haystack), string(needle))
}
func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
func operationID(i int) string { return "op-" + string(rune('0'+i/10)) + string(rune('0'+i%10)) }

func persistTestManifest(store *SnapshotStore, id string, state recoverymodel.OperationState, created time.Time) error {
	if err := os.Mkdir(store.OperationDir(id), 0o700); err != nil {
		return err
	}
	return store.persist(&SnapshotManifest{
		Version: manifestVersion, OperationID: id, Action: recoverymodel.ActionRemoveManagedTemp,
		Fingerprint: "fingerprint", CreatedAt: created, UpdatedAt: created, State: state,
	})
}

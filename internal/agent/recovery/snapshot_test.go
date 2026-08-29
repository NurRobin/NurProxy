package recovery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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
	defer store.Close()
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
	if _, err := store.Transition("op-1", recoverymodel.OperationStateSnapshotted, recoverymodel.OperationStateRollingBack, now.Add(time.Second)); err != nil {
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

func TestSnapshotSourceReadIsBoundToValidatedFile(t *testing.T) {
	root := t.TempDir()
	managed := filepath.Join(root, "managed")
	mustMkdir(t, managed, 0o700)
	path, external := filepath.Join(managed, "config"), filepath.Join(root, "external")
	mustWrite(t, path, []byte("managed"), 0o600)
	mustWrite(t, external, []byte("outside"), 0o600)
	guard, _ := NewPathGuard(managed)
	checked := resolveAll(t, guard, path)[0]
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, path); err != nil {
		t.Fatal(err)
	}
	if _, err := readValidatedSource(checked); err == nil {
		t.Fatal("validated source read followed replacement symlink")
	}
}

func TestSnapshotStoreRemainsBoundWhenOperationsPathIsSwapped(t *testing.T) {
	root := t.TempDir()
	data, managed := filepath.Join(root, "data"), filepath.Join(root, "managed")
	mustMkdir(t, managed, 0o700)
	path := filepath.Join(managed, "config")
	mustWrite(t, path, []byte("managed"), 0o600)
	guard, _ := NewPathGuard(managed)
	store, err := NewSnapshotStore(data)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	original := filepath.Join(root, "original-operations")
	if err := os.Rename(store.operationsDir, original); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(root, "external-operations")
	mustMkdir(t, external, 0o700)
	if err := os.Symlink(external, store.operationsDir); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create("op-bound", recoverymodel.ActionRemoveManagedTemp, "fp", resolveAll(t, guard, path), testTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(original, "op-bound", manifestFilename)); err != nil {
		t.Fatalf("bound directory did not receive snapshot: %v", err)
	}
	if _, err := os.Stat(filepath.Join(external, "op-bound")); !os.IsNotExist(err) {
		t.Fatalf("swapped path was used: %v", err)
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
	defer store.Close()
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
	matches, err := filepath.Glob(filepath.Join(store.OperationDir("op-atomic"), ".nurproxy-atomic-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary manifests remain: %v, %v", matches, err)
	}
	loaded, err := store.Load("op-atomic")
	if err != nil || loaded.OperationID != manifest.OperationID {
		t.Fatalf("load = %#v, %v", loaded, err)
	}
}

func TestSnapshotManifestPersistsExactOperationIdentityAndHistory(t *testing.T) {
	root := t.TempDir()
	managed := filepath.Join(root, "managed")
	mustMkdir(t, managed, 0o700)
	path := filepath.Join(managed, "artifact")
	mustWrite(t, path, []byte("before"), 0o600)
	guard, _ := NewPathGuard(managed)
	store, _ := NewSnapshotStore(filepath.Join(root, "data"))
	defer store.Close()
	now := testTime()
	report := recoverymodel.OperationReport{OperationID: "manual-exact", DiagnosticID: "diag-exact", Action: recoverymodel.ActionRemoveManagedTemp, Source: recoverymodel.RequestSourceUser, State: recoverymodel.OperationStateSnapshotted, SnapshotReference: "manual-exact", StartedAt: now, Steps: []recoverymodel.Step{{Name: "planned", Summary: "safe typed repair requested", State: recoverymodel.OperationStatePlanned, At: now}, {Name: "snapshotted", Summary: "prior filesystem state captured", State: recoverymodel.OperationStateSnapshotted, At: now}}}
	if _, err := store.CreateOperation(report, "fingerprint", resolveAll(t, guard, path), now); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(report.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded.Report, report) {
		t.Fatalf("report=%+v want=%+v", loaded.Report, report)
	}
}

func TestTransitionReportRejectsChangedHistoryAndIdempotentMismatch(t *testing.T) {
	root := t.TempDir()
	managed := filepath.Join(root, "managed")
	if err := os.Mkdir(managed, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(managed, "nurproxy-history.conf")
	if err := os.WriteFile(path, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	guard, _ := NewPathGuard(managed)
	checked, _ := guard.Resolve(path)
	store, _ := NewSnapshotStore(filepath.Join(root, "data"))
	defer store.Close()
	now := testTime()
	report := recoverymodel.OperationReport{OperationID: "history", DiagnosticID: "diag-history", Action: recoverymodel.ActionRemoveManagedTemp, Source: recoverymodel.RequestSourceAutomatic, State: recoverymodel.OperationStateSnapshotted, SnapshotReference: "history", StartedAt: now, Steps: []recoverymodel.Step{{Name: "detected", State: recoverymodel.OperationStateDetected, At: now}, {Name: "planned", State: recoverymodel.OperationStatePlanned, At: now}, {Name: "snapshotted", State: recoverymodel.OperationStateSnapshotted, At: now}}}
	if _, err := store.CreateOperation(report, "fingerprint", []GuardedPath{checked}, now); err != nil {
		t.Fatal(err)
	}
	changed := report
	changed.State = recoverymodel.OperationStateApplying
	changed.Steps = append([]recoverymodel.Step(nil), report.Steps...)
	changed.Steps[0].Name = "changed"
	changed.Steps = append(changed.Steps, recoverymodel.Step{Name: "applying", State: recoverymodel.OperationStateApplying, At: now})
	if _, err := store.TransitionReport("history", recoverymodel.OperationStateSnapshotted, changed, now); err == nil {
		t.Fatal("changed durable history was accepted")
	}
	valid := report
	valid.State = recoverymodel.OperationStateApplying
	valid.Steps = append(valid.Steps, recoverymodel.Step{Name: "applying", State: recoverymodel.OperationStateApplying, At: now})
	if _, err := store.TransitionReport("history", recoverymodel.OperationStateSnapshotted, valid, now); err != nil {
		t.Fatal(err)
	}
	changed = valid
	changed.ValidationOutcome = "different"
	if _, err := store.TransitionReport("history", recoverymodel.OperationStateSnapshotted, changed, now); err == nil {
		t.Fatal("mismatched idempotent report was accepted")
	}
}

func TestSnapshotRejectsAnEmptyMutationSet(t *testing.T) {
	store, err := NewSnapshotStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Create("op-empty", recoverymodel.ActionRemoveManagedTemp, "fp", nil, testTime()); err == nil {
		t.Fatal("empty snapshot accepted")
	}
}

func TestSnapshotStoreRejectsRecoverySymlinkWithoutTouchingTarget(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	external := filepath.Join(root, "external")
	mustMkdir(t, data, 0o700)
	mustMkdir(t, external, 0o755)
	if err := os.Symlink(external, filepath.Join(data, "recovery")); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSnapshotStore(data); err == nil {
		t.Fatal("recovery symlink accepted")
	}
	assertMode(t, external, 0o755)
	if _, err := os.Stat(filepath.Join(external, "operations")); !os.IsNotExist(err) {
		t.Fatalf("external target mutated: %v", err)
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
	defer store.Close()
	manifest, err := store.Create("op-blob", recoverymodel.ActionRemoveManagedTemp, "fp", resolveAll(t, guard, path), testTime())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition("op-blob", recoverymodel.OperationStateSnapshotted, recoverymodel.OperationStateRollingBack, testTime()); err != nil {
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
	defer store.Close()
	manifest, err := store.Create("op-link", recoverymodel.ActionRemoveManagedTemp, "fp", resolveAll(t, guard, link), testTime())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition("op-link", recoverymodel.OperationStateSnapshotted, recoverymodel.OperationStateRollingBack, testTime()); err != nil {
		t.Fatal(err)
	}
	manifest.State = recoverymodel.OperationStateRollingBack
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

func TestRollbackPrevalidatesEverySnapshotBeforeMutation(t *testing.T) {
	root := t.TempDir()
	managed := filepath.Join(root, "managed")
	mustMkdir(t, managed, 0o700)
	first, second := filepath.Join(managed, "first"), filepath.Join(managed, "second")
	mustWrite(t, first, []byte("first-before"), 0o600)
	mustWrite(t, second, []byte("second-before"), 0o600)
	guard, _ := NewPathGuard(managed)
	store, _ := NewSnapshotStore(filepath.Join(root, "data"))
	defer store.Close()
	manifest, err := store.Create("op-prevalidate", recoverymodel.ActionRemoveManagedTemp, "fp", resolveAll(t, guard, first, second), testTime())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition("op-prevalidate", recoverymodel.OperationStateSnapshotted, recoverymodel.OperationStateRollingBack, testTime()); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, first, []byte("first-after"), 0o600)
	mustWrite(t, second, []byte("second-after"), 0o600)
	blob := filepath.Join(store.OperationDir("op-prevalidate"), manifest.Entries[0].SnapshotFile)
	if err := os.WriteFile(blob, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Rollback("op-prevalidate"); err == nil {
		t.Fatal("tampered snapshot accepted")
	}
	assertContents(t, first, "first-after")
	assertContents(t, second, "second-after")
}

func TestRollbackPreflightsUnsupportedEntryBeforeAnyRestore(t *testing.T) {
	root := t.TempDir()
	one, two := filepath.Join(root, "one"), filepath.Join(root, "two")
	mustMkdir(t, one, 0o700)
	mustMkdir(t, two, 0o700)
	first, second := filepath.Join(one, "first"), filepath.Join(two, "second")
	mustWrite(t, first, []byte("first-before"), 0o600)
	mustWrite(t, second, []byte("second-before"), 0o600)
	guard, _ := NewPathGuard(one, two)
	store, _ := NewSnapshotStore(filepath.Join(root, "data"))
	defer store.Close()
	if _, err := store.Create("op-partial", recoverymodel.ActionRemoveManagedTemp, "fp", resolveAll(t, guard, first, second), testTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition("op-partial", recoverymodel.OperationStateSnapshotted, recoverymodel.OperationStateRollingBack, testTime()); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, first, []byte("first-after"), 0o600)
	if err := os.Remove(second); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(second, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.Rollback("op-partial"); err == nil {
		t.Fatal("partial restore failure not reported")
	}
	assertContents(t, first, "first-after")
}

func TestRestoreAllContinuesAfterRuntimeFailure(t *testing.T) {
	root := t.TempDir()
	one, two := filepath.Join(root, "one"), filepath.Join(root, "two")
	mustMkdir(t, one, 0o700)
	mustMkdir(t, two, 0o700)
	first, second := filepath.Join(one, "first"), filepath.Join(two, "second")
	mustWrite(t, first, []byte("first-after"), 0o600)
	mustWrite(t, second, []byte("second-after"), 0o600)
	firstInfo, _ := os.Stat(one)
	secondInfo, _ := os.Stat(two)
	fd1, _, dev1, ino1, typ1, err := preflightTarget(snapshotEntryForTest(t, first, firstInfo))
	if err != nil {
		t.Fatal(err)
	}
	fd2, _, dev2, ino2, typ2, err := preflightTarget(snapshotEntryForTest(t, second, secondInfo))
	if err != nil {
		t.Fatal(err)
	}
	items := []preparedSnapshot{
		{entry: snapshotEntryForTest(t, first, firstInfo), data: []byte("first-before"), parent: fd1, exists: true, device: dev1, inode: ino1, entryType: typ1},
		{entry: snapshotEntryForTest(t, second, secondInfo), data: []byte("second-before"), parent: fd2, exists: true, device: dev2, inode: ino2, entryType: typ2},
	}
	if err := fd2.Close(); err != nil {
		t.Fatal(err)
	}
	defer fd1.Close()
	if err := restoreAll(items); err == nil {
		t.Fatal("runtime restore failure not aggregated")
	}
	assertContents(t, first, "first-before")
	assertContents(t, second, "second-after")
}

func snapshotEntryForTest(t *testing.T, path string, parent os.FileInfo) SnapshotEntry {
	t.Helper()
	device, inode, ok := fileIdentity(parent)
	if !ok {
		t.Fatal("parent identity unavailable")
	}
	return SnapshotEntry{Path: path, ResolvedPath: path, Kind: SnapshotRegular, Mode: 0o600, ParentDevice: device, ParentInode: inode}
}

func TestRollbackRequiresRollingBackManifestState(t *testing.T) {
	root := t.TempDir()
	managed := filepath.Join(root, "managed")
	mustMkdir(t, managed, 0o700)
	path := filepath.Join(managed, "config")
	mustWrite(t, path, []byte("before"), 0o600)
	guard, _ := NewPathGuard(managed)
	store, _ := NewSnapshotStore(filepath.Join(root, "data"))
	defer store.Close()
	if _, err := store.Create("op-state", recoverymodel.ActionRemoveManagedTemp, "fp", resolveAll(t, guard, path), testTime()); err != nil {
		t.Fatal(err)
	}
	if err := store.Rollback("op-state"); err == nil {
		t.Fatal("rollback accepted non-rolling_back manifest")
	}
}

func TestRollbackRejectsReplacedParentDirectory(t *testing.T) {
	root := t.TempDir()
	managed := filepath.Join(root, "managed")
	mustMkdir(t, managed, 0o700)
	path := filepath.Join(managed, "config")
	mustWrite(t, path, []byte("before"), 0o600)
	guard, _ := NewPathGuard(managed)
	store, _ := NewSnapshotStore(filepath.Join(root, "data"))
	defer store.Close()
	if _, err := store.Create("op-parent", recoverymodel.ActionRemoveManagedTemp, "fp", resolveAll(t, guard, path), testTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition("op-parent", recoverymodel.OperationStateSnapshotted, recoverymodel.OperationStateRollingBack, testTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(managed, managed+"-original"); err != nil {
		t.Fatal(err)
	}
	mustMkdir(t, managed, 0o700)
	mustWrite(t, path, []byte("replacement"), 0o600)
	if err := store.Rollback("op-parent"); err == nil {
		t.Fatal("rollback accepted a replaced parent directory")
	}
	assertContents(t, path, "replacement")
}

func TestRollbackPreflightsAllTargetParentsBeforeAnyMutation(t *testing.T) {
	root := t.TempDir()
	one, two := filepath.Join(root, "one"), filepath.Join(root, "two")
	mustMkdir(t, one, 0o700)
	mustMkdir(t, two, 0o700)
	first, second := filepath.Join(one, "first"), filepath.Join(two, "second")
	mustWrite(t, first, []byte("first-before"), 0o600)
	mustWrite(t, second, []byte("second-before"), 0o600)
	guard, _ := NewPathGuard(one, two)
	store, _ := NewSnapshotStore(filepath.Join(root, "data"))
	defer store.Close()
	if _, err := store.Create("op-target-preflight", recoverymodel.ActionRemoveManagedTemp, "fp", resolveAll(t, guard, first, second), testTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition("op-target-preflight", recoverymodel.OperationStateSnapshotted, recoverymodel.OperationStateRollingBack, testTime()); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, first, []byte("first-after"), 0o600)
	mustWrite(t, second, []byte("second-after"), 0o600)
	if err := os.Rename(one, one+"-original"); err != nil {
		t.Fatal(err)
	}
	mustMkdir(t, one, 0o700)
	mustWrite(t, first, []byte("replacement"), 0o600)
	if err := store.Rollback("op-target-preflight"); err == nil {
		t.Fatal("replaced target parent accepted")
	}
	assertContents(t, first, "replacement")
	assertContents(t, second, "second-after")
}

func TestSnapshotStoreCloseIsIdempotentAndReleasesFD(t *testing.T) {
	before := countFDs(t)
	for i := 0; i < 40; i++ {
		store, err := NewSnapshotStore(filepath.Join(t.TempDir(), "data"))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatalf("second close: %v", err)
		}
	}
	after := countFDs(t)
	if after > before+4 {
		t.Fatalf("snapshot stores leaked descriptors: before=%d after=%d", before, after)
	}
}

func TestActiveOperationIDsUseBoundDirectoryAndFailClosed(t *testing.T) {
	root := t.TempDir()
	store, err := NewSnapshotStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	for id, state := range map[string]recoverymodel.OperationState{"z-applying": recoverymodel.OperationStateApplying, "a-validating": recoverymodel.OperationStateValidating, "m-done": recoverymodel.OperationStateSucceeded} {
		if err := persistTestManifest(store, id, state, testTime()); err != nil {
			t.Fatal(err)
		}
	}
	ids, err := store.ActiveOperationIDs()
	if err != nil || len(ids) != 2 || ids[0] != "a-validating" || ids[1] != "z-applying" {
		t.Fatalf("ids=%v err=%v", ids, err)
	}
	original := filepath.Join(root, "original-operations")
	if err := os.Rename(store.operationsDir, original); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), store.operationsDir); err != nil {
		t.Fatal(err)
	}
	ids, err = store.ActiveOperationIDs()
	if err != nil || len(ids) != 2 {
		t.Fatalf("bound ids=%v err=%v", ids, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ActiveOperationIDs(); err == nil {
		t.Fatal("closed store listed operations")
	}
}

func TestActiveOperationIDsRejectsCorruptManifest(t *testing.T) {
	store, err := NewSnapshotStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := persistTestManifest(store, "active", recoverymodel.OperationStateApplying, testTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.OperationDir("active"), manifestFilename), []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ActiveOperationIDs(); err == nil {
		t.Fatal("corrupt active manifest was ignored")
	}
}

func TestRetentionKeepsNewestTwentyRecentAndActiveWithoutFollowingSymlinks(t *testing.T) {
	root := t.TempDir()
	store, err := NewSnapshotStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
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

func TestRetentionRemovesOnlyOldIncompleteOperationDirectories(t *testing.T) {
	root := t.TempDir()
	store, err := NewSnapshotStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	oldDir, freshDir := store.OperationDir("op-incomplete-old"), store.OperationDir("op-incomplete-fresh")
	mustMkdir(t, oldDir, 0o700)
	mustMkdir(t, freshDir, 0o700)
	old := testTime().Add(-retentionAge - time.Hour)
	if err := os.Chtimes(oldDir, old, old); err != nil {
		t.Fatal(err)
	}
	if err := store.Prune(testTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldDir); !os.IsNotExist(err) {
		t.Fatalf("old incomplete operation retained: %v", err)
	}
	if _, err := os.Stat(freshDir); err != nil {
		t.Fatalf("fresh incomplete operation removed: %v", err)
	}
}

func TestRetentionPreservesOldOperationWithCorruptManifest(t *testing.T) {
	root := t.TempDir()
	store, err := NewSnapshotStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	dir := store.OperationDir("op-corrupt")
	mustMkdir(t, dir, 0o700)
	mustWrite(t, filepath.Join(dir, manifestFilename), []byte("not-json"), 0o600)
	old := testTime().Add(-retentionAge - time.Hour)
	if err := os.Chtimes(dir, old, old); err != nil {
		t.Fatal(err)
	}
	if err := store.Prune(testTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("corrupt operation was pruned: %v", err)
	}
}

func TestRetentionRemovalRequiresSelectedDirectoryIdentity(t *testing.T) {
	root := t.TempDir()
	store, err := NewSnapshotStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	selected, replacement := store.OperationDir("op-selected"), store.OperationDir("op-replacement")
	mustMkdir(t, selected, 0o700)
	mustMkdir(t, replacement, 0o700)
	info, err := os.Stat(selected)
	if err != nil {
		t.Fatal(err)
	}
	device, inode, ok := fileIdentity(info)
	if !ok {
		t.Fatal("selected identity unavailable")
	}
	if err := os.Remove(selected); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, selected); err != nil {
		t.Fatal(err)
	}
	if err := removeTreeAtExpected(int(store.operations.Fd()), "op-selected", device, inode); err == nil {
		t.Fatal("replacement directory was accepted")
	}
	if _, err := os.Stat(selected); err != nil {
		t.Fatalf("replacement directory removed: %v", err)
	}
}

func TestOpenDirNoSymlinksByComponentsRejectsIntermediateSymlink(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real", "child")
	mustMkdir(t, realDir, 0o700)
	opened, err := openDirNoSymlinksByComponents(realDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(filepath.Join(root, "real"), link); err != nil {
		t.Fatal(err)
	}
	if opened, err = openDirNoSymlinksByComponents(filepath.Join(link, "child")); err == nil {
		_ = opened.Close()
		t.Fatal("intermediate symlink was followed")
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
func assertContents(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != want {
		t.Fatalf("%s contents = %q, %v; want %q", path, got, err, want)
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

func countFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("fd accounting unavailable: %v", err)
	}
	return len(entries)
}

func persistTestManifest(store *SnapshotStore, id string, state recoverymodel.OperationState, created time.Time) error {
	if err := os.Mkdir(store.OperationDir(id), 0o700); err != nil {
		return err
	}
	report := recoverymodel.OperationReport{OperationID: id, DiagnosticID: "diag-" + id, Action: recoverymodel.ActionRemoveManagedTemp, Source: recoverymodel.RequestSourceAutomatic, State: state, StartedAt: created}
	return store.persist(&SnapshotManifest{
		Version: manifestVersion, OperationID: id, Action: recoverymodel.ActionRemoveManagedTemp,
		Fingerprint: "fingerprint", CreatedAt: created, UpdatedAt: created, State: state,
		Report: report, Diagnostic: snapshotDiagnostic(report, "fingerprint", nil, created),
	})
}

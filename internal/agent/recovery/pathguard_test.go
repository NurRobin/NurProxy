package recovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPathGuardRejectsUnsafeRootsAndPaths(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "managed")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := NewPathGuard("relative/root"); err == nil {
		t.Fatal("relative configured root accepted")
	}
	if _, err := NewPathGuard(string(filepath.Separator)); err == nil {
		t.Fatal("filesystem root accepted as a managed root")
	}
	if _, err := NewPathGuard(root + "\nunsafe"); err == nil {
		t.Fatal("unsafe configured root accepted")
	}
	guard, err := NewPathGuard(root)
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		"relative.conf",
		root + string(filepath.Separator) + "sub" + string(filepath.Separator) + ".." + string(filepath.Separator) + "nurproxy-app.conf",
		filepath.Join(outside, "nurproxy-app.conf"),
		root + "-deceptive/nurproxy-app.conf",
		root,
		root + string(filepath.Separator) + "unsafe\nname.conf",
	} {
		if _, err := guard.Resolve(path); err == nil {
			t.Errorf("Resolve(%q) accepted unsafe path", path)
		}
	}
}

func TestPathGuardRejectsSymlinkEscapeAndCanonicalizesExistingParents(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "managed")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{root, outside, filepath.Join(root, "real")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}

	guard, err := NewPathGuard(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.Resolve(filepath.Join(root, "escape", "nurproxy-app.conf")); err == nil {
		t.Fatal("symlink escape accepted")
	}
	got, err := guard.Resolve(filepath.Join(root, "alias", "nurproxy-app.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "real", "nurproxy-app.conf"); got.Path != want || got.ResolvedPath != want {
		t.Fatalf("canonical path = (%q, %q), want %q", got.Path, got.ResolvedPath, want)
	}
}

func TestPathGuardLstatsFinalSymlinkAndRechecksIdentity(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "managed")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(root, "first.conf")
	second := filepath.Join(root, "second.conf")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte(path), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(root, "nurproxy-app.conf")
	if err := os.Symlink(first, link); err != nil {
		t.Fatal(err)
	}
	guard, err := NewPathGuard(root)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := guard.Resolve(link)
	if err != nil {
		t.Fatal(err)
	}
	if checked.Path != link || checked.ResolvedPath != first {
		t.Fatalf("symlink identity paths = (%q, %q)", checked.Path, checked.ResolvedPath)
	}
	if err := guard.Recheck(checked); err != nil {
		t.Fatalf("unchanged path rejected: %v", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(second, link); err != nil {
		t.Fatal(err)
	}
	if err := guard.Recheck(checked); err == nil {
		t.Fatal("swapped final symlink retained a valid identity token")
	}
}

func TestPathGuardRechecksResolvedSymlinkTargetIdentity(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.conf")
	link := filepath.Join(root, "nurproxy-app.conf")
	if err := os.WriteFile(target, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	guard, err := NewPathGuard(root)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := guard.Resolve(link)
	if err != nil {
		t.Fatal(err)
	}
	oldTarget := target + ".old"
	if err := os.Rename(target, oldTarget); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := guard.Recheck(checked); err == nil {
		t.Fatal("replaced symlink target retained a valid identity token")
	}
}

func TestPathGuardRechecksParentForInitiallyAbsentEntry(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "managed")
	parent := filepath.Join(root, "nested")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	guard, err := NewPathGuard(root)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := guard.Resolve(filepath.Join(parent, "nurproxy-app.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Recheck(checked); err != nil {
		t.Fatalf("unchanged absent entry rejected: %v", err)
	}
	oldParent := parent + "-old"
	if err := os.Rename(parent, oldParent); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := guard.Recheck(checked); err == nil {
		t.Fatal("replaced parent retained a valid identity token")
	}
}

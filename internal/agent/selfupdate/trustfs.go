package selfupdate

import (
	"fmt"
	"os"
	"path/filepath"
)

// fsPolicy holds the ownership facts the root applier checks paths against.
// Tests run unprivileged and replace the seams; production uses
// defaultPolicy.
type fsPolicy struct {
	// rootUID is the owner every path the applier trusts must have.
	rootUID uint32
	lstat   func(string) (os.FileInfo, error)
	owner   func(os.FileInfo) uint32
	// chownRoot gives a file the applier wrote to root:root.
	chownRoot func(*os.File) error
}

func defaultPolicy() fsPolicy {
	return fsPolicy{
		rootUID:   0,
		lstat:     os.Lstat,
		owner:     fileOwner,
		chownRoot: func(f *os.File) error { return f.Chown(0, 0) },
	}
}

// checkTrustedPath refuses path unless it and every directory above it is
// owned by root, not group- or world-writable and not a symlink. Only then can
// no unprivileged user swap what root reads or executes at path. wantDir picks
// whether path itself must be a directory or a regular file.
func (p fsPolicy) checkTrustedPath(path string, wantDir bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%q is not a clean absolute path", path)
	}
	for cur := path; ; cur = filepath.Dir(cur) {
		info, err := p.lstat(cur)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("%s is a symlink", cur)
		case cur == path && !wantDir && !info.Mode().IsRegular():
			return fmt.Errorf("%s is not a regular file", cur)
		case (cur != path || wantDir) && !info.IsDir():
			return fmt.Errorf("%s is not a directory", cur)
		case p.owner(info) != p.rootUID:
			return fmt.Errorf("%s is owned by uid %d, not root", cur, p.owner(info))
		case info.Mode().Perm()&0o022 != 0:
			return fmt.Errorf("%s is group- or world-writable (mode %04o)", cur, info.Mode().Perm())
		}
		if parent := filepath.Dir(cur); parent == cur {
			return nil
		}
	}
}

// checkBinary is checkTrustedPath for the agent binary the root trigger
// executes, with the fix spelled out for the operator.
func (p fsPolicy) checkBinary(path string) error {
	if err := p.checkTrustedPath(path, false); err != nil {
		return fmt.Errorf("the root self-update applier runs %s, so it and every directory above it must be owned by root and not group- or world-writable: %w (fix: sudo chown root:root %s && sudo chmod 0755 %s, and the same for any parent directory named here)", path, err, path, path)
	}
	return nil
}

// CheckRootOwnedBinary reports whether path is safe for a root service to
// execute: the file and all its parent directories are owned by root and not
// writable by anyone else. The error says how to fix it.
func CheckRootOwnedBinary(path string) error { return defaultPolicy().checkBinary(path) }

// PrepareRootDir creates the applier's root-owned state directory below
// dataDir (see openHandoff for the checks it runs).
func PrepareRootDir(dataDir string) (string, error) {
	h, err := openHandoff(dataDir, defaultPolicy())
	if err != nil {
		return "", err
	}
	h.Close()
	return string(RootStateDir(dataDir)), nil
}

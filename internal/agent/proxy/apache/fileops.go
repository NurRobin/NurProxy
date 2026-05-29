package apache

import (
	"errors"
	"os"
)

// stagedFile tracks one artifact through the atomic apply (§10): the live
// destination path, the temp file written beside it, a snapshot of the prior
// on-disk content for rollback, and whether the new content has been committed
// (so rollback after commit is a no-op).
type stagedFile struct {
	// dest is the live config path the new content is written to.
	dest string
	// tempPath is the temp file written in the same dir during validation.
	tempPath string
	// priorContent is the destination's content before this apply, restored on
	// rollback. Meaningless when existed is false.
	priorContent []byte
	// existed reports whether dest had content before this apply; false means the
	// rollback action is to remove dest (it is a brand-new file).
	existed bool
	// enabledLink is the sites-enabled symlink this apply created (Debian layout),
	// empty if none (RHEL conf.d has no symlink). On rollback of a brand-new file
	// the symlink is removed too so no dangling activation survives.
	enabledLink string
	// linkPreexisted reports whether the sites-enabled symlink was already present
	// before this apply; when true rollback leaves it alone (it predates us).
	linkPreexisted bool
	// committed reports whether the new content is live and valid; once true a
	// rollback must not revert it.
	committed bool
}

// snapshot captures the current on-disk content of dest for rollback (§10). A
// missing file is recorded as existed=false (rollback removes the new file); any
// other read error is returned so Apply aborts before touching the live config.
func snapshot(dest string) (stagedFile, error) {
	s := stagedFile{dest: dest}
	data, err := os.ReadFile(dest)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return s, err
	}
	s.priorContent = data
	s.existed = true
	return s, nil
}

// restoreSnapshot reverts dest to its pre-apply state: rewrite the prior content
// if the file existed, or remove the file if it was brand-new this apply (§10).
// Best-effort: a restore error cannot itself be recovered, so it is swallowed —
// the subsequent apache state is reported via Validate/health.
func (s stagedFile) restoreSnapshot() {
	if s.existed {
		_ = os.WriteFile(s.dest, s.priorContent, 0o644)
	} else {
		_ = os.Remove(s.dest)
	}
	// Remove a symlink this apply created (the file was brand-new and is now gone),
	// but leave a symlink that predated us alone.
	if s.enabledLink != "" && !s.linkPreexisted {
		_ = os.Remove(s.enabledLink)
	}
}

// ensureSymlink makes link point at target, replacing any existing symlink. A
// pre-existing regular file at link (an operator's own activation) is left in
// place and reported as an error so we never clobber non-managed state.
func ensureSymlink(target, link string) error {
	if fi, err := os.Lstat(link); err == nil {
		if fi.Mode()&os.ModeSymlink == 0 {
			return errors.New("refusing to replace non-symlink at " + link)
		}
		if err := os.Remove(link); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Symlink(target, link)
}

// symlinkPresent reports whether link exists as a symlink (the sites-enabled
// activation marker). A non-symlink or a missing entry both report false. An
// empty link (RHEL conf.d has no symlink) reports false.
func symlinkPresent(link string) bool {
	if link == "" {
		return false
	}
	fi, err := os.Lstat(link)
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSymlink != 0
}

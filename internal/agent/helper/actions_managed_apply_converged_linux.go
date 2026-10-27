//go:build linux

package helper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

// Converged reports whether Execute would leave every target untouched. It
// walks the compilation in Execute's order and asks the same
// managedFileChangePending / managedLinkChangePending functions the mutators
// use, so any target Execute would change or refuse (including an unsafe
// destination directory) makes it return false or an error. It never writes
// and never stores a snapshot.
func (a *managedApplyAction) Converged(ctx context.Context, plan helperprotocol.ManagedApplyPlan, intent helperprotocol.ApplyIntent) (ActionResult, bool, error) {
	compilation, err := a.compile(intent)
	if err != nil {
		return ActionResult{}, false, err
	}
	executionHash, err := managedCompilationDigest(compilation)
	if err != nil || executionHash != plan.ExecutionPlanHash {
		return ActionResult{}, false, fmt.Errorf("managed compilation changed before convergence check")
	}
	fingerprint, err := a.fingerprint(ctx, compilation)
	if err != nil || fingerprint != plan.ResourceFingerprint {
		return ActionResult{}, false, fmt.Errorf("managed targets changed before convergence check")
	}
	pendingLink := func(link managedCompiledLink) (bool, error) { return managedLinkChangePending(link, a.ownerUID) }
	pendingFile := func(file managedCompiledFile) (bool, error) { return managedFileChangePending(file, a.ownerUID) }
	for _, link := range compilation.Links {
		if link.Delete {
			if pending, err := pendingLink(link); err != nil || pending {
				return ActionResult{}, false, err
			}
		}
	}
	for _, file := range compilation.Files {
		if file.Delete && !isManagedAuthDeletion(file) {
			if pending, err := pendingFile(file); err != nil || pending {
				return ActionResult{}, false, err
			}
		}
	}
	for _, file := range compilation.Files {
		if !file.Delete && !file.Preserve {
			if pending, err := pendingFile(file); err != nil || pending {
				return ActionResult{}, false, err
			}
		}
	}
	for _, link := range compilation.Links {
		if !link.Delete && !link.Preserve {
			if pending, err := pendingLink(link); err != nil || pending {
				return ActionResult{}, false, err
			}
		}
	}
	// Execute removes auth files after the reload; any still on disk is pending.
	for _, file := range compilation.Files {
		if isManagedAuthDeletion(file) {
			if pending, err := pendingFile(file); err != nil || pending {
				return ActionResult{}, false, err
			}
		}
	}
	if !compilation.hasDeletions() {
		if err := a.host.Validate(ctx, a.target); err != nil {
			return ActionResult{}, false, fmt.Errorf("native proxy validation failed for converged managed state: %w", err)
		}
	}
	artifacts, err := a.attestManagedArtifacts(compilation)
	if err != nil {
		return ActionResult{}, false, fmt.Errorf("managed proxy artifact attestation failed: %w", err)
	}
	return ActionResult{Mutated: false, Validated: true, SanitizedResult: "managed proxy state already converged" + compilation.retentionNote(), ManagedArtifacts: artifacts}, true, nil
}

// managedFileChangePending is the one decision for a compiled file: whether
// installManagedFile / removeManagedFile would write or delete it. An error
// means the mutator would refuse the target. A deletion of an absent file is a
// no-op without a directory check, exactly as removeManagedFile always behaved.
func managedFileChangePending(file managedCompiledFile, ownerUID uint32) (bool, error) {
	current, err := inspectManagedPath(file.Path, file.Class, "", ownerUID)
	if err != nil {
		return false, err
	}
	if file.Delete && !current.Exists {
		return false, nil
	}
	if file.Class == "auth" && !file.Delete {
		dirPending, err := managedAuthDirectoryPending(filepath.Dir(file.Path), ownerUID, file.GID)
		if err != nil || dirPending {
			return dirPending, err
		}
	}
	if err := validatePrivilegedManagedDirectory(filepath.Dir(file.Path), ownerUID); err != nil {
		return false, err
	}
	if file.Delete {
		return true, nil
	}
	return !managedFileConverged(current, file), nil
}

// managedAuthDirectoryPending reports whether ensureManagedAuthDirectory would
// create the auth directory or repair its group or mode. A directory it would
// refuse (wrong type, symlink, foreign owner, unsafe parent) is an error.
func managedAuthDirectoryPending(dir string, ownerUID, gid uint32) (bool, error) {
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return true, validatePrivilegedManagedDirectory(filepath.Dir(dir), ownerUID)
	}
	if err != nil {
		return false, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != ownerUID {
		return false, fmt.Errorf("managed auth directory is not owned by the configured privileged identity")
	}
	return stat.Gid != gid || info.Mode().Perm() != 0o750 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0, nil
}

// managedLinkChangePending is the same decision for an activation symlink.
func managedLinkChangePending(link managedCompiledLink, ownerUID uint32) (bool, error) {
	current, err := inspectManagedPath(link.Path, "link", link.Target, ownerUID)
	if err != nil {
		return false, err
	}
	if link.Delete && !current.Exists {
		return false, nil
	}
	if err := validatePrivilegedManagedDirectory(filepath.Dir(link.Path), ownerUID); err != nil {
		return false, err
	}
	return link.Delete || !current.Exists, nil
}

// managedFileConverged: present, same permission bits, same bytes, and for
// auth files the worker group. Owner is enforced by inspectManagedPath, which
// refuses a file not owned by the privileged identity before this is reached.
func managedFileConverged(current managedFileSnapshot, file managedCompiledFile) bool {
	return current.Exists && current.Mode == file.Mode && bytes.Equal(current.Content, file.Content) &&
		(file.Class != "auth" || current.GID == file.GID)
}

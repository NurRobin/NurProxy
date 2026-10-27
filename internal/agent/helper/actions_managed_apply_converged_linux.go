//go:build linux

package helper

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"

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
		if file.Delete {
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
	if !compilation.hasDeletions() {
		if err := a.host.Validate(ctx, a.target); err != nil {
			return ActionResult{}, false, fmt.Errorf("native proxy validation failed for converged managed state: %w", err)
		}
	}
	artifacts, err := a.attestManagedArtifacts(compilation)
	if err != nil {
		return ActionResult{}, false, fmt.Errorf("managed proxy artifact attestation failed: %w", err)
	}
	return ActionResult{Mutated: false, Validated: true, SanitizedResult: "managed proxy state already converged", ManagedArtifacts: artifacts}, true, nil
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
	if err := validatePrivilegedManagedDirectory(filepath.Dir(file.Path), ownerUID); err != nil {
		return false, err
	}
	if file.Delete {
		return true, nil
	}
	return !managedFileConverged(current, file), nil
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

// managedFileConverged: present, same permission bits, same bytes. Ownership is
// enforced by inspectManagedPath, which refuses a file not owned by the
// privileged identity before this is reached.
func managedFileConverged(current managedFileSnapshot, file managedCompiledFile) bool {
	return current.Exists && current.Mode == file.Mode && bytes.Equal(current.Content, file.Content)
}

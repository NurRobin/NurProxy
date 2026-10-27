//go:build linux

package helper

import (
	"bytes"
	"context"
	"fmt"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

// Converged reports whether Execute would leave every target untouched. It walks
// the same compilation with the same predicates Execute uses to decide whether to
// remove, install or link, so "converged" here means Execute would return
// Mutated false. It never writes and never stores a snapshot.
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
	for _, link := range compilation.Links {
		if link.Preserve {
			continue
		}
		current, err := inspectManagedPath(link.Path, "link", link.Target, a.ownerUID)
		if err != nil {
			return ActionResult{}, false, err
		}
		if current.Exists == link.Delete {
			return ActionResult{}, false, nil
		}
	}
	for _, file := range compilation.Files {
		if file.Preserve {
			continue
		}
		current, err := inspectManagedPath(file.Path, file.Class, "", a.ownerUID)
		if err != nil {
			return ActionResult{}, false, err
		}
		if file.Delete && current.Exists {
			return ActionResult{}, false, nil
		}
		if !file.Delete && !managedFileConverged(current, file) {
			return ActionResult{}, false, nil
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

// managedFileConverged is the single test for "this file already holds exactly
// what installManagedFile would write": present, same permission bits, same
// bytes. Ownership is enforced by inspectManagedPath, which refuses a file not
// owned by the privileged identity before this is reached.
func managedFileConverged(current managedFileSnapshot, file managedCompiledFile) bool {
	return current.Exists && current.Mode == file.Mode && bytes.Equal(current.Content, file.Content)
}

package recovery

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

type PathGuard struct {
	roots []string
}

type GuardedPathEntryType string

const (
	GuardedPathAbsent  GuardedPathEntryType = "absent"
	GuardedPathRegular GuardedPathEntryType = "regular"
	GuardedPathSymlink GuardedPathEntryType = "symlink"
)

type GuardedPath struct {
	Path         string
	ResolvedPath string
	EntryType    GuardedPathEntryType

	owner          *PathGuard
	root           string
	parentInfo     os.FileInfo
	finalInfo      os.FileInfo
	resolvedInfo   os.FileInfo
	resolvedExists bool
	finalExists    bool
}

func NewPathGuard(roots ...string) (*PathGuard, error) {
	guard := &PathGuard{}
	seen := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		if !safeAbsoluteCleanPath(root) || filepath.Dir(root) == root {
			return nil, fmt.Errorf("managed root must be an absolute clean path")
		}
		canonical, err := canonicalizeAllowMissing(root)
		if err != nil {
			return nil, fmt.Errorf("canonicalize managed root: %w", err)
		}
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		guard.roots = append(guard.roots, canonical)
	}
	if len(guard.roots) == 0 {
		return nil, fmt.Errorf("at least one managed root is required")
	}
	return guard, nil
}

func (g *PathGuard) Resolve(path string) (GuardedPath, error) {
	if g == nil || !safeAbsoluteCleanPath(path) {
		return GuardedPath{}, fmt.Errorf("path must be an absolute clean path")
	}
	parent := filepath.Dir(path)
	canonicalParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return GuardedPath{}, fmt.Errorf("resolve path parent: %w", err)
	}
	canonical := filepath.Join(canonicalParent, filepath.Base(path))
	root, ok := g.containingRoot(canonical)
	if !ok {
		return GuardedPath{}, fmt.Errorf("path is outside managed roots")
	}
	parentInfo, err := os.Stat(canonicalParent)
	if err != nil {
		return GuardedPath{}, fmt.Errorf("stat path parent: %w", err)
	}

	checked := GuardedPath{
		Path: canonical, ResolvedPath: canonical, EntryType: GuardedPathAbsent, owner: g, root: root,
		parentInfo: parentInfo,
	}
	finalInfo, err := os.Lstat(canonical)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return checked, nil
		}
		return GuardedPath{}, fmt.Errorf("lstat path: %w", err)
	}
	switch {
	case finalInfo.Mode().IsRegular():
		checked.EntryType = GuardedPathRegular
	case finalInfo.Mode()&os.ModeSymlink != 0:
		checked.EntryType = GuardedPathSymlink
	default:
		return GuardedPath{}, fmt.Errorf("path is not a regular file or symlink")
	}
	resolved, err := filepath.EvalSymlinks(canonical)
	if err != nil {
		if checked.EntryType != GuardedPathSymlink || !errors.Is(err, os.ErrNotExist) {
			return GuardedPath{}, fmt.Errorf("resolve final path: %w", err)
		}
		linkTarget, readErr := os.Readlink(canonical)
		if readErr != nil {
			return GuardedPath{}, fmt.Errorf("read final symlink: %w", readErr)
		}
		if !filepath.IsAbs(linkTarget) {
			linkTarget = filepath.Join(canonicalParent, linkTarget)
		}
		resolved, err = canonicalizeAllowMissing(filepath.Clean(linkTarget))
		if err != nil {
			return GuardedPath{}, fmt.Errorf("resolve missing symlink target: %w", err)
		}
	}
	if !withinRoot(root, resolved) {
		return GuardedPath{}, fmt.Errorf("final path escapes managed root")
	}
	resolvedInfo, err := os.Stat(canonical)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return GuardedPath{}, fmt.Errorf("stat resolved final path: %w", err)
		}
	} else {
		if !resolvedInfo.Mode().IsRegular() {
			return GuardedPath{}, fmt.Errorf("resolved path is not a regular file")
		}
		checked.resolvedInfo = resolvedInfo
		checked.resolvedExists = true
	}
	checked.ResolvedPath = resolved
	checked.finalInfo = finalInfo
	checked.finalExists = true
	return checked, nil
}

func safeAbsoluteCleanPath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || recoverymodel.SanitizeEvidence(path) != path {
		return false
	}
	for _, r := range path {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func (g *PathGuard) Recheck(path GuardedPath) error {
	if g == nil || path.owner != g || path.parentInfo == nil || path.Path == "" {
		return fmt.Errorf("invalid path identity token")
	}
	current, err := g.Resolve(path.Path)
	if err != nil {
		return err
	}
	if current.root != path.root || current.Path != path.Path || current.ResolvedPath != path.ResolvedPath || current.EntryType != path.EntryType || current.finalExists != path.finalExists || current.resolvedExists != path.resolvedExists {
		return fmt.Errorf("path identity changed")
	}
	if !os.SameFile(current.parentInfo, path.parentInfo) {
		return fmt.Errorf("path parent identity changed")
	}
	if path.finalExists && !os.SameFile(current.finalInfo, path.finalInfo) {
		return fmt.Errorf("path final identity changed")
	}
	if path.resolvedExists && !os.SameFile(current.resolvedInfo, path.resolvedInfo) {
		return fmt.Errorf("path resolved target identity changed")
	}
	return nil
}

func (g *PathGuard) containingRoot(path string) (string, bool) {
	for _, root := range g.roots {
		if withinRoot(root, path) {
			rel, err := filepath.Rel(root, path)
			if err == nil && rel != "." {
				return root, true
			}
		}
	}
	return "", false
}

func (g *PathGuard) containsDirectory(path string) bool {
	if g == nil {
		return false
	}
	for _, root := range g.roots {
		if withinRoot(root, path) {
			return true
		}
	}
	return false
}

func withinRoot(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func canonicalizeAllowMissing(path string) (string, error) {
	current := path
	var missing []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

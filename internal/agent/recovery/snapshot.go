package recovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

const (
	manifestFilename = "manifest.json"
	manifestVersion  = 1
	retentionAge     = 7 * 24 * time.Hour
	retentionCount   = 20
)

type SnapshotKind string

const (
	SnapshotAbsent  SnapshotKind = "absent"
	SnapshotRegular SnapshotKind = "regular"
	SnapshotSymlink SnapshotKind = "symlink"
)

type SnapshotEntry struct {
	Path          string       `json:"path"`
	ResolvedPath  string       `json:"resolved_path"`
	Kind          SnapshotKind `json:"kind"`
	Mode          uint32       `json:"mode"`
	SymlinkTarget string       `json:"symlink_target,omitempty"`
	SHA256        string       `json:"sha256,omitempty"`
	SnapshotFile  string       `json:"snapshot_file,omitempty"`
}

type SnapshotManifest struct {
	Version     int                          `json:"version"`
	OperationID string                       `json:"operation_id"`
	Action      recoverymodel.Action         `json:"action"`
	Fingerprint string                       `json:"fingerprint"`
	CreatedAt   time.Time                    `json:"created_at"`
	UpdatedAt   time.Time                    `json:"updated_at"`
	State       recoverymodel.OperationState `json:"state"`
	Entries     []SnapshotEntry              `json:"entries"`
}

type SnapshotStore struct {
	operationsDir string
}

func NewSnapshotStore(agentDataDir string) (*SnapshotStore, error) {
	if !safeAbsoluteCleanPath(agentDataDir) {
		return nil, fmt.Errorf("agent data directory must be an absolute clean path")
	}
	operations := filepath.Join(agentDataDir, "recovery", "operations")
	if err := mkdirPrivate(operations); err != nil {
		return nil, err
	}
	canonical, err := filepath.EvalSymlinks(operations)
	if err != nil {
		return nil, fmt.Errorf("resolve recovery operations directory: %w", err)
	}
	if canonical != operations {
		return nil, fmt.Errorf("recovery operations directory must not contain symlinks")
	}
	return &SnapshotStore{operationsDir: operations}, nil
}

func (s *SnapshotStore) OperationDir(operationID string) string {
	if s == nil || !validOperationID(operationID) {
		return ""
	}
	return filepath.Join(s.operationsDir, operationID)
}

func (s *SnapshotStore) Create(operationID string, action recoverymodel.Action, fingerprint string, paths []GuardedPath, now time.Time) (*SnapshotManifest, error) {
	if s == nil || !validOperationID(operationID) || !action.Valid() || !validOpaqueID(fingerprint) || now.IsZero() || len(paths) == 0 {
		return nil, fmt.Errorf("invalid snapshot metadata")
	}
	opDir := s.OperationDir(operationID)
	if err := os.Mkdir(opDir, 0o700); err != nil {
		return nil, fmt.Errorf("create operation directory: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(opDir)
		}
	}()
	if err := os.Chmod(opDir, 0o700); err != nil {
		return nil, fmt.Errorf("secure operation directory: %w", err)
	}

	manifest := &SnapshotManifest{
		Version: manifestVersion, OperationID: operationID, Action: action,
		Fingerprint: fingerprint, CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
		State:   recoverymodel.OperationStateSnapshotted,
		Entries: make([]SnapshotEntry, 0, len(paths)),
	}
	seen := make(map[string]struct{}, len(paths))
	for i, checked := range paths {
		if checked.owner == nil || checked.owner.Recheck(checked) != nil {
			return nil, fmt.Errorf("snapshot path %d identity changed", i)
		}
		if _, exists := seen[checked.Path]; exists {
			return nil, fmt.Errorf("duplicate snapshot path")
		}
		seen[checked.Path] = struct{}{}
		entry, err := s.capture(opDir, i, checked)
		if err != nil {
			return nil, err
		}
		manifest.Entries = append(manifest.Entries, entry)
	}
	if err := s.persist(manifest); err != nil {
		return nil, err
	}
	if err := syncDir(s.operationsDir); err != nil {
		return nil, err
	}
	cleanup = false
	return manifest, nil
}

func (s *SnapshotStore) capture(opDir string, index int, checked GuardedPath) (SnapshotEntry, error) {
	entry := SnapshotEntry{Path: checked.Path, ResolvedPath: checked.ResolvedPath}
	switch checked.EntryType {
	case GuardedPathAbsent:
		entry.Kind = SnapshotAbsent
	case GuardedPathRegular:
		entry.Kind = SnapshotRegular
		entry.Mode = uint32(checked.finalInfo.Mode().Perm())
		data, err := os.ReadFile(checked.Path)
		if err != nil {
			return SnapshotEntry{}, fmt.Errorf("read snapshot source: %w", err)
		}
		if err := checked.owner.Recheck(checked); err != nil {
			return SnapshotEntry{}, fmt.Errorf("snapshot source changed: %w", err)
		}
		sum := sha256.Sum256(data)
		entry.SHA256 = hex.EncodeToString(sum[:])
		entry.SnapshotFile = filepath.Join("files", fmt.Sprintf("%04d", index))
		if err := writePrivateFile(filepath.Join(opDir, entry.SnapshotFile), data); err != nil {
			return SnapshotEntry{}, err
		}
	case GuardedPathSymlink:
		entry.Kind = SnapshotSymlink
		target, err := os.Readlink(checked.Path)
		if err != nil {
			return SnapshotEntry{}, fmt.Errorf("read snapshot symlink: %w", err)
		}
		if err := checked.owner.Recheck(checked); err != nil {
			return SnapshotEntry{}, fmt.Errorf("snapshot symlink changed: %w", err)
		}
		entry.SymlinkTarget = target
		sum := sha256.Sum256([]byte(target))
		entry.SHA256 = hex.EncodeToString(sum[:])
	default:
		return SnapshotEntry{}, fmt.Errorf("unsupported snapshot entry type")
	}
	return entry, nil
}

func (s *SnapshotStore) Load(operationID string) (*SnapshotManifest, error) {
	if s == nil || !validOperationID(operationID) {
		return nil, fmt.Errorf("invalid operation ID")
	}
	raw, err := os.ReadFile(filepath.Join(s.OperationDir(operationID), manifestFilename))
	if err != nil {
		return nil, fmt.Errorf("read snapshot manifest: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest SnapshotManifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode snapshot manifest: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	if manifest.OperationID != operationID || validateManifest(&manifest, s.OperationDir(operationID)) != nil {
		return nil, fmt.Errorf("invalid snapshot manifest")
	}
	return &manifest, nil
}

func (s *SnapshotStore) Transition(operationID string, expected, next recoverymodel.OperationState, now time.Time) (*SnapshotManifest, error) {
	manifest, err := s.Load(operationID)
	if err != nil {
		return nil, err
	}
	if manifest.State == next && ValidTransition(expected, next) {
		return manifest, nil
	}
	if manifest.State != expected {
		return nil, fmt.Errorf("stale operation state: have %s, expected %s", manifest.State, expected)
	}
	if !ValidTransition(expected, next) {
		return nil, fmt.Errorf("invalid operation transition %s -> %s", expected, next)
	}
	manifest.State = next
	transitionAt := now.UTC()
	if transitionAt.Before(manifest.UpdatedAt) {
		transitionAt = manifest.UpdatedAt
	}
	manifest.UpdatedAt = transitionAt
	if err := s.persist(manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}

func (s *SnapshotStore) PrepareRestart(operationID string) (RestartDisposition, error) {
	manifest, err := s.Load(operationID)
	if err != nil {
		return RestartNone, err
	}
	disposition := RestartDispositionFor(manifest.State)
	if disposition != RestartBeginRollback {
		return disposition, nil
	}
	if _, err := s.Transition(operationID, recoverymodel.OperationStateApplying, recoverymodel.OperationStateRollingBack, time.Now().UTC()); err != nil {
		return RestartNone, err
	}
	return RestartResumeRollback, nil
}

func (s *SnapshotStore) Rollback(operationID string) error {
	manifest, err := s.Load(operationID)
	if err != nil {
		return err
	}
	for i := len(manifest.Entries) - 1; i >= 0; i-- {
		if err := s.restoreEntry(s.OperationDir(operationID), manifest.Entries[i]); err != nil {
			return fmt.Errorf("restore %s: %w", manifest.Entries[i].Path, err)
		}
	}
	return nil
}

func (s *SnapshotStore) restoreEntry(opDir string, entry SnapshotEntry) error {
	canonicalParent, err := filepath.EvalSymlinks(filepath.Dir(entry.Path))
	if err != nil || canonicalParent != filepath.Dir(entry.Path) {
		return fmt.Errorf("snapshot parent identity changed")
	}
	current, err := os.Lstat(entry.Path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil && !current.Mode().IsRegular() && current.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("refusing to replace unsupported entry type")
	}
	switch entry.Kind {
	case SnapshotAbsent:
		if err == nil && os.Remove(entry.Path) != nil {
			return fmt.Errorf("remove current entry")
		}
		return syncDir(filepath.Dir(entry.Path))
	case SnapshotRegular:
		data, readErr := readSnapshotBlob(filepath.Join(opDir, entry.SnapshotFile))
		if readErr != nil || digest(data) != entry.SHA256 {
			return fmt.Errorf("snapshot content hash mismatch")
		}
		return atomicReplaceRegular(entry.Path, data, os.FileMode(entry.Mode))
	case SnapshotSymlink:
		if digest([]byte(entry.SymlinkTarget)) != entry.SHA256 {
			return fmt.Errorf("snapshot symlink hash mismatch")
		}
		targetPath := entry.SymlinkTarget
		if !filepath.IsAbs(targetPath) {
			targetPath = filepath.Join(filepath.Dir(entry.Path), targetPath)
		}
		resolvedTarget, resolveErr := canonicalizeAllowMissing(filepath.Clean(targetPath))
		if resolveErr != nil || resolvedTarget != entry.ResolvedPath {
			return fmt.Errorf("snapshot symlink target identity mismatch")
		}
		return atomicReplaceSymlink(entry.Path, entry.SymlinkTarget)
	default:
		return fmt.Errorf("unknown snapshot kind")
	}
}

func (s *SnapshotStore) Prune(now time.Time) error {
	entries, err := os.ReadDir(s.operationsDir)
	if err != nil {
		return err
	}
	type candidate struct {
		id      string
		created time.Time
		active  bool
	}
	var operations []candidate
	for _, entry := range entries {
		info, infoErr := entry.Info()
		if infoErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !validOperationID(entry.Name()) {
			continue
		}
		manifest, loadErr := s.Load(entry.Name())
		if loadErr != nil {
			continue
		}
		operations = append(operations, candidate{id: entry.Name(), created: manifest.CreatedAt, active: activeSnapshotState(manifest.State)})
	}
	sort.Slice(operations, func(i, j int) bool { return operations[i].created.After(operations[j].created) })
	keptTerminal := 0
	for _, operation := range operations {
		if operation.active {
			continue
		}
		keptTerminal++
		if keptTerminal <= retentionCount && !operation.created.Before(now.Add(-retentionAge)) {
			continue
		}
		if err := removeOperationDir(s.operationsDir, operation.id); err != nil {
			return err
		}
	}
	return syncDir(s.operationsDir)
}

func (s *SnapshotStore) persist(manifest *SnapshotManifest) error {
	if s == nil || manifest == nil {
		return fmt.Errorf("invalid snapshot manifest")
	}
	if err := validateManifest(manifest, s.OperationDir(manifest.OperationID)); err != nil {
		return fmt.Errorf("invalid snapshot manifest: %w", err)
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	return atomicWritePrivate(filepath.Join(s.OperationDir(manifest.OperationID), manifestFilename), raw)
}

func validateManifest(manifest *SnapshotManifest, opDir string) error {
	if manifest.Version != manifestVersion {
		return fmt.Errorf("invalid manifest version")
	}
	if !validOperationID(manifest.OperationID) {
		return fmt.Errorf("invalid manifest operation ID")
	}
	if !manifest.Action.Valid() {
		return fmt.Errorf("invalid manifest action")
	}
	if !validOpaqueID(manifest.Fingerprint) {
		return fmt.Errorf("invalid manifest fingerprint")
	}
	if manifest.CreatedAt.IsZero() || manifest.UpdatedAt.IsZero() || manifest.UpdatedAt.Before(manifest.CreatedAt) {
		return fmt.Errorf("invalid manifest timestamps")
	}
	if !manifest.State.Valid() {
		return fmt.Errorf("invalid manifest state")
	}
	seen := make(map[string]struct{}, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		if !safeAbsoluteCleanPath(entry.Path) || !safeAbsoluteCleanPath(entry.ResolvedPath) || filepath.Dir(entry.Path) == entry.Path {
			return fmt.Errorf("invalid manifest path")
		}
		if _, exists := seen[entry.Path]; exists {
			return fmt.Errorf("duplicate manifest path")
		}
		seen[entry.Path] = struct{}{}
		switch entry.Kind {
		case SnapshotAbsent:
			if entry.Mode != 0 || entry.SymlinkTarget != "" || entry.SHA256 != "" || entry.SnapshotFile != "" {
				return fmt.Errorf("invalid absent entry")
			}
		case SnapshotRegular:
			if entry.Mode > 0o777 || !validDigest(entry.SHA256) || !validSnapshotFile(entry.SnapshotFile, opDir) || entry.SymlinkTarget != "" {
				return fmt.Errorf("invalid regular entry")
			}
		case SnapshotSymlink:
			if entry.Mode != 0 || entry.SymlinkTarget == "" || recoverymodel.SanitizeEvidence(entry.SymlinkTarget) != entry.SymlinkTarget || !validDigest(entry.SHA256) || entry.SnapshotFile != "" {
				return fmt.Errorf("invalid symlink entry")
			}
		default:
			return fmt.Errorf("invalid snapshot kind")
		}
	}
	return nil
}

func validSnapshotFile(name, opDir string) bool {
	if !strings.HasPrefix(name, "files/") || filepath.Clean(name) != name || filepath.IsAbs(name) {
		return false
	}
	full := filepath.Join(opDir, name)
	return withinRoot(opDir, full) && full != opDir
}

func validOperationID(value string) bool {
	if value == "" || len(value) > 128 || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func validOpaqueID(value string) bool {
	return value != "" && len(value) <= 256 && recoverymodel.SanitizeEvidence(value) == value
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}
func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func mkdirPrivate(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create private directory: %w", err)
	}
	current := path
	for filepath.Dir(current) != current {
		if strings.HasSuffix(current, filepath.Join("recovery", "operations")) || filepath.Base(current) == "recovery" {
			if err := os.Chmod(current, 0o700); err != nil {
				return err
			}
		}
		current = filepath.Dir(current)
	}
	return nil
}

func writePrivateFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return syncDir(filepath.Dir(path))
}

func readSnapshotBlob(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("snapshot blob is not a private regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, openedInfo) {
		file.Close()
		return nil, fmt.Errorf("snapshot blob identity changed")
	}
	data, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return data, nil
}

func atomicWritePrivate(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".manifest-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func atomicReplaceRegular(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".nurproxy-rollback-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if err == nil {
		err = tmp.Chmod(mode.Perm())
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func atomicReplaceSymlink(path, target string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".nurproxy-rollback-link-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Remove(tmpName); err != nil {
		return err
	}
	if err := os.Symlink(target, tmpName); err != nil {
		return err
	}
	defer os.Remove(tmpName)
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("snapshot manifest contains trailing data")
	}
	return nil
}

func activeSnapshotState(state recoverymodel.OperationState) bool {
	switch state {
	case recoverymodel.OperationStateSnapshotted, recoverymodel.OperationStateApplying, recoverymodel.OperationStateValidating, recoverymodel.OperationStateRollingBack, recoverymodel.OperationStateRollbackFailed:
		return true
	default:
		return false
	}
}

func removeOperationDir(root, id string) error {
	path := filepath.Join(root, id)
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to prune non-directory operation")
	}
	children, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, child := range children {
		childPath := filepath.Join(path, child.Name())
		childInfo, err := os.Lstat(childPath)
		if err != nil {
			return err
		}
		if childInfo.Mode()&os.ModeSymlink != 0 {
			if err := os.Remove(childPath); err != nil {
				return err
			}
			continue
		}
		if childInfo.IsDir() {
			if child.Name() != "files" {
				return fmt.Errorf("unexpected operation subdirectory")
			}
			files, err := os.ReadDir(childPath)
			if err != nil {
				return err
			}
			for _, file := range files {
				fi, err := os.Lstat(filepath.Join(childPath, file.Name()))
				if err != nil {
					return err
				}
				if !fi.Mode().IsRegular() {
					return fmt.Errorf("unexpected snapshot entry")
				}
				if err := os.Remove(filepath.Join(childPath, file.Name())); err != nil {
					return err
				}
			}
			if err := os.Remove(childPath); err != nil {
				return err
			}
			continue
		}
		if !childInfo.Mode().IsRegular() {
			return fmt.Errorf("unexpected operation entry")
		}
		if err := os.Remove(childPath); err != nil {
			return err
		}
	}
	return os.Remove(path)
}

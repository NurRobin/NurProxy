package recovery

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
	"golang.org/x/sys/unix"
)

const (
	manifestFilename = "manifest.json"
	manifestVersion  = 2
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
	ParentDevice  uint64       `json:"parent_device"`
	ParentInode   uint64       `json:"parent_inode"`
}

type SnapshotManifest struct {
	Version     int                           `json:"version"`
	OperationID string                        `json:"operation_id"`
	Action      recoverymodel.Action          `json:"action"`
	Fingerprint string                        `json:"fingerprint"`
	CreatedAt   time.Time                     `json:"created_at"`
	UpdatedAt   time.Time                     `json:"updated_at"`
	State       recoverymodel.OperationState  `json:"state"`
	Report      recoverymodel.OperationReport `json:"report"`
	Diagnostic  recoverymodel.Diagnostic      `json:"diagnostic"`
	Entries     []SnapshotEntry               `json:"entries"`
}

type SnapshotStore struct {
	operationsDir string
	operations    *os.File
	mu            sync.Mutex
}

func NewSnapshotStore(agentDataDir string) (*SnapshotStore, error) {
	if !safeAbsoluteCleanPath(agentDataDir) {
		return nil, fmt.Errorf("agent data directory must be an absolute clean path")
	}
	recoveryDir := filepath.Join(agentDataDir, "recovery")
	recovery, err := ensurePrivateDirectory(recoveryDir)
	if err != nil {
		return nil, err
	}
	defer recovery.Close()
	dir, err := openOrCreatePrivateDirAt(recovery, "operations")
	if err != nil {
		return nil, fmt.Errorf("open recovery operations directory: %w", err)
	}
	operations := filepath.Join(recoveryDir, "operations")
	return &SnapshotStore{operationsDir: operations, operations: dir}, nil
}

func (s *SnapshotStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.operations == nil {
		return nil
	}
	err := s.operations.Close()
	s.operations = nil
	return err
}

func (s *SnapshotStore) OperationDir(operationID string) string {
	if s == nil || !validOperationID(operationID) {
		return ""
	}
	return filepath.Join(s.operationsDir, operationID)
}

func (s *SnapshotStore) Create(operationID string, action recoverymodel.Action, fingerprint string, paths []GuardedPath, now time.Time) (*SnapshotManifest, error) {
	report := recoverymodel.OperationReport{OperationID: operationID, DiagnosticID: "legacy-" + fingerprint, Action: action, Source: recoverymodel.RequestSourceAutomatic, State: recoverymodel.OperationStateSnapshotted, SnapshotReference: operationID, StartedAt: now.UTC(), Steps: []recoverymodel.Step{{Name: "detected", State: recoverymodel.OperationStateDetected, At: now.UTC()}, {Name: "planned", State: recoverymodel.OperationStatePlanned, At: now.UTC()}, {Name: "snapshotted", State: recoverymodel.OperationStateSnapshotted, At: now.UTC()}}}
	return s.CreateOperation(report, fingerprint, paths, now)
}

func (s *SnapshotStore) CreateOperation(report recoverymodel.OperationReport, fingerprint string, paths []GuardedPath, now time.Time) (*SnapshotManifest, error) {
	return s.CreateOperationForDiagnostic(report, snapshotDiagnostic(report, fingerprint, paths, now), paths, now)
}

func (s *SnapshotStore) CreateOperationForDiagnostic(report recoverymodel.OperationReport, diagnostic recoverymodel.Diagnostic, paths []GuardedPath, now time.Time) (*SnapshotManifest, error) {
	operationID, action := report.OperationID, report.Action
	fingerprint := diagnostic.ResourceFingerprint
	if s == nil || !validOperationID(operationID) || !action.Valid() || !validOpaqueID(fingerprint) || now.IsZero() || len(paths) == 0 || report.State != recoverymodel.OperationStateSnapshotted || report.SnapshotReference != operationID || report.Validate() != nil || diagnostic.Validate() != nil || diagnostic.ID != report.DiagnosticID || diagnostic.ProposedAction != action {
		return nil, fmt.Errorf("invalid snapshot metadata")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.operations == nil {
		return nil, fmt.Errorf("snapshot store is closed")
	}
	if err := unix.Mkdirat(int(s.operations.Fd()), operationID, 0o700); err != nil {
		return nil, fmt.Errorf("create operation directory: %w", err)
	}
	opDir, err := openDirAt(int(s.operations.Fd()), operationID)
	if err != nil {
		_ = unix.Unlinkat(int(s.operations.Fd()), operationID, unix.AT_REMOVEDIR)
		return nil, err
	}
	cleanup := true
	defer func() {
		_ = opDir.Close()
		if cleanup {
			_ = removeTreeAt(int(s.operations.Fd()), operationID)
		}
	}()
	if err := opDir.Chmod(0o700); err != nil {
		return nil, err
	}
	if err := unix.Mkdirat(int(opDir.Fd()), "files", 0o700); err != nil {
		return nil, err
	}
	filesDir, err := openDirAt(int(opDir.Fd()), "files")
	if err != nil {
		return nil, err
	}
	defer filesDir.Close()
	if err := filesDir.Chmod(0o700); err != nil {
		return nil, err
	}
	manifest := &SnapshotManifest{Version: manifestVersion, OperationID: operationID, Action: action, Fingerprint: fingerprint, CreatedAt: now.UTC(), UpdatedAt: now.UTC(), State: recoverymodel.OperationStateSnapshotted, Report: report, Diagnostic: diagnostic, Entries: make([]SnapshotEntry, 0, len(paths))}
	seen := make(map[string]struct{}, len(paths))
	for i, checked := range paths {
		if checked.owner == nil || checked.owner.Recheck(checked) != nil {
			return nil, fmt.Errorf("snapshot path %d identity changed", i)
		}
		if _, exists := seen[checked.Path]; exists {
			return nil, fmt.Errorf("duplicate snapshot path")
		}
		seen[checked.Path] = struct{}{}
		entry, err := captureSnapshot(filesDir, i, checked)
		if err != nil {
			return nil, err
		}
		manifest.Entries = append(manifest.Entries, entry)
	}
	if err := persistManifestAt(opDir, manifest); err != nil {
		return nil, err
	}
	if err := opDir.Sync(); err != nil {
		return nil, err
	}
	if err := s.operations.Sync(); err != nil {
		return nil, err
	}
	cleanup = false
	return manifest, nil
}

func snapshotDiagnostic(report recoverymodel.OperationReport, fingerprint string, paths []GuardedPath, now time.Time) recoverymodel.Diagnostic {
	affected := make([]string, 0, len(paths))
	for _, path := range paths {
		affected = append(affected, path.Path)
	}
	sort.Strings(affected)
	return recoverymodel.Diagnostic{ID: report.DiagnosticID, Code: recoverymodel.CodeUnknownProxyError, Subsystem: "proxy", Severity: recoverymodel.SeverityError, Ownership: recoverymodel.OwnershipNurProxy, Summary: "Durable safe recovery operation", AffectedPaths: affected, ResourceFingerprint: fingerprint, ProposedAction: report.Action, AutoRepairEligible: true, FirstSeenAt: now.UTC(), LastSeenAt: now.UTC(), Occurrences: 1}
}

func captureSnapshot(filesDir *os.File, index int, checked GuardedPath) (SnapshotEntry, error) {
	entry := SnapshotEntry{Path: checked.Path, ResolvedPath: checked.ResolvedPath}
	device, inode, ok := fileIdentity(checked.parentInfo)
	if !ok {
		return SnapshotEntry{}, fmt.Errorf("snapshot parent identity unavailable")
	}
	entry.ParentDevice, entry.ParentInode = device, inode
	switch checked.EntryType {
	case GuardedPathAbsent:
		entry.Kind = SnapshotAbsent
	case GuardedPathRegular:
		entry.Kind = SnapshotRegular
		entry.Mode = uint32(checked.finalInfo.Mode().Perm())
		data, err := readValidatedSource(checked)
		if err != nil {
			return SnapshotEntry{}, err
		}
		entry.SHA256 = digest(data)
		name := fmt.Sprintf("%04d", index)
		entry.SnapshotFile = filepath.Join("files", name)
		if err := writePrivateAt(filesDir, name, data); err != nil {
			return SnapshotEntry{}, err
		}
	case GuardedPathSymlink:
		entry.Kind = SnapshotSymlink
		parent, err := openDirNoSymlinks(filepath.Dir(checked.Path))
		if err != nil {
			return SnapshotEntry{}, err
		}
		target, err := readlinkAt(parent, filepath.Base(checked.Path))
		_ = parent.Close()
		if err != nil {
			return SnapshotEntry{}, err
		}
		if err := checked.owner.Recheck(checked); err != nil {
			return SnapshotEntry{}, fmt.Errorf("snapshot symlink changed: %w", err)
		}
		entry.SymlinkTarget = target
		entry.SHA256 = digest([]byte(target))
	default:
		return SnapshotEntry{}, fmt.Errorf("unsupported snapshot entry type")
	}
	return entry, nil
}

func readValidatedSource(checked GuardedPath) ([]byte, error) {
	if checked.EntryType != GuardedPathRegular || checked.finalInfo == nil {
		return nil, fmt.Errorf("snapshot source is not a validated regular file")
	}
	parent, err := openDirNoSymlinks(filepath.Dir(checked.Path))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(checked.Path), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open snapshot source: %w", err)
	}
	file := os.NewFile(uintptr(fd), checked.Path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(info, checked.finalInfo) {
		return nil, fmt.Errorf("snapshot source identity changed")
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	if err := checked.owner.Recheck(checked); err != nil {
		return nil, fmt.Errorf("snapshot source changed: %w", err)
	}
	return data, nil
}

func (s *SnapshotStore) Load(operationID string) (*SnapshotManifest, error) {
	if s == nil || !validOperationID(operationID) {
		return nil, fmt.Errorf("invalid operation ID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.operations == nil {
		return nil, fmt.Errorf("snapshot store is closed")
	}
	return s.loadUnlocked(operationID)
}

func (s *SnapshotStore) loadUnlocked(operationID string) (*SnapshotManifest, error) {
	opDir, err := openDirAt(int(s.operations.Fd()), operationID)
	if err != nil {
		return nil, fmt.Errorf("open operation directory: %w", err)
	}
	defer opDir.Close()
	return loadManifestAt(opDir, operationID, s.OperationDir(operationID))
}

func (s *SnapshotStore) Transition(operationID string, expected, next recoverymodel.OperationState, now time.Time) (*SnapshotManifest, error) {
	return s.transition(operationID, expected, next, recoverymodel.OperationReport{}, now)
}

func (s *SnapshotStore) TransitionReport(operationID string, expected recoverymodel.OperationState, report recoverymodel.OperationReport, now time.Time) (*SnapshotManifest, error) {
	return s.transition(operationID, expected, report.State, report, now)
}

func (s *SnapshotStore) transition(operationID string, expected, next recoverymodel.OperationState, report recoverymodel.OperationReport, now time.Time) (*SnapshotManifest, error) {
	if s == nil || !validOperationID(operationID) {
		return nil, fmt.Errorf("invalid operation ID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.operations == nil {
		return nil, fmt.Errorf("snapshot store is closed")
	}
	manifest, err := s.loadUnlocked(operationID)
	if err != nil {
		return nil, err
	}
	if manifest.State == next && ValidTransition(expected, next) {
		if report.OperationID != "" && !reflect.DeepEqual(report, manifest.Report) {
			return nil, fmt.Errorf("idempotent operation report mismatch")
		}
		return manifest, nil
	}
	if manifest.State != expected {
		return nil, fmt.Errorf("stale operation state: have %s, expected %s", manifest.State, expected)
	}
	if !ValidTransition(expected, next) {
		return nil, fmt.Errorf("invalid operation transition %s -> %s", expected, next)
	}
	if report.OperationID != "" {
		if report.OperationID != manifest.OperationID || report.DiagnosticID != manifest.Report.DiagnosticID || report.Action != manifest.Action || report.Source != manifest.Report.Source || !report.StartedAt.Equal(manifest.Report.StartedAt) || report.SnapshotReference != manifest.Report.SnapshotReference || report.State != next {
			return nil, fmt.Errorf("operation report identity or state mismatch")
		}
		if err := report.Validate(); err != nil {
			return nil, fmt.Errorf("invalid operation report: %w", err)
		}
		if len(report.Steps) < len(manifest.Report.Steps) || !slices.Equal(report.Steps[:len(manifest.Report.Steps)], manifest.Report.Steps) {
			return nil, fmt.Errorf("operation report history prefix mismatch")
		}
		manifest.Report = report
	} else {
		manifest.Report.State = next
		manifest.Report.Steps = append(manifest.Report.Steps, recoverymodel.Step{Name: string(next), State: next, At: now.UTC()})
	}
	manifest.State = next
	transitionAt := now.UTC()
	if transitionAt.Before(manifest.UpdatedAt) {
		transitionAt = manifest.UpdatedAt
	}
	manifest.UpdatedAt = transitionAt
	if err := s.persistUnlocked(manifest); err != nil {
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
	report := manifest.Report
	report.State = recoverymodel.OperationStateRollingBack
	at := time.Now().UTC()
	if at.Before(manifest.UpdatedAt) {
		at = manifest.UpdatedAt
	}
	report.Steps = append(report.Steps, recoverymodel.Step{Name: string(report.State), Summary: "resuming rollback after restart", State: report.State, At: at})
	if err := report.Validate(); err != nil {
		return RestartNone, fmt.Errorf("invalid restart report: %w", err)
	}
	if _, err := s.TransitionReport(operationID, recoverymodel.OperationStateApplying, report, at); err != nil {
		return RestartNone, err
	}
	return RestartResumeRollback, nil
}

type preparedSnapshot struct {
	entry     SnapshotEntry
	data      []byte
	parent    *os.File
	exists    bool
	device    uint64
	inode     uint64
	entryType uint32
}

func (s *SnapshotStore) Rollback(operationID string) error {
	if s == nil || !validOperationID(operationID) {
		return fmt.Errorf("invalid operation ID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.operations == nil {
		return fmt.Errorf("snapshot store is closed")
	}
	opDir, err := openDirAt(int(s.operations.Fd()), operationID)
	if err != nil {
		return err
	}
	defer opDir.Close()
	manifest, err := loadManifestAt(opDir, operationID, s.OperationDir(operationID))
	if err != nil {
		return err
	}
	if manifest.State != recoverymodel.OperationStateRollingBack {
		return fmt.Errorf("rollback requires rolling_back state")
	}
	prepared := make([]preparedSnapshot, 0, len(manifest.Entries))
	defer func() {
		for i := range prepared {
			if prepared[i].parent != nil {
				_ = prepared[i].parent.Close()
			}
		}
	}()
	for _, entry := range manifest.Entries {
		item := preparedSnapshot{entry: entry}
		switch entry.Kind {
		case SnapshotRegular:
			item.data, err = readSnapshotBlobAt(opDir, entry.SnapshotFile)
			if err == nil && digest(item.data) != entry.SHA256 {
				err = fmt.Errorf("snapshot content hash mismatch")
			}
		case SnapshotSymlink:
			err = validateSymlinkSnapshot(entry)
		case SnapshotAbsent:
			err = nil
		}
		if err != nil {
			return fmt.Errorf("prevalidate %s: %w", entry.Path, err)
		}
		item.parent, item.exists, item.device, item.inode, item.entryType, err = preflightTarget(entry)
		if err != nil {
			return fmt.Errorf("preflight %s: %w", entry.Path, err)
		}
		prepared = append(prepared, item)
	}
	return restoreAll(prepared)
}

func restoreAll(prepared []preparedSnapshot) error {
	var restoreErrors []error
	for i := len(prepared) - 1; i >= 0; i-- {
		if err := restorePrepared(prepared[i]); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("restore %s: %w", prepared[i].entry.Path, err))
		}
	}
	return errors.Join(restoreErrors...)
}

func restorePrepared(item preparedSnapshot) error {
	entry := item.entry
	parent := item.parent
	parentInfo, err := parent.Stat()
	if err != nil {
		return err
	}
	device, inode, ok := fileIdentity(parentInfo)
	if !ok || device != entry.ParentDevice || inode != entry.ParentInode {
		return fmt.Errorf("snapshot parent identity changed")
	}
	name := filepath.Base(entry.Path)
	var stat unix.Stat_t
	err = unix.Fstatat(int(parent.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if item.exists {
		if err != nil || uint64(stat.Dev) != item.device || stat.Ino != item.inode || uint32(stat.Mode&unix.S_IFMT) != item.entryType {
			return fmt.Errorf("target identity changed after preflight")
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("absent target changed after preflight")
	}
	switch entry.Kind {
	case SnapshotAbsent:
		if err == nil {
			if err := unix.Unlinkat(int(parent.Fd()), name, 0); err != nil {
				return err
			}
		}
		return parent.Sync()
	case SnapshotRegular:
		return atomicReplaceRegularAt(parent, name, item.data, os.FileMode(entry.Mode))
	case SnapshotSymlink:
		return atomicReplaceSymlinkAt(parent, name, entry.SymlinkTarget)
	default:
		return fmt.Errorf("unknown snapshot kind")
	}
}

func preflightTarget(entry SnapshotEntry) (*os.File, bool, uint64, uint64, uint32, error) {
	parent, err := openDirNoSymlinks(filepath.Dir(entry.Path))
	if err != nil {
		return nil, false, 0, 0, 0, err
	}
	info, err := parent.Stat()
	if err != nil {
		_ = parent.Close()
		return nil, false, 0, 0, 0, err
	}
	device, inode, ok := fileIdentity(info)
	if !ok || device != entry.ParentDevice || inode != entry.ParentInode {
		_ = parent.Close()
		return nil, false, 0, 0, 0, fmt.Errorf("snapshot parent identity changed")
	}
	var stat unix.Stat_t
	err = unix.Fstatat(int(parent.Fd()), filepath.Base(entry.Path), &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return parent, false, 0, 0, 0, nil
	}
	if err != nil {
		_ = parent.Close()
		return nil, false, 0, 0, 0, err
	}
	entryType := uint32(stat.Mode & unix.S_IFMT)
	if entryType != uint32(unix.S_IFREG) && entryType != uint32(unix.S_IFLNK) {
		_ = parent.Close()
		return nil, false, 0, 0, 0, fmt.Errorf("refusing to replace unsupported entry type")
	}
	return parent, true, uint64(stat.Dev), stat.Ino, entryType, nil
}

func validateSymlinkSnapshot(entry SnapshotEntry) error {
	if digest([]byte(entry.SymlinkTarget)) != entry.SHA256 {
		return fmt.Errorf("snapshot symlink hash mismatch")
	}
	targetPath := entry.SymlinkTarget
	if !filepath.IsAbs(targetPath) {
		targetPath = filepath.Join(filepath.Dir(entry.Path), targetPath)
	}
	resolved, err := canonicalizeAllowMissing(filepath.Clean(targetPath))
	if err != nil || resolved != entry.ResolvedPath {
		return fmt.Errorf("snapshot symlink target identity mismatch")
	}
	return nil
}

func (s *SnapshotStore) Prune(now time.Time) error {
	if s == nil || now.IsZero() {
		return fmt.Errorf("invalid retention input")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.operations == nil {
		return fmt.Errorf("snapshot store is closed")
	}
	dup, err := unix.Dup(int(s.operations.Fd()))
	if err != nil {
		return err
	}
	if _, err := unix.Seek(dup, 0, 0); err != nil {
		_ = unix.Close(dup)
		return err
	}
	dir := os.NewFile(uintptr(dup), s.operationsDir)
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		return err
	}
	type candidate struct {
		id                 string
		created            time.Time
		active, incomplete bool
		device, inode      uint64
	}
	var operations []candidate
	for _, entry := range entries {
		if !validOperationID(entry.Name()) || entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
			continue
		}
		var selected unix.Stat_t
		if err := unix.Fstatat(int(s.operations.Fd()), entry.Name(), &selected, unix.AT_SYMLINK_NOFOLLOW); err != nil || selected.Mode&unix.S_IFMT != unix.S_IFDIR {
			continue
		}
		device, inode := uint64(selected.Dev), selected.Ino
		manifest, loadErr := s.loadUnlocked(entry.Name())
		if loadErr == nil {
			operations = append(operations, candidate{id: entry.Name(), created: manifest.CreatedAt, active: activeSnapshotState(manifest.State), device: device, inode: inode})
			continue
		}
		if !errors.Is(loadErr, unix.ENOENT) {
			continue
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(int(s.operations.Fd()), entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err == nil && stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			operations = append(operations, candidate{id: entry.Name(), created: time.Unix(int64(stat.Mtim.Sec), int64(stat.Mtim.Nsec)), incomplete: true, device: device, inode: inode})
		}
	}
	sort.Slice(operations, func(i, j int) bool { return operations[i].created.After(operations[j].created) })
	keptTerminal := 0
	for _, operation := range operations {
		if operation.active {
			continue
		}
		if operation.incomplete {
			if operation.created.Before(now.Add(-retentionAge)) {
				if err := removeTreeAtExpected(int(s.operations.Fd()), operation.id, operation.device, operation.inode); err != nil {
					return err
				}
			}
			continue
		}
		keptTerminal++
		if keptTerminal <= retentionCount && !operation.created.Before(now.Add(-retentionAge)) {
			continue
		}
		if err := removeTreeAtExpected(int(s.operations.Fd()), operation.id, operation.device, operation.inode); err != nil {
			return err
		}
	}
	return s.operations.Sync()
}

func (s *SnapshotStore) ActiveOperationIDs() ([]string, error) {
	if s == nil {
		return nil, fmt.Errorf("snapshot store is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.operations == nil {
		return nil, fmt.Errorf("snapshot store is closed")
	}
	dup, err := unix.Dup(int(s.operations.Fd()))
	if err != nil {
		return nil, err
	}
	if _, err := unix.Seek(dup, 0, 0); err != nil {
		_ = unix.Close(dup)
		return nil, err
	}
	dir := os.NewFile(uintptr(dup), s.operationsDir)
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, entry := range entries {
		if !validOperationID(entry.Name()) || entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
			continue
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(int(s.operations.Fd()), entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			continue
		}
		manifest, loadErr := s.loadUnlocked(entry.Name())
		if errors.Is(loadErr, unix.ENOENT) {
			continue
		}
		if loadErr != nil {
			return nil, fmt.Errorf("load recovery operation %q: %w", entry.Name(), loadErr)
		}
		if activeSnapshotState(manifest.State) {
			ids = append(ids, entry.Name())
		}
	}
	sort.Strings(ids)
	return ids, nil
}

func (s *SnapshotStore) persist(manifest *SnapshotManifest) error {
	if s == nil || manifest == nil {
		return fmt.Errorf("invalid snapshot manifest")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.operations == nil {
		return fmt.Errorf("snapshot store is closed")
	}
	return s.persistUnlocked(manifest)
}

func (s *SnapshotStore) persistUnlocked(manifest *SnapshotManifest) error {
	if err := validateManifest(manifest, s.OperationDir(manifest.OperationID)); err != nil {
		return fmt.Errorf("invalid snapshot manifest: %w", err)
	}
	opDir, err := openDirAt(int(s.operations.Fd()), manifest.OperationID)
	if err != nil {
		return err
	}
	defer opDir.Close()
	return persistManifestAt(opDir, manifest)
}

func persistManifestAt(opDir *os.File, manifest *SnapshotManifest) error {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	return atomicWriteAt(opDir, manifestFilename, raw, 0o600)
}

func loadManifestAt(opDir *os.File, operationID, logicalDir string) (*SnapshotManifest, error) {
	raw, err := readRegularAt(opDir, manifestFilename, 0o600)
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
	if manifest.OperationID != operationID || validateManifest(&manifest, logicalDir) != nil {
		return nil, fmt.Errorf("invalid snapshot manifest")
	}
	return &manifest, nil
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
	if manifest.Report.OperationID != manifest.OperationID || manifest.Report.Action != manifest.Action || manifest.Report.State != manifest.State || manifest.Report.Validate() != nil {
		return fmt.Errorf("invalid manifest operation report")
	}
	if manifest.Diagnostic.ID != manifest.Report.DiagnosticID || manifest.Diagnostic.ProposedAction != manifest.Action || manifest.Diagnostic.ResourceFingerprint != manifest.Fingerprint || manifest.Diagnostic.Validate() != nil {
		return fmt.Errorf("invalid manifest diagnostic")
	}
	seen := make(map[string]struct{}, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		if !safeAbsoluteCleanPath(entry.Path) || !safeAbsoluteCleanPath(entry.ResolvedPath) || filepath.Dir(entry.Path) == entry.Path {
			return fmt.Errorf("invalid manifest path")
		}
		if entry.ParentDevice == 0 || entry.ParentInode == 0 {
			return fmt.Errorf("invalid manifest parent identity")
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
	if !strings.HasPrefix(name, "files/") || filepath.Clean(name) != name || filepath.IsAbs(name) || filepath.Dir(name) != "files" {
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
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
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

func fileIdentity(info os.FileInfo) (uint64, uint64, bool) {
	if info == nil {
		return 0, 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return uint64(stat.Dev), stat.Ino, stat.Dev != 0 && stat.Ino != 0
}

func ensurePrivateDirectory(path string) (*os.File, error) {
	if !safeAbsoluteCleanPath(path) {
		return nil, fmt.Errorf("private directory must be an absolute clean path")
	}
	rootFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(rootFD), "/")
	components := strings.Split(strings.TrimPrefix(path, "/"), string(filepath.Separator))
	for i, component := range components {
		if component == "" {
			continue
		}
		next, openErr := openDirAt(int(current.Fd()), component)
		created := false
		if errors.Is(openErr, unix.ENOENT) {
			if err := unix.Mkdirat(int(current.Fd()), component, 0o700); err != nil {
				_ = current.Close()
				return nil, err
			}
			created = true
			next, openErr = openDirAt(int(current.Fd()), component)
		}
		if openErr != nil {
			_ = current.Close()
			return nil, openErr
		}
		if created || i == len(components)-1 {
			if err := next.Chmod(0o700); err != nil {
				_ = next.Close()
				_ = current.Close()
				return nil, err
			}
		}
		info, err := next.Stat()
		if err != nil || !info.IsDir() || ((created || i == len(components)-1) && info.Mode().Perm() != 0o700) {
			_ = next.Close()
			_ = current.Close()
			return nil, fmt.Errorf("invalid private directory component")
		}
		_ = current.Close()
		current = next
	}
	return current, nil
}

func openOrCreatePrivateDirAt(parent *os.File, name string) (*os.File, error) {
	dir, err := openDirAt(int(parent.Fd()), name)
	if errors.Is(err, unix.ENOENT) {
		if err := unix.Mkdirat(int(parent.Fd()), name, 0o700); err != nil {
			return nil, err
		}
		dir, err = openDirAt(int(parent.Fd()), name)
	}
	if err != nil {
		return nil, err
	}
	if err := dir.Chmod(0o700); err != nil {
		_ = dir.Close()
		return nil, err
	}
	info, err := dir.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		_ = dir.Close()
		return nil, fmt.Errorf("invalid private directory")
	}
	return dir, nil
}

func openDirNoSymlinksByComponents(path string) (*os.File, error) {
	if !safeAbsoluteCleanPath(path) {
		return nil, fmt.Errorf("directory must be an absolute clean path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), "/")
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		next, err := openDirAt(int(current.Fd()), component)
		if err != nil {
			_ = current.Close()
			return nil, err
		}
		_ = current.Close()
		current = next
	}
	return current, nil
}

func openDirAt(parent int, name string) (*os.File, error) {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func writePrivateAt(dir *os.File, name string, data []byte) error {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
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
	return dir.Sync()
}

func readRegularAt(dir *os.File, name string, requiredMode os.FileMode) ([]byte, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || (requiredMode != 0 && info.Mode().Perm() != requiredMode) {
		_ = file.Close()
		return nil, fmt.Errorf("entry is not a private regular file")
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

func readSnapshotBlobAt(opDir *os.File, name string) ([]byte, error) {
	if filepath.Dir(name) != "files" {
		return nil, fmt.Errorf("invalid snapshot blob path")
	}
	files, err := openDirAt(int(opDir.Fd()), "files")
	if err != nil {
		return nil, err
	}
	defer files.Close()
	return readRegularAt(files, filepath.Base(name), 0o600)
}

func atomicWriteAt(dir *os.File, name string, data []byte, mode os.FileMode) error {
	tmp, err := randomTempName(".nurproxy-atomic-")
	if err != nil {
		return err
	}
	fd, err := unix.Openat(int(dir.Fd()), tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode.Perm()))
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), tmp)
	cleanup := true
	defer func() {
		if cleanup {
			_ = unix.Unlinkat(int(dir.Fd()), tmp, 0)
		}
	}()
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
	if err := unix.Renameat(int(dir.Fd()), tmp, int(dir.Fd()), name); err != nil {
		return err
	}
	cleanup = false
	return dir.Sync()
}

func atomicReplaceRegularAt(dir *os.File, name string, data []byte, mode os.FileMode) error {
	tmp, err := randomTempName(".nurproxy-rollback-")
	if err != nil {
		return err
	}
	fd, err := unix.Openat(int(dir.Fd()), tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), tmp)
	cleanup := true
	defer func() {
		if cleanup {
			_ = unix.Unlinkat(int(dir.Fd()), tmp, 0)
		}
	}()
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if err == nil {
		err = file.Chmod(mode.Perm())
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := unix.Renameat(int(dir.Fd()), tmp, int(dir.Fd()), name); err != nil {
		return err
	}
	cleanup = false
	return dir.Sync()
}

func atomicReplaceSymlinkAt(dir *os.File, name, target string) error {
	tmp, err := randomTempName(".nurproxy-rollback-link-")
	if err != nil {
		return err
	}
	if err := unix.Symlinkat(target, int(dir.Fd()), tmp); err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = unix.Unlinkat(int(dir.Fd()), tmp, 0)
		}
	}()
	if err := unix.Renameat(int(dir.Fd()), tmp, int(dir.Fd()), name); err != nil {
		return err
	}
	cleanup = false
	return dir.Sync()
}
func randomTempName(prefix string) (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}
func readlinkAt(dir *os.File, name string) (string, error) {
	buffer := make([]byte, 256)
	for len(buffer) <= 1<<20 {
		n, err := unix.Readlinkat(int(dir.Fd()), name, buffer)
		if err != nil {
			return "", err
		}
		if n < len(buffer) {
			return string(buffer[:n]), nil
		}
		buffer = make([]byte, len(buffer)*2)
	}
	return "", fmt.Errorf("symlink target too long")
}

func removeTreeAt(parentFD int, name string) error {
	return removeTreeAtExpected(parentFD, name, 0, 0)
}

func removeTreeAtExpected(parentFD int, name string, expectedDevice, expectedInode uint64) error {
	child, err := openDirAt(parentFD, name)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	openedInfo, err := child.Stat()
	if err != nil {
		_ = child.Close()
		return err
	}
	openedDevice, openedInode, ok := fileIdentity(openedInfo)
	if !ok {
		_ = child.Close()
		return fmt.Errorf("operation directory identity unavailable")
	}
	if expectedDevice != 0 && (openedDevice != expectedDevice || openedInode != expectedInode) {
		_ = child.Close()
		return fmt.Errorf("operation directory identity changed")
	}
	entries, readErr := child.ReadDir(-1)
	if readErr != nil {
		_ = child.Close()
		return readErr
	}
	for _, entry := range entries {
		var stat unix.Stat_t
		if err := unix.Fstatat(int(child.Fd()), entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			_ = child.Close()
			return err
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			if err := removeTreeAtExpected(int(child.Fd()), entry.Name(), uint64(stat.Dev), stat.Ino); err != nil {
				_ = child.Close()
				return err
			}
		} else if err := unix.Unlinkat(int(child.Fd()), entry.Name(), 0); err != nil {
			_ = child.Close()
			return err
		}
	}
	if err := child.Close(); err != nil {
		return err
	}
	var current unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if uint64(current.Dev) != openedDevice || current.Ino != openedInode || current.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("operation directory identity changed")
	}
	return unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
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

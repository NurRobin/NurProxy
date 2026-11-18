package selfupdate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// The unprivileged agent and the privileged applier talk through two
// directories in the agent's data dir:
//
//	self-update/        owned by the agent user; root only reads and unlinks
//	  staged/*          release files the agent downloaded (untrusted input
//	                    for the applier, which verifies them again)
//	  request.json      written by the agent; its appearance starts the
//	                    applier (systemd path unit / launchd WatchPaths)
//	  healthy.json      written by the new agent after it reached the
//	                    orchestrator; the applier waits for it
//	  reported.json     the last result the agent relayed to the orchestrator
//	self-update-root/   owned by root, mode 0755; the agent can only read it
//	  pending.json      written by the applier once it has claimed the
//	                    request; tells the restarted agent what to prove
//	  result.json       written by the applier when it is done; the running
//	                    agent reports it once
//
// Root never writes into a directory the agent can write: there the agent
// could swap entries for symlinks and redirect root's writes, renames or
// deletes anywhere on the host.
const (
	stateDirName     = "self-update"
	rootStateDirName = "self-update-root"
	stagedDirName    = "staged"
	requestFile      = "request.json"
	pendingFile      = "pending.json"
	healthyFile      = "healthy.json"
	reportedFile     = "reported.json"
	resultFile       = "result.json"
	stagedArchive    = "release.tar.gz"
	maxStateBytes    = 64 << 10
	stateDirPerm     = 0o700
	stateFilePerm    = 0o644
	stagedFilePerm   = 0o600
)

// Request is what the agent asks the applier to install.
type Request struct {
	UpgradeID   string    `json:"upgrade_id"`
	Version     string    `json:"version"`
	FromVersion string    `json:"from_version"`
	RequestedAt time.Time `json:"requested_at"`
}

// Pending records an upgrade the applier is carrying out.
type Pending struct {
	UpgradeID   string    `json:"upgrade_id"`
	FromVersion string    `json:"from_version"`
	Version     string    `json:"version"`
	StartedAt   time.Time `json:"started_at"`
}

// Healthy is the restarted agent's proof that it runs and reached the
// orchestrator.
type Healthy struct {
	UpgradeID string    `json:"upgrade_id"`
	Version   string    `json:"version"`
	At        time.Time `json:"at"`
}

// Result is the applier's final verdict.
type Result struct {
	UpgradeID  string                   `json:"upgrade_id"`
	State      models.AgentUpgradeState `json:"state"`
	Version    string                   `json:"version"`
	Error      string                   `json:"error,omitempty"`
	FinishedAt time.Time                `json:"finished_at"`
}

// Dir is the agent-owned hand-off directory below an agent data dir.
type Dir string

// StateDir returns the hand-off directory for dataDir.
func StateDir(dataDir string) Dir { return Dir(filepath.Join(dataDir, stateDirName)) }

func (d Dir) path(name string) string   { return filepath.Join(string(d), name) }
func (d Dir) staged(name string) string { return filepath.Join(string(d), stagedDirName, name) }

// Ensure creates the directory tree with owner-only permissions.
func (d Dir) Ensure() error {
	if err := os.MkdirAll(filepath.Join(string(d), stagedDirName), stateDirPerm); err != nil {
		return fmt.Errorf("creating self-update directory: %w", err)
	}
	return nil
}

// Stage writes the downloaded release files for the applier.
func (d Dir) Stage(r Release) error {
	if err := d.Ensure(); err != nil {
		return err
	}
	for name, data := range map[string][]byte{
		ChecksumsFile: r.Checksums, SignatureFile: r.Signature, CertificateFile: r.Certificate, stagedArchive: r.Archive,
	} {
		if err := writeFileAtomic(d.staged(name), data, stagedFilePerm); err != nil {
			return fmt.Errorf("staging %s: %w", name, err)
		}
	}
	return nil
}

// ClearStaged removes the staged release files.
func (d Dir) ClearStaged() {
	_ = os.RemoveAll(filepath.Join(string(d), stagedDirName))
}

// Reported records which applier result the agent already relayed.
type Reported struct {
	UpgradeID  string    `json:"upgrade_id"`
	FinishedAt time.Time `json:"finished_at"`
}

func (d Dir) WriteRequest(r Request) error   { return writeJSON(d.path(requestFile), r) }
func (d Dir) WriteHealthy(h Healthy) error   { return writeJSON(d.path(healthyFile), h) }
func (d Dir) WriteReported(r Reported) error { return writeJSON(d.path(reportedFile), r) }

// ReadRequest returns the request, or nil when there is none.
func (d Dir) ReadRequest() (*Request, error) { return readJSON[Request](d.path(requestFile)) }

// ReadHealthy returns the health proof, or nil.
func (d Dir) ReadHealthy() (*Healthy, error) { return readJSON[Healthy](d.path(healthyFile)) }

// ReadReported returns the last relayed result, or nil.
func (d Dir) ReadReported() (*Reported, error) { return readJSON[Reported](d.path(reportedFile)) }

func (d Dir) RemoveRequest() error { return removeIfExists(d.path(requestFile)) }
func (d Dir) RemoveHealthy() error { return removeIfExists(d.path(healthyFile)) }

// RootDir is the applier's root-owned directory below an agent data dir. The
// agent only reads it.
type RootDir string

// RootStateDir returns the applier's directory for dataDir.
func RootStateDir(dataDir string) RootDir { return RootDir(filepath.Join(dataDir, rootStateDirName)) }

// ReadPending returns the upgrade the applier is carrying out, or nil.
func (d RootDir) ReadPending() (*Pending, error) {
	return readJSON[Pending](filepath.Join(string(d), pendingFile))
}

// ReadResult returns the applier's verdict, or nil.
func (d RootDir) ReadResult() (*Result, error) {
	return readJSON[Result](filepath.Join(string(d), resultFile))
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func writeJSON(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data, stateFilePerm)
}

func readJSON[T any](path string) (*T, error) {
	data, err := readRegular(path, maxStateBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", filepath.Base(path), err)
	}
	return &v, nil
}

// readRegular reads at most limit bytes from a regular file, refusing symlinks
// and other file types.
func readRegular(path string, limit int64) ([]byte, error) {
	f, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(path), limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(path), limit)
	}
	return data, nil
}

// writeFileAtomic writes data to a temp file in path's directory, fsyncs it and
// renames it over path, then fsyncs the directory. A rename replaces a symlink
// at path instead of following it.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	committed = true
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}

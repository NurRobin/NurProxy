package selfupdate

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// maxRequestBytes bounds the JSON files root reads from the agent's directory.
const maxRequestBytes = 4 << 10

// handoff is the root applier's view of an agent data dir. Every directory is
// opened relative to its parent's descriptor without following symlinks, and
// every check runs on the opened descriptor, so the unprivileged agent cannot
// swap a path between check and use:
//
//   - agent is <data-dir>/self-update, writable by the agent. Root only reads
//     from it (owner, type, link-count and size checked) and unlinks entries in
//     it; it never creates, renames or writes there.
//   - root is <data-dir>/self-update-root, owned by root, mode 0755. Everything
//     root writes goes here; the agent can only read it.
type handoff struct {
	pol      fsPolicy
	agentUID uint32
	agent    *os.File // nil when the agent never created self-update/
	root     *os.File
}

// openHandoff opens the hand-off directories below dataDir for the root
// applier. dataDir's parents must be root-owned and not group- or
// world-writable; dataDir itself must not be a symlink or group- or
// world-writable, and its owner is taken as the agent user. The root
// directory is created when missing and refused when someone else owns it.
func openHandoff(dataDir string, pol fsPolicy) (*handoff, error) {
	if !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return nil, fmt.Errorf("data dir %q is not a clean absolute path", dataDir)
	}
	if err := pol.checkTrustedPath(filepath.Dir(dataDir), true); err != nil {
		return nil, fmt.Errorf("data dir %s is not in a root-controlled location: %w", dataDir, err)
	}
	data, err := openDirAt(nil, dataDir)
	if err != nil {
		return nil, fmt.Errorf("opening data dir: %w", err)
	}
	defer data.Close()
	info, err := data.Stat()
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("data dir %s is group- or world-writable (mode %04o)", dataDir, info.Mode().Perm())
	}
	h := &handoff{pol: pol, agentUID: pol.owner(info)}
	if h.root, err = h.openRootDir(data); err != nil {
		return nil, err
	}
	agent, err := h.openAgentDir(data, stateDirName)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		h.Close()
		return nil, err
	default:
		h.agent = agent
	}
	return h, nil
}

func (h *handoff) Close() {
	if h.agent != nil {
		_ = h.agent.Close()
	}
	if h.root != nil {
		_ = h.root.Close()
	}
}

func (h *handoff) openRootDir(data *os.File) (*os.File, error) {
	if err := mkdirAt(data, rootStateDirName, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("creating %s: %w", rootStateDirName, err)
	}
	dir, err := openDirAt(data, rootStateDirName)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", rootStateDirName, err)
	}
	info, err := dir.Stat()
	if err == nil && h.pol.owner(info) != h.pol.rootUID {
		err = fmt.Errorf("%s is owned by uid %d, not root; remove it so the applier can recreate it", rootStateDirName, h.pol.owner(info))
	}
	if err == nil && info.Mode().Perm() != 0o755 {
		// Only root can have created a root-owned entry here; normalize the
		// mode so the agent can read what root leaves for it.
		err = dir.Chmod(0o755)
	}
	if err != nil {
		_ = dir.Close()
		return nil, err
	}
	return dir, nil
}

// openAgentDir opens an agent-owned directory below parent and checks that it
// belongs to the agent user and is not writable by anyone else.
func (h *handoff) openAgentDir(parent *os.File, name string) (*os.File, error) {
	dir, err := openDirAt(parent, name)
	if err != nil {
		return nil, err
	}
	info, err := dir.Stat()
	if err == nil {
		switch {
		case h.pol.owner(info) != h.agentUID:
			err = fmt.Errorf("%s is owned by uid %d, not the agent user (uid %d)", name, h.pol.owner(info), h.agentUID)
		case info.Mode().Perm()&0o022 != 0:
			err = fmt.Errorf("%s is group- or world-writable (mode %04o)", name, info.Mode().Perm())
		}
	}
	if err != nil {
		_ = dir.Close()
		return nil, err
	}
	return dir, nil
}

// readAgentFile reads name from an agent directory as untrusted input: no
// symlinks, no FIFOs or devices, owned by the agent user, a single link (so it
// cannot be a hard link to a file the agent may not read) and at most limit
// bytes.
func (h *handoff) readAgentFile(dir *os.File, name string, limit int64) ([]byte, error) {
	f, err := openFileAt(dir, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	switch {
	case !info.Mode().IsRegular():
		return nil, fmt.Errorf("%s is not a regular file", name)
	case h.pol.owner(info) != h.agentUID:
		return nil, fmt.Errorf("%s is owned by uid %d, not the agent user (uid %d)", name, h.pol.owner(info), h.agentUID)
	case linkCount(info) != 1:
		return nil, fmt.Errorf("%s has %d hard links", name, linkCount(info))
	case info.Size() > limit:
		return nil, fmt.Errorf("%s is larger than %d bytes", name, limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, limit)
	}
	return data, nil
}

// readAgentJSON strictly decodes one JSON object from the agent directory. It
// returns nil, nil when the file does not exist.
func readAgentJSON[T any](h *handoff, name string) (*T, error) {
	if h.agent == nil {
		return nil, nil
	}
	data, err := h.readAgentFile(h.agent, name, maxRequestBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var v T
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", name, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decoding %s: trailing data", name)
	}
	return &v, nil
}

func (h *handoff) readRequest() (*Request, error) { return readAgentJSON[Request](h, requestFile) }
func (h *handoff) readHealthy() (*Healthy, error) { return readAgentJSON[Healthy](h, healthyFile) }

// removeAgentFile unlinks name in the agent directory. unlinkat removes a
// symlink itself, never its target.
func (h *handoff) removeAgentFile(name string) error {
	if h.agent == nil {
		return nil
	}
	if err := unlinkAt(h.agent, name, false); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// loadStaged reads the staged release into memory. Root verifies and installs
// from this copy only, so changing the files afterwards has no effect.
func (h *handoff) loadStaged(version, asset string) (Release, error) {
	if h.agent == nil {
		return Release{}, fmt.Errorf("nothing staged: %w", os.ErrNotExist)
	}
	dir, err := h.openAgentDir(h.agent, stagedDirName)
	if err != nil {
		return Release{}, fmt.Errorf("opening staged release: %w", err)
	}
	defer dir.Close()
	r := Release{Version: version, Asset: asset}
	for _, f := range []struct {
		name string
		max  int64
		dst  *[]byte
	}{
		{ChecksumsFile, maxChecksumsBytes, &r.Checksums},
		{SignatureFile, maxSignatureBytes, &r.Signature},
		{CertificateFile, maxCertificateBytes, &r.Certificate},
		{stagedArchive, maxArchiveBytes, &r.Archive},
	} {
		data, err := h.readAgentFile(dir, f.name, f.max)
		if err != nil {
			return Release{}, fmt.Errorf("reading staged %s: %w", f.name, err)
		}
		*f.dst = data
	}
	return r, nil
}

// clearStaged unlinks the staged release files by name and then the empty
// staged directory. It never recurses, so a planted symlink or subdirectory
// cannot widen what root deletes.
func (h *handoff) clearStaged() {
	if h.agent == nil {
		return
	}
	if dir, err := openDirAt(h.agent, stagedDirName); err == nil {
		for _, name := range []string{ChecksumsFile, SignatureFile, CertificateFile, stagedArchive} {
			_ = unlinkAt(dir, name, false)
		}
		_ = dir.Close()
	}
	_ = unlinkAt(h.agent, stagedDirName, true)
}

// writeRootJSON atomically replaces name in the root directory.
func (h *handoff) writeRootJSON(name string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := "." + name + ".tmp-" + hex.EncodeToString(suffix[:])
	f, err := createFileAt(h.root, tmp, stateFilePerm)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = f.Close()
			_ = unlinkAt(h.root, tmp, false)
		}
	}()
	if err := f.Chmod(stateFilePerm); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := renameAt(h.root, tmp, name); err != nil {
		return err
	}
	committed = true
	if err := h.root.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}

func (h *handoff) removeRootFile(name string) error {
	if err := unlinkAt(h.root, name, false); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

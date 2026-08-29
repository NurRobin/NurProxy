package proxy

import (
	"errors"
	"fmt"
	"io"
	"os"
)

var ErrManagedArtifactNotRegular = errors.New("managed artifact is not a regular file")

type ManagedArtifactFileIdentity struct {
	path string
	info os.FileInfo
}

func ReadManagedArtifactFile(path string) ([]byte, bool, ManagedArtifactFileIdentity, error) {
	return readManagedArtifactFile(path, 0)
}

func ProbeManagedArtifactFile(path string) (bool, ManagedArtifactFileIdentity, error) {
	probe, managed, identity, err := readManagedArtifactFile(path, MaxManagedArtifactMarkerProbeBytes+1)
	_ = probe
	return managed, identity, err
}

func (identity ManagedArtifactFileIdentity) Recheck() error {
	if identity.path == "" || identity.info == nil {
		return fmt.Errorf("invalid managed artifact identity")
	}
	current, err := os.Lstat(identity.path)
	if err != nil {
		return fmt.Errorf("recheck managed artifact: %w", err)
	}
	if !current.Mode().IsRegular() || !sameManagedFileState(identity.info, current) {
		return fmt.Errorf("managed artifact identity changed")
	}
	return nil
}

func readManagedArtifactFile(path string, limit int64) ([]byte, bool, ManagedArtifactFileIdentity, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, false, ManagedArtifactFileIdentity{}, err
	}
	if !before.Mode().IsRegular() {
		return nil, false, ManagedArtifactFileIdentity{}, ErrManagedArtifactNotRegular
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false, ManagedArtifactFileIdentity{}, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, false, ManagedArtifactFileIdentity{}, err
	}
	if !opened.Mode().IsRegular() || !sameManagedFileState(before, opened) {
		_ = file.Close()
		return nil, false, ManagedArtifactFileIdentity{}, fmt.Errorf("managed artifact identity changed while opening")
	}
	reader := io.Reader(file)
	if limit > 0 {
		reader = io.LimitReader(file, limit)
	}
	data, readErr := io.ReadAll(reader)
	closeErr := file.Close()
	if readErr != nil {
		return nil, false, ManagedArtifactFileIdentity{}, readErr
	}
	if closeErr != nil {
		return nil, false, ManagedArtifactFileIdentity{}, closeErr
	}
	after, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !sameManagedFileState(opened, after) {
		return nil, false, ManagedArtifactFileIdentity{}, fmt.Errorf("managed artifact identity changed while reading")
	}
	identity := ManagedArtifactFileIdentity{path: path, info: after}
	return data, HasManagedArtifactMarker(string(data)), identity, nil
}

func sameManagedFileState(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime() == b.ModTime()
}

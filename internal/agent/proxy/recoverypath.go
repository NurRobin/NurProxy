package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
	"golang.org/x/sys/unix"
)

const maxRecoveryArtifactBytes = 8 << 20

func CaptureManagedRecoveryPath(path string) (RecoveryPathIdentity, bool, error) {
	marked, markerIdentity, err := ProbeManagedArtifactFile(path)
	if err != nil {
		return RecoveryPathIdentity{}, false, err
	}
	identity, err := CaptureRecoveryPath(path)
	if err != nil {
		return RecoveryPathIdentity{}, false, err
	}
	if err := markerIdentity.Recheck(); err != nil {
		return RecoveryPathIdentity{}, false, err
	}
	return identity, marked, nil
}

func NewRecoveryCandidate(action recoverymodel.Action, host string, identities ...RecoveryPathIdentity) RecoveryCandidate {
	paths := make([]string, 0, len(identities))
	for _, identity := range identities {
		paths = append(paths, identity.Path)
	}
	return RecoveryCandidate{Action: action, Host: host, Paths: paths, Identities: identities}
}

func RemoveRecoveryCandidatePaths(candidate RecoveryCandidate) error {
	if err := candidate.Validate(); err != nil {
		return err
	}
	if len(candidate.Identities) != len(candidate.Paths) {
		return fmt.Errorf("recovery candidate identity count mismatch")
	}
	for i, identity := range candidate.Identities {
		if identity.Path != candidate.Paths[i] {
			return fmt.Errorf("recovery candidate identity path mismatch")
		}
		if identity.Exists {
			if err := RemoveRecoveryPath(identity); err != nil {
				return err
			}
		}
	}
	return nil
}

func CaptureRecoveryPath(path string) (RecoveryPathIdentity, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return RecoveryPathIdentity{}, fmt.Errorf("recovery path must be absolute and clean")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return RecoveryPathIdentity{}, fmt.Errorf("resolve recovery parent: %w", err)
	}
	parentInfo, err := os.Stat(parent)
	if err != nil || !parentInfo.IsDir() {
		return RecoveryPathIdentity{}, fmt.Errorf("invalid recovery parent")
	}
	parentDevice, parentInode, ok := fileDeviceInode(parentInfo)
	if !ok {
		return RecoveryPathIdentity{}, fmt.Errorf("recovery parent has no stable identity")
	}
	canonical := filepath.Join(parent, filepath.Base(path))
	identity := RecoveryPathIdentity{Path: canonical, parentDevice: parentDevice, parentInode: parentInode}
	info, err := os.Lstat(canonical)
	if errors.Is(err, os.ErrNotExist) {
		return identity, nil
	}
	if err != nil {
		return RecoveryPathIdentity{}, err
	}
	device, inode, ok := fileDeviceInode(info)
	if !ok {
		return RecoveryPathIdentity{}, fmt.Errorf("recovery path has no stable identity")
	}
	identity.Exists = true
	identity.Mode = uint32(info.Mode())
	identity.Device = device
	identity.Inode = inode
	switch {
	case info.Mode().IsRegular():
		digest, err := hashRegularPath(canonical, info)
		if err != nil {
			return RecoveryPathIdentity{}, err
		}
		identity.SHA256 = digest
	case info.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(canonical)
		if err != nil {
			return RecoveryPathIdentity{}, err
		}
		identity.SymlinkTarget = target
	default:
		return RecoveryPathIdentity{}, fmt.Errorf("recovery path is not regular or symlink")
	}
	return identity, nil
}

func (identity RecoveryPathIdentity) Recheck() error {
	current, err := CaptureRecoveryPath(identity.Path)
	if err != nil {
		return err
	}
	if current.Path != identity.Path || current.Exists != identity.Exists || current.Mode != identity.Mode ||
		current.Device != identity.Device || current.Inode != identity.Inode || current.SymlinkTarget != identity.SymlinkTarget ||
		current.SHA256 != identity.SHA256 || current.parentDevice != identity.parentDevice || current.parentInode != identity.parentInode {
		return fmt.Errorf("recovery path identity changed")
	}
	return nil
}

func RemoveRecoveryPath(identity RecoveryPathIdentity) error {
	if !identity.Exists || identity.Path == "" {
		return fmt.Errorf("recovery path is absent")
	}
	parent := filepath.Dir(identity.Path)
	dirfd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open recovery parent: %w", err)
	}
	defer unix.Close(dirfd)
	var parentStat unix.Stat_t
	if err := unix.Fstat(dirfd, &parentStat); err != nil || uint64(parentStat.Dev) != identity.parentDevice || parentStat.Ino != identity.parentInode {
		return fmt.Errorf("recovery parent identity changed")
	}
	name := filepath.Base(identity.Path)
	var current unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("recheck recovery entry: %w", err)
	}
	if uint64(current.Dev) != identity.Device || current.Ino != identity.Inode {
		return fmt.Errorf("recovery entry identity changed")
	}
	if identity.SymlinkTarget != "" {
		buf := make([]byte, 4096)
		n, err := unix.Readlinkat(dirfd, name, buf)
		if err != nil || string(buf[:n]) != identity.SymlinkTarget {
			return fmt.Errorf("recovery symlink identity changed")
		}
	} else {
		fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return fmt.Errorf("open recovery entry: %w", err)
		}
		file := os.NewFile(uintptr(fd), name)
		var opened unix.Stat_t
		if err := unix.Fstat(fd, &opened); err != nil || uint64(opened.Dev) != identity.Device || opened.Ino != identity.Inode {
			_ = file.Close()
			return fmt.Errorf("recovery entry identity changed while opening")
		}
		digest, hashErr := hashBounded(file)
		closeErr := file.Close()
		if hashErr != nil || closeErr != nil || digest != identity.SHA256 {
			return fmt.Errorf("recovery entry content changed")
		}
	}
	var final unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &final, unix.AT_SYMLINK_NOFOLLOW); err != nil || uint64(final.Dev) != identity.Device || final.Ino != identity.Inode {
		return fmt.Errorf("recovery entry identity changed before unlink")
	}
	if err := unix.Unlinkat(dirfd, name, 0); err != nil {
		return fmt.Errorf("unlink recovery entry: %w", err)
	}
	return nil
}

func hashRegularPath(path string, expected os.FileInfo) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
		_ = file.Close()
		return "", fmt.Errorf("recovery file identity changed while opening")
	}
	digest, hashErr := hashBounded(file)
	closeErr := file.Close()
	after, statErr := os.Lstat(path)
	if hashErr != nil || closeErr != nil || statErr != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || opened.ModTime() != after.ModTime() {
		return "", fmt.Errorf("recovery file identity changed while reading")
	}
	return digest, nil
}

func hashBounded(reader io.Reader) (string, error) {
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(reader, maxRecoveryArtifactBytes+1))
	if err != nil {
		return "", err
	}
	if n > maxRecoveryArtifactBytes {
		return "", fmt.Errorf("recovery artifact exceeds size limit")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fileDeviceInode(info os.FileInfo) (uint64, uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return uint64(stat.Dev), stat.Ino, true
}

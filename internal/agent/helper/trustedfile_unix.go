//go:build !windows

package helper

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func readTrustedFile(path string, expectedOwnerUID uint32, maxBytes int64, private bool) ([]byte, error) {
	if err := validatePrivatePath(path); err != nil {
		return nil, err
	}
	if err := validateTrustedDirectory(filepath.Dir(path), expectedOwnerUID); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open trusted file", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open trusted file returned invalid descriptor")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maxBytes || fileOwnerUID(info) != expectedOwnerUID {
		return nil, fmt.Errorf("trusted file type, size, or owner is invalid")
	}
	if info.Mode().Perm()&0o022 != 0 || (private && info.Mode().Perm()&0o077 != 0) {
		return nil, fmt.Errorf("trusted file permissions are too broad")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > maxBytes {
		return nil, fmt.Errorf("trusted file exceeds size limit")
	}
	return payload, nil
}

func validateTrustedDirectory(path string, expectedOwnerUID uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || fileOwnerUID(info) != expectedOwnerUID || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("trusted parent directory type, owner, or permissions are invalid")
	}
	return nil
}

func fileOwnerUID(info os.FileInfo) uint32 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ^uint32(0)
	}
	return stat.Uid
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

//go:build unix

package selfupdate

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

// detach starts cmd in its own session so stopping the agent's service does
// not take the applier down with it.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

func fileOwner(info os.FileInfo) uint32 {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ^uint32(0)
	}
	return st.Uid
}

func linkCount(info os.FileInfo) uint64 {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(st.Nlink)
}

// dirFD returns parent's descriptor, or AT_FDCWD for a nil parent (name is
// then an absolute path).
func dirFD(parent *os.File) int {
	if parent == nil {
		return unix.AT_FDCWD
	}
	return int(parent.Fd())
}

func dirName(parent *os.File, name string) string {
	if parent == nil {
		return name
	}
	return filepath.Join(parent.Name(), name)
}

func newFile(fd int, parent *os.File, name string) *os.File {
	return os.NewFile(uintptr(fd), dirName(parent, name))
}

// openDirAt opens the directory name below parent without following a
// symlink in its last component.
func openDirAt(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(dirFD(parent), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open directory", Path: dirName(parent, name), Err: err}
	}
	return newFile(fd, parent, name), nil
}

// openFileAt opens name below parent for reading. O_NOFOLLOW refuses a
// symlink and O_NONBLOCK keeps a planted FIFO from blocking the open; the
// caller checks the file type on the descriptor.
func openFileAt(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(dirFD(parent), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: dirName(parent, name), Err: err}
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "open", Path: dirName(parent, name), Err: err}
	}
	return newFile(fd, parent, name), nil
}

// createFileAt creates a new file below parent; it fails if anything, a
// symlink included, already exists under that name.
func createFileAt(parent *os.File, name string, perm os.FileMode) (*os.File, error) {
	fd, err := unix.Openat(dirFD(parent), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(perm.Perm()))
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: dirName(parent, name), Err: err}
	}
	return newFile(fd, parent, name), nil
}

func mkdirAt(parent *os.File, name string, perm os.FileMode) error {
	if err := unix.Mkdirat(dirFD(parent), name, uint32(perm.Perm())); err != nil {
		return &os.PathError{Op: "mkdir", Path: dirName(parent, name), Err: err}
	}
	return nil
}

func unlinkAt(parent *os.File, name string, isDir bool) error {
	flags := 0
	if isDir {
		flags = unix.AT_REMOVEDIR
	}
	if err := unix.Unlinkat(dirFD(parent), name, flags); err != nil {
		return &os.PathError{Op: "remove", Path: dirName(parent, name), Err: err}
	}
	return nil
}

func renameAt(dir *os.File, from, to string) error {
	if err := unix.Renameat(dirFD(dir), from, dirFD(dir), to); err != nil {
		return &os.LinkError{Op: "rename", Old: dirName(dir, from), New: dirName(dir, to), Err: err}
	}
	return nil
}

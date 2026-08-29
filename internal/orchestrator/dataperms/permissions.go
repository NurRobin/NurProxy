//go:build unix

package dataperms

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	DirMode  = 0o700
	FileMode = 0o600
)

type Report struct {
	Hardened []string
	Skipped  []string
}
type Dir struct {
	fd   int
	path string
}

func SetPrivateUmask() { unix.Umask(0o077) }

func OpenDir(path string, create bool) (*Dir, error) {
	if path == "" {
		return nil, fmt.Errorf("data directory is empty")
	}
	for _, part := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' }) {
		if part == ".." {
			return nil, fmt.Errorf("data directory must not contain .. components")
		}
	}
	start := "."
	if filepath.IsAbs(path) {
		start = "/"
	}
	fd, err := unix.Open(start, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("opening data-directory anchor: %w", err)
	}
	parts := strings.FieldsFunc(filepath.Clean(path), func(r rune) bool { return r == '/' })
	for _, part := range parts {
		if part == "." || part == "" {
			continue
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr == unix.ENOENT && create {
			if mkdirErr := unix.Mkdirat(fd, part, DirMode); mkdirErr != nil && mkdirErr != unix.EEXIST {
				_ = unix.Close(fd)
				return nil, fmt.Errorf("creating data-directory component %q: %w", part, mkdirErr)
			}
			next, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("opening data-directory component %q without following links: %w", part, openErr)
		}
		_ = unix.Close(fd)
		fd = next
	}
	return &Dir{fd: fd, path: path}, nil
}

func (d *Dir) Close() error {
	if d == nil || d.fd < 0 {
		return nil
	}
	err := unix.Close(d.fd)
	d.fd = -1
	return err
}
func (d *Dir) OpenRegular(name string) (*os.File, error) {
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%s is not a unique regular file", name)
	}
	return os.NewFile(uintptr(fd), name), nil
}

func (d *Dir) OpenOrCreateRegular(name string) (*os.File, bool, error) {
	for {
		fd, err := unix.Openat(d.fd, name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		created := false
		if err == unix.ENOENT {
			fd, err = unix.Openat(d.fd, name, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, FileMode)
			created = err == nil
			if err == unix.EEXIST {
				continue
			}
		}
		if err != nil {
			return nil, false, err
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			_ = unix.Close(fd)
			return nil, false, err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
			_ = unix.Close(fd)
			return nil, false, fmt.Errorf("%s is not a unique regular file", name)
		}
		if err := unix.Fchmod(fd, FileMode); err != nil {
			_ = unix.Close(fd)
			return nil, false, err
		}
		return os.NewFile(uintptr(fd), name), created, nil
	}
}

func BoundFilePath(file *os.File) (string, error) {
	for _, root := range []string{"/proc/self/fd", "/dev/fd"} {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return fmt.Sprintf("%s/%d", root, file.Fd()), nil
		}
	}
	return "", fmt.Errorf("secure descriptor-backed file paths are unavailable on this platform")
}

func (d *Dir) SameFile(name string, opened *os.File) (bool, error) {
	var held, current unix.Stat_t
	if err := unix.Fstat(int(opened.Fd()), &held); err != nil {
		return false, err
	}
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	if err := unix.Fstat(fd, &current); err != nil {
		return false, err
	}
	return held.Dev == current.Dev && held.Ino == current.Ino && current.Nlink == 1, nil
}

func (d *Dir) Exists(name string) (bool, error) {
	var st unix.Stat_t
	err := unix.Fstatat(d.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == unix.ENOENT {
		return false, nil
	}
	return err == nil, err
}

func (d *Dir) ValidateReplace(name string) error {
	var st unix.Stat_t
	err := unix.Fstatat(d.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == unix.ENOENT {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return fmt.Errorf("destination %s is not a unique regular file", name)
	}
	return nil
}

func (d *Dir) CreateTemp(label string) (*os.File, string, error) {
	for i := 0; i < 100; i++ {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := ".nurproxy-" + label + "-" + hex.EncodeToString(random[:])
		fd, err := unix.Openat(d.fd, name, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, FileMode)
		if err == unix.EEXIST {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		if err := unix.Fchmod(fd, FileMode); err != nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(d.fd, name, 0)
			return nil, "", err
		}
		return os.NewFile(uintptr(fd), name), name, nil
	}
	return nil, "", fmt.Errorf("could not allocate a unique staging file")
}

func (d *Dir) Rename(oldName, newName string) error {
	return unix.Renameat(d.fd, oldName, d.fd, newName)
}
func (d *Dir) Remove(name string) error {
	err := unix.Unlinkat(d.fd, name, 0)
	if err == unix.ENOENT {
		return nil
	}
	return err
}

func Ensure(dataDir string) (Report, error) {
	d, err := OpenDir(dataDir, true)
	if err != nil {
		return Report{}, err
	}
	defer d.Close()
	return d.Harden()
}
func Harden(dataDir string) (Report, error) {
	d, err := OpenDir(dataDir, false)
	if err != nil {
		return Report{}, err
	}
	defer d.Close()
	return d.Harden()
}

func (d *Dir) Harden() (Report, error) {
	return d.harden(nil)
}

func (d *Dir) HardenOwned(uid, gid int) (Report, error) {
	owner := [2]int{uid, gid}
	return d.harden(&owner)
}

func (d *Dir) harden(owner *[2]int) (Report, error) {
	var report Report
	var unsafe []string
	if clean := filepath.Clean(d.path); clean == "." || clean == string(filepath.Separator) {
		return report, fmt.Errorf("refusing to harden broad data directory %q", d.path)
	}
	if err := unix.Fchmod(d.fd, DirMode); err != nil {
		return report, fmt.Errorf("restricting data directory %s: %w", d.path, err)
	}
	if owner != nil {
		if err := unix.Fchown(d.fd, owner[0], owner[1]); err != nil {
			return report, fmt.Errorf("owning data directory %s: %w", d.path, err)
		}
	}
	report.Hardened = append(report.Hardened, ".")
	dup, err := unix.Dup(d.fd)
	if err != nil {
		return report, err
	}
	reader := os.NewFile(uintptr(dup), d.path)
	entries, err := reader.ReadDir(-1)
	_ = reader.Close()
	if err != nil {
		return report, fmt.Errorf("reading data directory %s: %w", d.path, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !allowedName(name) {
			report.Skipped = append(report.Skipped, name+": not managed")
			continue
		}
		fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err == unix.ENOENT {
			continue
		}
		if err != nil {
			report.Skipped = append(report.Skipped, name+": open failed: "+err.Error())
			unsafe = append(unsafe, name)
			continue
		}
		var st unix.Stat_t
		entryErr := unix.Fstat(fd, &st)
		if entryErr == nil && (st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1) {
			entryErr = fmt.Errorf("not a unique regular file")
		}
		if entryErr == nil {
			entryErr = unix.Fchmod(fd, FileMode)
		}
		if entryErr == nil && owner != nil {
			entryErr = unix.Fchown(fd, owner[0], owner[1])
		}
		_ = unix.Close(fd)
		if entryErr != nil {
			report.Skipped = append(report.Skipped, name+": not hardened: "+entryErr.Error())
			unsafe = append(unsafe, name)
			continue
		}
		report.Hardened = append(report.Hardened, name)
	}
	if len(unsafe) > 0 {
		return report, fmt.Errorf("unsafe managed data entries: %s", strings.Join(unsafe, ", "))
	}
	return report, nil
}

func allowedName(name string) bool {
	switch name {
	case "nurproxy.db", "nurproxy.db-wal", "nurproxy.db-shm", "encryption.key", "acme-account.key":
		return true
	}
	return safeBackupName(name, "nurproxy.db.backup-") || safeBackupName(name, "nurproxy.db.bak-")
}
func safeBackupName(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) || len(name) == len(prefix) {
		return false
	}
	for _, r := range name[len(prefix):] {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

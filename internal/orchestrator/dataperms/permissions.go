//go:build unix

// Package dataperms enforces the private on-disk boundary of an orchestrator.
package dataperms

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	DirMode  = 0o700
	FileMode = 0o600
)

// Report names entries deliberately left untouched. Harden never recurses.
type Report struct {
	Hardened []string
	Skipped  []string
}

// SetPrivateUmask makes subsequently created runtime files owner-only.
func SetPrivateUmask() { unix.Umask(0o077) }

// Ensure creates dataDir when absent, then applies Harden's descriptor-based
// checks. A symlink in the final data-directory component is rejected.
func Ensure(dataDir string) (Report, error) {
	if err := os.MkdirAll(dataDir, DirMode); err != nil {
		return Report{}, fmt.Errorf("creating data directory %s: %w", dataDir, err)
	}
	return Harden(dataDir)
}

// Harden restricts the data directory and the small, explicit set of private
// orchestrator files. It opens the directory and children without following
// the final symlink component, operates through descriptors, and never walks
// nested directories.
func Harden(dataDir string) (Report, error) {
	var report Report
	var unsafe []string
	fd, err := unix.Open(dataDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return report, fmt.Errorf("opening data directory without following links: %w", err)
	}
	dir := os.NewFile(uintptr(fd), dataDir)
	defer dir.Close()

	if err := unix.Fchmod(fd, DirMode); err != nil {
		return report, fmt.Errorf("restricting data directory %s: %w", dataDir, err)
	}
	report.Hardened = append(report.Hardened, ".")

	entries, err := dir.ReadDir(-1)
	if err != nil {
		return report, fmt.Errorf("reading data directory %s: %w", dataDir, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !allowedName(name) {
			report.Skipped = append(report.Skipped, name+": not managed")
			continue
		}
		var before unix.Stat_t
		if err := unix.Fstatat(fd, name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			report.Skipped = append(report.Skipped, name+": stat failed: "+err.Error())
			if err != unix.ENOENT {
				unsafe = append(unsafe, name)
			}
			continue
		}
		if before.Mode&unix.S_IFMT != unix.S_IFREG {
			report.Skipped = append(report.Skipped, name+": not a regular file")
			unsafe = append(unsafe, name)
			continue
		}
		childFD, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			report.Skipped = append(report.Skipped, name+": open failed: "+err.Error())
			if err != unix.ENOENT {
				unsafe = append(unsafe, name)
			}
			continue
		}
		var opened unix.Stat_t
		statErr := unix.Fstat(childFD, &opened)
		if statErr == nil && opened.Mode&unix.S_IFMT != unix.S_IFREG {
			statErr = fmt.Errorf("entry changed to a non-regular file")
		}
		if statErr == nil {
			statErr = unix.Fchmod(childFD, FileMode)
		}
		_ = unix.Close(childFD)
		if statErr != nil {
			report.Skipped = append(report.Skipped, name+": not hardened: "+statErr.Error())
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
	default:
		return strings.HasPrefix(name, ".nurproxy.db.restore-") ||
			strings.HasPrefix(name, ".encryption.key.restore-") ||
			strings.HasPrefix(name, ".acme-account.key.restore-") ||
			safeBackupName(name, "nurproxy.db.backup-") ||
			safeBackupName(name, "nurproxy.db.bak-")
	}
}

func safeBackupName(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) || len(name) == len(prefix) {
		return false
	}
	for _, r := range name[len(prefix):] {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

//go:build !linux

package proxy

import "golang.org/x/sys/unix"

func renameRecoveryNoReplace(dirfd int, oldName, newName string) error {
	if err := unix.Linkat(dirfd, oldName, dirfd, newName, 0); err != nil {
		return err
	}
	return unix.Unlinkat(dirfd, oldName, 0)
}

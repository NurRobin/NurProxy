//go:build linux

package proxy

import "golang.org/x/sys/unix"

func renameRecoveryNoReplace(dirfd int, oldName, newName string) error {
	return unix.Renameat2(dirfd, oldName, dirfd, newName, unix.RENAME_NOREPLACE)
}

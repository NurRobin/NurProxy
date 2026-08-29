//go:build linux

package main

import (
	"fmt"
	"math"
	"os"

	"golang.org/x/sys/unix"
)

type helperBootstrapPrivilegeOps struct {
	setGroups func([]int) error
	setResGID func(int, int, int) error
	setResUID func(int, int, int) error
	getUID    func() int
	getEUID   func() int
	getGID    func() int
	getEGID   func() int
}

func dropHelperBootstrapPrivileges(uid, gid uint32) error {
	return dropHelperBootstrapPrivilegesWith(uid, gid, helperBootstrapPrivilegeOps{
		setGroups: unix.Setgroups,
		setResGID: unix.Setresgid,
		setResUID: unix.Setresuid,
		getUID:    os.Getuid,
		getEUID:   os.Geteuid,
		getGID:    os.Getgid,
		getEGID:   os.Getegid,
	})
}

func dropHelperBootstrapPrivilegesWith(uid, gid uint32, ops helperBootstrapPrivilegeOps) error {
	if uid == 0 || gid == 0 || uid == math.MaxUint32 || gid == math.MaxUint32 {
		return fmt.Errorf("dedicated bootstrap identity must be non-root")
	}
	if ops.setGroups == nil || ops.setResGID == nil || ops.setResUID == nil ||
		ops.getUID == nil || ops.getEUID == nil || ops.getGID == nil || ops.getEGID == nil {
		return fmt.Errorf("bootstrap privilege operations are incomplete")
	}
	if err := ops.setGroups([]int{int(gid)}); err != nil {
		return fmt.Errorf("replace supplementary groups: %w", err)
	}
	if err := ops.setResGID(int(gid), int(gid), int(gid)); err != nil {
		return fmt.Errorf("drop group identity: %w", err)
	}
	if err := ops.setResUID(int(uid), int(uid), int(uid)); err != nil {
		return fmt.Errorf("drop user identity: %w", err)
	}
	if ops.getUID() != int(uid) || ops.getEUID() != int(uid) || ops.getGID() != int(gid) || ops.getEGID() != int(gid) {
		return fmt.Errorf("bootstrap privilege drop did not bind every process identity")
	}
	return nil
}

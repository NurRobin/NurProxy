//go:build linux

package helper

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type Credentials struct {
	PID int32
	UID uint32
	GID uint32
}

func PeerCredentials(conn net.Conn) (Credentials, error) {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return Credentials{}, fmt.Errorf("connection does not expose peer credentials")
	}
	raw, err := syscallConn.SyscallConn()
	if err != nil {
		return Credentials{}, err
	}
	var credentials *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return Credentials{}, err
	}
	if controlErr != nil || credentials == nil {
		return Credentials{}, fmt.Errorf("read peer credentials: %w", controlErr)
	}
	return Credentials{PID: credentials.Pid, UID: credentials.Uid, GID: credentials.Gid}, nil
}

func VerifyPeerExecutable(pid int32) error {
	if pid <= 0 {
		return fmt.Errorf("invalid peer pid")
	}
	peer, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return fmt.Errorf("stat peer executable: %w", err)
	}
	self, err := os.Stat("/proc/self/exe")
	if err != nil {
		return fmt.Errorf("stat helper executable: %w", err)
	}
	peerStat, peerOK := peer.Sys().(*syscall.Stat_t)
	selfStat, selfOK := self.Sys().(*syscall.Stat_t)
	if !peerOK || !selfOK || peerStat.Dev != selfStat.Dev || peerStat.Ino != selfStat.Ino {
		return fmt.Errorf("peer and helper executable identities differ")
	}
	return nil
}

func validateSelfExecutable(expectedOwnerUID uint32) error {
	info, err := os.Stat("/proc/self/exe")
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || fileOwnerUID(info) != expectedOwnerUID || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("helper executable type, owner, or permissions are not trusted")
	}
	return nil
}

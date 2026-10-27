//go:build linux

package helper

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

const activationSocketName = "nurproxy-agent-helper"

func activationFD(getenv func(string) string, pid int) (int, error) {
	listenPID, err := strconv.Atoi(getenv("LISTEN_PID"))
	if err != nil || listenPID != pid {
		return -1, fmt.Errorf("socket activation LISTEN_PID does not match helper process")
	}
	listenFDs, err := strconv.Atoi(getenv("LISTEN_FDS"))
	if err != nil || listenFDs != 1 {
		return -1, fmt.Errorf("socket activation requires exactly one descriptor")
	}
	if getenv("LISTEN_FDNAMES") != activationSocketName {
		return -1, fmt.Errorf("socket activation descriptor name is invalid")
	}
	return 3, nil
}

func SystemdListener() (*net.UnixListener, error) {
	fd, err := activationFD(os.Getenv, os.Getpid())
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), activationSocketName)
	if file == nil {
		return nil, fmt.Errorf("socket activation descriptor is invalid")
	}
	listener, err := net.FileListener(file)
	_ = file.Close()
	if err != nil {
		return nil, fmt.Errorf("adopt socket activation descriptor: %w", err)
	}
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		_ = listener.Close()
		return nil, fmt.Errorf("socket activation descriptor is not a unix listener")
	}
	if unixListener.Addr().Network() != "unixpacket" {
		_ = listener.Close()
		return nil, fmt.Errorf("socket activation descriptor is not SOCK_SEQPACKET")
	}
	return unixListener, nil
}

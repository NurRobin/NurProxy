//go:build !linux

package helper

import (
	"fmt"
	"net"
)

func SystemdListener() (*net.UnixListener, error) {
	return nil, fmt.Errorf("privileged helper socket activation is supported only on Linux")
}

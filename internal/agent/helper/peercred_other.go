//go:build !linux

package helper

import (
	"fmt"
	"net"
)

type Credentials struct {
	PID int32
	UID uint32
	GID uint32
}

func PeerCredentials(net.Conn) (Credentials, error) {
	return Credentials{}, fmt.Errorf("privileged helper peer credentials are supported only on Linux")
}

func VerifyPeerExecutable(int32) error {
	return fmt.Errorf("privileged helper executable verification is supported only on Linux")
}

func validateSelfExecutable(uint32) error {
	return fmt.Errorf("privileged helper is supported only on Linux")
}

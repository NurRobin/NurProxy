//go:build !linux

package helper

import (
	"net"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

func readConnectionFrame(conn net.Conn) ([]byte, error) {
	return helperprotocol.ReadFrame(conn)
}

func writeConnectionFrame(conn net.Conn, payload []byte) error {
	return helperprotocol.WriteFrame(conn, payload)
}

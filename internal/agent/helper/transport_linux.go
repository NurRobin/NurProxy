//go:build linux

package helper

import (
	"net"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

func readConnectionFrame(conn net.Conn) ([]byte, error) {
	if unixConn, ok := conn.(*net.UnixConn); ok && unixConn.LocalAddr().Network() == "unixpacket" {
		return helperprotocol.ReadUnixPacketFrame(unixConn)
	}
	return helperprotocol.ReadFrame(conn)
}

func writeConnectionFrame(conn net.Conn, payload []byte) error {
	if unixConn, ok := conn.(*net.UnixConn); ok && unixConn.LocalAddr().Network() == "unixpacket" {
		return helperprotocol.WriteUnixPacketFrame(unixConn, payload)
	}
	return helperprotocol.WriteFrame(conn, payload)
}

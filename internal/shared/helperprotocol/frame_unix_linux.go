//go:build linux

package helperprotocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"syscall"
)

const maxUnixControlBytes = 4096

// ReadUnixPacketFrame receives one complete SOCK_SEQPACKET message. Reading the
// length prefix separately would truncate and discard the remainder of the
// packet on Linux, so the prefix and payload must share one ReadMsgUnix call.
func ReadUnixPacketFrame(conn *net.UnixConn) ([]byte, error) {
	if conn == nil {
		return nil, fmt.Errorf("read unix protocol frame: nil connection")
	}
	packet := make([]byte, MaxFrameBytes+4)
	control := make([]byte, maxUnixControlBytes)
	n, controlBytes, flags, _, err := conn.ReadMsgUnix(packet, control)
	if err != nil {
		return nil, fmt.Errorf("read unix protocol frame: %w", err)
	}
	if controlBytes != 0 {
		closeReceivedRights(control[:controlBytes])
		return nil, fmt.Errorf("unix protocol frame contains forbidden ancillary data")
	}
	if flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 {
		return nil, fmt.Errorf("unix protocol frame was truncated")
	}
	if n < 4 {
		return nil, fmt.Errorf("unix protocol frame length prefix is incomplete")
	}
	size := binary.BigEndian.Uint32(packet[:4])
	if size == 0 || size > MaxFrameBytes {
		return nil, fmt.Errorf("unix protocol frame length outside bounds")
	}
	if int(size)+4 != n {
		return nil, fmt.Errorf("unix protocol frame length does not match packet")
	}
	payload := make([]byte, int(size))
	copy(payload, packet[4:n])
	return payload, nil
}

func WriteUnixPacketFrame(conn *net.UnixConn, payload []byte) error {
	if conn == nil {
		return fmt.Errorf("write unix protocol frame: nil connection")
	}
	if len(payload) == 0 || len(payload) > MaxFrameBytes {
		return fmt.Errorf("unix protocol frame length outside bounds")
	}
	packet := make([]byte, len(payload)+4)
	binary.BigEndian.PutUint32(packet[:4], uint32(len(payload)))
	copy(packet[4:], payload)
	written, controlBytes, err := conn.WriteMsgUnix(packet, nil, nil)
	if err != nil {
		return fmt.Errorf("write unix protocol frame: %w", err)
	}
	if controlBytes != 0 || written != len(packet) {
		return fmt.Errorf("write unix protocol frame: %w", io.ErrShortWrite)
	}
	return nil
}

func closeReceivedRights(control []byte) {
	messages, err := syscall.ParseSocketControlMessage(control)
	if err != nil {
		return
	}
	for _, message := range messages {
		rights, err := syscall.ParseUnixRights(&message)
		if err != nil {
			continue
		}
		for _, fd := range rights {
			_ = syscall.Close(fd)
		}
	}
}

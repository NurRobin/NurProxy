//go:build linux

package helperprotocol

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func unixPacketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: socketPath, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan *net.UnixConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	client, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: socketPath, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	var server *net.UnixConn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}

func TestUnixPacketFrameRoundTrip(t *testing.T) {
	client, server := unixPacketPair(t)
	payload := []byte(`{"operation_id":"op-1"}`)
	if err := WriteUnixPacketFrame(client, payload); err != nil {
		t.Fatal(err)
	}
	got, err := ReadUnixPacketFrame(server)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}

func TestUnixPacketFrameRejectsAncillaryFileDescriptor(t *testing.T) {
	client, server := unixPacketPair(t)
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	packet := append([]byte{0, 0, 0, 2}, []byte(`{}`)...)
	if _, _, err := client.WriteMsgUnix(packet, syscall.UnixRights(int(file.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadUnixPacketFrame(server); err == nil || !strings.Contains(err.Error(), "ancillary") {
		t.Fatalf("ReadUnixPacketFrame error = %v, want ancillary rejection", err)
	}
}

func TestUnixPacketFrameRejectsDeclaredLengthMismatch(t *testing.T) {
	client, server := unixPacketPair(t)
	if _, _, err := client.WriteMsgUnix([]byte{0, 0, 0, 3, '{', '}'}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadUnixPacketFrame(server); err == nil || !strings.Contains(err.Error(), "length") {
		t.Fatalf("ReadUnixPacketFrame error = %v, want length rejection", err)
	}
}

func TestUnixPacketFrameRejectsTruncation(t *testing.T) {
	client, server := unixPacketPair(t)
	packet := make([]byte, MaxFrameBytes+5)
	packet[0], packet[1], packet[2], packet[3] = 0, 4, 0, 1
	if _, _, err := client.WriteMsgUnix(packet, nil, nil); err != nil {
		if strings.Contains(err.Error(), "message too long") {
			t.Skip("kernel send buffer rejects oversized unixpacket before receiver truncation")
		}
		t.Fatal(err)
	}
	if _, err := ReadUnixPacketFrame(server); err == nil {
		t.Fatal("truncated unixpacket frame was accepted")
	}
}

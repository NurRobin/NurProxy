//go:build linux

package helper

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestPeerCredentialsAndExecutableIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan *net.UnixConn, 1)
	go func() {
		conn, acceptErr := listener.AcceptUnix()
		if acceptErr == nil {
			accepted <- conn
			return
		}
		close(accepted)
	}()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	defer server.Close()

	credentials, err := PeerCredentials(server)
	if err != nil {
		t.Fatal(err)
	}
	if credentials.UID != uint32(os.Getuid()) || credentials.PID != int32(os.Getpid()) {
		t.Fatalf("credentials = %+v", credentials)
	}
	if err := VerifyPeerExecutable(credentials.PID); err != nil {
		t.Fatalf("same executable rejected: %v", err)
	}
	if err := VerifyPeerExecutable(999999); err == nil {
		t.Fatal("missing peer executable accepted")
	}
}

func TestValidateSelfExecutableChecksOwnerAndMode(t *testing.T) {
	if err := validateSelfExecutable(uint32(os.Getuid())); err != nil {
		t.Fatalf("current test executable rejected: %v", err)
	}
	if err := validateSelfExecutable(uint32(os.Getuid() + 1)); err == nil {
		t.Fatal("wrong executable owner accepted")
	}
}

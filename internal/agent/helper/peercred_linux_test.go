//go:build linux

package helper

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
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

func TestTrustedSystemdSocketActivatorIsPinnedToPIDOneAndRootBinary(t *testing.T) {
	info, err := os.Stat("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	stat.Uid = 0
	wrapped := fileInfoWithStat{FileInfo: info, stat: stat}
	for _, path := range []string{"/usr/lib/systemd/systemd", "/lib/systemd/systemd"} {
		if !trustedSystemdSocketActivator(1, path, wrapped) {
			t.Fatalf("trusted socket activator path rejected: %s", path)
		}
	}
	for _, test := range []struct {
		pid  int32
		path string
	}{{2, "/usr/lib/systemd/systemd"}, {1, "/usr/local/bin/systemd"}, {1, "/usr/lib/systemd/systemd (deleted)"}} {
		if trustedSystemdSocketActivator(test.pid, test.path, wrapped) {
			t.Fatalf("untrusted socket activator accepted: pid=%d path=%s", test.pid, test.path)
		}
	}
}

type fileInfoWithStat struct {
	os.FileInfo
	stat *syscall.Stat_t
}

func (f fileInfoWithStat) Sys() any { return f.stat }

func TestValidateSelfExecutableChecksOwnerAndMode(t *testing.T) {
	if err := validateSelfExecutable(uint32(os.Getuid())); err != nil {
		t.Fatalf("current test executable rejected: %v", err)
	}
	if err := validateSelfExecutable(uint32(os.Getuid() + 1)); err == nil {
		t.Fatal("wrong executable owner accepted")
	}
}

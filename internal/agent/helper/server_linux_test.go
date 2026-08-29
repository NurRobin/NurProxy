//go:build linux

package helper

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

func TestServerAcceptsStrictHelloFromExpectedPeer(t *testing.T) {
	fixture := newEngineFixture(t)
	fixture.engine.config.AgentUID = uint32(os.Getuid())
	path := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(fixture.engine)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()

	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	request := helperprotocol.NewEnvelope(helperprotocol.MessageHelperHelloRequest, helperprotocol.HelperHelloRequest{
		RequestID: "request-1", AgentID: "agent-1", AgentBuildID: fixture.engine.buildID,
	})
	payload, err := helperprotocol.CanonicalBytes(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeConnectionFrame(conn, payload); err != nil {
		t.Fatal(err)
	}
	responsePayload, err := readConnectionFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	response, err := helperprotocol.Decode[helperprotocol.Signed[helperprotocol.HelperHello]](responsePayload)
	if err != nil {
		t.Fatal(err)
	}
	if err := helperprotocol.Verify(fixture.attestationPub, response, helperprotocol.MessageHelperHello); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	_ = listener.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func TestServerRejectsWrongPeerBeforeDispatch(t *testing.T) {
	fixture := newEngineFixture(t)
	fixture.engine.config.AgentUID = uint32(os.Getuid() + 1)
	server := NewServer(fixture.engine)
	path := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	clientDone := make(chan error, 1)
	go func() {
		conn, dialErr := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
		if dialErr != nil {
			clientDone <- dialErr
			return
		}
		defer conn.Close()
		response, readErr := readConnectionFrame(conn)
		if readErr != nil {
			clientDone <- readErr
			return
		}
		envelope, decodeErr := helperprotocol.DecodeEnvelope[helperprotocol.ErrorResponse](response, helperprotocol.MessageErrorResponse)
		if decodeErr != nil {
			clientDone <- decodeErr
			return
		}
		if envelope.Payload.Code != helperprotocol.ErrorPeerCredentialsInvalid {
			clientDone <- errors.New("wrong peer refusal code")
			return
		}
		clientDone <- nil
	}()
	conn, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	server.serveConn(context.Background(), conn)
	if err := <-clientDone; err != nil {
		t.Fatal(err)
	}
}

func TestServerStrictDispatcherRejectsDuplicateEnvelopeField(t *testing.T) {
	fixture := newEngineFixture(t)
	fixture.engine.config.AgentUID = uint32(os.Getuid())
	server := NewServer(fixture.engine)
	server.peerCredentials = func(net.Conn) (Credentials, error) {
		return Credentials{PID: int32(os.Getpid()), UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}, nil
	}
	server.verifyPeerExecutable = func(int32) error { return nil }
	client, root := net.Pipe()
	done := make(chan struct{})
	go func() {
		server.serveConn(context.Background(), root)
		close(done)
	}()
	input := `{"protocol_version":1,"protocol_version":1,"message_type":"helper_hello_request","domain":"nurproxy.helper.v1","payload":{"request_id":"request-1","agent_id":"agent-1","agent_build_id":"dev-010e5a7"}}`
	if err := helperprotocol.WriteFrame(client, []byte(input)); err != nil {
		t.Fatal(err)
	}
	response, err := helperprotocol.ReadFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := helperprotocol.DecodeEnvelope[helperprotocol.ErrorResponse](response, helperprotocol.MessageErrorResponse)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Payload.Code != helperprotocol.ErrorRequestConflict {
		t.Fatalf("error code = %s", envelope.Payload.Code)
	}
	_ = client.Close()
	<-done
}

func TestActivationFDRequiresExactlyOneMatchingSystemdDescriptor(t *testing.T) {
	pid := os.Getpid()
	valid := func(key string) string {
		switch key {
		case "LISTEN_PID":
			return strconv.Itoa(pid)
		case "LISTEN_FDS":
			return "1"
		case "LISTEN_FDNAMES":
			return "nurproxy-agent-helper"
		default:
			return ""
		}
	}
	if fd, err := activationFD(valid, pid); err != nil || fd != 3 {
		t.Fatalf("activation fd = %d, %v", fd, err)
	}
	for name, mutate := range map[string]func(string) string{
		"wrong pid": func(key string) string {
			if key == "LISTEN_PID" {
				return strconv.Itoa(pid + 1)
			}
			return valid(key)
		},
		"two fds": func(key string) string {
			if key == "LISTEN_FDS" {
				return "2"
			}
			return valid(key)
		},
		"wrong name": func(key string) string {
			if key == "LISTEN_FDNAMES" {
				return "other"
			}
			return valid(key)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := activationFD(mutate, pid); err == nil || !strings.Contains(err.Error(), "socket activation") {
				t.Fatalf("invalid activation environment accepted: %v", err)
			}
		})
	}
}

//go:build linux

package helperclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

func serveHello(t *testing.T, path string, keyID, instanceID, buildID string, privateKey ed25519.PrivateKey, mutate func(*helperprotocol.HelperHello)) {
	t.Helper()
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		defer conn.Close()
		payload, err := helperprotocol.ReadUnixPacketFrame(conn)
		if err != nil {
			return
		}
		request, err := helperprotocol.DecodeEnvelope[helperprotocol.HelperHelloRequest](payload, helperprotocol.MessageHelperHelloRequest)
		if err != nil {
			return
		}
		hello := helperprotocol.HelperHello{
			RequestID: request.Payload.RequestID, HelperInstanceID: instanceID,
			HelperBuildID: buildID, AttestationKeyID: keyID,
			AttestationPublicKey: base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)),
		}
		if mutate != nil {
			mutate(&hello)
		}
		signed, err := helperprotocol.Sign(keyID, privateKey, helperprotocol.NewEnvelope(helperprotocol.MessageHelperHello, hello))
		if err != nil {
			return
		}
		encoded, err := helperprotocol.CanonicalBytes(signed)
		if err == nil {
			_ = helperprotocol.WriteUnixPacketFrame(conn, encoded)
		}
	}()
}

func helloClientFixture(t *testing.T, mutate func(*helperprotocol.HelperHello)) *Client {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "helper.sock")
	serveHello(t, path, "attestation-helper-1", "helper-1", "dev-build-1", privateKey, mutate)
	client, err := newClient(path, "agent-1", "dev-build-1", Pin{
		HelperInstanceID: "helper-1", AttestationKeyID: "attestation-helper-1",
		AttestationPublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	client.expectedRootUID = uint32(os.Getuid())
	client.verifyPeerExecutable = func(int32) error { return nil }
	return client
}

func planClientFixture(t *testing.T, mutate func(*helperprotocol.HelperPlan)) *Client {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		defer conn.Close()
		payload, err := helperprotocol.ReadUnixPacketFrame(conn)
		if err != nil {
			return
		}
		request, err := helperprotocol.DecodeEnvelope[helperprotocol.PlanActionRequest](payload, helperprotocol.MessagePlanActionRequest)
		if err != nil {
			return
		}
		plan := helperprotocol.HelperPlan{
			HelperPlanID: "plan-1", HelperInstanceID: "helper-1", DiagnosticID: request.Payload.DiagnosticReference,
			Action: request.Payload.Action, LogicalTarget: request.Payload.LogicalTarget,
			ExecutionPlanHash: strings.Repeat("a", 64), ResourceFingerprint: strings.Repeat("b", 64),
			RollbackCoverage: helperprotocol.RollbackCoverageFull,
			Steps:            []helperprotocol.PlanStep{{Kind: "validate", Summary: "Validate and reload the detected proxy"}},
			ExpiresAt:        time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano),
		}
		if mutate != nil {
			mutate(&plan)
		}
		plan.DisplayPlanHash, _ = helperprotocol.DisplayPlanDigest(plan)
		signed, _ := helperprotocol.Sign("attestation-helper-1", privateKey, helperprotocol.NewEnvelope(helperprotocol.MessageHelperPlan, plan))
		encoded, _ := helperprotocol.CanonicalBytes(signed)
		_ = helperprotocol.WriteUnixPacketFrame(conn, encoded)
	}()
	client, err := newClient(path, "agent-1", "dev-build-1", Pin{
		HelperInstanceID: "helper-1", AttestationKeyID: "attestation-helper-1",
		AttestationPublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	client.expectedRootUID = uint32(os.Getuid())
	client.verifyPeerExecutable = func(int32) error { return nil }
	return client
}

func TestClientHelloVerifiesPinnedHelperIdentity(t *testing.T) {
	client := helloClientFixture(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	hello, err := client.Hello(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if hello.HelperInstanceID != "helper-1" || hello.HelperBuildID != "dev-build-1" {
		t.Fatalf("hello = %#v", hello)
	}
}

func TestClientHelloRejectsSignedButUnpinnedIdentity(t *testing.T) {
	client := helloClientFixture(t, func(hello *helperprotocol.HelperHello) {
		hello.HelperInstanceID = "helper-attacker"
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := client.Hello(ctx); err == nil {
		t.Fatal("signed response for an unpinned helper instance was accepted")
	}
}

func TestClientHelloRejectsNonRootPeerBeforeProtocol(t *testing.T) {
	client := helloClientFixture(t, nil)
	client.expectedRootUID = uint32(os.Getuid() + 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := client.Hello(ctx); err == nil {
		t.Fatal("non-root helper peer was accepted")
	}
}

func TestClientPlanVerifiesAttestedBindings(t *testing.T) {
	client := planClientFixture(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	plan, err := client.Plan(ctx, helperprotocol.ActionValidateReloadProxy, helperprotocol.LogicalTargetDetectedProxy, "diagnostic-1")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Envelope.Payload.HelperPlanID != "plan-1" || plan.Envelope.Payload.DiagnosticID != "diagnostic-1" {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestClientPlanRejectsSignedResponseForAnotherDiagnostic(t *testing.T) {
	client := planClientFixture(t, func(plan *helperprotocol.HelperPlan) {
		plan.DiagnosticID = "diagnostic-other"
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := client.Plan(ctx, helperprotocol.ActionValidateReloadProxy, helperprotocol.LogicalTargetDetectedProxy, "diagnostic-1"); err == nil {
		t.Fatal("signed helper plan for another diagnostic was accepted")
	}
}

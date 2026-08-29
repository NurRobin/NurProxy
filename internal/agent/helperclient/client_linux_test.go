//go:build linux

package helperclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
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

func managedIntentFixture(t *testing.T) helperprotocol.Signed[helperprotocol.ApplyIntent] {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	intent := helperprotocol.ApplyIntent{
		AgentID: "agent-1", HelperInstanceID: "helper-1", OperationID: "apply-operation-1", DesiredStateRevision: strings.Repeat("1", 64),
		Resources: []string{}, Artifacts: []helperprotocol.LogicalArtifact{}, DeletionSet: []helperprotocol.ManagedDeletion{}, Routes: []proxymodel.RouteIntent{}, CertificateKeep: []string{},
		AuthorizationKind: helperprotocol.AuthorizationStoredConvergence, AuthorizationEventID: "desired-event-1",
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
	}
	signed, err := helperprotocol.Sign("orchestrator-1", privateKey, helperprotocol.NewEnvelope(helperprotocol.MessageApplyIntent, intent))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func managedPlanClientFixture(t *testing.T, mutate func(*helperprotocol.ManagedApplyPlan)) (*Client, helperprotocol.Signed[helperprotocol.ApplyIntent]) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intent := managedIntentFixture(t)
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
		request, err := helperprotocol.DecodeEnvelope[helperprotocol.PlanManagedApplyRequest](payload, helperprotocol.MessagePlanManagedApplyRequest)
		if err != nil {
			return
		}
		plan := helperprotocol.ManagedApplyPlan{
			HelperPlanID: "managed-plan-1", HelperInstanceID: "helper-1", OperationID: request.Payload.Intent.Envelope.Payload.OperationID,
			DesiredStateRevision:  request.Payload.Intent.Envelope.Payload.DesiredStateRevision,
			LogicalManifestDigest: strings.Repeat("a", 64), ArtifactManifestDigest: strings.Repeat("b", 64), DeletionSetDigest: strings.Repeat("c", 64),
			CertificateIdentityDigest: strings.Repeat("d", 64), CustomPolicyVersion: "proxy-policy-v1", ExecutionPlanHash: strings.Repeat("e", 64),
			ResourceFingerprint: strings.Repeat("f", 64), RollbackCoverage: helperprotocol.RollbackCoverageFull,
			ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano),
		}
		if mutate != nil {
			mutate(&plan)
		}
		signed, _ := helperprotocol.Sign("attestation-helper-1", privateKey, helperprotocol.NewEnvelope(helperprotocol.MessageManagedApplyPlan, plan))
		encoded, _ := helperprotocol.CanonicalBytes(signed)
		_ = helperprotocol.WriteUnixPacketFrame(conn, encoded)
	}()
	client, err := newClient(path, "agent-1", "dev-build-1", Pin{
		HelperInstanceID: "helper-1", AttestationKeyID: "attestation-helper-1", AttestationPublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	client.expectedRootUID = uint32(os.Getuid())
	client.verifyPeerExecutable = func(int32) error { return nil }
	return client, intent
}

func TestClientHelloVerifiesPinnedHelperIdentity(t *testing.T) {
	client := helloClientFixture(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	signed, err := client.SignedHello(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello := signed.Envelope.Payload
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

func TestClientManagedPlanVerifiesAttestedDesiredStateBindings(t *testing.T) {
	client, intent := managedPlanClientFixture(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	plan, err := client.PlanManagedApply(ctx, intent)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Envelope.Payload.OperationID != intent.Envelope.Payload.OperationID || plan.Envelope.Payload.HelperInstanceID != "helper-1" {
		t.Fatalf("managed plan = %#v", plan)
	}
}

func TestClientManagedPlanRejectsAnotherDesiredRevision(t *testing.T) {
	client, intent := managedPlanClientFixture(t, func(plan *helperprotocol.ManagedApplyPlan) {
		plan.DesiredStateRevision = strings.Repeat("2", 64)
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := client.PlanManagedApply(ctx, intent); err == nil {
		t.Fatal("attested managed plan for another desired revision was accepted")
	}
}

func executionGrantFixture(t *testing.T) helperprotocol.Signed[helperprotocol.ExecutionGrant] {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	grant := helperprotocol.ExecutionGrant{
		GrantID: "grant-1", AgentID: "agent-1", HelperInstanceID: "helper-1", DiagnosticID: "diagnostic-1",
		OperationID: "operation-1", Action: helperprotocol.ActionValidateReloadProxy, HelperPlanID: "plan-1",
		DisplayPlanHash: strings.Repeat("a", 64), ExecutionPlanHash: strings.Repeat("b", 64), ResourceFingerprint: strings.Repeat("c", 64),
		ConfirmationEventIDs: []string{"confirmation-1", "confirmation-2"},
		IssuedAt:             now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
	}
	signed, err := helperprotocol.Sign("orchestrator-1", privateKey, helperprotocol.NewEnvelope(helperprotocol.MessageExecutionGrant, grant))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func applyGrantFixture(t *testing.T) helperprotocol.Signed[helperprotocol.ApplyGrant] {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	grant := helperprotocol.ApplyGrant{
		GrantID: "apply-grant-1", AuthorizationKind: helperprotocol.AuthorizationStoredConvergence, AuthorizationEventID: "desired-event-1",
		AgentID: "agent-1", HelperInstanceID: "helper-1", OperationID: "apply-operation-1", HelperPlanID: "managed-plan-1",
		DesiredStateRevision: strings.Repeat("1", 64), LogicalManifestDigest: strings.Repeat("a", 64), ArtifactManifestDigest: strings.Repeat("b", 64),
		DeletionSetDigest: strings.Repeat("c", 64), CertificateIdentityDigest: strings.Repeat("d", 64), CustomPolicyVersion: "proxy-policy-v1",
		ExecutionPlanHash: strings.Repeat("e", 64), ResourceFingerprint: strings.Repeat("f", 64), RollbackCoverage: helperprotocol.RollbackCoverageFull,
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
	}
	signed, err := helperprotocol.Sign("orchestrator-1", privateKey, helperprotocol.NewEnvelope(helperprotocol.MessageApplyGrant, grant))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func receiptClientFixture(t *testing.T, expectedType helperprotocol.MessageType, mutate func(*helperprotocol.HelperReceipt)) *Client {
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
		var operationID, requestDigest string
		action := helperprotocol.ActionValidateReloadProxy
		switch expectedType {
		case helperprotocol.MessageExecuteActionRequest:
			request, decodeErr := helperprotocol.DecodeEnvelope[helperprotocol.ExecuteActionRequest](payload, expectedType)
			if decodeErr != nil {
				return
			}
			operationID = request.Payload.OperationID
			requestDigest, _ = helperprotocol.Digest(request)
			action = request.Payload.Grant.Envelope.Payload.Action
		case helperprotocol.MessageExecuteManagedApplyRequest:
			request, decodeErr := helperprotocol.DecodeEnvelope[helperprotocol.ExecuteManagedApplyRequest](payload, expectedType)
			if decodeErr != nil {
				return
			}
			operationID = request.Payload.OperationID
			requestDigest, _ = helperprotocol.Digest(request)
			action = helperprotocol.ActionApplyManagedProxyState
		case helperprotocol.MessageGetReceiptRequest:
			request, decodeErr := helperprotocol.DecodeEnvelope[helperprotocol.GetReceiptRequest](payload, expectedType)
			if decodeErr != nil {
				return
			}
			operationID = request.Payload.OperationID
			requestDigest = request.Payload.CanonicalRequestDigest
		default:
			return
		}
		receipt := helperprotocol.HelperReceipt{
			OperationID: operationID, CanonicalRequestDigest: requestDigest, HelperInstanceID: "helper-1",
			Action: action, State: helperprotocol.JournalSucceeded, RollbackCoverage: helperprotocol.RollbackCoverageFull,
			SnapshotDigest: strings.Repeat("d", 64), SanitizedResult: "proxy reloaded",
			UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		}
		if mutate != nil {
			mutate(&receipt)
		}
		signed, _ := helperprotocol.Sign("attestation-helper-1", privateKey, helperprotocol.NewEnvelope(helperprotocol.MessageHelperReceipt, receipt))
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

func TestClientExecuteVerifiesReceiptRequestDigest(t *testing.T) {
	client := receiptClientFixture(t, helperprotocol.MessageExecuteActionRequest, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	receipt, requestDigest, err := client.Execute(ctx, executionGrantFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Envelope.Payload.CanonicalRequestDigest != requestDigest || receipt.Envelope.Payload.State != helperprotocol.JournalSucceeded {
		t.Fatalf("receipt = %#v, request digest = %q", receipt, requestDigest)
	}
}

func TestClientExecuteRejectsSignedReceiptForAnotherRequest(t *testing.T) {
	client := receiptClientFixture(t, helperprotocol.MessageExecuteActionRequest, func(receipt *helperprotocol.HelperReceipt) {
		receipt.CanonicalRequestDigest = strings.Repeat("e", 64)
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := client.Execute(ctx, executionGrantFixture(t)); err == nil {
		t.Fatal("signed receipt for another canonical request was accepted")
	}
}

func TestClientExecuteManagedApplyVerifiesReceiptBinding(t *testing.T) {
	client := receiptClientFixture(t, helperprotocol.MessageExecuteManagedApplyRequest, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	receipt, requestDigest, err := client.ExecuteManagedApply(ctx, applyGrantFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Envelope.Payload.Action != helperprotocol.ActionApplyManagedProxyState || receipt.Envelope.Payload.CanonicalRequestDigest != requestDigest {
		t.Fatalf("managed receipt = %#v digest=%s", receipt, requestDigest)
	}
}

func TestClientGetReceiptVerifiesOperationAndDigest(t *testing.T) {
	requestDigest := strings.Repeat("f", 64)
	client := receiptClientFixture(t, helperprotocol.MessageGetReceiptRequest, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	receipt, err := client.GetReceipt(ctx, "operation-1", requestDigest)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Envelope.Payload.OperationID != "operation-1" || receipt.Envelope.Payload.CanonicalRequestDigest != requestDigest {
		t.Fatalf("receipt = %#v", receipt)
	}
}

func TestClientPlanReturnsStableRemoteError(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		payload, readErr := helperprotocol.ReadUnixPacketFrame(conn)
		if readErr != nil {
			return
		}
		request, decodeErr := helperprotocol.DecodeEnvelope[helperprotocol.PlanActionRequest](payload, helperprotocol.MessagePlanActionRequest)
		if decodeErr != nil {
			return
		}
		response := helperprotocol.NewEnvelope(helperprotocol.MessageErrorResponse, helperprotocol.ErrorResponse{
			RequestID: request.Payload.RequestID, Code: helperprotocol.ErrorStalePlan, Message: "host facts changed", Retryable: false,
		})
		encoded, _ := helperprotocol.CanonicalBytes(response)
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = client.Plan(ctx, helperprotocol.ActionValidateReloadProxy, helperprotocol.LogicalTargetDetectedProxy, "diagnostic-1")
	var remoteErr *RemoteError
	if !errors.As(err, &remoteErr) || remoteErr.Code != helperprotocol.ErrorStalePlan {
		t.Fatalf("error = %#v", err)
	}
}

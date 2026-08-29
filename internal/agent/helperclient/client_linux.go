//go:build linux

package helperclient

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/helper"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/google/uuid"
)

const requestTimeout = 30 * time.Second

type Client struct {
	socketPath           string
	agentID              string
	buildID              string
	pin                  Pin
	expectedRootUID      uint32
	peerCredentials      func(net.Conn) (helper.Credentials, error)
	verifyPeerExecutable func(int32) error
}

func New(agentID, buildID string, pin Pin) (*Client, error) {
	return newClient(DefaultSocketPath, agentID, buildID, pin)
}

func newClient(socketPath, agentID, buildID string, pin Pin) (*Client, error) {
	if socketPath == "" || !validID(agentID) || !validID(buildID) || pin.Validate() != nil {
		return nil, fmt.Errorf("invalid helper client configuration")
	}
	return &Client{
		socketPath: socketPath, agentID: agentID, buildID: buildID, pin: pin,
		expectedRootUID: 0, peerCredentials: helper.PeerCredentials,
		verifyPeerExecutable: helper.VerifyPeerExecutable,
	}, nil
}

func (c *Client) Hello(ctx context.Context) (helperprotocol.HelperHello, error) {
	signed, err := c.SignedHello(ctx)
	return signed.Envelope.Payload, err
}

func (c *Client) SignedHello(ctx context.Context) (helperprotocol.Signed[helperprotocol.HelperHello], error) {
	request := helperprotocol.HelperHelloRequest{
		RequestID: uuid.NewString(), AgentID: c.agentID, AgentBuildID: c.buildID,
	}
	payload, err := helperprotocol.CanonicalBytes(helperprotocol.NewEnvelope(helperprotocol.MessageHelperHelloRequest, request))
	if err != nil {
		return helperprotocol.Signed[helperprotocol.HelperHello]{}, err
	}
	response, err := c.exchange(ctx, payload)
	if err != nil {
		return helperprotocol.Signed[helperprotocol.HelperHello]{}, err
	}
	signed, err := helperprotocol.Decode[helperprotocol.Signed[helperprotocol.HelperHello]](response)
	if err != nil {
		if remoteErr := decodeRemoteError(response, request.RequestID); remoteErr != nil {
			return helperprotocol.Signed[helperprotocol.HelperHello]{}, remoteErr
		}
		return helperprotocol.Signed[helperprotocol.HelperHello]{}, fmt.Errorf("helper hello is not a valid protocol response")
	}
	if signed.KeyID != c.pin.AttestationKeyID || helperprotocol.Verify(c.pin.publicKey(), signed, helperprotocol.MessageHelperHello) != nil {
		return helperprotocol.Signed[helperprotocol.HelperHello]{}, fmt.Errorf("helper hello attestation is invalid")
	}
	hello := signed.Envelope.Payload
	if hello.RequestID != request.RequestID || hello.HelperInstanceID != c.pin.HelperInstanceID ||
		hello.HelperBuildID != c.buildID || hello.AttestationKeyID != c.pin.AttestationKeyID ||
		hello.AttestationPublicKey != c.pin.AttestationPublicKey {
		return helperprotocol.Signed[helperprotocol.HelperHello]{}, fmt.Errorf("helper hello does not match the enrolled identity")
	}
	return signed, nil
}

func (c *Client) Plan(ctx context.Context, action helperprotocol.Action, target helperprotocol.LogicalTarget, diagnosticID string) (helperprotocol.Signed[helperprotocol.HelperPlan], error) {
	request := helperprotocol.PlanActionRequest{
		RequestID: uuid.NewString(), Action: action, LogicalTarget: target, DiagnosticReference: diagnosticID,
	}
	if err := request.Validate(); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperPlan]{}, err
	}
	payload, err := helperprotocol.CanonicalBytes(helperprotocol.NewEnvelope(helperprotocol.MessagePlanActionRequest, request))
	if err != nil {
		return helperprotocol.Signed[helperprotocol.HelperPlan]{}, err
	}
	response, err := c.exchange(ctx, payload)
	if err != nil {
		return helperprotocol.Signed[helperprotocol.HelperPlan]{}, err
	}
	signed, err := helperprotocol.Decode[helperprotocol.Signed[helperprotocol.HelperPlan]](response)
	if err != nil {
		if remoteErr := decodeRemoteError(response, request.RequestID); remoteErr != nil {
			return helperprotocol.Signed[helperprotocol.HelperPlan]{}, remoteErr
		}
		return helperprotocol.Signed[helperprotocol.HelperPlan]{}, fmt.Errorf("helper plan is not a valid protocol response")
	}
	if signed.KeyID != c.pin.AttestationKeyID || helperprotocol.Verify(c.pin.publicKey(), signed, helperprotocol.MessageHelperPlan) != nil {
		return helperprotocol.Signed[helperprotocol.HelperPlan]{}, fmt.Errorf("helper plan attestation is invalid")
	}
	plan := signed.Envelope.Payload
	if plan.HelperInstanceID != c.pin.HelperInstanceID || plan.DiagnosticID != diagnosticID ||
		plan.Action != action || plan.LogicalTarget != target {
		return helperprotocol.Signed[helperprotocol.HelperPlan]{}, fmt.Errorf("helper plan does not match the requested action")
	}
	return signed, nil
}

func (c *Client) PlanManagedApply(ctx context.Context, intent helperprotocol.Signed[helperprotocol.ApplyIntent]) (helperprotocol.Signed[helperprotocol.ManagedApplyPlan], error) {
	payload := intent.Envelope.Payload
	if intent.Validate() != nil || intent.Envelope.MessageType != helperprotocol.MessageApplyIntent ||
		payload.AgentID != c.agentID || payload.HelperInstanceID != c.pin.HelperInstanceID {
		return helperprotocol.Signed[helperprotocol.ManagedApplyPlan]{}, fmt.Errorf("managed apply intent does not match the enrolled agent helper")
	}
	request := helperprotocol.PlanManagedApplyRequest{RequestID: uuid.NewString(), Intent: intent}
	encoded, err := helperprotocol.CanonicalBytes(helperprotocol.NewEnvelope(helperprotocol.MessagePlanManagedApplyRequest, request))
	if err != nil {
		return helperprotocol.Signed[helperprotocol.ManagedApplyPlan]{}, err
	}
	response, err := c.exchange(ctx, encoded)
	if err != nil {
		return helperprotocol.Signed[helperprotocol.ManagedApplyPlan]{}, err
	}
	signed, err := helperprotocol.Decode[helperprotocol.Signed[helperprotocol.ManagedApplyPlan]](response)
	if err != nil {
		if remoteErr := decodeRemoteError(response, request.RequestID); remoteErr != nil {
			return helperprotocol.Signed[helperprotocol.ManagedApplyPlan]{}, remoteErr
		}
		return helperprotocol.Signed[helperprotocol.ManagedApplyPlan]{}, fmt.Errorf("managed helper plan is not a valid protocol response")
	}
	if signed.KeyID != c.pin.AttestationKeyID || helperprotocol.Verify(c.pin.publicKey(), signed, helperprotocol.MessageManagedApplyPlan) != nil {
		return helperprotocol.Signed[helperprotocol.ManagedApplyPlan]{}, fmt.Errorf("managed helper plan attestation is invalid")
	}
	plan := signed.Envelope.Payload
	if plan.HelperInstanceID != c.pin.HelperInstanceID || plan.OperationID != payload.OperationID || plan.DesiredStateRevision != payload.DesiredStateRevision {
		return helperprotocol.Signed[helperprotocol.ManagedApplyPlan]{}, fmt.Errorf("managed helper plan does not match the signed desired state")
	}
	return signed, nil
}

func (c *Client) Execute(ctx context.Context, grant helperprotocol.Signed[helperprotocol.ExecutionGrant]) (helperprotocol.Signed[helperprotocol.HelperReceipt], string, error) {
	payload := grant.Envelope.Payload
	if grant.Validate() != nil || grant.Envelope.MessageType != helperprotocol.MessageExecutionGrant ||
		payload.AgentID != c.agentID || payload.HelperInstanceID != c.pin.HelperInstanceID {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, "", fmt.Errorf("execution grant does not match the enrolled agent helper")
	}
	request := helperprotocol.NewEnvelope(helperprotocol.MessageExecuteActionRequest, helperprotocol.ExecuteActionRequest{
		OperationID: payload.OperationID, HelperPlanID: payload.HelperPlanID, Grant: grant,
	})
	requestDigest, err := helperprotocol.Digest(request)
	if err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, "", err
	}
	encoded, err := helperprotocol.CanonicalBytes(request)
	if err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, "", err
	}
	response, err := c.exchange(ctx, encoded)
	if err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, requestDigest, err
	}
	receipt, err := c.decodeReceipt(response, payload.OperationID, requestDigest, payload.Action)
	return receipt, requestDigest, err
}

func (c *Client) ExecuteManagedApply(ctx context.Context, grant helperprotocol.Signed[helperprotocol.ApplyGrant]) (helperprotocol.Signed[helperprotocol.HelperReceipt], string, error) {
	payload := grant.Envelope.Payload
	if grant.Validate() != nil || grant.Envelope.MessageType != helperprotocol.MessageApplyGrant ||
		payload.AgentID != c.agentID || payload.HelperInstanceID != c.pin.HelperInstanceID {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, "", fmt.Errorf("managed apply grant does not match the enrolled agent helper")
	}
	request := helperprotocol.NewEnvelope(helperprotocol.MessageExecuteManagedApplyRequest, helperprotocol.ExecuteManagedApplyRequest{
		OperationID: payload.OperationID, HelperPlanID: payload.HelperPlanID, Grant: grant,
	})
	requestDigest, err := helperprotocol.Digest(request)
	if err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, "", err
	}
	encoded, err := helperprotocol.CanonicalBytes(request)
	if err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, "", err
	}
	response, err := c.exchange(ctx, encoded)
	if err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, requestDigest, err
	}
	receipt, err := c.decodeReceipt(response, payload.OperationID, requestDigest, helperprotocol.ActionApplyManagedProxyState)
	return receipt, requestDigest, err
}

func (c *Client) GetReceipt(ctx context.Context, operationID, requestDigest string) (helperprotocol.Signed[helperprotocol.HelperReceipt], error) {
	request := helperprotocol.GetReceiptRequest{OperationID: operationID, CanonicalRequestDigest: requestDigest}
	if err := request.Validate(); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	encoded, err := helperprotocol.CanonicalBytes(helperprotocol.NewEnvelope(helperprotocol.MessageGetReceiptRequest, request))
	if err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	response, err := c.exchange(ctx, encoded)
	if err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	return c.decodeReceipt(response, operationID, requestDigest, "")
}

func (c *Client) decodeReceipt(response []byte, operationID, requestDigest string, expectedAction helperprotocol.Action) (helperprotocol.Signed[helperprotocol.HelperReceipt], error) {
	signed, err := helperprotocol.Decode[helperprotocol.Signed[helperprotocol.HelperReceipt]](response)
	if err != nil {
		if remoteErr := decodeRemoteError(response, operationID); remoteErr != nil {
			return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, remoteErr
		}
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, fmt.Errorf("helper receipt is not a valid protocol response")
	}
	if signed.KeyID != c.pin.AttestationKeyID || helperprotocol.Verify(c.pin.publicKey(), signed, helperprotocol.MessageHelperReceipt) != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, fmt.Errorf("helper receipt attestation is invalid")
	}
	receipt := signed.Envelope.Payload
	if receipt.OperationID != operationID || receipt.CanonicalRequestDigest != requestDigest || receipt.HelperInstanceID != c.pin.HelperInstanceID ||
		(expectedAction != "" && receipt.Action != expectedAction) {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, fmt.Errorf("helper receipt does not match the canonical request")
	}
	return signed, nil
}

func decodeRemoteError(response []byte, requestID string) error {
	envelope, err := helperprotocol.DecodeEnvelope[helperprotocol.ErrorResponse](response, helperprotocol.MessageErrorResponse)
	if err != nil || (envelope.Payload.RequestID != requestID && envelope.Payload.RequestID != "unknown") {
		return nil
	}
	return &RemoteError{Code: envelope.Payload.Code, Message: envelope.Payload.Message, Retryable: envelope.Payload.Retryable}
}

func (c *Client) exchange(ctx context.Context, payload []byte) ([]byte, error) {
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unixpacket", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect root helper: %w", err)
	}
	defer connection.Close()
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok || unixConnection.RemoteAddr().Network() != "unixpacket" {
		return nil, fmt.Errorf("root helper connection is not SOCK_SEQPACKET")
	}
	credentials, err := c.peerCredentials(connection)
	if err != nil || credentials.UID != c.expectedRootUID {
		return nil, fmt.Errorf("root helper peer credentials are invalid")
	}
	if err := c.verifyPeerExecutable(credentials.PID); err != nil {
		return nil, fmt.Errorf("root helper executable identity is invalid: %w", err)
	}
	deadline := time.Now().Add(requestTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := unixConnection.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err := helperprotocol.WriteUnixPacketFrame(unixConnection, payload); err != nil {
		return nil, err
	}
	response, err := helperprotocol.ReadUnixPacketFrame(unixConnection)
	if err != nil {
		return nil, err
	}
	return response, nil
}

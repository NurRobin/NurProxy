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
	request := helperprotocol.HelperHelloRequest{
		RequestID: uuid.NewString(), AgentID: c.agentID, AgentBuildID: c.buildID,
	}
	payload, err := helperprotocol.CanonicalBytes(helperprotocol.NewEnvelope(helperprotocol.MessageHelperHelloRequest, request))
	if err != nil {
		return helperprotocol.HelperHello{}, err
	}
	response, err := c.exchange(ctx, payload)
	if err != nil {
		return helperprotocol.HelperHello{}, err
	}
	signed, err := helperprotocol.Decode[helperprotocol.Signed[helperprotocol.HelperHello]](response)
	if err != nil || signed.KeyID != c.pin.AttestationKeyID ||
		helperprotocol.Verify(c.pin.publicKey(), signed, helperprotocol.MessageHelperHello) != nil {
		return helperprotocol.HelperHello{}, fmt.Errorf("helper hello attestation is invalid")
	}
	hello := signed.Envelope.Payload
	if hello.RequestID != request.RequestID || hello.HelperInstanceID != c.pin.HelperInstanceID ||
		hello.HelperBuildID != c.buildID || hello.AttestationKeyID != c.pin.AttestationKeyID ||
		hello.AttestationPublicKey != c.pin.AttestationPublicKey {
		return helperprotocol.HelperHello{}, fmt.Errorf("helper hello does not match the enrolled identity")
	}
	return hello, nil
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
	if err != nil || signed.KeyID != c.pin.AttestationKeyID ||
		helperprotocol.Verify(c.pin.publicKey(), signed, helperprotocol.MessageHelperPlan) != nil {
		return helperprotocol.Signed[helperprotocol.HelperPlan]{}, fmt.Errorf("helper plan attestation is invalid")
	}
	plan := signed.Envelope.Payload
	if plan.HelperInstanceID != c.pin.HelperInstanceID || plan.DiagnosticID != diagnosticID ||
		plan.Action != action || plan.LogicalTarget != target {
		return helperprotocol.Signed[helperprotocol.HelperPlan]{}, fmt.Errorf("helper plan does not match the requested action")
	}
	return signed, nil
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

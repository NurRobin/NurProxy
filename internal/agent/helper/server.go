package helper

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

const (
	requestTimeout       = 30 * time.Second
	maxConcurrentClients = 4
)

type requestHeader struct {
	ProtocolVersion uint16                     `json:"protocol_version"`
	MessageType     helperprotocol.MessageType `json:"message_type"`
	Domain          string                     `json:"domain"`
	Payload         any                        `json:"payload"`
}

func (h requestHeader) Validate() error {
	if h.ProtocolVersion != helperprotocol.ProtocolVersion || h.Domain != helperprotocol.ProtocolDomain || !h.MessageType.Valid() || h.Payload == nil {
		return fmt.Errorf("invalid protocol request header")
	}
	return nil
}

type Server struct {
	engine               *Engine
	peerCredentials      func(net.Conn) (Credentials, error)
	verifyPeerExecutable func(int32) error
	requestTimeout       time.Duration
}

func NewServer(engine *Engine) *Server {
	return &Server{
		engine:               engine,
		peerCredentials:      PeerCredentials,
		verifyPeerExecutable: VerifyPeerExecutable,
		requestTimeout:       requestTimeout,
	}
}

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if s == nil || s.engine == nil || listener == nil {
		return fmt.Errorf("helper server is not initialized")
	}
	semaphore := make(chan struct{}, maxConcurrentClients)
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-done:
		}
	}()
	defer close(done)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		select {
		case semaphore <- struct{}{}:
			go func() {
				defer func() { <-semaphore }()
				s.serveConn(ctx, conn)
			}()
		default:
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			s.writeError(conn, "unknown", protocolFailure(helperprotocol.ErrorOutcomeIndeterminate, "helper concurrency limit reached", true))
			_ = conn.Close()
		}
	}
}

func (s *Server) serveConn(parent context.Context, conn net.Conn) {
	defer conn.Close()
	deadline := time.Now().Add(s.requestTimeout)
	_ = conn.SetDeadline(deadline)
	credentials, err := s.peerCredentials(conn)
	if err != nil || credentials.UID != s.engine.config.AgentUID {
		s.writeError(conn, "unknown", protocolFailure(helperprotocol.ErrorPeerCredentialsInvalid, "unix peer credentials do not match the configured agent uid", false))
		return
	}
	if err := s.verifyPeerExecutable(credentials.PID); err != nil {
		s.writeError(conn, "unknown", protocolFailure(helperprotocol.ErrorBuildIDMismatch, "peer and helper are not running the same executable", false))
		return
	}
	payload, err := readConnectionFrame(conn)
	if err != nil {
		s.writeError(conn, "unknown", protocolFailure(helperprotocol.ErrorRequestConflict, "invalid bounded protocol frame", false))
		return
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	response, requestID, err := s.dispatch(ctx, payload)
	if err != nil {
		s.writeError(conn, requestID, err)
		return
	}
	encoded, err := helperprotocol.CanonicalBytes(response)
	if err != nil {
		s.writeError(conn, requestID, protocolFailure(helperprotocol.ErrorOutcomeIndeterminate, "helper could not encode its bounded response", false))
		return
	}
	_ = writeConnectionFrame(conn, encoded)
}

func (s *Server) dispatch(ctx context.Context, payload []byte) (any, string, error) {
	header, err := helperprotocol.Decode[requestHeader](payload)
	if err != nil {
		return nil, "unknown", protocolFailure(helperprotocol.ErrorRequestConflict, "strict protocol decoding rejected the request", false)
	}
	switch header.MessageType {
	case helperprotocol.MessageHelperHelloRequest:
		envelope, err := helperprotocol.DecodeEnvelope[helperprotocol.HelperHelloRequest](payload, helperprotocol.MessageHelperHelloRequest)
		if err != nil {
			return nil, "unknown", err
		}
		response, err := s.engine.Hello(envelope.Payload)
		return response, envelope.Payload.RequestID, err
	case helperprotocol.MessagePlanActionRequest:
		envelope, err := helperprotocol.DecodeEnvelope[helperprotocol.PlanActionRequest](payload, helperprotocol.MessagePlanActionRequest)
		if err != nil {
			return nil, "unknown", err
		}
		response, err := s.engine.Plan(ctx, envelope.Payload)
		return response, envelope.Payload.RequestID, err
	case helperprotocol.MessageExecuteActionRequest:
		envelope, err := helperprotocol.DecodeEnvelope[helperprotocol.ExecuteActionRequest](payload, helperprotocol.MessageExecuteActionRequest)
		if err != nil {
			return nil, "unknown", err
		}
		response, err := s.engine.Execute(ctx, envelope)
		return response, envelope.Payload.OperationID, err
	case helperprotocol.MessageGetReceiptRequest:
		envelope, err := helperprotocol.DecodeEnvelope[helperprotocol.GetReceiptRequest](payload, helperprotocol.MessageGetReceiptRequest)
		if err != nil {
			return nil, "unknown", err
		}
		response, err := s.engine.GetReceipt(envelope.Payload)
		return response, envelope.Payload.OperationID, err
	default:
		return nil, "unknown", protocolFailure(helperprotocol.ErrorRequestConflict, "message type is not executable by this helper build", false)
	}
}

func (s *Server) writeError(conn net.Conn, requestID string, err error) {
	if !validConfigID(requestID) {
		requestID = "unknown"
	}
	code := helperprotocol.ErrorOutcomeIndeterminate
	message := "helper request failed closed"
	retryable := false
	var protocolErr *ProtocolError
	switch {
	case errors.As(err, &protocolErr):
		code = protocolErr.Code
		message = protocolErr.Message
		retryable = protocolErr.Retryable
	case errors.Is(err, ErrJournalCorrupt):
		code = helperprotocol.ErrorHelperJournalCorrupt
		message = "helper journal integrity check failed"
	case errors.Is(err, ErrPlanNotFound):
		code = helperprotocol.ErrorHelperPlanNotFound
		message = "helper-local plan was not found"
	case errors.Is(err, ErrRequestConflict), errors.Is(err, fs.ErrExist):
		code = helperprotocol.ErrorRequestConflict
		message = "request conflicts with durable helper state"
	}
	response := helperprotocol.NewEnvelope(helperprotocol.MessageErrorResponse, helperprotocol.ErrorResponse{
		RequestID: requestID,
		Code:      code,
		Message:   truncateUTF8(message, 512),
		Retryable: retryable,
	})
	payload, encodeErr := helperprotocol.CanonicalBytes(response)
	if encodeErr == nil {
		_ = writeConnectionFrame(conn, payload)
	}
}

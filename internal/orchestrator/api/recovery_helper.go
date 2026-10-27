package api

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

func (s *Server) handleEnrollRecoveryHelper(w http.ResponseWriter, r *http.Request) {
	agentID := pathParam(r, "id")
	if _, err := s.db.GetAgent(agentID); err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	payload, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody+1))
	if err != nil || len(payload) == 0 || len(payload) > maxJSONBody {
		writeRecoveryError(w, http.StatusBadRequest, "invalid_helper_enrollment", "invalid bounded helper enrollment")
		return
	}
	signed, err := helperprotocol.Decode[helperprotocol.Signed[helperprotocol.HelperHello]](payload)
	if err != nil || signed.Envelope.MessageType != helperprotocol.MessageHelperHello ||
		signed.KeyID != signed.Envelope.Payload.AttestationKeyID {
		writeRecoveryError(w, http.StatusBadRequest, "invalid_helper_enrollment", "helper enrollment envelope is invalid")
		return
	}
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(signed.Envelope.Payload.AttestationPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize ||
		helperprotocol.Verify(ed25519.PublicKey(publicKey), signed, helperprotocol.MessageHelperHello) != nil {
		writeRecoveryError(w, http.StatusBadRequest, "invalid_helper_attestation", "helper attestation signature is invalid")
		return
	}
	digest, err := helperprotocol.Digest(signed)
	if err != nil {
		writeRecoveryError(w, http.StatusBadRequest, "invalid_helper_enrollment", "helper enrollment digest is invalid")
		return
	}
	if err := s.db.EnrollRecoveryHelper(agentID, signed.Envelope.Payload, digest, time.Now().UTC()); err != nil {
		if errors.Is(err, db.ErrRecoveryHelperEnrollmentConflict) {
			writeRecoveryError(w, http.StatusConflict, "helper_enrollment_conflict", "an explicit rotation workflow is required")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to persist helper enrollment")
		return
	}
	hello := signed.Envelope.Payload
	s.audit(r, "recovery_helper", hello.HelperInstanceID, "enrolled",
		fmt.Sprintf("agent=%s build=%s attestation_key_id=%s", agentID, hello.HelperBuildID, hello.AttestationKeyID))
	instance, err := s.db.GetRecoveryHelper(agentID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read helper enrollment")
		return
	}
	writeJSON(w, http.StatusCreated, instance)
}

func (s *Server) handleGetRecoveryHelper(w http.ResponseWriter, r *http.Request) {
	agentID := pathParam(r, "id")
	if callerID, _ := r.Context().Value(ctxAgentID).(string); callerID != agentID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	instance, err := s.db.GetRecoveryHelper(agentID)
	if err != nil {
		writeRecoveryError(w, http.StatusNotFound, "helper_not_enrolled", "recovery helper is not enrolled")
		return
	}
	writeJSON(w, http.StatusOK, instance)
}

func (s *Server) handleGetRecoveryHelperAdmin(w http.ResponseWriter, r *http.Request) {
	agentID := pathParam(r, "id")
	if _, err := s.db.GetAgent(agentID); err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	instance, err := s.db.GetRecoveryHelper(agentID)
	if errors.Is(err, db.ErrRecoveryHelperNotEnrolled) {
		writeJSON(w, http.StatusOK, map[string]any{"enrolled": false})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read helper enrollment")
		return
	}
	status := map[string]any{"enrolled": true, "helper": instance}
	breaker, leftovers, err := s.managedApplyFindings(agentID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read managed apply history")
		return
	}
	if breaker != nil {
		status["managed_apply_breaker"] = breaker
	}
	if leftovers != nil {
		status["managed_apply_leftovers"] = leftovers
	}
	writeJSON(w, http.StatusOK, status)
}

// managedApplyLeftoversView lists the vhost files the newest managed apply
// reported as left on disk without a desired route. The helper repeats the
// list in every receipt until the files are gone.
type managedApplyLeftoversView struct {
	OperationID string     `json:"operation_id"`
	Files       string     `json:"files"`
	ReportedAt  *time.Time `json:"reported_at,omitempty"`
}

// leftoverVhostsFromReceipt extracts the leftover list the helper appends to
// its receipt message, or "" when there is none.
func leftoverVhostsFromReceipt(message string) string {
	index := strings.Index(message, helperprotocol.ManagedLeftoverVhostsNote)
	if index < 0 {
		return ""
	}
	list := message[index+len(helperprotocol.ManagedLeftoverVhostsNote):]
	if end := strings.Index(list, "; "); end >= 0 {
		list = list[:end]
	}
	return strings.TrimSpace(list)
}

// managedApplyBreakerView describes the helper's persistent breaker as seen
// from the orchestrator. The helper latches it whenever a managed apply ends
// as rollback_failed and then refuses every later apply without a receipt, so
// the newest receipt the orchestrator holds tells whether it is still open.
type managedApplyBreakerView struct {
	Open        bool       `json:"open"`
	OperationID string     `json:"operation_id"`
	Reason      string     `json:"reason"`
	OpenedAt    *time.Time `json:"opened_at,omitempty"`
}

// managedReceiptLatchesBreaker reports the terminal states after which the
// helper has written its permanent breaker: a rollback it could not prove, and
// an execution its journal recovered as indeterminate after a crash.
func managedReceiptLatchesBreaker(state helperprotocol.JournalState) bool {
	return state == helperprotocol.JournalRollbackFailed || state == helperprotocol.JournalOutcomeIndeterminate
}

// managedApplyFindings derives the open breaker and the reported leftover
// vhosts from the newest managed apply receipt; either is nil when absent.
func (s *Server) managedApplyFindings(agentID string) (*managedApplyBreakerView, *managedApplyLeftoversView, error) {
	execution, err := s.db.GetLatestReceiptedManagedApply(agentID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	receipt := execution.SignedReceipt.Envelope.Payload
	var breaker *managedApplyBreakerView
	if managedReceiptLatchesBreaker(receipt.State) {
		breaker = &managedApplyBreakerView{
			Open: true, OperationID: receipt.OperationID, Reason: receipt.SanitizedResult, OpenedAt: execution.ReceiptReceivedAt,
		}
	}
	var leftovers *managedApplyLeftoversView
	if files := leftoverVhostsFromReceipt(receipt.SanitizedResult); files != "" {
		leftovers = &managedApplyLeftoversView{OperationID: receipt.OperationID, Files: files, ReportedAt: execution.ReceiptReceivedAt}
	}
	return breaker, leftovers, nil
}

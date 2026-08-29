package api

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/recoverypolicy"
	"github.com/google/uuid"
)

type recoveryConfirmationRequest struct {
	Phase               int    `json:"phase"`
	ConfirmationEventID string `json:"confirmation_event_id"`
	DisplayPlanHash     string `json:"display_plan_hash"`
}

func (s *Server) handleSubmitRecoveryExecutionPlan(w http.ResponseWriter, r *http.Request) {
	agentID := pathParam(r, "id")
	if callerID, _ := r.Context().Value(ctxAgentID).(string); callerID != agentID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	payload, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody+1))
	if err != nil || len(payload) == 0 || len(payload) > maxJSONBody {
		writeRecoveryError(w, http.StatusBadRequest, "invalid_helper_plan", "invalid bounded helper plan")
		return
	}
	signed, err := helperprotocol.Decode[helperprotocol.Signed[helperprotocol.HelperPlan]](payload)
	if err != nil || signed.Envelope.MessageType != helperprotocol.MessageHelperPlan {
		writeRecoveryError(w, http.StatusBadRequest, "invalid_helper_plan", "helper plan envelope is invalid")
		return
	}
	enrolled, err := s.db.GetRecoveryHelper(agentID)
	if err != nil {
		writeRecoveryError(w, http.StatusConflict, "helper_not_enrolled", "recovery helper is not enrolled")
		return
	}
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(enrolled.AttestationPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || signed.KeyID != enrolled.AttestationKeyID ||
		signed.Envelope.Payload.HelperInstanceID != enrolled.HelperInstanceID ||
		helperprotocol.Verify(ed25519.PublicKey(publicKey), signed, helperprotocol.MessageHelperPlan) != nil {
		writeRecoveryError(w, http.StatusBadRequest, "invalid_helper_attestation", "helper plan attestation is invalid")
		return
	}
	plan := signed.Envelope.Payload
	diagnostic, err := s.db.GetDiagnostic(agentID, plan.DiagnosticID)
	if err != nil || diagnostic.ResolvedAt != nil {
		writeRecoveryError(w, http.StatusNotFound, "diagnostic_not_found", "active diagnostic not found")
		return
	}
	expectedAction, expectedTarget, ok := recoverypolicy.HardActionForDiagnostic(diagnostic.Code, diagnostic.RepairScope)
	if !ok || !diagnostic.HardChange || !diagnostic.RepairEligible || plan.Action != expectedAction ||
		plan.LogicalTarget != expectedTarget || plan.ResourceFingerprint != diagnostic.ResourceFingerprint {
		writeRecoveryError(w, http.StatusUnprocessableEntity, "helper_plan_mismatch", "helper plan does not match the current deterministic diagnosis")
		return
	}
	if existing, getErr := s.db.GetRecoveryExecutionPlan(agentID, plan.HelperPlanID); getErr == nil {
		existingDigest, digestErr := helperprotocol.Digest(existing.SignedPlan)
		incomingDigest, incomingErr := helperprotocol.Digest(signed)
		if digestErr == nil && incomingErr == nil && existingDigest == incomingDigest {
			writeJSON(w, http.StatusOK, existing)
			return
		}
		writeRecoveryError(w, http.StatusConflict, "helper_plan_conflict", "helper plan identity conflicts with durable state")
		return
	}
	operationID := uuid.NewString()
	if err := s.db.StoreRecoveryExecutionPlan(agentID, operationID, signed, time.Now().UTC()); err != nil {
		switch {
		case errors.Is(err, db.ErrRecoveryPlanExpired):
			writeRecoveryError(w, http.StatusConflict, "helper_plan_expired", "helper plan has expired")
		case errors.Is(err, db.ErrRecoveryPlanMismatch):
			writeRecoveryError(w, http.StatusConflict, "helper_plan_conflict", "helper plan conflicts with enrolled helper state")
		case errors.Is(err, db.ErrActiveRecoveryPlan):
			writeRecoveryError(w, http.StatusConflict, "active_helper_plan", "an unexpired helper plan already exists for this diagnosis")
		default:
			writeError(w, http.StatusInternalServerError, "failed to persist helper plan")
		}
		return
	}
	stored, err := s.db.GetRecoveryExecutionPlan(agentID, plan.HelperPlanID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read helper plan")
		return
	}
	s.auditAs(r, models.AuditSourceAgent, "recovery_plan", plan.HelperPlanID, "attested", "agent="+agentID+" action="+string(plan.Action))
	writeJSON(w, http.StatusCreated, stored)
}

func (s *Server) handleGetRecoveryExecutionPlan(w http.ResponseWriter, r *http.Request) {
	plan, err := s.db.GetRecoveryExecutionPlan(pathParam(r, "id"), pathParam(r, "planId"))
	if err != nil {
		writeRecoveryError(w, http.StatusNotFound, "helper_plan_not_found", "helper plan not found")
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func (s *Server) handleConfirmRecoveryExecutionPlan(w http.ResponseWriter, r *http.Request) {
	agentID, planID := pathParam(r, "id"), pathParam(r, "planId")
	var request recoveryConfirmationRequest
	if err := readRecoveryJSON(r, &request); err != nil {
		writeRecoveryError(w, http.StatusBadRequest, "invalid_confirmation", err.Error())
		return
	}
	s.recoveryMu.Lock()
	defer s.recoveryMu.Unlock()
	confirmed, err := s.db.ConfirmRecoveryExecutionPlan(agentID, planID, request.DisplayPlanHash, request.Phase, request.ConfirmationEventID, time.Now().UTC())
	if err != nil {
		switch {
		case errors.Is(err, db.ErrRecoveryPlanMismatch):
			writeRecoveryError(w, http.StatusConflict, "display_plan_mismatch", "displayed plan hash does not match the helper-attested plan")
		case errors.Is(err, db.ErrRecoveryPlanExpired):
			writeRecoveryError(w, http.StatusConflict, "helper_plan_expired", "helper plan has expired")
		case errors.Is(err, db.ErrRecoveryConfirmationOrder):
			writeRecoveryError(w, http.StatusConflict, "confirmation_order_invalid", "confirmation phases must be completed in order")
		case errors.Is(err, db.ErrRecoveryConfirmationConflict):
			writeRecoveryError(w, http.StatusConflict, "confirmation_conflict", "confirmation event conflicts with durable state")
		default:
			writeRecoveryError(w, http.StatusBadRequest, "invalid_confirmation", "confirmation request is invalid")
		}
		return
	}
	s.audit(r, "recovery_plan", planID, "confirmation_"+string(rune('0'+request.Phase)), "agent="+agentID+" event="+request.ConfirmationEventID)
	if request.Phase == 2 && confirmed.SignedGrant == nil {
		if s.recoveryAuthority == nil {
			writeRecoveryError(w, http.StatusServiceUnavailable, "recovery_authority_unavailable", "recovery grant authority is unavailable")
			return
		}
		issuedAt := confirmed.ConfirmationTimes[1]
		expiresAt := issuedAt.Add(5 * time.Minute)
		if confirmed.ExpiresAt.Before(expiresAt) {
			expiresAt = confirmed.ExpiresAt
		}
		grant := helperprotocol.ExecutionGrant{
			GrantID: deterministicRecoveryGrantID(agentID, planID, confirmed.ConfirmationEventIDs[1]),
			AgentID: agentID, HelperInstanceID: confirmed.HelperInstanceID,
			DiagnosticID: confirmed.DiagnosticID, OperationID: confirmed.OperationID,
			Action: confirmed.Action, HelperPlanID: confirmed.HelperPlanID,
			DisplayPlanHash: confirmed.DisplayPlanHash, ExecutionPlanHash: confirmed.ExecutionPlanHash,
			ResourceFingerprint:  confirmed.ResourceFingerprint,
			ConfirmationEventIDs: append([]string(nil), confirmed.ConfirmationEventIDs...),
			IssuedAt:             issuedAt.Format(time.RFC3339Nano), ExpiresAt: expiresAt.Format(time.RFC3339Nano),
		}
		signedGrant, signErr := s.recoveryAuthority.SignExecutionGrant(grant)
		if signErr != nil || signedGrant.KeyID != s.recoveryAuthority.KeyID() {
			writeError(w, http.StatusInternalServerError, "failed to sign recovery execution grant")
			return
		}
		if err := s.db.StoreRecoveryExecutionGrant(agentID, planID, signedGrant); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to persist recovery execution grant")
			return
		}
		confirmed, err = s.db.GetRecoveryExecutionPlan(agentID, planID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to read recovery execution grant")
			return
		}
		s.audit(r, "recovery_plan", planID, "grant_issued", "agent="+agentID+" operation="+confirmed.OperationID)
	}
	writeJSON(w, http.StatusOK, confirmed)
}

func (s *Server) handleGetRecoveryExecutionGrant(w http.ResponseWriter, r *http.Request) {
	agentID := pathParam(r, "id")
	if callerID, _ := r.Context().Value(ctxAgentID).(string); callerID != agentID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	plan, err := s.db.GetRecoveryExecutionPlan(agentID, pathParam(r, "planId"))
	if err != nil {
		writeRecoveryError(w, http.StatusNotFound, "helper_plan_not_found", "helper plan not found")
		return
	}
	if plan.SignedGrant == nil {
		writeRecoveryError(w, http.StatusConflict, "execution_grant_pending", "two confirmations are required before execution")
		return
	}
	writeJSON(w, http.StatusOK, plan.SignedGrant)
}

func deterministicRecoveryGrantID(agentID, planID, eventID string) string {
	digest := sha256.Sum256([]byte(agentID + "\x00" + planID + "\x00" + eventID))
	return "grant-" + hex.EncodeToString(digest[:16])
}

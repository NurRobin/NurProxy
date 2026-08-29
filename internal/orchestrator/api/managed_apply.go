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
)

func (s *Server) handleSubmitManagedApplyPlan(w http.ResponseWriter, r *http.Request) {
	agentID, operationID := pathParam(r, "id"), pathParam(r, "operationId")
	if callerID, _ := r.Context().Value(ctxAgentID).(string); callerID != agentID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	payload, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody+1))
	if err != nil || len(payload) == 0 || len(payload) > maxJSONBody {
		writeRecoveryError(w, http.StatusBadRequest, "invalid_managed_apply_plan", "invalid bounded managed apply plan")
		return
	}
	signed, err := helperprotocol.Decode[helperprotocol.Signed[helperprotocol.ManagedApplyPlan]](payload)
	if err != nil || signed.Envelope.MessageType != helperprotocol.MessageManagedApplyPlan || signed.Envelope.Payload.OperationID != operationID {
		writeRecoveryError(w, http.StatusBadRequest, "invalid_managed_apply_plan", "managed apply plan envelope is invalid")
		return
	}
	if s.recoveryAuthority == nil {
		writeRecoveryError(w, http.StatusServiceUnavailable, "recovery_authority_unavailable", "managed apply grant authority is unavailable")
		return
	}
	enrolled, err := s.db.GetRecoveryHelper(agentID)
	if err != nil {
		writeRecoveryError(w, http.StatusConflict, "helper_not_enrolled", "recovery helper is not enrolled")
		return
	}
	helperPublicKey, err := base64.RawURLEncoding.Strict().DecodeString(enrolled.AttestationPublicKey)
	if err != nil || len(helperPublicKey) != ed25519.PublicKeySize || signed.KeyID != enrolled.AttestationKeyID ||
		signed.Envelope.Payload.HelperInstanceID != enrolled.HelperInstanceID ||
		helperprotocol.Verify(ed25519.PublicKey(helperPublicKey), signed, helperprotocol.MessageManagedApplyPlan) != nil {
		writeRecoveryError(w, http.StatusBadRequest, "invalid_helper_attestation", "managed apply plan attestation is invalid")
		return
	}

	s.recoveryMu.Lock()
	defer s.recoveryMu.Unlock()
	existing, getErr := s.db.GetManagedApply(agentID, operationID)
	if getErr != nil {
		writeRecoveryError(w, http.StatusNotFound, "managed_apply_not_found", "managed apply intent not found")
		return
	}
	if !existing.Current {
		writeRecoveryError(w, http.StatusConflict, "managed_apply_superseded", "managed apply intent was superseded")
		return
	}
	orchestratorPublicKey, err := base64.RawURLEncoding.Strict().DecodeString(s.recoveryAuthority.PublicKeyText())
	if err != nil || len(orchestratorPublicKey) != ed25519.PublicKeySize ||
		existing.SignedIntent.KeyID != s.recoveryAuthority.KeyID() ||
		helperprotocol.Verify(ed25519.PublicKey(orchestratorPublicKey), existing.SignedIntent, helperprotocol.MessageApplyIntent) != nil {
		writeRecoveryError(w, http.StatusConflict, "managed_apply_intent_invalid", "stored managed apply intent failed verification")
		return
	}
	created := existing.SignedPlan == nil
	if err := s.db.StoreManagedApplyPlan(agentID, signed, time.Now().UTC()); err != nil {
		switch {
		case errors.Is(err, db.ErrManagedApplySuperseded):
			writeRecoveryError(w, http.StatusConflict, "managed_apply_superseded", "managed apply intent was superseded")
		case errors.Is(err, db.ErrManagedApplyExpired):
			writeRecoveryError(w, http.StatusConflict, "managed_apply_expired", "managed apply plan expired")
		case errors.Is(err, db.ErrManagedApplyMismatch):
			writeRecoveryError(w, http.StatusConflict, "managed_apply_mismatch", "managed apply plan does not match current desired state")
		default:
			writeError(w, http.StatusInternalServerError, "failed to persist managed apply plan")
		}
		return
	}
	execution, err := s.db.GetManagedApply(agentID, operationID)
	if err != nil || execution.SignedPlan == nil {
		writeError(w, http.StatusInternalServerError, "failed to read managed apply plan")
		return
	}
	if execution.SignedGrant == nil {
		plan := execution.SignedPlan.Envelope.Payload
		intent := execution.SignedIntent.Envelope.Payload
		issuedAt := time.Now().UTC()
		expiresAt := issuedAt.Add(5 * time.Minute)
		if execution.PlanExpiresAt != nil && execution.PlanExpiresAt.Before(expiresAt) {
			expiresAt = *execution.PlanExpiresAt
		}
		grant := helperprotocol.ApplyGrant{
			GrantID:           deterministicManagedApplyGrantID(agentID, operationID, plan.HelperPlanID),
			AuthorizationKind: intent.AuthorizationKind, AuthorizationEventID: intent.AuthorizationEventID,
			AgentID: agentID, HelperInstanceID: plan.HelperInstanceID, OperationID: operationID, HelperPlanID: plan.HelperPlanID,
			DesiredStateRevision: plan.DesiredStateRevision, LogicalManifestDigest: plan.LogicalManifestDigest,
			ArtifactManifestDigest: plan.ArtifactManifestDigest, DeletionSetDigest: plan.DeletionSetDigest,
			CertificateIdentityDigest: plan.CertificateIdentityDigest, CustomPolicyVersion: plan.CustomPolicyVersion,
			ExecutionPlanHash: plan.ExecutionPlanHash, ResourceFingerprint: plan.ResourceFingerprint,
			RollbackCoverage: plan.RollbackCoverage, IssuedAt: issuedAt.Format(time.RFC3339Nano), ExpiresAt: expiresAt.Format(time.RFC3339Nano),
		}
		signedGrant, signErr := s.recoveryAuthority.SignApplyGrant(grant)
		if signErr != nil || signedGrant.KeyID != s.recoveryAuthority.KeyID() {
			writeError(w, http.StatusInternalServerError, "failed to sign managed apply grant")
			return
		}
		if err := s.db.StoreManagedApplyGrant(agentID, operationID, signedGrant); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to persist managed apply grant")
			return
		}
		execution, err = s.db.GetManagedApply(agentID, operationID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to read managed apply grant")
			return
		}
		s.auditAs(r, models.AuditSourceAgent, "managed_apply", operationID, "grant_issued", "agent="+agentID+" revision="+intent.DesiredStateRevision)
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, execution)
}

func (s *Server) handleGetManagedApply(w http.ResponseWriter, r *http.Request) {
	agentID := pathParam(r, "id")
	if callerID, _ := r.Context().Value(ctxAgentID).(string); callerID != agentID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	execution, err := s.db.GetManagedApply(agentID, pathParam(r, "operationId"))
	if err != nil {
		writeRecoveryError(w, http.StatusNotFound, "managed_apply_not_found", "managed apply execution not found")
		return
	}
	writeJSON(w, http.StatusOK, execution)
}

func (s *Server) handleSubmitManagedApplyReceipt(w http.ResponseWriter, r *http.Request) {
	agentID, operationID := pathParam(r, "id"), pathParam(r, "operationId")
	if callerID, _ := r.Context().Value(ctxAgentID).(string); callerID != agentID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	payload, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody+1))
	if err != nil || len(payload) == 0 || len(payload) > maxJSONBody {
		writeRecoveryError(w, http.StatusBadRequest, "invalid_helper_receipt", "invalid bounded managed apply receipt")
		return
	}
	signed, err := helperprotocol.Decode[helperprotocol.Signed[helperprotocol.HelperReceipt]](payload)
	if err != nil || signed.Envelope.MessageType != helperprotocol.MessageHelperReceipt || signed.Envelope.Payload.OperationID != operationID {
		writeRecoveryError(w, http.StatusBadRequest, "invalid_helper_receipt", "managed apply receipt envelope is invalid")
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
		helperprotocol.Verify(ed25519.PublicKey(publicKey), signed, helperprotocol.MessageHelperReceipt) != nil {
		writeRecoveryError(w, http.StatusBadRequest, "invalid_helper_attestation", "managed apply receipt attestation is invalid")
		return
	}
	if err := s.db.StoreManagedApplyReceipt(agentID, operationID, signed, time.Now().UTC()); err != nil {
		if errors.Is(err, db.ErrManagedApplyMismatch) {
			writeRecoveryError(w, http.StatusConflict, "managed_apply_mismatch", "managed apply receipt does not match its exact execution request")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to persist managed apply receipt")
		return
	}
	if signed.Envelope.Payload.State == helperprotocol.JournalSucceeded {
		execution, getErr := s.db.GetManagedApply(agentID, operationID)
		if getErr != nil || s.db.DeleteManagedRouteTombstones(agentID, execution.SignedIntent.Envelope.Payload.DeletionSet) != nil {
			writeError(w, http.StatusInternalServerError, "failed to finalize managed route deletions")
			return
		}
	}
	s.auditAs(r, models.AuditSourceAgent, "managed_apply", operationID, string(signed.Envelope.Payload.State), "agent="+agentID)
	w.WriteHeader(http.StatusNoContent)
}

func deterministicManagedApplyGrantID(agentID, operationID, helperPlanID string) string {
	digest := sha256.Sum256([]byte(agentID + "\x00" + operationID + "\x00" + helperPlanID))
	return "managed-grant-" + hex.EncodeToString(digest[:16])
}

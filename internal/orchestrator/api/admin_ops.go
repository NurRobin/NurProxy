package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// adminOpTTL is how long a minted confirmation code stays claimable (§19). It is
// deliberately short: configure once in the UI, apply within minutes on the host.
const adminOpTTL = 15 * time.Minute

// adminOpView is the safe, code-free projection of an admin op returned to the
// dashboard. It deliberately omits CodeHash (and never carries the plaintext
// code) so listing or inspecting pending ops can never leak the confirmation
// secret (§19: only a hash is stored; the plaintext is shown once at mint).
type adminOpView struct {
	ID        string     `json:"id"`
	OpType    string     `json:"op_type"`
	Status    string     `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	AppliedAt *time.Time `json:"applied_at,omitempty"`
	Result    string     `json:"result,omitempty"`
}

func toAdminOpView(op models.AgentAdminOp) adminOpView {
	return adminOpView{
		ID:        op.ID,
		OpType:    op.OpType,
		Status:    op.Status,
		CreatedAt: op.CreatedAt,
		ExpiresAt: op.ExpiresAt,
		AppliedAt: op.AppliedAt,
		Result:    op.Result,
	}
}

// validateAdminOpPayload validates op_type and returns the canonical JSON the
// store should persist for that op. Unknown op types are rejected so the channel
// stays a closed set (set_proxy_mode is the only op for now; §19).
func validateAdminOpPayload(opType string, raw json.RawMessage) (string, error) {
	switch opType {
	case models.AdminOpSetProxyMode:
		var p models.SetProxyModePayload
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &p); err != nil {
				return "", fmt.Errorf("invalid set_proxy_mode payload: %w", err)
			}
		}
		return models.MarshalSetProxyModePayload(p)
	default:
		return "", fmt.Errorf("unknown op_type %q", opType)
	}
}

// POST /api/v1/agents/{id}/admin-ops — dashboard user prepares a pending admin
// op and receives a one-time confirmation code (§19). requireAuth.
func (s *Server) handlePrepareAdminOp(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")

	if _, err := s.db.GetAgent(id); err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	var req struct {
		OpType  string          `json:"op_type"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	payloadJSON, err := validateAdminOpPayload(req.OpType, req.Payload)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	code, err := db.GenerateConfirmationCode()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to mint confirmation code")
		return
	}
	codeHash := db.HashConfirmationCode(code)

	op, err := s.db.CreateAdminOp(r.Context(), id, req.OpType, payloadJSON, codeHash, actorFromCtx(r), adminOpTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create admin op")
		return
	}

	s.audit(r, "agent", id, "admin_op.prepare", "op_type="+op.OpType)

	// The plaintext code is shown exactly once here; only its hash is stored.
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":         op.ID,
		"code":       code,
		"expires_at": op.ExpiresAt,
	})
}

// GET /api/v1/agents/{id}/admin-ops — dashboard lists the agent's pending,
// non-expired ops. Never includes the code or its hash. requireAuth.
func (s *Server) handleListAdminOps(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")

	if _, err := s.db.GetAgent(id); err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	ops, err := s.db.ListPendingAdminOps(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list admin ops")
		return
	}

	views := make([]adminOpView, 0, len(ops))
	for _, op := range ops {
		views = append(views, toAdminOpView(op))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ops": views})
}

// DELETE /api/v1/agents/{id}/admin-ops/{opId} — dashboard revokes a pending op
// before it is claimed. Verifies the op belongs to the agent. requireAuth.
func (s *Server) handleCancelAdminOp(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	opID := pathParam(r, "opId")

	op, err := s.db.GetAdminOp(r.Context(), opID)
	if err != nil || op.AgentID != id {
		writeError(w, http.StatusNotFound, "admin op not found")
		return
	}

	if err := s.db.CancelAdminOp(r.Context(), opID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to cancel admin op")
		return
	}

	s.audit(r, "agent", id, "admin_op.cancel", "op_type="+op.OpType)

	w.WriteHeader(http.StatusNoContent)
}

// POST /api/v1/agents/{id}/admin-ops/claim — the agent presents the confirmation
// code (bound to its local shell presence) and pulls the op payload, atomically
// flipping it pending->applied (§19). requireAgentAuth, scoped to the caller.
func (s *Server) handleClaimAdminOp(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	if callerID, _ := r.Context().Value(ctxAgentID).(string); callerID != id {
		writeError(w, http.StatusForbidden, "agent can only claim for itself")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	codeHash := db.HashConfirmationCode(req.Code)
	op, err := s.db.ClaimAdminOp(r.Context(), id, codeHash)
	if err != nil {
		if errors.Is(err, db.ErrAdminOpNotFound) {
			writeError(w, http.StatusNotFound, "no matching pending change (wrong, expired, or already-used code)")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to claim admin op")
		return
	}

	s.audit(r, "agent", id, "admin_op.claim", "op_type="+op.OpType)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":      op.ID,
		"op_type": op.OpType,
		"payload": json.RawMessage(op.Payload),
	})
}

// POST /api/v1/agents/{id}/admin-ops/{opId}/ack — the agent reports the outcome
// of a claimed op (apply report or error) (§19). requireAgentAuth, scoped to the
// caller.
func (s *Server) handleAckAdminOp(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	opID := pathParam(r, "opId")
	if callerID, _ := r.Context().Value(ctxAgentID).(string); callerID != id {
		writeError(w, http.StatusForbidden, "agent can only ack for itself")
		return
	}

	op, err := s.db.GetAdminOp(r.Context(), opID)
	if err != nil || op.AgentID != id {
		writeError(w, http.StatusNotFound, "admin op not found")
		return
	}

	var req struct {
		OK     bool   `json:"ok"`
		Result string `json:"result"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.db.AckAdminOp(r.Context(), opID, req.Result); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to ack admin op")
		return
	}

	s.audit(r, "agent", id, "admin_op.ack", fmt.Sprintf("ok=%t result=%s", req.OK, req.Result))

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

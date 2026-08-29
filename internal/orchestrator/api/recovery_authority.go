package api

import (
	"net/http"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

type recoveryAuthorityPublic interface {
	KeyID() string
	PublicKeyText() string
	SignExecutionGrant(helperprotocol.ExecutionGrant) (helperprotocol.Signed[helperprotocol.ExecutionGrant], error)
	SignApplyGrant(helperprotocol.ApplyGrant) (helperprotocol.Signed[helperprotocol.ApplyGrant], error)
}

type recoveryAuthorityResponse struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

func (s *Server) SetRecoveryAuthority(authority recoveryAuthorityPublic) {
	s.recoveryAuthority = authority
}

func (s *Server) handleGetRecoveryAuthority(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	if callerID, _ := r.Context().Value(ctxAgentID).(string); callerID != id {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if s.recoveryAuthority == nil {
		writeRecoveryError(w, http.StatusServiceUnavailable, "recovery_authority_unavailable", "recovery grant authority is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, recoveryAuthorityResponse{
		KeyID:     s.recoveryAuthority.KeyID(),
		Algorithm: "Ed25519",
		PublicKey: s.recoveryAuthority.PublicKeyText(),
	})
}

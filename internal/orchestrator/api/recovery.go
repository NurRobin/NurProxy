package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
	"github.com/google/uuid"
)

const maxRecoveryReportItems = 500

type manualRepairRequest struct {
	DiagnosticID string               `json:"diagnostic_id"`
	Action       recoverymodel.Action `json:"action"`
}

type safeAutoRepairRequest struct {
	Mode string `json:"mode"`
}

type recoveryBreakerView struct {
	Open      bool       `json:"open"`
	Reason    string     `json:"reason,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type recoveryDiagnosticView struct {
	recoverymodel.Diagnostic
	Breaker recoveryBreakerView `json:"breaker"`
}

func (request *manualRepairRequest) UnmarshalJSON(data []byte) error {
	type plain manualRepairRequest
	var decoded plain
	if err := recoverymodel.DecodeStrict(data, &decoded); err != nil {
		return err
	}
	if strings.TrimSpace(decoded.DiagnosticID) == "" {
		return fmt.Errorf("diagnostic_id is required")
	}
	if !decoded.Action.Valid() {
		return fmt.Errorf("unknown action %q", decoded.Action)
	}
	*request = manualRepairRequest(decoded)
	return nil
}

func writeRecoveryError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": message, "code": code})
}

func readRecoveryJSON(r *http.Request, destination any) error {
	if r.Body == nil {
		return fmt.Errorf("empty request body")
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody+1))
	if err != nil {
		return fmt.Errorf("reading request body: %w", err)
	}
	if len(data) > maxJSONBody {
		return fmt.Errorf("request body too large (max %d bytes)", maxJSONBody)
	}
	if err := recoverymodel.DecodeStrict(data, destination); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

func (s *Server) handleListRecoveryDiagnostics(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	if _, err := s.db.GetAgent(id); err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	includeResolved := r.URL.Query().Get("include_resolved") == "true"
	resolvedLimit := 0
	if includeResolved {
		resolvedLimit = 100
		if raw := r.URL.Query().Get("resolved_limit"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 0 || parsed > 200 {
				writeError(w, http.StatusBadRequest, "resolved_limit must be between 0 and 200")
				return
			}
			resolvedLimit = parsed
		}
	}
	diagnostics, err := s.db.ListDiagnosticsForRecoveryView(id, resolvedLimit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list recovery diagnostics")
		return
	}
	statuses, err := s.db.GetRepairBreakerStatuses(id, diagnostics, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to inspect recovery circuit breakers")
		return
	}
	views := make([]recoveryDiagnosticView, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		view := recoveryDiagnosticView{Diagnostic: diagnostic}
		if diagnostic.ProposedAction.Valid() {
			status := statuses[db.RepairBreakerKey{Action: diagnostic.ProposedAction, ResourceFingerprint: diagnostic.ResourceFingerprint}]
			view.Breaker = recoveryBreakerView{Open: status.Open, Reason: status.Reason, ExpiresAt: status.ExpiresAt}
		}
		views = append(views, view)
	}
	writeJSON(w, http.StatusOK, views)
}

func (s *Server) handleListRepairs(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	if _, err := s.db.GetAgent(id); err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			writeError(w, http.StatusBadRequest, "limit must be between 1 and 200")
			return
		}
		limit = parsed
	}
	operations, err := s.db.ListRepairOperations(id, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list repair operations")
		return
	}
	writeJSON(w, http.StatusOK, operations)
}

func (s *Server) handleCreateRepair(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	var request manualRepairRequest
	if err := readRecoveryJSON(r, &request); err != nil {
		writeRecoveryError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	s.recoveryMu.Lock()
	defer s.recoveryMu.Unlock()

	activeDiagnostics, err := s.db.ListDiagnostics(id, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to inspect active diagnostics")
		return
	}
	var diagnostic *recoverymodel.Diagnostic
	for i := range activeDiagnostics {
		if activeDiagnostics[i].ID == request.DiagnosticID {
			diagnostic = &activeDiagnostics[i]
			break
		}
	}
	if diagnostic == nil {
		writeRecoveryError(w, http.StatusNotFound, "diagnostic_not_found", "active diagnostic not found")
		return
	}
	if diagnostic.ProposedAction != request.Action {
		writeRecoveryError(w, http.StatusUnprocessableEntity, "action_mismatch", "action does not match the current diagnosis")
		return
	}
	if diagnostic.Ownership != recoverymodel.OwnershipNurProxy {
		writeRecoveryError(w, http.StatusUnprocessableEntity, "ownership_not_nurproxy", "resource is not provably NurProxy-owned")
		return
	}
	if diagnostic.HardChange {
		writeRecoveryError(w, http.StatusUnprocessableEntity, "hard_change", "hard changes are diagnosis-only in this recovery stage")
		return
	}
	if !diagnostic.AutoRepairEligible || !diagnostic.ProposedAction.Valid() {
		writeRecoveryError(w, http.StatusUnprocessableEntity, "not_safe_repair_eligible", "diagnostic is not eligible for a safe typed repair")
		return
	}
	if s.hub == nil || !s.hub.Connected(id) {
		writeRecoveryError(w, http.StatusConflict, "agent_disconnected", "agent must be connected before starting a repair")
		return
	}
	agent, err := s.db.GetAgent(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if agent.RecoveryCapability == nil || agent.RecoveryCapability.Stage < 1 {
		writeRecoveryError(w, http.StatusConflict, "recovery_capability_unavailable", "agent has not advertised safe recovery support")
		return
	}
	if !capabilityHasAction(agent.RecoveryCapability, request.Action) {
		writeRecoveryError(w, http.StatusConflict, "action_unsupported", "agent does not support this typed recovery action")
		return
	}
	history, err := s.db.ListRepairOperations(id, 200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to inspect repair history")
		return
	}
	for _, operation := range history {
		if operation.DiagnosticID == diagnostic.ID && !terminalRecoveryState(operation.State) {
			writeRecoveryError(w, http.StatusConflict, "operation_active", "a repair is already active for this diagnostic")
			return
		}
	}
	breakerOpen, err := s.db.RepairBreakerOpen(id, request.Action, diagnostic.ResourceFingerprint, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to inspect repair circuit breaker")
		return
	}
	if breakerOpen {
		rollbackFailed, err := s.db.RepairRollbackFailedLatched(id, request.Action, diagnostic.ResourceFingerprint)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to inspect repair rollback latch")
			return
		}
		if !rollbackFailed {
			writeRecoveryError(w, http.StatusConflict, "circuit_breaker_open", "repair circuit breaker is open")
			return
		}
	}

	now := time.Now().UTC()
	operation := recoverymodel.OperationReport{
		OperationID: uuid.NewString(), DiagnosticID: diagnostic.ID, Action: request.Action,
		Source: recoverymodel.RequestSourceUser, State: recoverymodel.OperationStatePlanned,
		Steps:     []recoverymodel.Step{{Name: string(recoverymodel.OperationStatePlanned), Summary: "safe typed repair requested", State: recoverymodel.OperationStatePlanned, At: now}},
		StartedAt: now,
	}
	if err := s.db.CreateRepairOperationIfNoActive(id, operation, diagnostic.ResourceFingerprint); err != nil {
		if errors.Is(err, db.ErrActiveRepairOperation) {
			writeRecoveryError(w, http.StatusConflict, "operation_active", "a repair is already active for this diagnostic")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to create repair operation")
		return
	}
	s.audit(r, "recovery_operation", operation.OperationID, "planned", "typed action="+string(operation.Action)+" agent="+id)
	if !s.hub.PublishRepairRequest(id, recoverymodel.RepairRequest{OperationID: operation.OperationID, DiagnosticID: operation.DiagnosticID, Action: operation.Action, StartedAt: operation.StartedAt, InitialStep: operation.Steps[0]}) {
		s.audit(r, "recovery_operation", operation.OperationID, "delivery_pending", "typed repair remains queued for reconnect delivery")
	}
	writeJSON(w, http.StatusAccepted, operation)
}

func capabilityHasAction(capability *recoverymodel.Capability, action recoverymodel.Action) bool {
	if capability == nil {
		return false
	}
	for _, supported := range capability.Actions {
		if supported == action {
			return true
		}
	}
	return false
}

func terminalRecoveryState(state recoverymodel.OperationState) bool {
	switch state {
	case recoverymodel.OperationStateDiagnosisOnly, recoverymodel.OperationStateSucceeded,
		recoverymodel.OperationStateRolledBack, recoverymodel.OperationStateRollbackFailed,
		recoverymodel.OperationStateSuppressed:
		return true
	default:
		return false
	}
}

func (s *Server) handleRecoveryReport(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	if callerID, _ := r.Context().Value(ctxAgentID).(string); callerID != id {
		writeError(w, http.StatusForbidden, "agent can only report recovery state for itself")
		return
	}
	var envelope proxymodel.RecoveryReportEnvelope
	if err := readRecoveryJSON(r, &envelope); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := envelope.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(envelope.Report.Diagnostics) > maxRecoveryReportItems || len(envelope.Report.Operations) > maxRecoveryReportItems {
		writeError(w, http.StatusBadRequest, "recovery report has too many items")
		return
	}
	diagnosticIDs := make(map[string]struct{}, len(envelope.Report.Diagnostics))
	for _, diagnostic := range envelope.Report.Diagnostics {
		if _, duplicate := diagnosticIDs[diagnostic.ID]; duplicate {
			writeError(w, http.StatusBadRequest, "recovery report has duplicate diagnostic IDs")
			return
		}
		diagnosticIDs[diagnostic.ID] = struct{}{}
	}
	operationIDs := make(map[string]struct{}, len(envelope.Report.Operations))
	for _, operation := range envelope.Report.Operations {
		if _, duplicate := operationIDs[operation.OperationID]; duplicate {
			writeError(w, http.StatusBadRequest, "recovery report has duplicate operation IDs")
			return
		}
		operationIDs[operation.OperationID] = struct{}{}
	}

	s.recoveryMu.Lock()
	defer s.recoveryMu.Unlock()
	if envelope.Report.Capability != nil {
		if err := s.db.UpdateAgentRecoveryCapability(id, envelope.Report.Capability); err != nil {
			writeError(w, http.StatusBadRequest, "failed to persist recovery capability")
			return
		}
	}
	activeBefore := make(map[string]struct{})
	if len(envelope.Report.Diagnostics) > 0 {
		active, err := s.db.ListDiagnostics(id, false)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to inspect recovery diagnostic state")
			return
		}
		for _, diagnostic := range active {
			activeBefore[diagnostic.ID] = struct{}{}
		}
	}
	activeIDs := make([]string, 0, len(envelope.Report.Diagnostics))
	for _, diagnostic := range envelope.Report.Diagnostics {
		prior, priorErr := s.db.GetDiagnostic(id, diagnostic.ID)
		if err := s.db.UpsertDiagnostic(id, diagnostic); err != nil {
			writeError(w, http.StatusBadRequest, "failed to persist recovery diagnostic")
			return
		}
		activeIDs = append(activeIDs, diagnostic.ID)
		if priorErr != nil {
			s.auditAs(r, models.AuditSourceAgent, "recovery_diagnostic", diagnostic.ID, "detected", "code="+string(diagnostic.Code)+" agent="+id)
			continue
		}
		stored, err := s.db.GetDiagnostic(id, diagnostic.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to verify recovery diagnostic")
			return
		}
		if _, wasActive := activeBefore[diagnostic.ID]; !wasActive {
			s.auditAs(r, models.AuditSourceAgent, "recovery_diagnostic", diagnostic.ID, "reactivated", "code="+string(stored.Code)+" agent="+id)
		} else if diagnosticStateChanged(*prior, *stored) {
			s.auditAs(r, models.AuditSourceAgent, "recovery_diagnostic", diagnostic.ID, "state_changed", "code="+string(stored.Code)+" agent="+id)
		}
	}
	if envelope.Report.Diagnostics != nil {
		active, err := s.db.ListDiagnostics(id, false)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to inspect active recovery diagnostics")
			return
		}
		at := time.Now().UTC()
		if err := s.db.ResolveMissingDiagnostics(id, activeIDs, at); err != nil {
			writeError(w, http.StatusBadRequest, "failed to resolve recovery diagnostics")
			return
		}
		remaining, err := s.db.ListDiagnostics(id, false)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to verify resolved recovery diagnostics")
			return
		}
		remainingIDs := make(map[string]struct{}, len(remaining))
		for _, diagnostic := range remaining {
			remainingIDs[diagnostic.ID] = struct{}{}
		}
		for _, diagnostic := range active {
			if _, stillActive := remainingIDs[diagnostic.ID]; !stillActive {
				s.auditAs(r, models.AuditSourceAgent, "recovery_diagnostic", diagnostic.ID, "resolved", "code="+string(diagnostic.Code)+" agent="+id)
			}
		}
	}
	for _, operation := range envelope.Report.Operations {
		if err := s.persistReportedOperation(r, id, operation); err != nil {
			writeRecoveryError(w, http.StatusConflict, "operation_conflict", err.Error())
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func diagnosticStateChanged(previous, next recoverymodel.Diagnostic) bool {
	return previous.Code != next.Code || previous.Severity != next.Severity || previous.Ownership != next.Ownership ||
		previous.ProposedAction != next.ProposedAction || previous.AutoRepairEligible != next.AutoRepairEligible || previous.HardChange != next.HardChange
}

func (s *Server) persistReportedOperation(r *http.Request, agentID string, operation recoverymodel.OperationReport) error {
	prior, err := s.db.GetRepairOperation(agentID, operation.OperationID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to inspect repair operation")
	}
	if prior == nil {
		if operation.Source != recoverymodel.RequestSourceAutomatic || operation.State != recoverymodel.OperationStateDetected {
			return fmt.Errorf("repair operation must begin with an automatic detected report")
		}
		diagnostic, err := s.activeRecoveryDiagnostic(agentID, operation.DiagnosticID)
		if err != nil {
			return fmt.Errorf("recovery diagnostic not found for operation")
		}
		if err := s.db.CreateRepairOperationIfNoActive(agentID, operation, diagnostic.ResourceFingerprint); err != nil {
			return err
		}
		s.auditAs(r, models.AuditSourceAgent, "recovery_operation", operation.OperationID, string(operation.State), "typed action="+string(operation.Action)+" agent="+agentID)
		return nil
	}
	if recoveryReportsEqual(*prior, operation) {
		return nil
	}
	if err := s.db.AdvanceRepairOperation(agentID, operation); err != nil {
		return err
	}
	s.auditAs(r, models.AuditSourceAgent, "recovery_operation", operation.OperationID, string(operation.State), "typed action="+string(operation.Action)+" agent="+agentID)
	return nil
}

func (s *Server) activeRecoveryDiagnostic(agentID, diagnosticID string) (*recoverymodel.Diagnostic, error) {
	diagnostics, err := s.db.ListDiagnostics(agentID, false)
	if err != nil {
		return nil, err
	}
	for i := range diagnostics {
		if diagnostics[i].ID == diagnosticID {
			return &diagnostics[i], nil
		}
	}
	return nil, fmt.Errorf("active recovery diagnostic not found")
}

func recoveryReportsEqual(left, right recoverymodel.OperationReport) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return bytes.Equal(leftJSON, rightJSON)
}

func (s *Server) handleRepairAck(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	if callerID, _ := r.Context().Value(ctxAgentID).(string); callerID != id {
		writeError(w, http.StatusForbidden, "agent can only acknowledge repairs for itself")
		return
	}
	var operation recoverymodel.OperationReport
	if err := readRecoveryJSON(r, &operation); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if operation.OperationID != pathParam(r, "opId") {
		writeRecoveryError(w, http.StatusUnprocessableEntity, "operation_id_mismatch", "operation ID does not match request path")
		return
	}
	s.recoveryMu.Lock()
	defer s.recoveryMu.Unlock()
	if err := s.persistReportedOperation(r, id, operation); err != nil {
		writeRecoveryError(w, http.StatusConflict, "operation_conflict", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) publishRecoveryPolicy(agentID string, enabled bool) {
	if s.hub != nil {
		s.hub.PublishRecoveryPolicy(agentID, enabled)
	}
}

package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

const maxRecoveryExecutionPlansPerAgent = 256

var (
	ErrRecoveryPlanMismatch         = errors.New("recovery plan does not match durable state")
	ErrRecoveryPlanExpired          = errors.New("recovery plan has expired")
	ErrRecoveryConfirmationOrder    = errors.New("recovery confirmations are out of order")
	ErrRecoveryConfirmationConflict = errors.New("recovery confirmation conflicts with durable state")
)

type RecoveryExecutionPlan struct {
	AgentID              string                                                `json:"agent_id"`
	OperationID          string                                                `json:"operation_id"`
	HelperPlanID         string                                                `json:"helper_plan_id"`
	HelperInstanceID     string                                                `json:"helper_instance_id"`
	DiagnosticID         string                                                `json:"diagnostic_id"`
	Action               helperprotocol.Action                                 `json:"action"`
	LogicalTarget        helperprotocol.LogicalTarget                          `json:"logical_target"`
	DisplayPlanHash      string                                                `json:"display_plan_hash"`
	ExecutionPlanHash    string                                                `json:"execution_plan_hash"`
	ResourceFingerprint  string                                                `json:"resource_fingerprint"`
	RollbackCoverage     helperprotocol.RollbackCoverage                       `json:"rollback_coverage"`
	SignedPlan           helperprotocol.Signed[helperprotocol.HelperPlan]      `json:"signed_plan"`
	PlanDigest           string                                                `json:"plan_digest"`
	ReceivedAt           time.Time                                             `json:"received_at"`
	ExpiresAt            time.Time                                             `json:"expires_at"`
	ConfirmationEventIDs []string                                              `json:"confirmation_event_ids"`
	ConfirmationTimes    []time.Time                                           `json:"confirmation_times"`
	SignedGrant          *helperprotocol.Signed[helperprotocol.ExecutionGrant] `json:"signed_execution_grant,omitempty"`
}

func (d *DB) StoreRecoveryExecutionPlan(agentID, operationID string, signed helperprotocol.Signed[helperprotocol.HelperPlan], at time.Time) error {
	plan := signed.Envelope.Payload
	if !validRecoverySemanticID(agentID) || !validRecoverySemanticID(operationID) || signed.Validate() != nil ||
		signed.Envelope.MessageType != helperprotocol.MessageHelperPlan || at.IsZero() {
		return fmt.Errorf("invalid recovery execution plan")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, plan.ExpiresAt)
	if err != nil || !expiresAt.After(at) {
		return ErrRecoveryPlanExpired
	}
	encoded, err := helperprotocol.CanonicalBytes(signed)
	if err != nil {
		return fmt.Errorf("encode recovery execution plan: %w", err)
	}
	digest, err := helperprotocol.Digest(signed)
	if err != nil {
		return fmt.Errorf("digest recovery execution plan: %w", err)
	}
	receivedNanos, err := recoveryUnixNano(at)
	if err != nil {
		return fmt.Errorf("encode recovery plan receive time: %w", err)
	}
	expiresNanos, err := recoveryUnixNano(expiresAt)
	if err != nil {
		return fmt.Errorf("encode recovery plan expiry: %w", err)
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return fmt.Errorf("begin recovery plan store: %w", err)
	}
	defer tx.Rollback()
	var enrolledInstance, enrolledKey string
	if err := tx.QueryRow(`SELECT helper_instance_id, attestation_key_id FROM recovery_helper_instances WHERE agent_id = ?`, agentID).Scan(&enrolledInstance, &enrolledKey); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("recovery helper not enrolled for agent: %s", agentID)
		}
		return fmt.Errorf("query enrolled recovery helper: %w", err)
	}
	if enrolledInstance != plan.HelperInstanceID || enrolledKey != signed.KeyID {
		return ErrRecoveryPlanMismatch
	}
	existing, scanErr := scanRecoveryExecutionPlan(tx.QueryRow(recoveryExecutionPlanSelect+` WHERE agent_id = ? AND helper_plan_id = ?`, agentID, plan.HelperPlanID))
	if scanErr == nil {
		if existing.OperationID == operationID && existing.PlanDigest == digest {
			return nil
		}
		return ErrRecoveryPlanMismatch
	}
	if scanErr != sql.ErrNoRows {
		return fmt.Errorf("query existing recovery execution plan: %w", scanErr)
	}
	if _, err := tx.Exec(`DELETE FROM recovery_execution_plans
		WHERE agent_id = ? AND expires_at <= ? AND confirmation_1_id = '' AND signed_grant = ''`, agentID, receivedNanos); err != nil {
		return fmt.Errorf("prune expired recovery execution plans: %w", err)
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM recovery_execution_plans WHERE agent_id = ?`, agentID).Scan(&count); err != nil {
		return fmt.Errorf("count recovery execution plans: %w", err)
	}
	if count >= maxRecoveryExecutionPlansPerAgent {
		return fmt.Errorf("recovery execution plan capacity exceeded")
	}
	if _, err := tx.Exec(`INSERT INTO recovery_execution_plans (
		agent_id, helper_plan_id, operation_id, helper_instance_id, diagnostic_id,
		action, logical_target, display_plan_hash, execution_plan_hash,
		resource_fingerprint, rollback_coverage, signed_plan, plan_digest,
		received_at, expires_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, agentID, plan.HelperPlanID,
		operationID, plan.HelperInstanceID, plan.DiagnosticID, string(plan.Action), string(plan.LogicalTarget),
		plan.DisplayPlanHash, plan.ExecutionPlanHash, plan.ResourceFingerprint, string(plan.RollbackCoverage),
		string(encoded), digest, receivedNanos, expiresNanos); err != nil {
		return fmt.Errorf("insert recovery execution plan: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit recovery execution plan: %w", err)
	}
	return nil
}

func (d *DB) GetRecoveryExecutionPlan(agentID, helperPlanID string) (*RecoveryExecutionPlan, error) {
	if !validRecoverySemanticID(agentID) || !validRecoverySemanticID(helperPlanID) {
		return nil, fmt.Errorf("recovery execution plan identity is required")
	}
	plan, err := scanRecoveryExecutionPlan(d.read.QueryRow(recoveryExecutionPlanSelect+` WHERE agent_id = ? AND helper_plan_id = ?`, agentID, helperPlanID))
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("recovery execution plan not found")
	}
	if err != nil {
		return nil, fmt.Errorf("query recovery execution plan: %w", err)
	}
	return &plan, nil
}

func (d *DB) ConfirmRecoveryExecutionPlan(agentID, helperPlanID, displayPlanHash string, phase int, eventID string, at time.Time) (*RecoveryExecutionPlan, error) {
	if !validRecoverySemanticID(agentID) || !validRecoverySemanticID(helperPlanID) || !validRecoveryDigest(displayPlanHash) ||
		(phase != 1 && phase != 2) || !validRecoverySemanticID(eventID) || at.IsZero() {
		return nil, fmt.Errorf("invalid recovery confirmation")
	}
	atNanos, err := recoveryUnixNano(at)
	if err != nil {
		return nil, fmt.Errorf("encode recovery confirmation time: %w", err)
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin recovery confirmation: %w", err)
	}
	defer tx.Rollback()
	plan, err := scanRecoveryExecutionPlan(tx.QueryRow(recoveryExecutionPlanSelect+` WHERE agent_id = ? AND helper_plan_id = ?`, agentID, helperPlanID))
	if err != nil {
		return nil, fmt.Errorf("query recovery confirmation plan: %w", err)
	}
	if plan.DisplayPlanHash != displayPlanHash {
		return nil, ErrRecoveryPlanMismatch
	}
	if !at.Before(plan.ExpiresAt) {
		return nil, ErrRecoveryPlanExpired
	}
	if phase == 2 && len(plan.ConfirmationEventIDs) == 0 {
		return nil, ErrRecoveryConfirmationOrder
	}
	if phase == 2 && (eventID == plan.ConfirmationEventIDs[0] || !at.After(plan.ConfirmationTimes[0])) {
		return nil, ErrRecoveryConfirmationConflict
	}
	index := phase - 1
	if len(plan.ConfirmationEventIDs) > index {
		if plan.ConfirmationEventIDs[index] == eventID {
			return &plan, nil
		}
		return nil, ErrRecoveryConfirmationConflict
	}
	if phase == 1 && len(plan.ConfirmationEventIDs) != 0 || phase == 2 && len(plan.ConfirmationEventIDs) != 1 {
		return nil, ErrRecoveryConfirmationOrder
	}
	columnID, columnAt := "confirmation_1_id", "confirmation_1_at"
	if phase == 2 {
		columnID, columnAt = "confirmation_2_id", "confirmation_2_at"
	}
	result, err := tx.Exec(`UPDATE recovery_execution_plans SET `+columnID+` = ?, `+columnAt+` = ?
		WHERE agent_id = ? AND helper_plan_id = ? AND `+columnID+` = ''`, eventID, atNanos, agentID, helperPlanID)
	if err != nil {
		return nil, fmt.Errorf("persist recovery confirmation: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return nil, ErrRecoveryConfirmationConflict
	}
	plan, err = scanRecoveryExecutionPlan(tx.QueryRow(recoveryExecutionPlanSelect+` WHERE agent_id = ? AND helper_plan_id = ?`, agentID, helperPlanID))
	if err != nil {
		return nil, fmt.Errorf("reload recovery confirmation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit recovery confirmation: %w", err)
	}
	return &plan, nil
}

func (d *DB) StoreRecoveryExecutionGrant(agentID, helperPlanID string, signed helperprotocol.Signed[helperprotocol.ExecutionGrant]) error {
	if !validRecoverySemanticID(agentID) || !validRecoverySemanticID(helperPlanID) || signed.Validate() != nil ||
		signed.Envelope.MessageType != helperprotocol.MessageExecutionGrant {
		return fmt.Errorf("invalid recovery execution grant")
	}
	encoded, err := helperprotocol.CanonicalBytes(signed)
	if err != nil {
		return fmt.Errorf("encode recovery execution grant: %w", err)
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return fmt.Errorf("begin recovery execution grant store: %w", err)
	}
	defer tx.Rollback()
	plan, err := scanRecoveryExecutionPlan(tx.QueryRow(recoveryExecutionPlanSelect+` WHERE agent_id = ? AND helper_plan_id = ?`, agentID, helperPlanID))
	if err != nil {
		return fmt.Errorf("query confirmed recovery plan: %w", err)
	}
	if len(plan.ConfirmationEventIDs) != 2 {
		return ErrRecoveryConfirmationOrder
	}
	grant := signed.Envelope.Payload
	issuedAt, issuedErr := time.Parse(time.RFC3339Nano, grant.IssuedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	if issuedErr != nil || expiresErr != nil || issuedAt.Before(plan.ConfirmationTimes[1]) || expiresAt.After(plan.ExpiresAt) ||
		grant.AgentID != agentID || grant.HelperInstanceID != plan.HelperInstanceID ||
		grant.DiagnosticID != plan.DiagnosticID || grant.OperationID != plan.OperationID ||
		grant.Action != plan.Action || grant.HelperPlanID != plan.HelperPlanID ||
		grant.DisplayPlanHash != plan.DisplayPlanHash || grant.ExecutionPlanHash != plan.ExecutionPlanHash ||
		grant.ResourceFingerprint != plan.ResourceFingerprint ||
		len(grant.ConfirmationEventIDs) != 2 || grant.ConfirmationEventIDs[0] != plan.ConfirmationEventIDs[0] ||
		grant.ConfirmationEventIDs[1] != plan.ConfirmationEventIDs[1] {
		return ErrRecoveryPlanMismatch
	}
	if plan.SignedGrant != nil {
		existing, encodeErr := helperprotocol.CanonicalBytes(*plan.SignedGrant)
		if encodeErr == nil && string(existing) == string(encoded) {
			return nil
		}
		return ErrRecoveryPlanMismatch
	}
	result, err := tx.Exec(`UPDATE recovery_execution_plans SET signed_grant = ?
		WHERE agent_id = ? AND helper_plan_id = ? AND signed_grant = ''`, string(encoded), agentID, helperPlanID)
	if err != nil {
		return fmt.Errorf("persist recovery execution grant: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrRecoveryPlanMismatch
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit recovery execution grant: %w", err)
	}
	return nil
}

const recoveryExecutionPlanSelect = `SELECT agent_id, operation_id, helper_plan_id,
	helper_instance_id, diagnostic_id, action, logical_target, display_plan_hash,
	execution_plan_hash, resource_fingerprint, rollback_coverage, signed_plan,
	plan_digest, received_at, expires_at, confirmation_1_id, confirmation_1_at,
	confirmation_2_id, confirmation_2_at, signed_grant
	FROM recovery_execution_plans`

func scanRecoveryExecutionPlan(scanner interface{ Scan(...any) error }) (RecoveryExecutionPlan, error) {
	var plan RecoveryExecutionPlan
	var action, target, coverage, signedPlanText, signedGrantText string
	var receivedAt, expiresAt int64
	var confirmation1ID, confirmation2ID string
	var confirmation1At, confirmation2At sql.NullInt64
	if err := scanner.Scan(&plan.AgentID, &plan.OperationID, &plan.HelperPlanID, &plan.HelperInstanceID,
		&plan.DiagnosticID, &action, &target, &plan.DisplayPlanHash, &plan.ExecutionPlanHash,
		&plan.ResourceFingerprint, &coverage, &signedPlanText, &plan.PlanDigest, &receivedAt,
		&expiresAt, &confirmation1ID, &confirmation1At, &confirmation2ID, &confirmation2At,
		&signedGrantText); err != nil {
		return plan, err
	}
	plan.Action, plan.LogicalTarget, plan.RollbackCoverage = helperprotocol.Action(action), helperprotocol.LogicalTarget(target), helperprotocol.RollbackCoverage(coverage)
	signed, err := helperprotocol.Decode[helperprotocol.Signed[helperprotocol.HelperPlan]]([]byte(signedPlanText))
	if err != nil {
		return plan, fmt.Errorf("decode stored signed recovery plan: %w", err)
	}
	plan.SignedPlan = signed
	plan.ReceivedAt, err = recoveryTimeFromUnixNano(receivedAt)
	if err != nil {
		return plan, err
	}
	plan.ExpiresAt, err = recoveryTimeFromUnixNano(expiresAt)
	if err != nil {
		return plan, err
	}
	for _, confirmation := range []struct {
		id string
		at sql.NullInt64
	}{{confirmation1ID, confirmation1At}, {confirmation2ID, confirmation2At}} {
		if confirmation.id == "" && !confirmation.at.Valid {
			continue
		}
		if !validRecoverySemanticID(confirmation.id) || !confirmation.at.Valid {
			return plan, fmt.Errorf("invalid stored recovery confirmation")
		}
		decodedAt, timeErr := recoveryTimeFromUnixNano(confirmation.at.Int64)
		if timeErr != nil {
			return plan, timeErr
		}
		plan.ConfirmationEventIDs = append(plan.ConfirmationEventIDs, confirmation.id)
		plan.ConfirmationTimes = append(plan.ConfirmationTimes, decodedAt)
	}
	if signedGrantText != "" {
		grant, decodeErr := helperprotocol.Decode[helperprotocol.Signed[helperprotocol.ExecutionGrant]]([]byte(signedGrantText))
		if decodeErr != nil {
			return plan, fmt.Errorf("decode stored signed recovery grant: %w", decodeErr)
		}
		plan.SignedGrant = &grant
	}
	payload := signed.Envelope.Payload
	digest, err := helperprotocol.Digest(signed)
	if err != nil || digest != plan.PlanDigest || payload.HelperPlanID != plan.HelperPlanID ||
		payload.HelperInstanceID != plan.HelperInstanceID || payload.DiagnosticID != plan.DiagnosticID ||
		payload.Action != plan.Action || payload.LogicalTarget != plan.LogicalTarget ||
		payload.DisplayPlanHash != plan.DisplayPlanHash || payload.ExecutionPlanHash != plan.ExecutionPlanHash ||
		payload.ResourceFingerprint != plan.ResourceFingerprint || payload.RollbackCoverage != plan.RollbackCoverage ||
		!payloadExpiresAt(payload, plan.ExpiresAt) || !validRecoverySemanticID(plan.AgentID) || !validRecoverySemanticID(plan.OperationID) {
		return plan, fmt.Errorf("stored recovery execution plan failed integrity checks")
	}
	return plan, nil
}

func payloadExpiresAt(plan helperprotocol.HelperPlan, expiresAt time.Time) bool {
	parsed, err := time.Parse(time.RFC3339Nano, plan.ExpiresAt)
	return err == nil && parsed.Equal(expiresAt)
}

func validRecoverySemanticID(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r)) {
			return false
		}
	}
	return true
}

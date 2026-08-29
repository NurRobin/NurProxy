package db

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

const maxManagedApplyExecutionsPerAgent = 256

var (
	ErrManagedApplyMismatch   = errors.New("managed apply does not match durable desired state")
	ErrManagedApplySuperseded = errors.New("managed apply intent was superseded")
	ErrManagedApplyExpired    = errors.New("managed apply authorization expired")
)

type ManagedApplyExecution struct {
	AgentID              string                                                  `json:"agent_id"`
	OperationID          string                                                  `json:"operation_id"`
	HelperInstanceID     string                                                  `json:"helper_instance_id"`
	DesiredStateRevision string                                                  `json:"desired_state_revision"`
	SignedIntent         helperprotocol.Signed[helperprotocol.ApplyIntent]       `json:"signed_apply_intent"`
	IntentDigest         string                                                  `json:"intent_digest"`
	IntentReceivedAt     time.Time                                               `json:"intent_received_at"`
	IntentExpiresAt      time.Time                                               `json:"intent_expires_at"`
	Current              bool                                                    `json:"current"`
	HelperPlanID         string                                                  `json:"helper_plan_id,omitempty"`
	SignedPlan           *helperprotocol.Signed[helperprotocol.ManagedApplyPlan] `json:"signed_helper_plan,omitempty"`
	PlanDigest           string                                                  `json:"plan_digest,omitempty"`
	PlanReceivedAt       *time.Time                                              `json:"plan_received_at,omitempty"`
	PlanExpiresAt        *time.Time                                              `json:"plan_expires_at,omitempty"`
	SignedGrant          *helperprotocol.Signed[helperprotocol.ApplyGrant]       `json:"signed_apply_grant,omitempty"`
	GrantDigest          string                                                  `json:"grant_digest,omitempty"`
	SignedReceipt        *helperprotocol.Signed[helperprotocol.HelperReceipt]    `json:"signed_helper_receipt,omitempty"`
	ReceiptDigest        string                                                  `json:"receipt_digest,omitempty"`
	ReceiptReceivedAt    *time.Time                                              `json:"receipt_received_at,omitempty"`
}

func (d *DB) StoreManagedApplyIntent(agentID string, signed helperprotocol.Signed[helperprotocol.ApplyIntent], at time.Time) error {
	intent := signed.Envelope.Payload
	if !validRecoverySemanticID(agentID) || signed.Validate() != nil || signed.Envelope.MessageType != helperprotocol.MessageApplyIntent ||
		intent.AgentID != agentID || at.IsZero() {
		return fmt.Errorf("invalid managed apply intent")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, intent.ExpiresAt)
	if err != nil || !expiresAt.After(at) {
		return ErrManagedApplyExpired
	}
	encoded, err := helperprotocol.CanonicalBytes(signed)
	if err != nil {
		return fmt.Errorf("encode managed apply intent: %w", err)
	}
	digest, err := helperprotocol.Digest(signed)
	if err != nil {
		return fmt.Errorf("digest managed apply intent: %w", err)
	}
	receivedNanos, err := recoveryUnixNano(at)
	if err != nil {
		return err
	}
	expiresNanos, err := recoveryUnixNano(expiresAt)
	if err != nil {
		return err
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return fmt.Errorf("begin managed apply intent store: %w", err)
	}
	defer tx.Rollback()
	var enrolledInstance string
	if err := tx.QueryRow(`SELECT helper_instance_id FROM recovery_helper_instances WHERE agent_id = ?`, agentID).Scan(&enrolledInstance); err != nil {
		return fmt.Errorf("query managed apply helper enrollment: %w", err)
	}
	if enrolledInstance != intent.HelperInstanceID {
		return ErrManagedApplyMismatch
	}
	var existingDigest string
	if err := tx.QueryRow(`SELECT intent_digest FROM managed_apply_executions WHERE agent_id = ? AND operation_id = ?`, agentID, intent.OperationID).Scan(&existingDigest); err == nil {
		if existingDigest == digest {
			return nil
		}
		return ErrManagedApplyMismatch
	} else if err != sql.ErrNoRows {
		return fmt.Errorf("query existing managed apply intent: %w", err)
	}
	if _, err := tx.Exec(`UPDATE managed_apply_executions SET is_current = 0 WHERE agent_id = ? AND is_current = 1`, agentID); err != nil {
		return fmt.Errorf("supersede managed apply intent: %w", err)
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM managed_apply_executions WHERE agent_id = ?`, agentID).Scan(&count); err != nil {
		return fmt.Errorf("count managed apply executions: %w", err)
	}
	if count >= maxManagedApplyExecutionsPerAgent {
		result, deleteErr := tx.Exec(`DELETE FROM managed_apply_executions WHERE rowid = (
			SELECT rowid FROM managed_apply_executions WHERE agent_id = ? AND is_current = 0
			ORDER BY intent_received_at ASC LIMIT 1
		)`, agentID)
		if deleteErr != nil {
			return fmt.Errorf("prune managed apply execution: %w", deleteErr)
		}
		if rows, _ := result.RowsAffected(); rows != 1 {
			return fmt.Errorf("managed apply execution capacity exceeded")
		}
	}
	if _, err := tx.Exec(`INSERT INTO managed_apply_executions (
		agent_id, operation_id, helper_instance_id, desired_state_revision,
		signed_intent, intent_digest, intent_received_at, intent_expires_at, is_current
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)`, agentID, intent.OperationID, intent.HelperInstanceID,
		intent.DesiredStateRevision, string(encoded), digest, receivedNanos, expiresNanos); err != nil {
		return fmt.Errorf("insert managed apply intent: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit managed apply intent: %w", err)
	}
	return nil
}

func (d *DB) GetCurrentManagedApply(agentID string) (*ManagedApplyExecution, error) {
	if !validRecoverySemanticID(agentID) {
		return nil, fmt.Errorf("managed apply agent identity is required")
	}
	return getManagedApply(d.read.QueryRow(managedApplySelect+` WHERE agent_id = ? AND is_current = 1`, agentID))
}

func (d *DB) GetManagedApply(agentID, operationID string) (*ManagedApplyExecution, error) {
	if !validRecoverySemanticID(agentID) || !validRecoverySemanticID(operationID) {
		return nil, fmt.Errorf("managed apply identity is required")
	}
	return getManagedApply(d.read.QueryRow(managedApplySelect+` WHERE agent_id = ? AND operation_id = ?`, agentID, operationID))
}

func (d *DB) StoreManagedApplyPlan(agentID string, signed helperprotocol.Signed[helperprotocol.ManagedApplyPlan], at time.Time) error {
	plan := signed.Envelope.Payload
	if !validRecoverySemanticID(agentID) || signed.Validate() != nil || signed.Envelope.MessageType != helperprotocol.MessageManagedApplyPlan || at.IsZero() {
		return fmt.Errorf("invalid managed apply plan")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, plan.ExpiresAt)
	if err != nil || !expiresAt.After(at) {
		return ErrManagedApplyExpired
	}
	encoded, err := helperprotocol.CanonicalBytes(signed)
	if err != nil {
		return err
	}
	digest, err := helperprotocol.Digest(signed)
	if err != nil {
		return err
	}
	atNanos, err := recoveryUnixNano(at)
	if err != nil {
		return err
	}
	expiresNanos, err := recoveryUnixNano(expiresAt)
	if err != nil {
		return err
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	execution, err := getManagedApply(tx.QueryRow(managedApplySelect+` WHERE agent_id = ? AND operation_id = ?`, agentID, plan.OperationID))
	if err != nil {
		return err
	}
	if !execution.Current {
		return ErrManagedApplySuperseded
	}
	if execution.SignedPlan != nil {
		if execution.PlanDigest == digest {
			return nil
		}
		return ErrManagedApplyMismatch
	}
	var enrolledKey string
	if err := tx.QueryRow(`SELECT attestation_key_id FROM recovery_helper_instances WHERE agent_id = ?`, agentID).Scan(&enrolledKey); err != nil {
		return err
	}
	intent := execution.SignedIntent.Envelope.Payload
	logical, artifacts, deletions, certificates, digestErr := helperprotocol.ManagedApplyDigests(intent)
	if digestErr != nil || signed.KeyID != enrolledKey || plan.HelperInstanceID != intent.HelperInstanceID ||
		plan.OperationID != intent.OperationID || plan.DesiredStateRevision != intent.DesiredStateRevision ||
		plan.LogicalManifestDigest != logical || plan.ArtifactManifestDigest != artifacts ||
		plan.DeletionSetDigest != deletions || plan.CertificateIdentityDigest != certificates ||
		expiresAt.After(execution.IntentExpiresAt) {
		return ErrManagedApplyMismatch
	}
	if _, err := tx.Exec(`UPDATE managed_apply_executions SET helper_plan_id = ?, signed_plan = ?, plan_digest = ?,
		plan_received_at = ?, plan_expires_at = ? WHERE agent_id = ? AND operation_id = ? AND is_current = 1 AND signed_plan = ''`,
		plan.HelperPlanID, string(encoded), digest, atNanos, expiresNanos, agentID, plan.OperationID); err != nil {
		return fmt.Errorf("store managed apply plan: %w", err)
	}
	return tx.Commit()
}

func (d *DB) StoreManagedApplyGrant(agentID, operationID string, signed helperprotocol.Signed[helperprotocol.ApplyGrant]) error {
	if !validRecoverySemanticID(agentID) || !validRecoverySemanticID(operationID) || signed.Validate() != nil || signed.Envelope.MessageType != helperprotocol.MessageApplyGrant {
		return fmt.Errorf("invalid managed apply grant")
	}
	encoded, err := helperprotocol.CanonicalBytes(signed)
	if err != nil {
		return err
	}
	digest, err := helperprotocol.Digest(signed)
	if err != nil {
		return err
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	execution, err := getManagedApply(tx.QueryRow(managedApplySelect+` WHERE agent_id = ? AND operation_id = ?`, agentID, operationID))
	if err != nil {
		return err
	}
	if !execution.Current {
		return ErrManagedApplySuperseded
	}
	if execution.SignedGrant != nil {
		if execution.GrantDigest == digest {
			return nil
		}
		return ErrManagedApplyMismatch
	}
	if execution.SignedPlan == nil || !helperprotocol.ApplyGrantMatchesPlan(signed.Envelope.Payload, execution.SignedPlan.Envelope.Payload, execution.SignedIntent.Envelope.Payload) {
		return ErrManagedApplyMismatch
	}
	if _, err := tx.Exec(`UPDATE managed_apply_executions SET signed_grant = ?, grant_digest = ?
		WHERE agent_id = ? AND operation_id = ? AND is_current = 1 AND signed_grant = ''`,
		string(encoded), digest, agentID, operationID); err != nil {
		return fmt.Errorf("store managed apply grant: %w", err)
	}
	return tx.Commit()
}

func (d *DB) StoreManagedApplyReceipt(agentID, operationID string, signed helperprotocol.Signed[helperprotocol.HelperReceipt], at time.Time) error {
	if !validRecoverySemanticID(agentID) || !validRecoverySemanticID(operationID) || signed.Validate() != nil ||
		signed.Envelope.MessageType != helperprotocol.MessageHelperReceipt || at.IsZero() {
		return fmt.Errorf("invalid managed apply receipt")
	}
	encoded, err := helperprotocol.CanonicalBytes(signed)
	if err != nil {
		return err
	}
	digest, err := helperprotocol.Digest(signed)
	if err != nil {
		return err
	}
	atNanos, err := recoveryUnixNano(at)
	if err != nil {
		return err
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	execution, err := getManagedApply(tx.QueryRow(managedApplySelect+` WHERE agent_id = ? AND operation_id = ?`, agentID, operationID))
	if err != nil {
		return err
	}
	if execution.SignedReceipt != nil {
		if execution.ReceiptDigest == digest {
			return nil
		}
		return ErrManagedApplyMismatch
	}
	if execution.SignedGrant == nil || execution.SignedPlan == nil {
		return ErrManagedApplyMismatch
	}
	var enrolledKey string
	if err := tx.QueryRow(`SELECT attestation_key_id FROM recovery_helper_instances WHERE agent_id = ?`, agentID).Scan(&enrolledKey); err != nil {
		return err
	}
	grant := execution.SignedGrant.Envelope.Payload
	executeRequest := helperprotocol.NewEnvelope(helperprotocol.MessageExecuteManagedApplyRequest, helperprotocol.ExecuteManagedApplyRequest{
		OperationID: grant.OperationID, HelperPlanID: grant.HelperPlanID, Grant: *execution.SignedGrant,
	})
	requestDigest, err := helperprotocol.Digest(executeRequest)
	receipt := signed.Envelope.Payload
	if err != nil || signed.KeyID != enrolledKey || receipt.OperationID != operationID ||
		receipt.CanonicalRequestDigest != requestDigest || receipt.HelperInstanceID != execution.HelperInstanceID ||
		receipt.Action != helperprotocol.ActionApplyManagedProxyState || !terminalHelperReceiptState(receipt.State) {
		return ErrManagedApplyMismatch
	}
	if _, err := tx.Exec(`UPDATE managed_apply_executions SET signed_receipt = ?, receipt_digest = ?, receipt_received_at = ?
		WHERE agent_id = ? AND operation_id = ? AND signed_receipt = ''`, string(encoded), digest, atNanos, agentID, operationID); err != nil {
		return fmt.Errorf("store managed apply receipt: %w", err)
	}
	return tx.Commit()
}

const managedApplySelect = `SELECT agent_id, operation_id, helper_instance_id, desired_state_revision,
	signed_intent, intent_digest, intent_received_at, intent_expires_at, is_current,
	helper_plan_id, signed_plan, plan_digest, plan_received_at, plan_expires_at,
	signed_grant, grant_digest, signed_receipt, receipt_digest, receipt_received_at
	FROM managed_apply_executions`

func getManagedApply(row interface{ Scan(...any) error }) (*ManagedApplyExecution, error) {
	var execution ManagedApplyExecution
	var intentText, planText, grantText, receiptText string
	var intentReceived, intentExpires int64
	var current int
	var planReceived, planExpires, receiptReceived sql.NullInt64
	if err := row.Scan(&execution.AgentID, &execution.OperationID, &execution.HelperInstanceID, &execution.DesiredStateRevision,
		&intentText, &execution.IntentDigest, &intentReceived, &intentExpires, &current,
		&execution.HelperPlanID, &planText, &execution.PlanDigest, &planReceived, &planExpires,
		&grantText, &execution.GrantDigest, &receiptText, &execution.ReceiptDigest, &receiptReceived); err != nil {
		return nil, err
	}
	var err error
	execution.IntentReceivedAt, err = recoveryTimeFromUnixNano(intentReceived)
	if err != nil {
		return nil, err
	}
	execution.IntentExpiresAt, err = recoveryTimeFromUnixNano(intentExpires)
	if err != nil {
		return nil, err
	}
	execution.Current = current == 1
	execution.SignedIntent, err = helperprotocol.Decode[helperprotocol.Signed[helperprotocol.ApplyIntent]]([]byte(intentText))
	if err != nil {
		return nil, fmt.Errorf("decode stored managed apply intent: %w", err)
	}
	if digest, digestErr := helperprotocol.Digest(execution.SignedIntent); digestErr != nil || digest != execution.IntentDigest {
		return nil, fmt.Errorf("stored managed apply intent digest mismatch")
	}
	if planText != "" {
		plan, decodeErr := helperprotocol.Decode[helperprotocol.Signed[helperprotocol.ManagedApplyPlan]]([]byte(planText))
		if decodeErr != nil {
			return nil, decodeErr
		}
		execution.SignedPlan = &plan
		execution.PlanReceivedAt, err = nullableManagedTime(planReceived)
		if err != nil {
			return nil, err
		}
		execution.PlanExpiresAt, err = nullableManagedTime(planExpires)
		if err != nil {
			return nil, err
		}
		if digest, digestErr := helperprotocol.Digest(plan); digestErr != nil || digest != execution.PlanDigest {
			return nil, fmt.Errorf("stored managed apply plan digest mismatch")
		}
	} else if execution.HelperPlanID != "" || execution.PlanDigest != "" || planReceived.Valid || planExpires.Valid {
		return nil, fmt.Errorf("incomplete stored managed apply plan")
	}
	if grantText != "" {
		grant, decodeErr := helperprotocol.Decode[helperprotocol.Signed[helperprotocol.ApplyGrant]]([]byte(grantText))
		if decodeErr != nil {
			return nil, decodeErr
		}
		execution.SignedGrant = &grant
		if digest, digestErr := helperprotocol.Digest(grant); digestErr != nil || digest != execution.GrantDigest {
			return nil, fmt.Errorf("stored managed apply grant digest mismatch")
		}
	} else if execution.GrantDigest != "" {
		return nil, fmt.Errorf("incomplete stored managed apply grant")
	}
	if receiptText != "" {
		receipt, decodeErr := helperprotocol.Decode[helperprotocol.Signed[helperprotocol.HelperReceipt]]([]byte(receiptText))
		if decodeErr != nil {
			return nil, decodeErr
		}
		execution.SignedReceipt = &receipt
		execution.ReceiptReceivedAt, err = nullableManagedTime(receiptReceived)
		if err != nil {
			return nil, err
		}
		if digest, digestErr := helperprotocol.Digest(receipt); digestErr != nil || digest != execution.ReceiptDigest {
			return nil, fmt.Errorf("stored managed apply receipt digest mismatch")
		}
	} else if execution.ReceiptDigest != "" || receiptReceived.Valid {
		return nil, fmt.Errorf("incomplete stored managed apply receipt")
	}
	return &execution, nil
}

func nullableManagedTime(value sql.NullInt64) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	parsed, err := recoveryTimeFromUnixNano(value.Int64)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

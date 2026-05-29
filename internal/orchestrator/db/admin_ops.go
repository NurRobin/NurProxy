package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/google/uuid"
)

// ErrAdminOpNotFound is returned by ClaimAdminOp when no pending, non-expired op
// for the agent matches the presented confirmation code (wrong, expired, or
// already-used code). It is a sentinel so callers can distinguish "no match"
// from a real database error.
var ErrAdminOpNotFound = errors.New("admin op not found")

const adminOpColumns = `id, agent_id, op_type, payload, code_hash, status,
	result, created_by, created_at, expires_at, applied_at`

func scanAdminOp(sc interface {
	Scan(dest ...any) error
}) (*models.AgentAdminOp, error) {
	var op models.AgentAdminOp
	var createdAt, expiresAt string
	var appliedAt sql.NullString

	err := sc.Scan(
		&op.ID, &op.AgentID, &op.OpType, &op.Payload, &op.CodeHash, &op.Status,
		&op.Result, &op.CreatedBy, &createdAt, &expiresAt, &appliedAt,
	)
	if err != nil {
		return nil, err
	}

	op.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	op.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	if appliedAt.Valid && appliedAt.String != "" {
		t, _ := time.Parse(time.RFC3339, appliedAt.String)
		op.AppliedAt = &t
	}
	return &op, nil
}

// CreateAdminOp mints a new pending admin op for an agent (§19). It generates a
// UUID id, stamps created_at=now and expires_at=now+ttl, and persists status
// pending. payloadJSON is the op-type-specific arguments (see
// models.MarshalSetProxyModePayload); codeHash is the sha256 hex of the
// confirmation code (the plaintext is never passed in or stored).
func (d *DB) CreateAdminOp(ctx context.Context, agentID, opType, payloadJSON, codeHash, createdBy string, ttl time.Duration) (*models.AgentAdminOp, error) {
	if agentID == "" {
		return nil, fmt.Errorf("agent id is required")
	}
	if opType == "" {
		return nil, fmt.Errorf("op type is required")
	}
	if codeHash == "" {
		return nil, fmt.Errorf("code hash is required")
	}
	if payloadJSON == "" {
		payloadJSON = "{}"
	}

	now := time.Now().UTC()
	op := &models.AgentAdminOp{
		ID:        uuid.New().String(),
		AgentID:   agentID,
		OpType:    opType,
		Payload:   payloadJSON,
		CodeHash:  codeHash,
		Status:    models.AdminOpPending,
		CreatedBy: createdBy,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}

	if _, err := d.sql.ExecContext(ctx, `
		INSERT INTO agent_admin_ops (id, agent_id, op_type, payload, code_hash,
			status, result, created_by, created_at, expires_at, applied_at)
		VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?, NULL)`,
		op.ID, op.AgentID, op.OpType, op.Payload, op.CodeHash, op.Status,
		op.CreatedBy, op.CreatedAt.Format(time.RFC3339), op.ExpiresAt.Format(time.RFC3339),
	); err != nil {
		return nil, fmt.Errorf("inserting admin op: %w", err)
	}
	return op, nil
}

// GetAdminOp retrieves a single admin op by ID.
func (d *DB) GetAdminOp(ctx context.Context, id string) (*models.AgentAdminOp, error) {
	row := d.sql.QueryRowContext(ctx,
		"SELECT "+adminOpColumns+" FROM agent_admin_ops WHERE id = ?", id,
	)
	op, err := scanAdminOp(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("admin op not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("querying admin op: %w", err)
	}
	return op, nil
}

// ListPendingAdminOps returns the agent's pending, non-expired ops, newest
// first. It lazily marks any pending ops whose TTL has elapsed as expired (so
// the list reflects truth and the expiry transition is recorded), then returns
// only those still genuinely pending.
func (d *DB) ListPendingAdminOps(ctx context.Context, agentID string) ([]models.AgentAdminOp, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	// Lazily expire stale pending ops for this agent.
	if _, err := d.sql.ExecContext(ctx, `
		UPDATE agent_admin_ops
		SET status = ?
		WHERE agent_id = ? AND status = ? AND expires_at <= ?`,
		models.AdminOpExpired, agentID, models.AdminOpPending, now,
	); err != nil {
		return nil, fmt.Errorf("expiring stale admin ops: %w", err)
	}

	rows, err := d.sql.QueryContext(ctx,
		"SELECT "+adminOpColumns+` FROM agent_admin_ops
		WHERE agent_id = ? AND status = ?
		ORDER BY created_at DESC, id`,
		agentID, models.AdminOpPending,
	)
	if err != nil {
		return nil, fmt.Errorf("listing pending admin ops: %w", err)
	}
	defer rows.Close()

	var ops []models.AgentAdminOp
	for rows.Next() {
		op, err := scanAdminOp(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning admin op: %w", err)
		}
		ops = append(ops, *op)
	}
	return ops, rows.Err()
}

// ClaimAdminOp atomically claims a pending, non-expired op for the agent whose
// code_hash matches the presented one, transitioning it pending -> applied and
// stamping applied_at=now (§19). It is single-use: the UPDATE only fires while
// the op is still pending, so a second claim of the same code finds no pending
// row and returns ErrAdminOpNotFound. Wrong, expired, or already-claimed codes
// likewise return ErrAdminOpNotFound.
func (d *DB) ClaimAdminOp(ctx context.Context, agentID, codeHash string) (*models.AgentAdminOp, error) {
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("beginning claim admin op: %w", err)
	}
	defer tx.Rollback()

	// Single-use, atomic transition: only a still-pending, non-expired, matching
	// op flips to applied. RowsAffected tells us whether we won the claim.
	res, err := tx.ExecContext(ctx, `
		UPDATE agent_admin_ops
		SET status = ?, applied_at = ?
		WHERE agent_id = ? AND code_hash = ? AND status = ? AND expires_at > ?`,
		models.AdminOpApplied, nowStr, agentID, codeHash, models.AdminOpPending, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("claiming admin op: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("reading claim result: %w", err)
	}
	if n == 0 {
		return nil, ErrAdminOpNotFound
	}

	row := tx.QueryRowContext(ctx,
		"SELECT "+adminOpColumns+` FROM agent_admin_ops
		WHERE agent_id = ? AND code_hash = ? AND status = ?`,
		agentID, codeHash, models.AdminOpApplied,
	)
	op, err := scanAdminOp(row)
	if err != nil {
		return nil, fmt.Errorf("reading claimed admin op: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing claim admin op: %w", err)
	}
	return op, nil
}

// CancelAdminOp transitions an op to canceled (e.g. an operator revokes a
// pending op before it is claimed). It is idempotent at the row level: a missing
// op returns an error so the caller can surface it.
func (d *DB) CancelAdminOp(ctx context.Context, id string) error {
	res, err := d.sql.ExecContext(ctx,
		"UPDATE agent_admin_ops SET status = ? WHERE id = ?",
		models.AdminOpCanceled, id,
	)
	if err != nil {
		return fmt.Errorf("canceling admin op: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("admin op not found: %s", id)
	}
	return nil
}

// AckAdminOp records the result text of an op (e.g. the agent's apply report or
// error after carrying out a claimed op).
func (d *DB) AckAdminOp(ctx context.Context, id, result string) error {
	res, err := d.sql.ExecContext(ctx,
		"UPDATE agent_admin_ops SET result = ? WHERE id = ?",
		result, id,
	)
	if err != nil {
		return fmt.Errorf("acking admin op: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("admin op not found: %s", id)
	}
	return nil
}

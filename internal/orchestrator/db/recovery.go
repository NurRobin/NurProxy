package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

const recoveryTimeFormat = time.RFC3339Nano

func (d *DB) UpsertDiagnostic(agentID string, diagnostic recoverymodel.Diagnostic) error {
	if strings.TrimSpace(agentID) == "" {
		return fmt.Errorf("diagnostic agent ID is required")
	}
	if err := diagnostic.Validate(); err != nil {
		return fmt.Errorf("validating diagnostic: %w", err)
	}
	paths, err := encodeStringSlice(diagnostic.AffectedPaths)
	if err != nil {
		return fmt.Errorf("encoding diagnostic paths: %w", err)
	}
	_, err = d.sql.Exec(`
		INSERT INTO recovery_diagnostics (
			id, agent_id, code, subsystem, severity, ownership, summary, evidence,
			affected_paths, resource_fingerprint, proposed_action,
			auto_repair_eligible, hard_change, first_seen_at, last_seen_at, occurrences
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(agent_id, code, resource_fingerprint) DO UPDATE SET
			subsystem = excluded.subsystem,
			severity = excluded.severity,
			ownership = excluded.ownership,
			summary = excluded.summary,
			evidence = excluded.evidence,
			affected_paths = excluded.affected_paths,
			proposed_action = excluded.proposed_action,
			auto_repair_eligible = excluded.auto_repair_eligible,
			hard_change = excluded.hard_change,
			last_seen_at = excluded.last_seen_at,
			occurrences = recovery_diagnostics.occurrences + 1,
			resolved_at = NULL`,
		diagnostic.ID, agentID, string(diagnostic.Code), diagnostic.Subsystem,
		string(diagnostic.Severity), string(diagnostic.Ownership), diagnostic.Summary,
		diagnostic.Evidence, paths, diagnostic.ResourceFingerprint,
		string(diagnostic.ProposedAction), boolToInt(diagnostic.AutoRepairEligible),
		boolToInt(diagnostic.HardChange), formatRecoveryTime(diagnostic.FirstSeenAt),
		formatRecoveryTime(diagnostic.LastSeenAt), diagnostic.Occurrences,
	)
	if err != nil {
		return fmt.Errorf("upserting recovery diagnostic: %w", err)
	}
	return nil
}

func (d *DB) ResolveMissingDiagnostics(agentID string, activeIDs []string, at time.Time) error {
	if strings.TrimSpace(agentID) == "" || at.IsZero() {
		return fmt.Errorf("agent ID and resolution time are required")
	}
	query := `UPDATE recovery_diagnostics SET resolved_at = ? WHERE agent_id = ? AND resolved_at IS NULL`
	args := []any{formatRecoveryTime(at), agentID}
	if len(activeIDs) > 0 {
		query += ` AND id NOT IN (` + strings.TrimRight(strings.Repeat("?,", len(activeIDs)), ",") + `)`
		for _, id := range activeIDs {
			args = append(args, id)
		}
	}
	if _, err := d.sql.Exec(query, args...); err != nil {
		return fmt.Errorf("resolving missing recovery diagnostics: %w", err)
	}
	return nil
}

func (d *DB) ListDiagnostics(agentID string, includeResolved bool) ([]recoverymodel.Diagnostic, error) {
	query := diagnosticSelect + ` WHERE agent_id = ?`
	if !includeResolved {
		query += ` AND resolved_at IS NULL`
	}
	query += ` ORDER BY last_seen_at DESC, id`
	rows, err := d.read.Query(query, agentID)
	if err != nil {
		return nil, fmt.Errorf("listing recovery diagnostics: %w", err)
	}
	defer rows.Close()
	var diagnostics []recoverymodel.Diagnostic
	for rows.Next() {
		diagnostic, err := scanDiagnostic(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning recovery diagnostic: %w", err)
		}
		diagnostics = append(diagnostics, diagnostic)
	}
	return diagnostics, rows.Err()
}

func (d *DB) GetDiagnostic(agentID, diagnosticID string) (*recoverymodel.Diagnostic, error) {
	row := d.read.QueryRow(diagnosticSelect+` WHERE agent_id = ? AND id = ?`, agentID, diagnosticID)
	diagnostic, err := scanDiagnostic(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("recovery diagnostic not found: %s", diagnosticID)
	}
	if err != nil {
		return nil, fmt.Errorf("querying recovery diagnostic: %w", err)
	}
	return &diagnostic, nil
}

const diagnosticSelect = `SELECT id, code, subsystem, severity, ownership, summary, evidence,
	affected_paths, resource_fingerprint, proposed_action, auto_repair_eligible,
	hard_change, first_seen_at, last_seen_at, occurrences, resolved_at
	FROM recovery_diagnostics`

func scanDiagnostic(scanner interface{ Scan(...any) error }) (recoverymodel.Diagnostic, error) {
	var diagnostic recoverymodel.Diagnostic
	var code, severity, ownership, action, pathsJSON, firstSeen, lastSeen string
	var eligible, hardChange int
	var resolvedAt sql.NullString
	if err := scanner.Scan(
		&diagnostic.ID, &code, &diagnostic.Subsystem, &severity, &ownership,
		&diagnostic.Summary, &diagnostic.Evidence, &pathsJSON,
		&diagnostic.ResourceFingerprint, &action, &eligible, &hardChange,
		&firstSeen, &lastSeen, &diagnostic.Occurrences, &resolvedAt,
	); err != nil {
		return diagnostic, err
	}
	if eligible != 0 && eligible != 1 || hardChange != 0 && hardChange != 1 {
		return diagnostic, fmt.Errorf("invalid stored diagnostic boolean")
	}
	diagnostic.Code = recoverymodel.Code(code)
	diagnostic.Severity = recoverymodel.Severity(severity)
	diagnostic.Ownership = recoverymodel.Ownership(ownership)
	diagnostic.ProposedAction = recoverymodel.Action(action)
	diagnostic.AutoRepairEligible = eligible == 1
	diagnostic.HardChange = hardChange == 1
	if err := recoverymodel.DecodeStrict([]byte(pathsJSON), &diagnostic.AffectedPaths); err != nil {
		return diagnostic, fmt.Errorf("decoding diagnostic paths: %w", err)
	}
	var err error
	if diagnostic.FirstSeenAt, err = parseRecoveryTime(firstSeen); err != nil {
		return diagnostic, fmt.Errorf("decoding diagnostic first-seen time: %w", err)
	}
	if diagnostic.LastSeenAt, err = parseRecoveryTime(lastSeen); err != nil {
		return diagnostic, fmt.Errorf("decoding diagnostic last-seen time: %w", err)
	}
	if resolvedAt.Valid {
		if _, err := parseRecoveryTime(resolvedAt.String); err != nil {
			return diagnostic, fmt.Errorf("decoding diagnostic resolution time: %w", err)
		}
	}
	if err := diagnostic.Validate(); err != nil {
		return diagnostic, fmt.Errorf("validating stored diagnostic: %w", err)
	}
	return diagnostic, nil
}

func (d *DB) CreateRepairOperation(agentID string, report recoverymodel.OperationReport, fingerprint string) error {
	if strings.TrimSpace(agentID) == "" || strings.TrimSpace(fingerprint) == "" {
		return fmt.Errorf("operation agent ID and fingerprint are required")
	}
	if err := report.Validate(); err != nil {
		return fmt.Errorf("validating repair operation: %w", err)
	}
	steps, err := encodeSteps(report.Steps)
	if err != nil {
		return err
	}
	now := formatRecoveryTime(time.Now().UTC())
	_, err = d.sql.Exec(`
		INSERT INTO recovery_operations (
			id, agent_id, diagnostic_id, action, resource_fingerprint, risk,
			request_source, state, step_summaries, snapshot_reference,
			validation_outcome, rollback_outcome, error, started_at, updated_at, finished_at
		) VALUES (?, ?, ?, ?, ?, 'safe', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		report.OperationID, agentID, report.DiagnosticID, string(report.Action), fingerprint,
		string(report.Source), string(report.State), steps, report.SnapshotReference,
		report.ValidationOutcome, report.RollbackOutcome, report.Error,
		formatRecoveryTime(report.StartedAt), now, nullableRecoveryTime(report.FinishedAt),
	)
	if err != nil {
		return fmt.Errorf("creating repair operation: %w", err)
	}
	return nil
}

func (d *DB) AdvanceRepairOperation(agentID string, report recoverymodel.OperationReport) error {
	if err := report.Validate(); err != nil {
		return fmt.Errorf("validating repair operation: %w", err)
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return fmt.Errorf("beginning repair operation transition: %w", err)
	}
	defer tx.Rollback()
	stored, _, err := scanRepairOperation(tx.QueryRow(operationSelect+` WHERE agent_id = ? AND id = ?`, agentID, report.OperationID))
	if err == sql.ErrNoRows {
		return fmt.Errorf("repair operation not found: %s", report.OperationID)
	}
	if err != nil {
		return fmt.Errorf("querying repair operation: %w", err)
	}
	if stored.State == report.State {
		if !operationReportsEqual(stored, report) {
			return fmt.Errorf("conflicting duplicate repair operation state %q", report.State)
		}
		return nil
	}
	if stored.DiagnosticID != report.DiagnosticID || stored.Action != report.Action ||
		stored.Source != report.Source || !stored.StartedAt.Equal(report.StartedAt) {
		return fmt.Errorf("repair operation identity changed during transition")
	}
	if !legalOperationTransition(stored.State, report.State) {
		return fmt.Errorf("illegal repair operation transition %q -> %q", stored.State, report.State)
	}
	steps, err := encodeSteps(report.Steps)
	if err != nil {
		return err
	}
	res, err := tx.Exec(`UPDATE recovery_operations SET state = ?, step_summaries = ?,
		snapshot_reference = ?, validation_outcome = ?, rollback_outcome = ?, error = ?,
		updated_at = ?, finished_at = ? WHERE agent_id = ? AND id = ? AND state = ?`,
		string(report.State), steps, report.SnapshotReference, report.ValidationOutcome,
		report.RollbackOutcome, report.Error, formatRecoveryTime(time.Now().UTC()),
		nullableRecoveryTime(report.FinishedAt), agentID, report.OperationID, string(stored.State),
	)
	if err != nil {
		return fmt.Errorf("advancing repair operation: %w", err)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return fmt.Errorf("repair operation changed concurrently")
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing repair operation transition: %w", err)
	}
	return nil
}

func operationReportsEqual(left, right recoverymodel.OperationReport) bool {
	if left.OperationID != right.OperationID || left.DiagnosticID != right.DiagnosticID ||
		left.Action != right.Action || left.Source != right.Source || left.State != right.State ||
		left.SnapshotReference != right.SnapshotReference || left.ValidationOutcome != right.ValidationOutcome ||
		left.RollbackOutcome != right.RollbackOutcome || left.Error != right.Error ||
		!left.StartedAt.Equal(right.StartedAt) || len(left.Steps) != len(right.Steps) {
		return false
	}
	if (left.FinishedAt == nil) != (right.FinishedAt == nil) ||
		left.FinishedAt != nil && !left.FinishedAt.Equal(*right.FinishedAt) {
		return false
	}
	for i := range left.Steps {
		if left.Steps[i].Name != right.Steps[i].Name || left.Steps[i].Summary != right.Steps[i].Summary ||
			left.Steps[i].State != right.Steps[i].State || !left.Steps[i].At.Equal(right.Steps[i].At) {
			return false
		}
	}
	return true
}

func (d *DB) ListRepairOperations(agentID string, limit int) ([]recoverymodel.OperationReport, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := d.read.Query(operationSelect+` WHERE agent_id = ? ORDER BY started_at DESC, id DESC LIMIT ?`, agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("listing repair operations: %w", err)
	}
	defer rows.Close()
	var reports []recoverymodel.OperationReport
	for rows.Next() {
		report, _, err := scanRepairOperation(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning repair operation: %w", err)
		}
		reports = append(reports, report)
	}
	return reports, rows.Err()
}

func (d *DB) CountRecentRepairFailures(agentID string, action recoverymodel.Action, fingerprint string, since time.Time) (int, error) {
	if !action.Valid() || since.IsZero() || strings.TrimSpace(fingerprint) == "" {
		return 0, fmt.Errorf("valid action, fingerprint, and since time are required")
	}
	var count int
	err := d.read.QueryRow(`SELECT COUNT(*) FROM recovery_operations
		WHERE agent_id = ? AND action = ? AND resource_fingerprint = ?
		AND state IN (?, ?) AND julianday(started_at) >= julianday(?)`,
		agentID, string(action), fingerprint, string(recoverymodel.OperationStateRolledBack),
		string(recoverymodel.OperationStateRollbackFailed), formatRecoveryTime(since),
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting recent repair failures: %w", err)
	}
	return count, nil
}

const operationSelect = `SELECT id, diagnostic_id, action, request_source, state,
	step_summaries, snapshot_reference, validation_outcome, rollback_outcome, error,
	started_at, finished_at, resource_fingerprint FROM recovery_operations`

func scanRepairOperation(scanner interface{ Scan(...any) error }) (recoverymodel.OperationReport, string, error) {
	var report recoverymodel.OperationReport
	var action, source, state, stepsJSON, startedAt, fingerprint string
	var finishedAt sql.NullString
	if err := scanner.Scan(
		&report.OperationID, &report.DiagnosticID, &action, &source, &state,
		&stepsJSON, &report.SnapshotReference, &report.ValidationOutcome,
		&report.RollbackOutcome, &report.Error, &startedAt, &finishedAt, &fingerprint,
	); err != nil {
		return report, "", err
	}
	report.Action = recoverymodel.Action(action)
	report.Source = recoverymodel.RequestSource(source)
	report.State = recoverymodel.OperationState(state)
	if err := recoverymodel.DecodeStrict([]byte(stepsJSON), &report.Steps); err != nil {
		return report, "", fmt.Errorf("decoding repair steps: %w", err)
	}
	var err error
	if report.StartedAt, err = parseRecoveryTime(startedAt); err != nil {
		return report, "", fmt.Errorf("decoding repair start time: %w", err)
	}
	if finishedAt.Valid {
		finished, err := parseRecoveryTime(finishedAt.String)
		if err != nil {
			return report, "", fmt.Errorf("decoding repair finish time: %w", err)
		}
		report.FinishedAt = &finished
	}
	if err := report.Validate(); err != nil {
		return report, "", fmt.Errorf("validating stored repair operation: %w", err)
	}
	return report, fingerprint, nil
}

func legalOperationTransition(from, to recoverymodel.OperationState) bool {
	allowed := map[recoverymodel.OperationState][]recoverymodel.OperationState{
		recoverymodel.OperationStateDetected:    {recoverymodel.OperationStateDiagnosisOnly, recoverymodel.OperationStatePlanned, recoverymodel.OperationStateSuppressed},
		recoverymodel.OperationStatePlanned:     {recoverymodel.OperationStateSnapshotted, recoverymodel.OperationStateSuppressed},
		recoverymodel.OperationStateSnapshotted: {recoverymodel.OperationStateApplying, recoverymodel.OperationStateRollingBack},
		recoverymodel.OperationStateApplying:    {recoverymodel.OperationStateValidating, recoverymodel.OperationStateRollingBack},
		recoverymodel.OperationStateValidating:  {recoverymodel.OperationStateSucceeded, recoverymodel.OperationStateRollingBack},
		recoverymodel.OperationStateRollingBack: {recoverymodel.OperationStateRolledBack, recoverymodel.OperationStateRollbackFailed},
	}
	for _, candidate := range allowed[from] {
		if candidate == to {
			return true
		}
	}
	return false
}

func encodeStringSlice(values []string) (string, error) {
	if values == nil {
		values = []string{}
	}
	b, err := json.Marshal(values)
	return string(b), err
}

func encodeSteps(steps []recoverymodel.Step) (string, error) {
	if steps == nil {
		steps = []recoverymodel.Step{}
	}
	b, err := json.Marshal(steps)
	if err != nil {
		return "", fmt.Errorf("encoding repair steps: %w", err)
	}
	return string(b), nil
}

func formatRecoveryTime(value time.Time) string {
	return value.UTC().Format(recoveryTimeFormat)
}

func parseRecoveryTime(value string) (time.Time, error) {
	return time.Parse(recoveryTimeFormat, value)
}

func nullableRecoveryTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return formatRecoveryTime(*value)
}

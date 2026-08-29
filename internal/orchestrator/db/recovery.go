package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

const maxActiveDiagnosticIDs = 500

var ErrActiveRepairOperation = errors.New("active repair operation already exists for action and fingerprint")

type RecoveryDiagnosticAggregate struct {
	Code      recoverymodel.Code
	Severity  recoverymodel.Severity
	Ownership recoverymodel.Ownership
	Count     int
}

type RecoveryOperationAggregate struct {
	Action        recoverymodel.Action
	Outcome       recoverymodel.OperationState
	RequestSource recoverymodel.RequestSource
	Count         int
}

type RecoveryActionAggregate struct {
	Action recoverymodel.Action
	Count  int
}

type RecoveryMetricAggregates struct {
	DiagnosticsActive    []RecoveryDiagnosticAggregate
	OperationsTotal      []RecoveryOperationAggregate
	OperationsInProgress []RecoveryActionAggregate
	CircuitBreakersOpen  []RecoveryActionAggregate
}

func (d *DB) RecoveryAggregates(now time.Time) (RecoveryMetricAggregates, error) {
	if now.IsZero() {
		return RecoveryMetricAggregates{}, fmt.Errorf("recovery aggregate time is required")
	}
	tx, err := d.read.Begin()
	if err != nil {
		return RecoveryMetricAggregates{}, fmt.Errorf("beginning recovery aggregate read: %w", err)
	}
	defer tx.Rollback()

	var result RecoveryMetricAggregates
	rows, err := tx.Query(`SELECT code, severity, ownership, COUNT(*)
		FROM recovery_diagnostics WHERE resolved_at IS NULL
		GROUP BY code, severity, ownership ORDER BY code, severity, ownership`)
	if err != nil {
		return RecoveryMetricAggregates{}, fmt.Errorf("aggregating active recovery diagnostics: %w", err)
	}
	for rows.Next() {
		var code, severity, ownership string
		var count int
		if err := rows.Scan(&code, &severity, &ownership, &count); err != nil {
			rows.Close()
			return RecoveryMetricAggregates{}, fmt.Errorf("scanning active recovery diagnostic aggregate: %w", err)
		}
		aggregate := RecoveryDiagnosticAggregate{Code: recoverymodel.Code(code), Severity: recoverymodel.Severity(severity), Ownership: recoverymodel.Ownership(ownership), Count: count}
		if !aggregate.Code.Valid() || !aggregate.Severity.Valid() || !aggregate.Ownership.Valid() || aggregate.Count < 1 {
			rows.Close()
			return RecoveryMetricAggregates{}, fmt.Errorf("unknown diagnostic aggregate dimensions")
		}
		result.DiagnosticsActive = append(result.DiagnosticsActive, aggregate)
	}
	if err := rows.Close(); err != nil {
		return RecoveryMetricAggregates{}, fmt.Errorf("closing active recovery diagnostic aggregates: %w", err)
	}
	if err := rows.Err(); err != nil {
		return RecoveryMetricAggregates{}, fmt.Errorf("reading active recovery diagnostic aggregates: %w", err)
	}

	rows, err = tx.Query(`SELECT action, outcome, request_source, count
		FROM recovery_operation_totals ORDER BY action, outcome, request_source`)
	if err != nil {
		return RecoveryMetricAggregates{}, fmt.Errorf("reading recovery operation totals: %w", err)
	}
	for rows.Next() {
		var action, outcome, source string
		var count int
		if err := rows.Scan(&action, &outcome, &source, &count); err != nil {
			rows.Close()
			return RecoveryMetricAggregates{}, fmt.Errorf("scanning recovery operation total: %w", err)
		}
		a, terminalState, requestSource := recoverymodel.Action(action), recoverymodel.OperationState(outcome), recoverymodel.RequestSource(source)
		if !a.Valid() || !recoveryOperationTerminal(terminalState) || !requestSource.Valid() || count < 1 {
			rows.Close()
			return RecoveryMetricAggregates{}, fmt.Errorf("unknown recovery operation total dimensions")
		}
		result.OperationsTotal = append(result.OperationsTotal, RecoveryOperationAggregate{Action: a, Outcome: terminalState, RequestSource: requestSource, Count: count})
	}
	if err := rows.Close(); err != nil {
		return RecoveryMetricAggregates{}, fmt.Errorf("closing recovery operation totals: %w", err)
	}
	if err := rows.Err(); err != nil {
		return RecoveryMetricAggregates{}, fmt.Errorf("reading recovery operation totals: %w", err)
	}

	rows, err = tx.Query(`SELECT action, COUNT(*) FROM recovery_operations
		WHERE state NOT IN (?, ?, ?, ?, ?)
		GROUP BY action ORDER BY action`,
		string(recoverymodel.OperationStateDiagnosisOnly), string(recoverymodel.OperationStateSucceeded),
		string(recoverymodel.OperationStateRolledBack), string(recoverymodel.OperationStateRollbackFailed),
		string(recoverymodel.OperationStateSuppressed))
	if err != nil {
		return RecoveryMetricAggregates{}, fmt.Errorf("aggregating in-progress recovery operations: %w", err)
	}
	inProgress := make(map[recoverymodel.Action]int)
	for rows.Next() {
		var action string
		var count int
		if err := rows.Scan(&action, &count); err != nil {
			rows.Close()
			return RecoveryMetricAggregates{}, fmt.Errorf("scanning in-progress recovery operation aggregate: %w", err)
		}
		a := recoverymodel.Action(action)
		if !a.Valid() || count < 1 {
			rows.Close()
			return RecoveryMetricAggregates{}, fmt.Errorf("unknown in-progress recovery operation dimensions")
		}
		inProgress[a] = count
	}
	if err := rows.Close(); err != nil {
		return RecoveryMetricAggregates{}, fmt.Errorf("closing in-progress recovery operation aggregates: %w", err)
	}
	if err := rows.Err(); err != nil {
		return RecoveryMetricAggregates{}, fmt.Errorf("reading in-progress recovery operation aggregates: %w", err)
	}
	result.OperationsInProgress = sortedRecoveryActionAggregates(inProgress)

	type breakerKey struct {
		agentID, fingerprint string
		action               recoverymodel.Action
	}
	nowNanos, err := recoveryUnixNano(now)
	if err != nil {
		return RecoveryMetricAggregates{}, fmt.Errorf("encoding recovery aggregate breaker time: %w", err)
	}
	oldestBreakerCandidate := subtractRecoveryDuration(nowNanos, int64(75*time.Minute))
	rows, err = tx.Query(`SELECT DISTINCT candidate.agent_id, candidate.action, candidate.resource_fingerprint
		FROM recovery_operations AS candidate
		WHERE (
			candidate.state IN (?, ?) AND candidate.received_at > ?
		) OR (
			candidate.state = ? AND NOT EXISTS (
				SELECT 1 FROM recovery_operations AS cleared
				WHERE cleared.agent_id = candidate.agent_id
					AND cleared.action = candidate.action
					AND cleared.resource_fingerprint = candidate.resource_fingerprint
					AND cleared.state = ? AND cleared.request_source = ?
					AND cleared.received_at > candidate.received_at
			)
		)
		ORDER BY candidate.action, candidate.agent_id, candidate.resource_fingerprint`,
		string(recoverymodel.OperationStateRolledBack), string(recoverymodel.OperationStateRollbackFailed), oldestBreakerCandidate,
		string(recoverymodel.OperationStateRollbackFailed), string(recoverymodel.OperationStateSucceeded), string(recoverymodel.RequestSourceUser))
	if err != nil {
		return RecoveryMetricAggregates{}, fmt.Errorf("listing recovery circuit breaker keys: %w", err)
	}
	keys := make([]breakerKey, 0)
	for rows.Next() {
		var key breakerKey
		if err := rows.Scan(&key.agentID, &key.action, &key.fingerprint); err != nil {
			rows.Close()
			return RecoveryMetricAggregates{}, fmt.Errorf("scanning recovery circuit breaker key: %w", err)
		}
		if strings.TrimSpace(key.agentID) == "" || !key.action.Valid() || strings.TrimSpace(key.fingerprint) == "" {
			rows.Close()
			return RecoveryMetricAggregates{}, fmt.Errorf("unknown recovery circuit breaker dimensions")
		}
		keys = append(keys, key)
	}
	if err := rows.Close(); err != nil {
		return RecoveryMetricAggregates{}, fmt.Errorf("closing recovery circuit breaker keys: %w", err)
	}
	if err := rows.Err(); err != nil {
		return RecoveryMetricAggregates{}, fmt.Errorf("reading recovery circuit breaker keys: %w", err)
	}
	openByAction := make(map[recoverymodel.Action]int)
	for _, key := range keys {
		open, err := repairBreakerOpen(tx, key.agentID, key.action, key.fingerprint, now)
		if err != nil {
			return RecoveryMetricAggregates{}, err
		}
		if open {
			openByAction[key.action]++
		}
	}
	result.CircuitBreakersOpen = sortedRecoveryActionAggregates(openByAction)
	if err := tx.Commit(); err != nil {
		return RecoveryMetricAggregates{}, fmt.Errorf("committing recovery aggregate read: %w", err)
	}
	return result, nil
}

func recoveryOperationTerminal(state recoverymodel.OperationState) bool {
	switch state {
	case recoverymodel.OperationStateDiagnosisOnly, recoverymodel.OperationStateSucceeded,
		recoverymodel.OperationStateRolledBack, recoverymodel.OperationStateRollbackFailed,
		recoverymodel.OperationStateSuppressed:
		return true
	default:
		return false
	}
}

func sortedRecoveryActionAggregates(counts map[recoverymodel.Action]int) []RecoveryActionAggregate {
	actions := make([]string, 0, len(counts))
	for action := range counts {
		actions = append(actions, string(action))
	}
	sort.Strings(actions)
	result := make([]RecoveryActionAggregate, 0, len(actions))
	for _, action := range actions {
		result = append(result, RecoveryActionAggregate{Action: recoverymodel.Action(action), Count: counts[recoverymodel.Action(action)]})
	}
	return result
}

func (d *DB) UpsertDiagnostic(agentID string, diagnostic recoverymodel.Diagnostic) error {
	if strings.TrimSpace(agentID) == "" {
		return fmt.Errorf("diagnostic agent ID is required")
	}
	if err := diagnostic.Validate(); err != nil {
		return fmt.Errorf("validating diagnostic: %w", err)
	}
	expectedID := recoverymodel.StableDiagnosticID(agentID, diagnostic.Code, diagnostic.ResourceFingerprint)
	if diagnostic.ID != expectedID {
		return fmt.Errorf("diagnostic ID %q does not match stable identity %q", diagnostic.ID, expectedID)
	}
	paths, err := encodeStringSlice(diagnostic.AffectedPaths)
	if err != nil {
		return fmt.Errorf("encoding diagnostic paths: %w", err)
	}
	firstSeenAt, err := recoveryUnixNano(diagnostic.FirstSeenAt)
	if err != nil {
		return fmt.Errorf("encoding diagnostic first-seen time: %w", err)
	}
	lastSeenAt, err := recoveryUnixNano(diagnostic.LastSeenAt)
	if err != nil {
		return fmt.Errorf("encoding diagnostic last-seen time: %w", err)
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
			resolved_at = NULL
		WHERE excluded.last_seen_at >= recovery_diagnostics.last_seen_at
			AND (recovery_diagnostics.resolved_at IS NULL OR excluded.last_seen_at > recovery_diagnostics.resolved_at)`,
		diagnostic.ID, agentID, string(diagnostic.Code), diagnostic.Subsystem,
		string(diagnostic.Severity), string(diagnostic.Ownership), diagnostic.Summary,
		diagnostic.Evidence, paths, diagnostic.ResourceFingerprint,
		string(diagnostic.ProposedAction), boolToInt(diagnostic.AutoRepairEligible),
		boolToInt(diagnostic.HardChange), firstSeenAt, lastSeenAt, diagnostic.Occurrences,
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
	if len(activeIDs) > maxActiveDiagnosticIDs {
		return fmt.Errorf("active diagnostic set exceeds %d entries", maxActiveDiagnosticIDs)
	}
	seen := make(map[string]struct{}, len(activeIDs))
	for _, id := range activeIDs {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("active diagnostic ID is required")
		}
		if _, exists := seen[id]; exists {
			return fmt.Errorf("duplicate active diagnostic ID %q", id)
		}
		seen[id] = struct{}{}
	}
	query := `UPDATE recovery_diagnostics SET resolved_at = ? WHERE agent_id = ? AND resolved_at IS NULL AND last_seen_at <= ?`
	resolvedAt, err := recoveryUnixNano(at)
	if err != nil {
		return fmt.Errorf("encoding diagnostic resolution time: %w", err)
	}
	args := []any{resolvedAt, agentID, resolvedAt}
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
	return d.queryDiagnostics(query, agentID)
}

func (d *DB) ListDiagnosticsForRecoveryView(agentID string, resolvedLimit int) ([]recoverymodel.Diagnostic, error) {
	if strings.TrimSpace(agentID) == "" || resolvedLimit < 0 || resolvedLimit > 200 {
		return nil, fmt.Errorf("agent ID is required and resolved limit must be between 0 and 200")
	}
	active, err := d.ListDiagnostics(agentID, false)
	if err != nil || resolvedLimit == 0 {
		return active, err
	}
	resolved, err := d.queryDiagnostics(diagnosticSelect+`
		WHERE agent_id = ? AND resolved_at IS NOT NULL
		ORDER BY resolved_at DESC, last_seen_at DESC, id LIMIT ?`, agentID, resolvedLimit)
	if err != nil {
		return nil, err
	}
	return append(active, resolved...), nil
}

func (d *DB) queryDiagnostics(query string, args ...any) ([]recoverymodel.Diagnostic, error) {
	rows, err := d.read.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing recovery diagnostics: %w", err)
	}
	defer rows.Close()
	diagnostics := make([]recoverymodel.Diagnostic, 0)
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
	var code, severity, ownership, action, pathsJSON string
	var firstSeen, lastSeen int64
	var eligible, hardChange int
	var resolvedAt sql.NullInt64
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
	if diagnostic.FirstSeenAt, err = recoveryTimeFromUnixNano(firstSeen); err != nil {
		return diagnostic, fmt.Errorf("decoding diagnostic first-seen time: %w", err)
	}
	if diagnostic.LastSeenAt, err = recoveryTimeFromUnixNano(lastSeen); err != nil {
		return diagnostic, fmt.Errorf("decoding diagnostic last-seen time: %w", err)
	}
	if resolvedAt.Valid {
		if _, err := recoveryTimeFromUnixNano(resolvedAt.Int64); err != nil {
			return diagnostic, fmt.Errorf("decoding diagnostic resolution time: %w", err)
		}
	}
	if err := diagnostic.Validate(); err != nil {
		return diagnostic, fmt.Errorf("validating stored diagnostic: %w", err)
	}
	return diagnostic, nil
}

func (d *DB) CreateRepairOperation(agentID string, report recoverymodel.OperationReport, fingerprint string) error {
	return d.createRepairOperation(agentID, report, fingerprint, false)
}

func (d *DB) CreateRepairOperationIfNoActive(agentID string, report recoverymodel.OperationReport, fingerprint string) error {
	return d.createRepairOperation(agentID, report, fingerprint, true)
}

func (d *DB) createRepairOperation(agentID string, report recoverymodel.OperationReport, fingerprint string, rejectActive bool) error {
	if strings.TrimSpace(agentID) == "" || strings.TrimSpace(fingerprint) == "" {
		return fmt.Errorf("operation agent ID and fingerprint are required")
	}
	if err := report.Validate(); err != nil {
		return fmt.Errorf("validating repair operation: %w", err)
	}
	if err := validatePersistedOperation(report); err != nil {
		return err
	}
	if report.Source == recoverymodel.RequestSourceAutomatic && report.State != recoverymodel.OperationStateDetected {
		return fmt.Errorf("automatic repair operation must start detected")
	}
	if report.Source == recoverymodel.RequestSourceUser && report.State != recoverymodel.OperationStatePlanned {
		return fmt.Errorf("user repair operation must start planned")
	}
	if len(report.Steps) != 1 || report.Steps[0].State != report.State {
		return fmt.Errorf("initial repair operation requires exactly one step matching state %q", report.State)
	}
	startedAt, err := recoveryUnixNano(report.StartedAt)
	if err != nil {
		return fmt.Errorf("encoding repair operation start time: %w", err)
	}
	finishedAt, err := nullableRecoveryTime(report.FinishedAt)
	if err != nil {
		return fmt.Errorf("encoding repair operation finish time: %w", err)
	}
	steps, err := encodeSteps(report.Steps)
	if err != nil {
		return err
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return fmt.Errorf("beginning repair operation create: %w", err)
	}
	defer tx.Rollback()
	var existingAgentID string
	err = tx.QueryRow(`SELECT agent_id FROM recovery_operations WHERE id = ?`, report.OperationID).Scan(&existingAgentID)
	if err == nil {
		if existingAgentID != agentID {
			return fmt.Errorf("repair operation ID belongs to another agent")
		}
		existing, existingFingerprint, scanErr := scanRepairOperation(tx.QueryRow(operationSelect+` WHERE agent_id = ? AND id = ?`, agentID, report.OperationID))
		if scanErr != nil {
			return fmt.Errorf("querying duplicate repair operation: %w", scanErr)
		}
		if existingFingerprint != fingerprint ||
			(!operationReportsEqual(existing, report) && !historicalReplayCompatible(report, existing)) {
			return fmt.Errorf("conflicting duplicate repair operation create")
		}
		return nil
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("querying repair operation identity: %w", err)
	}
	var agentExists int
	if err := tx.QueryRow(`SELECT 1 FROM agents WHERE id = ?`, agentID).Scan(&agentExists); err == sql.ErrNoRows {
		return fmt.Errorf("agent not found: %s", agentID)
	} else if err != nil {
		return fmt.Errorf("querying repair operation agent: %w", err)
	}
	var diagnosticFingerprint, proposedAction string
	if err := tx.QueryRow(`SELECT resource_fingerprint, proposed_action FROM recovery_diagnostics WHERE agent_id = ? AND id = ?`, agentID, report.DiagnosticID).
		Scan(&diagnosticFingerprint, &proposedAction); err == sql.ErrNoRows {
		return fmt.Errorf("recovery diagnostic not found for agent: %s", report.DiagnosticID)
	} else if err != nil {
		return fmt.Errorf("querying repair operation diagnostic: %w", err)
	}
	if diagnosticFingerprint != fingerprint {
		return fmt.Errorf("repair operation fingerprint does not match diagnostic")
	}
	if proposedAction != string(report.Action) {
		return fmt.Errorf("repair operation action does not match diagnostic")
	}
	if rejectActive {
		var active int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM recovery_operations
			WHERE agent_id = ? AND action = ? AND resource_fingerprint = ?
			AND state NOT IN (?, ?, ?, ?, ?)`,
			agentID, string(report.Action), fingerprint,
			string(recoverymodel.OperationStateDiagnosisOnly), string(recoverymodel.OperationStateSucceeded),
			string(recoverymodel.OperationStateRolledBack), string(recoverymodel.OperationStateRollbackFailed),
			string(recoverymodel.OperationStateSuppressed),
		).Scan(&active); err != nil {
			return fmt.Errorf("checking active repair operations: %w", err)
		}
		if active != 0 {
			return ErrActiveRepairOperation
		}
	}
	createdAt, err := nextRecoveryCreatedAt(tx, agentID)
	if err != nil {
		return err
	}
	receivedAt, err := nextRecoveryReceivedAt(tx, agentID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`
		INSERT INTO recovery_operations (
			id, agent_id, diagnostic_id, action, resource_fingerprint, risk,
			request_source, state, step_summaries, snapshot_reference,
			validation_outcome, rollback_outcome, error, started_at, created_at, received_at, finished_at
		) VALUES (?, ?, ?, ?, ?, 'safe', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		report.OperationID, agentID, report.DiagnosticID, string(report.Action), fingerprint,
		string(report.Source), string(report.State), steps, report.SnapshotReference,
		report.ValidationOutcome, report.RollbackOutcome, report.Error,
		startedAt, createdAt, receivedAt, finishedAt,
	)
	if err != nil {
		return fmt.Errorf("creating repair operation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing repair operation create: %w", err)
	}
	return nil
}

func (d *DB) AdvanceRepairOperation(agentID string, report recoverymodel.OperationReport) error {
	if err := report.Validate(); err != nil {
		return fmt.Errorf("validating repair operation: %w", err)
	}
	if err := validatePersistedOperation(report); err != nil {
		return err
	}
	if _, err := recoveryUnixNano(report.StartedAt); err != nil {
		return fmt.Errorf("encoding repair operation start time: %w", err)
	}
	finishedAt, err := nullableRecoveryTime(report.FinishedAt)
	if err != nil {
		return fmt.Errorf("encoding repair operation finish time: %w", err)
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
	if operationStateReachable(report.State, stored.State) {
		if historicalReplayCompatible(report, stored) {
			return nil
		}
		return fmt.Errorf("conflicting historical repair operation replay")
	}
	if !legalOperationTransition(stored.State, report.State) {
		return fmt.Errorf("illegal repair operation transition %q -> %q", stored.State, report.State)
	}
	if err := validateAppendOnlySteps(stored.Steps, report.Steps); err != nil {
		return err
	}
	for _, field := range []struct {
		name     string
		previous string
		next     string
	}{
		{"snapshot reference", stored.SnapshotReference, report.SnapshotReference},
		{"validation outcome", stored.ValidationOutcome, report.ValidationOutcome},
		{"rollback outcome", stored.RollbackOutcome, report.RollbackOutcome},
	} {
		if field.previous != "" && field.next != field.previous {
			return fmt.Errorf("repair operation %s is immutable once set", field.name)
		}
	}
	steps, err := encodeSteps(report.Steps)
	if err != nil {
		return err
	}
	receivedAt, err := nextRecoveryReceivedAt(tx, agentID)
	if err != nil {
		return err
	}
	res, err := tx.Exec(`UPDATE recovery_operations SET state = ?, step_summaries = ?,
		snapshot_reference = ?, validation_outcome = ?, rollback_outcome = ?, error = ?,
		received_at = ?,
		finished_at = ? WHERE agent_id = ? AND id = ? AND state = ?`,
		string(report.State), steps, report.SnapshotReference, report.ValidationOutcome,
		report.RollbackOutcome, report.Error, receivedAt,
		finishedAt, agentID, report.OperationID, string(stored.State),
	)
	if err != nil {
		return fmt.Errorf("advancing repair operation: %w", err)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return fmt.Errorf("repair operation changed concurrently")
	}
	if recoveryOperationTerminal(report.State) {
		if _, err := tx.Exec(`INSERT INTO recovery_operation_totals (action, outcome, request_source, count)
			VALUES (?, ?, ?, 1)
			ON CONFLICT(action, outcome, request_source) DO UPDATE SET count = count + 1`,
			string(report.Action), string(report.State), string(report.Source)); err != nil {
			return fmt.Errorf("incrementing recovery operation total: %w", err)
		}
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

func historicalReplayCompatible(submitted, stored recoverymodel.OperationReport) bool {
	if submitted.State == stored.State || !operationStateReachable(submitted.State, stored.State) {
		return false
	}
	if submitted.OperationID != stored.OperationID || submitted.DiagnosticID != stored.DiagnosticID ||
		submitted.Action != stored.Action || submitted.Source != stored.Source ||
		!submitted.StartedAt.Equal(stored.StartedAt) || !stepsArePrefix(submitted.Steps, stored.Steps) {
		return false
	}
	for _, values := range [][2]string{
		{submitted.SnapshotReference, stored.SnapshotReference},
		{submitted.ValidationOutcome, stored.ValidationOutcome},
		{submitted.RollbackOutcome, stored.RollbackOutcome},
		{submitted.Error, stored.Error},
	} {
		if values[0] != "" && values[0] != values[1] {
			return false
		}
	}
	if submitted.FinishedAt != nil &&
		(stored.FinishedAt == nil || !submitted.FinishedAt.Equal(*stored.FinishedAt)) {
		return false
	}
	return true
}

func stepsArePrefix(prefix, complete []recoverymodel.Step) bool {
	if len(prefix) > len(complete) {
		return false
	}
	for i := range prefix {
		if prefix[i].Name != complete[i].Name || prefix[i].Summary != complete[i].Summary ||
			prefix[i].State != complete[i].State || !prefix[i].At.Equal(complete[i].At) {
			return false
		}
	}
	return true
}

func operationStateReachable(from, target recoverymodel.OperationState) bool {
	if from == target {
		return true
	}
	seen := map[recoverymodel.OperationState]bool{from: true}
	queue := []recoverymodel.OperationState{from}
	for len(queue) > 0 {
		state := queue[0]
		queue = queue[1:]
		for _, candidate := range operationSuccessors(state) {
			if candidate == target {
				return true
			}
			if !seen[candidate] {
				seen[candidate] = true
				queue = append(queue, candidate)
			}
		}
	}
	return false
}

func validatePersistedOperation(report recoverymodel.OperationReport) error {
	terminal := report.State == recoverymodel.OperationStateDiagnosisOnly ||
		report.State == recoverymodel.OperationStateSucceeded ||
		report.State == recoverymodel.OperationStateRolledBack ||
		report.State == recoverymodel.OperationStateRollbackFailed ||
		report.State == recoverymodel.OperationStateSuppressed
	if terminal && report.FinishedAt == nil {
		return fmt.Errorf("terminal repair operation state %q requires finished_at", report.State)
	}
	if !terminal && report.FinishedAt != nil {
		return fmt.Errorf("nonterminal repair operation state %q cannot set finished_at", report.State)
	}
	if operationRequiresSnapshot(report.State) {
		if strings.TrimSpace(report.SnapshotReference) == "" {
			return fmt.Errorf("repair operation state %q requires a snapshot reference", report.State)
		}
	} else if report.SnapshotReference != "" {
		return fmt.Errorf("repair operation state %q cannot set a snapshot reference", report.State)
	}
	if err := validateOperationHistory(report); err != nil {
		return err
	}
	return nil
}

func validateAppendOnlySteps(previous, next []recoverymodel.Step) error {
	if len(next) != len(previous)+1 {
		return fmt.Errorf("repair operation transition must append exactly one step")
	}
	for i := range previous {
		if previous[i].Name != next[i].Name || previous[i].Summary != next[i].Summary ||
			previous[i].State != next[i].State || !previous[i].At.Equal(next[i].At) {
			return fmt.Errorf("repair operation step history is not an immutable prefix")
		}
	}
	return nil
}

func validateOperationHistory(report recoverymodel.OperationReport) error {
	if len(report.Steps) == 0 {
		return fmt.Errorf("repair operation history requires an initial step")
	}
	initial := recoverymodel.OperationStateDetected
	if report.Source == recoverymodel.RequestSourceUser {
		initial = recoverymodel.OperationStatePlanned
	}
	if report.Steps[0].State != initial {
		return fmt.Errorf("repair operation initial step state %q does not match source %q", report.Steps[0].State, report.Source)
	}
	for i := 1; i < len(report.Steps); i++ {
		if !legalOperationTransition(report.Steps[i-1].State, report.Steps[i].State) {
			return fmt.Errorf("repair operation step %d is not a legal successor", i)
		}
	}
	if report.Steps[len(report.Steps)-1].State != report.State {
		return fmt.Errorf("repair operation final step does not match state %q", report.State)
	}
	return nil
}

func operationRequiresSnapshot(state recoverymodel.OperationState) bool {
	switch state {
	case recoverymodel.OperationStateSnapshotted, recoverymodel.OperationStateApplying,
		recoverymodel.OperationStateValidating, recoverymodel.OperationStateSucceeded,
		recoverymodel.OperationStateRollingBack, recoverymodel.OperationStateRolledBack,
		recoverymodel.OperationStateRollbackFailed:
		return true
	default:
		return false
	}
}

func nextRecoveryCreatedAt(tx *sql.Tx, agentID string) (int64, error) {
	var latest int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(created_at), 0) FROM recovery_operations WHERE agent_id = ?`, agentID).Scan(&latest); err != nil {
		return 0, fmt.Errorf("reading recovery operation chronology: %w", err)
	}
	now, err := recoveryUnixNano(time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("encoding recovery operation creation time: %w", err)
	}
	if now <= latest {
		if latest == math.MaxInt64 {
			return 0, fmt.Errorf("recovery operation creation chronology exhausted")
		}
		now = latest + 1
	}
	return now, nil
}

func nextRecoveryReceivedAt(tx *sql.Tx, agentID string) (int64, error) {
	var latest int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(received_at), 0) FROM recovery_operations WHERE agent_id = ?`, agentID).Scan(&latest); err != nil {
		return 0, fmt.Errorf("reading recovery operation receipt chronology: %w", err)
	}
	now, err := recoveryUnixNano(time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("encoding recovery operation receipt time: %w", err)
	}
	if now <= latest {
		if latest == math.MaxInt64 {
			return 0, fmt.Errorf("recovery operation receipt chronology exhausted")
		}
		now = latest + 1
	}
	return now, nil
}

func (d *DB) ListRepairOperations(agentID string, limit int) ([]recoverymodel.OperationReport, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := d.read.Query(operationSelect+` WHERE agent_id = ? ORDER BY created_at DESC, id DESC LIMIT ?`, agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("listing repair operations: %w", err)
	}
	defer rows.Close()
	reports := make([]recoverymodel.OperationReport, 0)
	for rows.Next() {
		report, _, err := scanRepairOperation(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning repair operation: %w", err)
		}
		reports = append(reports, report)
	}
	return reports, rows.Err()
}

func (d *DB) ListPendingUserRepairOperations(agentID string, limit int) ([]recoverymodel.OperationReport, error) {
	if strings.TrimSpace(agentID) == "" {
		return nil, fmt.Errorf("repair operation agent ID is required")
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := d.read.Query(operationSelect+` WHERE agent_id = ? AND request_source = ? AND state = ?
		ORDER BY created_at ASC, id ASC LIMIT ?`, agentID, string(recoverymodel.RequestSourceUser), string(recoverymodel.OperationStatePlanned), limit)
	if err != nil {
		return nil, fmt.Errorf("listing pending user repair operations: %w", err)
	}
	defer rows.Close()
	reports := make([]recoverymodel.OperationReport, 0)
	for rows.Next() {
		report, _, err := scanRepairOperation(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning pending user repair operation: %w", err)
		}
		reports = append(reports, report)
	}
	return reports, rows.Err()
}

func (d *DB) GetRepairOperation(agentID, operationID string) (*recoverymodel.OperationReport, error) {
	if strings.TrimSpace(agentID) == "" || strings.TrimSpace(operationID) == "" {
		return nil, fmt.Errorf("repair operation agent and ID are required")
	}
	report, _, err := scanRepairOperation(d.read.QueryRow(operationSelect+` WHERE agent_id = ? AND id = ?`, agentID, operationID))
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("repair operation not found %s: %w", operationID, sql.ErrNoRows)
	}
	if err != nil {
		return nil, fmt.Errorf("querying repair operation: %w", err)
	}
	return &report, nil
}

func (d *DB) CountRecentRepairFailures(agentID string, action recoverymodel.Action, fingerprint string, since time.Time) (int, error) {
	if !action.Valid() || since.IsZero() || strings.TrimSpace(fingerprint) == "" {
		return 0, fmt.Errorf("valid action, fingerprint, and since time are required")
	}
	sinceUnixNano, err := recoveryUnixNano(since)
	if err != nil {
		return 0, fmt.Errorf("encoding repair failure boundary: %w", err)
	}
	var count int
	err = d.read.QueryRow(`SELECT COUNT(*) FROM recovery_operations
		WHERE agent_id = ? AND action = ? AND resource_fingerprint = ?
		AND state IN (?, ?) AND received_at >= ?
		AND received_at > COALESCE((
			SELECT MAX(succeeded.received_at) FROM recovery_operations AS succeeded
			WHERE succeeded.agent_id = ? AND succeeded.action = ?
				AND succeeded.resource_fingerprint = ? AND succeeded.state = ?
		), -9223372036854775808)`,
		agentID, string(action), fingerprint, string(recoverymodel.OperationStateRolledBack),
		string(recoverymodel.OperationStateRollbackFailed), sinceUnixNano,
		agentID, string(action), fingerprint, string(recoverymodel.OperationStateSucceeded),
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting recent repair failures: %w", err)
	}
	return count, nil
}

func (d *DB) RepairBreakerOpen(agentID string, action recoverymodel.Action, fingerprint string, now time.Time) (bool, error) {
	return repairBreakerOpen(d.read, agentID, action, fingerprint, now)
}

type RepairBreakerStatus struct {
	Open      bool
	Reason    string
	ExpiresAt *time.Time
}

type RepairBreakerKey struct {
	Action              recoverymodel.Action
	ResourceFingerprint string
}

func (d *DB) GetRepairBreakerStatus(agentID string, action recoverymodel.Action, fingerprint string, now time.Time) (RepairBreakerStatus, error) {
	return repairBreakerStatus(d.read, agentID, action, fingerprint, now)
}

func (d *DB) GetRepairBreakerStatuses(agentID string, diagnostics []recoverymodel.Diagnostic, now time.Time) (map[RepairBreakerKey]RepairBreakerStatus, error) {
	const maxProjectedDiagnostics = maxActiveDiagnosticIDs + 200
	if strings.TrimSpace(agentID) == "" || now.IsZero() || len(diagnostics) > maxProjectedDiagnostics {
		return nil, fmt.Errorf("agent, current time, and at most %d diagnostics are required", maxProjectedDiagnostics)
	}
	nowNanos, err := recoveryUnixNano(now)
	if err != nil {
		return nil, fmt.Errorf("encoding repair breaker time: %w", err)
	}
	keys := make([]RepairBreakerKey, 0, len(diagnostics))
	result := make(map[RepairBreakerKey]RepairBreakerStatus, len(diagnostics))
	for _, diagnostic := range diagnostics {
		if !diagnostic.ProposedAction.Valid() {
			continue
		}
		key := RepairBreakerKey{Action: diagnostic.ProposedAction, ResourceFingerprint: diagnostic.ResourceFingerprint}
		if strings.TrimSpace(key.ResourceFingerprint) == "" {
			return nil, fmt.Errorf("diagnostic breaker fingerprint is required")
		}
		if _, exists := result[key]; !exists {
			keys = append(keys, key)
			result[key] = RepairBreakerStatus{}
		}
	}
	type history struct {
		failures      []int64
		latestSuccess int64
		latched       bool
	}
	histories := make(map[RepairBreakerKey]*history, len(keys))
	for _, key := range keys {
		histories[key] = &history{latestSuccess: math.MinInt64}
	}
	const batchSize = 250
	oldest := subtractRecoveryDuration(nowNanos, int64(75*time.Minute))
	for start := 0; start < len(keys); start += batchSize {
		end := min(start+batchSize, len(keys))
		predicates := make([]string, 0, end-start)
		args := make([]any, 0, 2*(end-start)+8)
		args = append(args, agentID)
		for _, key := range keys[start:end] {
			predicates = append(predicates, `(action = ? AND resource_fingerprint = ?)`)
			args = append(args, string(key.Action), key.ResourceFingerprint)
		}
		args = append(args,
			string(recoverymodel.OperationStateRolledBack), string(recoverymodel.OperationStateRollbackFailed), oldest,
			string(recoverymodel.OperationStateRollbackFailed), string(recoverymodel.OperationStateSucceeded), string(recoverymodel.RequestSourceUser),
			string(recoverymodel.OperationStateSucceeded),
		)
		query := `WITH selected AS (
			SELECT action, resource_fingerprint, state, request_source, received_at
			FROM recovery_operations WHERE agent_id = ? AND (` + strings.Join(predicates, ` OR `) + `)
		), recent_ranked AS (
			SELECT *, ROW_NUMBER() OVER (PARTITION BY action, resource_fingerprint ORDER BY received_at DESC) AS rn
			FROM selected WHERE state IN (?, ?) AND received_at > ?
		), latch_ranked AS (
			SELECT *, ROW_NUMBER() OVER (PARTITION BY action, resource_fingerprint ORDER BY received_at DESC) AS rn
			FROM selected WHERE state = ? OR (state = ? AND request_source = ?)
		), success_ranked AS (
			SELECT *, ROW_NUMBER() OVER (PARTITION BY action, resource_fingerprint ORDER BY received_at DESC) AS rn
			FROM selected WHERE state = ?
		)
		SELECT action, resource_fingerprint, state, request_source, received_at, 'failure' FROM recent_ranked WHERE rn <= 256
		UNION ALL SELECT action, resource_fingerprint, state, request_source, received_at, 'latch' FROM latch_ranked WHERE rn = 1
		UNION ALL SELECT action, resource_fingerprint, state, request_source, received_at, 'success' FROM success_ranked WHERE rn = 1`
		rows, err := d.read.Query(query, args...)
		if err != nil {
			return nil, fmt.Errorf("reading batch repair breaker history: %w", err)
		}
		for rows.Next() {
			var action, fingerprint, state, source, kind string
			var receipt int64
			if err := rows.Scan(&action, &fingerprint, &state, &source, &receipt, &kind); err != nil {
				rows.Close()
				return nil, fmt.Errorf("scanning batch repair breaker history: %w", err)
			}
			key := RepairBreakerKey{Action: recoverymodel.Action(action), ResourceFingerprint: fingerprint}
			h := histories[key]
			if h == nil {
				rows.Close()
				return nil, fmt.Errorf("batch repair breaker returned an unknown key")
			}
			switch kind {
			case "failure":
				h.failures = append(h.failures, receipt)
			case "latch":
				h.latched = state == string(recoverymodel.OperationStateRollbackFailed)
			case "success":
				h.latestSuccess = receipt
			default:
				rows.Close()
				return nil, fmt.Errorf("unknown batch repair breaker history kind")
			}
		}
		if err := rows.Close(); err != nil {
			return nil, fmt.Errorf("closing batch repair breaker history: %w", err)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("reading batch repair breaker history: %w", err)
		}
	}
	for key, history := range histories {
		sort.Slice(history.failures, func(i, j int) bool { return history.failures[i] > history.failures[j] })
		result[key], err = repairBreakerStatusFromHistory(history.latched, history.latestSuccess, history.failures, nowNanos)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

type recoveryQueryer interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

func repairBreakerOpen(q recoveryQueryer, agentID string, action recoverymodel.Action, fingerprint string, now time.Time) (bool, error) {
	status, err := repairBreakerStatus(q, agentID, action, fingerprint, now)
	return status.Open, err
}

func repairBreakerStatus(q recoveryQueryer, agentID string, action recoverymodel.Action, fingerprint string, now time.Time) (RepairBreakerStatus, error) {
	if strings.TrimSpace(agentID) == "" || !action.Valid() || strings.TrimSpace(fingerprint) == "" || now.IsZero() {
		return RepairBreakerStatus{}, fmt.Errorf("agent, valid action, fingerprint, and current time are required")
	}
	nowNanos, err := recoveryUnixNano(now)
	if err != nil {
		return RepairBreakerStatus{}, fmt.Errorf("encoding repair breaker time: %w", err)
	}

	latched, err := repairRollbackFailedLatched(q, agentID, action, fingerprint)
	if err != nil {
		return RepairBreakerStatus{}, err
	}
	if latched {
		return RepairBreakerStatus{Open: true, Reason: "rollback_failed_latched"}, nil
	}

	var latestReceipt int64
	err = q.QueryRow(`SELECT received_at FROM recovery_operations
		WHERE agent_id = ? AND action = ? AND resource_fingerprint = ?
		AND state = ? ORDER BY received_at DESC LIMIT 1`,
		agentID, string(action), fingerprint,
		string(recoverymodel.OperationStateSucceeded),
	).Scan(&latestReceipt)
	if err != nil && err != sql.ErrNoRows {
		return RepairBreakerStatus{}, fmt.Errorf("reading latest repair breaker outcome: %w", err)
	}
	afterSuccess := int64(math.MinInt64)
	if err == nil {
		afterSuccess = latestReceipt
	}

	const (
		failureWindow = int64(15 * time.Minute)
		openDuration  = int64(time.Hour)
		lookback      = failureWindow + openDuration
	)
	oldest := subtractRecoveryDuration(nowNanos, lookback)
	if afterSuccess > oldest {
		oldest = afterSuccess
	}
	rows, err := q.Query(`SELECT received_at FROM recovery_operations
		WHERE agent_id = ? AND action = ? AND resource_fingerprint = ?
		AND state IN (?, ?) AND received_at > ?
		ORDER BY received_at DESC LIMIT 256`,
		agentID, string(action), fingerprint,
		string(recoverymodel.OperationStateRolledBack), string(recoverymodel.OperationStateRollbackFailed), oldest,
	)
	if err != nil {
		return RepairBreakerStatus{}, fmt.Errorf("reading repair breaker failures: %w", err)
	}
	defer rows.Close()
	receiptsDesc := make([]int64, 0, 16)
	for rows.Next() {
		var receipt int64
		if err := rows.Scan(&receipt); err != nil {
			return RepairBreakerStatus{}, fmt.Errorf("scanning repair breaker failure: %w", err)
		}
		receiptsDesc = append(receiptsDesc, receipt)
	}
	if err := rows.Err(); err != nil {
		return RepairBreakerStatus{}, fmt.Errorf("reading repair breaker failures: %w", err)
	}
	return repairBreakerStatusFromHistory(false, afterSuccess, receiptsDesc, nowNanos)
}

func repairBreakerStatusFromHistory(latched bool, latestSuccess int64, receiptsDesc []int64, nowNanos int64) (RepairBreakerStatus, error) {
	if latched {
		return RepairBreakerStatus{Open: true, Reason: "rollback_failed_latched"}, nil
	}
	const (
		failureWindow = int64(15 * time.Minute)
		openDuration  = int64(time.Hour)
	)
	openSince := subtractRecoveryDuration(nowNanos, openDuration)
	filtered := receiptsDesc[:0]
	for _, receipt := range receiptsDesc {
		if receipt > latestSuccess {
			filtered = append(filtered, receipt)
		}
	}
	for i := 0; i <= len(filtered)-3; i++ {
		openedAt := filtered[i]
		first := filtered[i+2]
		if openedAt > openSince && openedAt-first <= failureWindow {
			opened, err := recoveryTimeFromUnixNano(openedAt)
			if err != nil {
				return RepairBreakerStatus{}, fmt.Errorf("decoding repair breaker expiry: %w", err)
			}
			expiresAt := opened.Add(time.Hour)
			return RepairBreakerStatus{Open: true, Reason: "failure_threshold", ExpiresAt: &expiresAt}, nil
		}
	}
	return RepairBreakerStatus{}, nil
}

func (d *DB) RepairRollbackFailedLatched(agentID string, action recoverymodel.Action, fingerprint string) (bool, error) {
	return repairRollbackFailedLatched(d.read, agentID, action, fingerprint)
}

func repairRollbackFailedLatched(q recoveryQueryer, agentID string, action recoverymodel.Action, fingerprint string) (bool, error) {
	if strings.TrimSpace(agentID) == "" || !action.Valid() || strings.TrimSpace(fingerprint) == "" {
		return false, fmt.Errorf("agent, valid action, and fingerprint are required")
	}
	var state string
	err := q.QueryRow(`SELECT state FROM recovery_operations
		WHERE agent_id = ? AND action = ? AND resource_fingerprint = ?
		AND (state = ? OR (state = ? AND request_source = ?))
		ORDER BY received_at DESC LIMIT 1`,
		agentID, string(action), fingerprint,
		string(recoverymodel.OperationStateRollbackFailed), string(recoverymodel.OperationStateSucceeded),
		string(recoverymodel.RequestSourceUser),
	).Scan(&state)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading rollback-failed repair latch: %w", err)
	}
	return state == string(recoverymodel.OperationStateRollbackFailed), nil
}

func subtractRecoveryDuration(value, duration int64) int64 {
	if value < math.MinInt64+duration {
		return math.MinInt64
	}
	return value - duration
}

const operationSelect = `SELECT id, diagnostic_id, action, request_source, state,
	step_summaries, snapshot_reference, validation_outcome, rollback_outcome, error,
	started_at, finished_at, resource_fingerprint FROM recovery_operations`

func scanRepairOperation(scanner interface{ Scan(...any) error }) (recoverymodel.OperationReport, string, error) {
	var report recoverymodel.OperationReport
	var action, source, state, stepsJSON, fingerprint string
	var startedAt int64
	var finishedAt sql.NullInt64
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
	if report.StartedAt, err = recoveryTimeFromUnixNano(startedAt); err != nil {
		return report, "", fmt.Errorf("decoding repair start time: %w", err)
	}
	if finishedAt.Valid {
		finished, err := recoveryTimeFromUnixNano(finishedAt.Int64)
		if err != nil {
			return report, "", fmt.Errorf("decoding repair finish time: %w", err)
		}
		report.FinishedAt = &finished
	}
	if err := report.Validate(); err != nil {
		return report, "", fmt.Errorf("validating stored repair operation: %w", err)
	}
	if err := validatePersistedOperation(report); err != nil {
		return report, "", fmt.Errorf("validating stored repair operation lifecycle: %w", err)
	}
	return report, fingerprint, nil
}

func legalOperationTransition(from, to recoverymodel.OperationState) bool {
	for _, candidate := range operationSuccessors(from) {
		if candidate == to {
			return true
		}
	}
	return false
}

func operationSuccessors(state recoverymodel.OperationState) []recoverymodel.OperationState {
	allowed := map[recoverymodel.OperationState][]recoverymodel.OperationState{
		recoverymodel.OperationStateDetected:    {recoverymodel.OperationStateDiagnosisOnly, recoverymodel.OperationStatePlanned, recoverymodel.OperationStateSuppressed},
		recoverymodel.OperationStatePlanned:     {recoverymodel.OperationStateDiagnosisOnly, recoverymodel.OperationStateSuppressed, recoverymodel.OperationStateSnapshotted},
		recoverymodel.OperationStateSnapshotted: {recoverymodel.OperationStateApplying, recoverymodel.OperationStateRollingBack},
		recoverymodel.OperationStateApplying:    {recoverymodel.OperationStateValidating, recoverymodel.OperationStateRollingBack},
		recoverymodel.OperationStateValidating:  {recoverymodel.OperationStateSucceeded, recoverymodel.OperationStateRollingBack},
		recoverymodel.OperationStateRollingBack: {recoverymodel.OperationStateRolledBack, recoverymodel.OperationStateRollbackFailed},
	}
	return allowed[state]
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

func recoveryUnixNano(value time.Time) (int64, error) {
	value = value.UTC()
	nanos := value.UnixNano()
	if !time.Unix(0, nanos).UTC().Equal(value) {
		return 0, fmt.Errorf("timestamp %s is outside signed Unix-nanosecond range", value.Format(time.RFC3339Nano))
	}
	return nanos, nil
}

func recoveryTimeFromUnixNano(nanos int64) (time.Time, error) {
	value := time.Unix(0, nanos).UTC()
	roundTrip, err := recoveryUnixNano(value)
	if err != nil || roundTrip != nanos {
		return time.Time{}, fmt.Errorf("stored Unix-nanosecond timestamp %d does not round trip", nanos)
	}
	return value, nil
}

func nullableRecoveryTime(value *time.Time) (any, error) {
	if value == nil {
		return nil, nil
	}
	return recoveryUnixNano(*value)
}

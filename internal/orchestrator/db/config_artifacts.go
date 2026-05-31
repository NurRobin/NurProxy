package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/configeq"
	// Register the Caddy semantic comparator so version-gating treats Caddy's
	// re-serialized route JSON as unchanged (no phantom versions, §4/§11). File
	// backends fall back to configeq.RawEqual automatically.
	_ "github.com/NurRobin/NurProxy/internal/shared/configeq/caddyeq"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// ChecksumContent returns the hex-encoded SHA-256 of the given config content.
// It is the raw-checksum used for file artifacts and version equality (§11);
// semantic equality (Caddy JSON) is decided by the backend before a version is
// written, not here.
func ChecksumContent(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// ConfigArtifactFilter controls which artifacts ListConfigArtifacts returns. An
// empty field means "no constraint" for that dimension.
type ConfigArtifactFilter struct {
	AgentID    string
	DomainID   *int64
	Source     string
	ApplyState string
	// Drifted, when non-nil, restricts to artifacts whose drifted flag matches.
	Drifted *bool
}

// CreateConfigArtifact inserts a new managed config artifact and writes its
// first version (version 1) into the append-only history, atomically. The
// artifact's Checksum is (re)computed from Content, LiveVersion is set to 1, and
// the version's actor/note are taken from the supplied arguments. The caller
// supplies art.ID (a UUID, mirroring servers/providers).
func (d *DB) CreateConfigArtifact(art *models.ConfigArtifact, actor, note string) error {
	if art.ID == "" {
		return fmt.Errorf("config artifact id is required")
	}
	now := time.Now().UTC()
	art.UpdatedAt = now
	art.Checksum = ChecksumContent(art.Content)
	art.LiveVersion = 1
	if art.Source == "" {
		art.Source = models.ArtifactSourceGenerated
	}
	if art.ApplyState == "" {
		art.ApplyState = models.ArtifactStateLive
	}

	tx, err := d.sql.Begin()
	if err != nil {
		return fmt.Errorf("beginning create artifact: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`
		INSERT INTO config_artifacts (id, agent_id, backend, target_kind, target_path,
			source, domain_id, content, checksum, live_version, enabled, drifted,
			apply_state, last_error, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		art.ID, art.AgentID, art.Backend, art.Target.Kind, art.Target.Path,
		art.Source, art.DomainID, art.Content, art.Checksum, art.LiveVersion,
		boolToInt(art.Enabled), boolToInt(art.Drifted), art.ApplyState,
		art.LastError, now.Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("inserting config artifact: %w", err)
	}

	if _, err := tx.Exec(`
		INSERT INTO config_artifact_versions (artifact_id, version, content, checksum,
			source, actor, note, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		art.ID, art.LiveVersion, art.Content, art.Checksum, art.Source,
		actor, note, now.Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("inserting initial artifact version: %w", err)
	}

	return tx.Commit()
}

const configArtifactColumns = `id, agent_id, backend, target_kind, target_path,
	source, domain_id, content, checksum, live_version, enabled, drifted,
	apply_state, last_error, drift_content, updated_at`

func scanConfigArtifact(sc interface {
	Scan(dest ...any) error
}) (*models.ConfigArtifact, error) {
	var art models.ConfigArtifact
	var domainID sql.NullInt64
	var enabled, drifted int
	var updatedAt string

	err := sc.Scan(
		&art.ID, &art.AgentID, &art.Backend, &art.Target.Kind, &art.Target.Path,
		&art.Source, &domainID, &art.Content, &art.Checksum, &art.LiveVersion,
		&enabled, &drifted, &art.ApplyState, &art.LastError, &art.DriftContent, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	if domainID.Valid {
		v := domainID.Int64
		art.DomainID = &v
	}
	art.Enabled = enabled != 0
	art.Drifted = drifted != 0
	art.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	return &art, nil
}

// GetConfigArtifact retrieves a single artifact by ID.
func (d *DB) GetConfigArtifact(id string) (*models.ConfigArtifact, error) {
	row := d.sql.QueryRow(
		"SELECT "+configArtifactColumns+" FROM config_artifacts WHERE id = ?", id,
	)
	art, err := scanConfigArtifact(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("config artifact not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("querying config artifact: %w", err)
	}
	return art, nil
}

// GetConfigArtifactByTarget retrieves the artifact occupying a given on-host
// target (agent_id, target_kind, target_path) — the table's uniqueness key. It
// lets the adopt path detect that a file is ALREADY tracked under another
// artifact ID (e.g. a generated "dom-N" the agent just applied) so it skips
// creating a duplicate "adopt-…" row that would violate the unique constraint.
// Returns (nil, nil) when no artifact occupies that target.
func (d *DB) GetConfigArtifactByTarget(agentID, targetKind, targetPath string) (*models.ConfigArtifact, error) {
	row := d.sql.QueryRow(
		"SELECT "+configArtifactColumns+" FROM config_artifacts WHERE agent_id = ? AND target_kind = ? AND target_path = ?",
		agentID, targetKind, targetPath,
	)
	art, err := scanConfigArtifact(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying config artifact by target: %w", err)
	}
	return art, nil
}

// ListConfigArtifacts returns artifacts matching the filter, newest-updated
// first.
func (d *DB) ListConfigArtifacts(filter ConfigArtifactFilter) ([]models.ConfigArtifact, error) {
	query := "SELECT " + configArtifactColumns + " FROM config_artifacts"
	var conditions []string
	var args []any

	if filter.AgentID != "" {
		conditions = append(conditions, "agent_id = ?")
		args = append(args, filter.AgentID)
	}
	if filter.DomainID != nil {
		conditions = append(conditions, "domain_id = ?")
		args = append(args, *filter.DomainID)
	}
	if filter.Source != "" {
		conditions = append(conditions, "source = ?")
		args = append(args, filter.Source)
	}
	if filter.ApplyState != "" {
		conditions = append(conditions, "apply_state = ?")
		args = append(args, filter.ApplyState)
	}
	if filter.Drifted != nil {
		conditions = append(conditions, "drifted = ?")
		args = append(args, boolToInt(*filter.Drifted))
	}

	if len(conditions) > 0 {
		query += " WHERE "
		for i, c := range conditions {
			if i > 0 {
				query += " AND "
			}
			query += c
		}
	}
	query += " ORDER BY updated_at DESC, id"

	rows, err := d.sql.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing config artifacts: %w", err)
	}
	defer rows.Close()

	var artifacts []models.ConfigArtifact
	for rows.Next() {
		art, err := scanConfigArtifact(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning config artifact: %w", err)
		}
		artifacts = append(artifacts, *art)
	}
	return artifacts, rows.Err()
}

// AppendConfigArtifactVersion writes a new version of an artifact into the
// append-only history and promotes it to the live state, atomically. The new
// version number is LiveVersion+1; content/checksum/source become the live
// values and the drift flag is cleared (apply_state -> live).
//
// Version writes are gated on *semantic* change (§4, §11): the per-backend
// configeq.Equal decides whether content differs meaningfully against the
// currently-live content. If it is semantically equal — the common case when
// Caddy re-serializes its route JSON on reload — NO new version is written (no
// phantom versions) and the existing live version is returned unchanged, with
// the drift flag cleared (the on-disk state is back in agreement). actor/note
// are recorded for audit (apply/accept/rollback) only when a version is
// actually appended.
func (d *DB) AppendConfigArtifactVersion(artifactID, content string, source models.ArtifactSource, actor, note string) (*models.ConfigArtifactVersion, error) {
	now := time.Now().UTC()
	checksum := ChecksumContent(content)

	tx, err := d.sql.Begin()
	if err != nil {
		return nil, fmt.Errorf("beginning append version: %w", err)
	}
	defer tx.Rollback()

	var liveVersion int
	var curSource, curContent, backend string
	err = tx.QueryRow(
		"SELECT live_version, source, content, backend FROM config_artifacts WHERE id = ?", artifactID,
	).Scan(&liveVersion, &curSource, &curContent, &backend)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("config artifact not found: %s", artifactID)
	}
	if err != nil {
		return nil, fmt.Errorf("reading artifact version: %w", err)
	}

	if source == "" {
		source = curSource
	}

	// Gate: no phantom versions. If the incoming content is semantically equal
	// to the live content for this backend, do not append — just clear any drift
	// (the host is back in agreement) and return the existing live version.
	if configeq.Equal(backend, curContent, content) {
		if _, err := tx.Exec(`
			UPDATE config_artifacts
			SET drifted = 0, apply_state = ?, last_error = '', drift_content = '', updated_at = ?
			WHERE id = ?`,
			models.ArtifactStateLive, now.Format(time.RFC3339), artifactID,
		); err != nil {
			return nil, fmt.Errorf("clearing drift on unchanged artifact: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("committing unchanged artifact: %w", err)
		}
		return d.GetConfigArtifactVersion(artifactID, liveVersion)
	}

	next := liveVersion + 1

	if _, err := tx.Exec(`
		INSERT INTO config_artifact_versions (artifact_id, version, content, checksum,
			source, actor, note, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		artifactID, next, content, checksum, source, actor, note,
		now.Format(time.RFC3339),
	); err != nil {
		return nil, fmt.Errorf("inserting artifact version: %w", err)
	}

	if _, err := tx.Exec(`
		UPDATE config_artifacts
		SET content = ?, checksum = ?, live_version = ?, source = ?,
			drifted = 0, apply_state = ?, last_error = '', drift_content = '', updated_at = ?
		WHERE id = ?`,
		content, checksum, next, source, models.ArtifactStateLive,
		now.Format(time.RFC3339), artifactID,
	); err != nil {
		return nil, fmt.Errorf("promoting artifact version: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing append version: %w", err)
	}

	return &models.ConfigArtifactVersion{
		ArtifactID: artifactID,
		Version:    next,
		Content:    content,
		Checksum:   checksum,
		Source:     source,
		Actor:      actor,
		Note:       note,
		CreatedAt:  now,
	}, nil
}

// ListConfigArtifactVersions returns the full version history of an artifact,
// newest version first.
func (d *DB) ListConfigArtifactVersions(artifactID string) ([]models.ConfigArtifactVersion, error) {
	rows, err := d.sql.Query(`
		SELECT id, artifact_id, version, content, checksum, source, actor, note, created_at
		FROM config_artifact_versions
		WHERE artifact_id = ?
		ORDER BY version DESC`, artifactID)
	if err != nil {
		return nil, fmt.Errorf("listing artifact versions: %w", err)
	}
	defer rows.Close()

	var versions []models.ConfigArtifactVersion
	for rows.Next() {
		var v models.ConfigArtifactVersion
		var createdAt string
		if err := rows.Scan(&v.ID, &v.ArtifactID, &v.Version, &v.Content,
			&v.Checksum, &v.Source, &v.Actor, &v.Note, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning artifact version: %w", err)
		}
		v.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

// GetConfigArtifactVersion retrieves a single version of an artifact by its
// version number.
func (d *DB) GetConfigArtifactVersion(artifactID string, version int) (*models.ConfigArtifactVersion, error) {
	row := d.sql.QueryRow(`
		SELECT id, artifact_id, version, content, checksum, source, actor, note, created_at
		FROM config_artifact_versions
		WHERE artifact_id = ? AND version = ?`, artifactID, version)

	var v models.ConfigArtifactVersion
	var createdAt string
	err := row.Scan(&v.ID, &v.ArtifactID, &v.Version, &v.Content, &v.Checksum,
		&v.Source, &v.Actor, &v.Note, &createdAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("artifact version not found: %s@%d", artifactID, version)
	}
	if err != nil {
		return nil, fmt.Errorf("querying artifact version: %w", err)
	}
	v.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &v, nil
}

// MarkConfigArtifactDrifted records that an artifact's on-disk content diverged
// from the accepted state (§11). It flips drifted=1 and apply_state=drifted but
// does NOT touch the stored content — the accepted state is preserved for the
// review (accept/reject) flow. onDiskChecksum is recorded in last_error context
// only via the caller's note; here we just flag.
func (d *DB) MarkConfigArtifactDrifted(id string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.sql.Exec(`
		UPDATE config_artifacts
		SET drifted = 1, apply_state = ?, updated_at = ?
		WHERE id = ?`,
		models.ArtifactStateDrifted, now, id,
	)
	if err != nil {
		return fmt.Errorf("marking artifact drifted: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("config artifact not found: %s", id)
	}
	return nil
}

// ReconcileArtifactChecksum compares an agent's heartbeat-reported on-disk
// checksum against the accepted (stored) checksum and updates the drift state
// (§11). It is the heartbeat half of drift detection: the agent reports each
// managed artifact's checksum, the orchestrator decides whether the host
// diverged from the last accepted state.
//
// Behavior (idempotent, never overwrites stored content — the accepted state is
// preserved for the review flow):
//   - checksum matches accepted: if the artifact was drifted, clear it back to
//     live (the host is back in agreement); otherwise no-op. Returns drifted=false.
//   - checksum differs: flag drifted + apply_state=drifted (if not already).
//     Returns drifted=true.
//
// changed reports whether this call actually transitioned the drift state (so the
// caller can audit only genuine transitions, not every heartbeat). An artifact in
// apply_failed state is left untouched (the failure, not drift, is the story).
func (d *DB) ReconcileArtifactChecksum(id, agentID, onDiskChecksum, onDiskContent string) (drifted, changed bool, err error) {
	now := time.Now().UTC().Format(time.RFC3339)

	tx, err := d.sql.Begin()
	if err != nil {
		return false, false, fmt.Errorf("beginning checksum reconcile: %w", err)
	}
	defer tx.Rollback()

	var accepted, applyState string
	var wasDrifted int
	// Scope by agent_id so an agent's heartbeat can only flag/clear drift on its
	// OWN artifact, never another agent's row that happens to share the ID.
	row := tx.QueryRow(
		"SELECT checksum, drifted, apply_state FROM config_artifacts WHERE id = ? AND agent_id = ?", id, agentID,
	)
	if scanErr := row.Scan(&accepted, &wasDrifted, &applyState); scanErr == sql.ErrNoRows {
		return false, false, fmt.Errorf("config artifact not found: %s", id)
	} else if scanErr != nil {
		return false, false, fmt.Errorf("reading artifact checksum: %w", scanErr)
	}

	// A failed apply owns the state until it is resolved by a fresh apply-ACK; a
	// heartbeat checksum doesn't override that story.
	if applyState == models.ArtifactStateApplyFailed {
		return wasDrifted != 0, false, tx.Commit()
	}

	matches := onDiskChecksum == accepted
	switch {
	case matches && wasDrifted != 0:
		// Host came back into agreement — clear drift and the captured on-disk bytes.
		if _, err := tx.Exec(`
			UPDATE config_artifacts
			SET drifted = 0, apply_state = ?, last_error = '', drift_content = '', updated_at = ?
			WHERE id = ?`,
			models.ArtifactStateLive, now, id,
		); err != nil {
			return false, false, fmt.Errorf("clearing drift: %w", err)
		}
		return false, true, tx.Commit()
	case !matches && wasDrifted == 0:
		// Newly diverged — flag for review and capture the operator's on-disk bytes
		// so the dashboard can diff accepted vs on-disk and Accept can persist them
		// (§11). The accepted content (content/checksum) is left intact.
		if _, err := tx.Exec(`
			UPDATE config_artifacts
			SET drifted = 1, apply_state = ?, drift_content = ?, updated_at = ?
			WHERE id = ?`,
			models.ArtifactStateDrifted, onDiskContent, now, id,
		); err != nil {
			return false, false, fmt.Errorf("flagging drift: %w", err)
		}
		return true, true, tx.Commit()
	case !matches && wasDrifted != 0 && onDiskContent != "":
		// Still drifted but the operator edited again — refresh the captured bytes so
		// the diff/Accept reflect the latest on-disk state. Not a flag transition.
		if _, err := tx.Exec(`
			UPDATE config_artifacts SET drift_content = ?, updated_at = ? WHERE id = ?`,
			onDiskContent, now, id,
		); err != nil {
			return true, false, fmt.Errorf("updating drift content: %w", err)
		}
		return true, false, tx.Commit()
	default:
		// No transition (matches && live, or differs && already drifted, no content).
		return wasDrifted != 0, false, tx.Commit()
	}
}

// RejectConfigArtifactDrift resolves a drift by reverting to the accepted state:
// it clears the drift flag without writing a new version (the stored content IS
// the accepted state to re-apply to disk). The caller is responsible for pushing
// the stored content back to the agent (re-apply). Returns the artifact so the
// caller can re-render/re-push it.
func (d *DB) RejectConfigArtifactDrift(id string) (*models.ConfigArtifact, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.sql.Exec(`
		UPDATE config_artifacts
		SET drifted = 0, apply_state = ?, last_error = '', drift_content = '', updated_at = ?
		WHERE id = ?`,
		models.ArtifactStateLive, now, id,
	)
	if err != nil {
		return nil, fmt.Errorf("rejecting artifact drift: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, fmt.Errorf("config artifact not found: %s", id)
	}
	return d.GetConfigArtifact(id)
}

// RollbackConfigArtifact promotes a prior version's content to a new live version
// (§11). It re-uses the version-append path so a rollback is itself recorded as a
// new version with actor/note for audit — history is append-only, never rewound.
// The semantic-equality gate still applies: rolling back to content semantically
// equal to the current live state writes no phantom version (and clears drift).
// The caller re-applies the resulting live content to the agent.
func (d *DB) RollbackConfigArtifact(id string, toVersion int, actor, note string) (*models.ConfigArtifactVersion, error) {
	target, err := d.GetConfigArtifactVersion(id, toVersion)
	if err != nil {
		return nil, err
	}
	return d.AppendConfigArtifactVersion(id, target.Content, target.Source, actor, note)
}

// SetConfigArtifactApplyState updates the lifecycle status and last error of an
// artifact (e.g. apply_failed after a failed write/validate/reload). It also
// keeps the drifted flag consistent with the drifted state.
func (d *DB) SetConfigArtifactApplyState(id string, state models.ArtifactApplyState, lastError string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.sql.Exec(`
		UPDATE config_artifacts
		SET apply_state = ?, drifted = ?, last_error = ?, updated_at = ?
		WHERE id = ?`,
		state, boolToInt(state == models.ArtifactStateDrifted), lastError, now, id,
	)
	if err != nil {
		return fmt.Errorf("setting artifact apply state: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("config artifact not found: %s", id)
	}
	return nil
}

// SetConfigArtifactEnabled toggles the enabled flag (e.g. nginx sites-enabled
// symlink present).
func (d *DB) SetConfigArtifactEnabled(id string, enabled bool) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.sql.Exec(`
		UPDATE config_artifacts SET enabled = ?, updated_at = ? WHERE id = ?`,
		boolToInt(enabled), now, id,
	)
	if err != nil {
		return fmt.Errorf("setting artifact enabled: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("config artifact not found: %s", id)
	}
	return nil
}

// DeleteConfigArtifact removes an artifact and (via ON DELETE CASCADE) its full
// version history. Used by the domain lifecycle: a server move removes the
// artifact on the old agent; a domain delete removes its artifact (no ghost
// vhosts, §3).
func (d *DB) DeleteConfigArtifact(id string) error {
	res, err := d.sql.Exec("DELETE FROM config_artifacts WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("deleting config artifact: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("config artifact not found: %s", id)
	}
	return nil
}

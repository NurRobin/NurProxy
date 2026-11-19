package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// ErrUpgradeInProgress is returned when an agent already has an unfinished
// upgrade.
var ErrUpgradeInProgress = errors.New("an upgrade is already in progress for this agent")

// ErrUpgradeTransition is returned for a progress report the state machine
// does not allow (backwards, or after the upgrade finished).
var ErrUpgradeTransition = errors.New("upgrade state transition not allowed")

const upgradeColumns = `id, agent_id, from_version, target_version, state, error, triggered_by, rollout_id, requested_by, created_at, updated_at`

func scanUpgrade(sc interface{ Scan(...any) error }) (*models.AgentUpgrade, error) {
	var u models.AgentUpgrade
	var state, created, updated string
	if err := sc.Scan(&u.ID, &u.AgentID, &u.FromVersion, &u.TargetVersion, &state, &u.Error, &u.Trigger, &u.RolloutID, &u.RequestedBy, &created, &updated); err != nil {
		return nil, err
	}
	u.State = models.AgentUpgradeState(state)
	u.CreatedAt, _ = time.Parse(time.RFC3339, created)
	u.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	return &u, nil
}

// CreateAgentUpgrade inserts a new upgrade in state requested. It fails with
// ErrUpgradeInProgress when the agent has an unfinished one.
func (d *DB) CreateAgentUpgrade(u *models.AgentUpgrade) error {
	now := time.Now().UTC()
	u.State = models.UpgradeRequested
	u.CreatedAt, u.UpdatedAt = now, now
	ts := now.Format(time.RFC3339)
	_, err := d.sql.Exec(`INSERT INTO agent_upgrades (`+upgradeColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.AgentID, u.FromVersion, u.TargetVersion, string(u.State), u.Error, u.Trigger, u.RolloutID, u.RequestedBy, ts, ts)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: agent_upgrades.agent_id") {
			return ErrUpgradeInProgress
		}
		return fmt.Errorf("inserting agent upgrade: %w", err)
	}
	return nil
}

// GetAgentUpgrade returns one upgrade.
func (d *DB) GetAgentUpgrade(id string) (*models.AgentUpgrade, error) {
	u, err := scanUpgrade(d.sql.QueryRow(`SELECT `+upgradeColumns+` FROM agent_upgrades WHERE id = ?`, id))
	if err != nil {
		return nil, fmt.Errorf("getting agent upgrade %s: %w", id, err)
	}
	return u, nil
}

// ListAgentUpgrades returns an agent's upgrades, newest first.
func (d *DB) ListAgentUpgrades(agentID string, limit int) ([]models.AgentUpgrade, error) {
	rows, err := d.sql.Query(`SELECT `+upgradeColumns+` FROM agent_upgrades WHERE agent_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ?`, agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("listing agent upgrades: %w", err)
	}
	defer rows.Close()
	out := []models.AgentUpgrade{}
	for rows.Next() {
		u, err := scanUpgrade(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// LatestAgentUpgrades returns the newest upgrade of every agent that has one.
func (d *DB) LatestAgentUpgrades() (map[string]*models.AgentUpgrade, error) {
	rows, err := d.sql.Query(`SELECT ` + upgradeColumns + ` FROM agent_upgrades ORDER BY created_at ASC, rowid ASC`)
	if err != nil {
		return nil, fmt.Errorf("listing agent upgrades: %w", err)
	}
	defer rows.Close()
	out := make(map[string]*models.AgentUpgrade)
	for rows.Next() {
		u, err := scanUpgrade(rows)
		if err != nil {
			return nil, err
		}
		out[u.AgentID] = u
	}
	return out, rows.Err()
}

// ListActiveAgentUpgrades returns every unfinished upgrade.
func (d *DB) ListActiveAgentUpgrades() ([]models.AgentUpgrade, error) {
	rows, err := d.sql.Query(`SELECT ` + upgradeColumns + ` FROM agent_upgrades WHERE state IN ('requested', 'downloading', 'installed', 'restarting') ORDER BY created_at, rowid`)
	if err != nil {
		return nil, fmt.Errorf("listing active agent upgrades: %w", err)
	}
	defer rows.Close()
	var out []models.AgentUpgrade
	for rows.Next() {
		u, err := scanUpgrade(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// ActiveAgentUpgrade returns the agent's unfinished upgrade, or nil.
func (d *DB) ActiveAgentUpgrade(agentID string) (*models.AgentUpgrade, error) {
	u, err := scanUpgrade(d.sql.QueryRow(`SELECT `+upgradeColumns+` FROM agent_upgrades
		WHERE agent_id = ? AND state IN ('requested', 'downloading', 'installed', 'restarting')`, agentID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting active agent upgrade: %w", err)
	}
	return u, nil
}

// HasUnsuccessfulUpgrade reports whether an upgrade of agentID to version
// already ended in failed or rolled_back. Automatic upgrades do not retry such
// a target; an operator can.
func (d *DB) HasUnsuccessfulUpgrade(agentID, version string) (bool, error) {
	var n int
	err := d.sql.QueryRow(`SELECT COUNT(*) FROM agent_upgrades WHERE agent_id = ? AND target_version = ? AND state IN ('failed', 'rolled_back')`, agentID, version).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("checking agent upgrade history: %w", err)
	}
	return n > 0, nil
}

// TransitionAgentUpgrade moves an upgrade to state to (see
// models.CanTransitionUpgrade), recording errMsg. It returns the upgrade before
// and after the move. A repeated non-terminal state only refreshes updated_at.
func (d *DB) TransitionAgentUpgrade(id string, to models.AgentUpgradeState, errMsg string) (before, after *models.AgentUpgrade, err error) {
	tx, err := d.sql.Begin()
	if err != nil {
		return nil, nil, fmt.Errorf("beginning upgrade transition: %w", err)
	}
	defer tx.Rollback()
	before, err = scanUpgrade(tx.QueryRow(`SELECT `+upgradeColumns+` FROM agent_upgrades WHERE id = ?`, id))
	if err != nil {
		return nil, nil, fmt.Errorf("getting agent upgrade %s: %w", id, err)
	}
	if !models.CanTransitionUpgrade(before.State, to) {
		return before, nil, fmt.Errorf("%w: %s -> %s", ErrUpgradeTransition, before.State, to)
	}
	if len(errMsg) > 2000 {
		errMsg = errMsg[:2000]
	}
	now := time.Now().UTC()
	if _, err := tx.Exec(`UPDATE agent_upgrades SET state = ?, error = ?, updated_at = ? WHERE id = ?`,
		string(to), errMsg, now.Format(time.RFC3339), id); err != nil {
		return nil, nil, fmt.Errorf("updating agent upgrade: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("committing upgrade transition: %w", err)
	}
	a := *before
	a.State, a.Error, a.UpdatedAt = to, errMsg, now
	return before, &a, nil
}

// AgentSelfUpdate is the per-agent self-update record.
type AgentSelfUpdate struct {
	AutoUpgrade bool
	Capability  *models.SelfUpdateStatus
}

// ListAgentSelfUpdate returns the self-update record of every agent that has
// one.
func (d *DB) ListAgentSelfUpdate() (map[string]AgentSelfUpdate, error) {
	rows, err := d.sql.Query(`SELECT agent_id, auto_upgrade, capability FROM agent_self_update`)
	if err != nil {
		return nil, fmt.Errorf("listing agent self-update settings: %w", err)
	}
	defer rows.Close()
	out := make(map[string]AgentSelfUpdate)
	for rows.Next() {
		var id string
		var auto int
		var capability sql.NullString
		if err := rows.Scan(&id, &auto, &capability); err != nil {
			return nil, err
		}
		rec := AgentSelfUpdate{AutoUpgrade: auto != 0}
		if capability.Valid && capability.String != "" {
			var st models.SelfUpdateStatus
			if json.Unmarshal([]byte(capability.String), &st) == nil {
				rec.Capability = &st
			}
		}
		out[id] = rec
	}
	return out, rows.Err()
}

// GetAgentSelfUpdate returns one agent's record (zero value when none).
func (d *DB) GetAgentSelfUpdate(agentID string) (AgentSelfUpdate, error) {
	all, err := d.ListAgentSelfUpdate()
	if err != nil {
		return AgentSelfUpdate{}, err
	}
	return all[agentID], nil
}

// SetAgentAutoUpgrade sets the per-agent auto-upgrade opt-in.
func (d *DB) SetAgentAutoUpgrade(agentID string, enabled bool) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := d.sql.Exec(`INSERT INTO agent_self_update (agent_id, auto_upgrade, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(agent_id) DO UPDATE SET auto_upgrade = excluded.auto_upgrade, updated_at = excluded.updated_at`,
		agentID, boolToInt(enabled), now)
	if err != nil {
		return fmt.Errorf("setting agent auto-upgrade: %w", err)
	}
	return nil
}

// SetAgentSelfUpdateCapability stores the agent's latest self-update report.
func (d *DB) SetAgentSelfUpdateCapability(agentID string, st *models.SelfUpdateStatus) error {
	var payload any
	if st != nil {
		data, err := json.Marshal(st)
		if err != nil {
			return err
		}
		payload = string(data)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := d.sql.Exec(`INSERT INTO agent_self_update (agent_id, capability, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(agent_id) DO UPDATE SET capability = excluded.capability, updated_at = excluded.updated_at`,
		agentID, payload, now)
	if err != nil {
		return fmt.Errorf("storing agent self-update capability: %w", err)
	}
	return nil
}

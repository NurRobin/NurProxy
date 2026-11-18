package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/google/uuid"
)

// Agent self-update coordination (#73). The orchestrator records an upgrade,
// pushes the command down the agent's stream and follows the agent's progress
// reports. A sweeper fails upgrades that stop reporting, a heartbeat that
// carries the target version completes one, and a rollout runs upgrades one
// agent at a time and stops at the first failure.

// How long an upgrade may sit in a state before the orchestrator gives up.
// restarting covers the agent's own health window (3 min) plus a rollback.
var upgradeStateTimeouts = map[models.AgentUpgradeState]time.Duration{
	models.UpgradeRequested:   2 * time.Minute,
	models.UpgradeDownloading: 15 * time.Minute,
	models.UpgradeInstalled:   5 * time.Minute,
	models.UpgradeRestarting:  10 * time.Minute,
}

// Rollout agent states.
const (
	rolloutPending   = "pending"
	rolloutUpgrading = "upgrading"
	rolloutDone      = "done"
	rolloutFailed    = "failed"
	rolloutSkipped   = "skipped"
)

// UpgradeRolloutAgent is one agent's place in a rollout.
type UpgradeRolloutAgent struct {
	AgentID     string `json:"agent_id"`
	Name        string `json:"name"`
	FromVersion string `json:"from_version"`
	State       string `json:"state"`
	UpgradeID   string `json:"upgrade_id,omitempty"`
	Error       string `json:"error,omitempty"`
}

// UpgradeRollout is a sequential "upgrade all outdated agents" run.
type UpgradeRollout struct {
	ID             string                `json:"id"`
	TargetVersion  string                `json:"target_version"`
	State          string                `json:"state"` // running | done | failed
	StartedAt      time.Time             `json:"started_at"`
	FinishedAt     *time.Time            `json:"finished_at,omitempty"`
	CurrentAgentID string                `json:"current_agent_id,omitempty"`
	Error          string                `json:"error,omitempty"`
	Agents         []UpgradeRolloutAgent `json:"agents"`
}

type upgradeCoordinator struct {
	s *Server

	mu      sync.Mutex
	rollout *UpgradeRollout
	// busy is held by a running rollout or automatic upgrade so the two never
	// overlap.
	busy bool

	poll          time.Duration
	settleTimeout time.Duration
	now           func() time.Time
}

func newUpgradeCoordinator(s *Server) *upgradeCoordinator {
	return &upgradeCoordinator{s: s, poll: 2 * time.Second, settleTimeout: 2 * time.Minute, now: time.Now}
}

// upgradeError carries the HTTP status for a refused upgrade request.
type upgradeError struct {
	status int
	msg    string
}

func (e *upgradeError) Error() string { return e.msg }

func refuse(status int, format string, args ...any) error {
	return &upgradeError{status: status, msg: fmt.Sprintf(format, args...)}
}

// resolveTarget picks the requested version or the orchestrator's own.
func (c *upgradeCoordinator) resolveTarget(requested string) (string, error) {
	if strings.TrimSpace(requested) == "" {
		v, ok := models.NormalizeReleaseVersion(c.s.version)
		if !ok {
			return "", refuse(http.StatusBadRequest, "the orchestrator runs %q, which is not a release; pass an explicit version", c.s.version)
		}
		return v, nil
	}
	v, ok := models.NormalizeReleaseVersion(requested)
	if !ok {
		return "", refuse(http.StatusBadRequest, "invalid version %q (want MAJOR.MINOR.PATCH[-PRERELEASE])", requested)
	}
	return v, nil
}

// eligibility explains why agent cannot be upgraded to target right now, or
// returns nil.
func (c *upgradeCoordinator) eligibility(agent *models.Agent, target string, su db.AgentSelfUpdate) error {
	if agent.Status != models.AgentStatusAdopted {
		return refuse(http.StatusConflict, "agent is %s; only adopted, online agents can be upgraded", agent.Status)
	}
	if c.s.hub == nil || !c.s.hub.Connected(agent.ID) {
		return refuse(http.StatusConflict, "agent is not connected")
	}
	if su.Capability != nil && !su.Capability.Supported {
		return refuse(http.StatusConflict, "agent cannot self-update: %s", su.Capability.Reason)
	}
	if cmp, ok := models.CompareReleaseVersions(agent.Version, target); ok && cmp >= 0 {
		return refuse(http.StatusConflict, "agent already runs %s; self-update only moves to newer releases", agent.Version)
	}
	return nil
}

// start records an upgrade of agent to target and pushes it to the agent.
func (c *upgradeCoordinator) start(agent *models.Agent, target, trigger, rolloutID, actor string, audit func(action, details string)) (*models.AgentUpgrade, error) {
	su, err := c.s.db.GetAgentSelfUpdate(agent.ID)
	if err != nil {
		return nil, err
	}
	if err := c.eligibility(agent, target, su); err != nil {
		return nil, err
	}
	up := &models.AgentUpgrade{
		ID: "up-" + uuid.NewString(), AgentID: agent.ID, FromVersion: agent.Version, TargetVersion: target,
		Trigger: trigger, RolloutID: rolloutID, RequestedBy: actor,
	}
	if err := c.s.db.CreateAgentUpgrade(up); err != nil {
		if errors.Is(err, db.ErrUpgradeInProgress) {
			return nil, refuse(http.StatusConflict, "%v", err)
		}
		return nil, err
	}
	audit("upgrade_requested", fmt.Sprintf("upgrade %s: %s -> %s (%s)", up.ID, agent.Version, target, trigger))
	if !c.s.hub.PublishUpgrade(agent.ID, models.UpgradeCommand{UpgradeID: up.ID, Version: target}) {
		msg := "the agent's stream did not accept the upgrade command"
		if _, after, terr := c.s.db.TransitionAgentUpgrade(up.ID, models.UpgradeFailed, msg); terr == nil {
			up = after
		}
		audit("upgrade_failed", fmt.Sprintf("upgrade %s: %s", up.ID, msg))
		return nil, refuse(http.StatusConflict, "%s", msg)
	}
	return up, nil
}

// apply records a progress report (from the agent, the heartbeat or the
// sweeper) and audits real state changes.
func (c *upgradeCoordinator) apply(id string, to models.AgentUpgradeState, errMsg string, audit func(action, details string)) (*models.AgentUpgrade, error) {
	before, after, err := c.s.db.TransitionAgentUpgrade(id, to, errMsg)
	if err != nil {
		return nil, err
	}
	if before.State != after.State {
		details := fmt.Sprintf("upgrade %s to %s: %s", after.ID, after.TargetVersion, after.State)
		if errMsg != "" {
			details += ": " + errMsg
		}
		audit("upgrade_"+string(after.State), details)
	}
	return after, nil
}

func (c *upgradeCoordinator) systemAudit(actor, agentID string) func(action, details string) {
	return func(action, details string) {
		if err := c.s.db.InsertAuditLog(&models.AuditLogEntry{
			EntityType: "agent", EntityID: agentID, Action: action, Actor: actor, Source: "system", Details: details,
		}); err != nil {
			log.Printf("failed to insert audit log: %v", err)
		}
	}
}

// observeVersion completes an unfinished upgrade once the agent reports the
// target version (a lost "done" report must not leave it hanging).
func (c *upgradeCoordinator) observeVersion(agentID, version string, audit func(action, details string)) {
	up, err := c.s.db.ActiveAgentUpgrade(agentID)
	if err != nil || up == nil {
		return
	}
	if v, ok := models.NormalizeReleaseVersion(version); !ok || v != up.TargetVersion {
		return
	}
	if _, err := c.apply(up.ID, models.UpgradeDone, "", audit); err != nil && !errors.Is(err, db.ErrUpgradeTransition) {
		log.Printf("upgrade %s: completing from heartbeat: %v", up.ID, err)
	}
}

// sweep fails upgrades that stopped making progress.
func (c *upgradeCoordinator) sweep() {
	active, err := c.s.db.ListActiveAgentUpgrades()
	if err != nil {
		log.Printf("upgrade sweep: %v", err)
		return
	}
	now := c.now()
	for _, up := range active {
		limit := upgradeStateTimeouts[up.State]
		if limit == 0 || now.Sub(up.UpdatedAt) < limit {
			continue
		}
		msg := fmt.Sprintf("no progress from the agent for %s while %s", limit, up.State)
		if up.State == models.UpgradeRestarting {
			msg = fmt.Sprintf("the agent did not come back reporting %s within %s", up.TargetVersion, limit)
		}
		if _, err := c.apply(up.ID, models.UpgradeFailed, msg, c.systemAudit("upgrade-sweeper", up.AgentID)); err != nil && !errors.Is(err, db.ErrUpgradeTransition) {
			log.Printf("upgrade sweep %s: %v", up.ID, err)
		}
	}
}

func (c *upgradeCoordinator) tryAcquire() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.busy {
		return false
	}
	c.busy = true
	return true
}

func (c *upgradeCoordinator) release() {
	c.mu.Lock()
	c.busy = false
	c.mu.Unlock()
}

// snapshot returns a copy of the latest rollout, or nil.
func (c *upgradeCoordinator) snapshot() *UpgradeRollout {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rollout == nil {
		return nil
	}
	cp := *c.rollout
	cp.Agents = append([]UpgradeRolloutAgent(nil), c.rollout.Agents...)
	return &cp
}

func (c *upgradeCoordinator) update(fn func(r *UpgradeRollout)) {
	c.mu.Lock()
	fn(c.rollout)
	c.mu.Unlock()
}

// startRollout plans a rollout of every adopted agent older than target and
// runs it in the background.
func (c *upgradeCoordinator) startRollout(ctx context.Context, target, actor string) (*UpgradeRollout, error) {
	agents, err := c.s.db.ListAgents()
	if err != nil {
		return nil, err
	}
	selfUpdate, err := c.s.db.ListAgentSelfUpdate()
	if err != nil {
		return nil, err
	}
	r := &UpgradeRollout{ID: "rollout-" + uuid.NewString(), TargetVersion: target, State: "running", StartedAt: c.now().UTC()}
	for i := range agents {
		a := &agents[i]
		if a.Status != models.AgentStatusAdopted && a.Status != models.AgentStatusOffline {
			continue
		}
		cmp, ok := models.CompareReleaseVersions(a.Version, target)
		if !ok || cmp >= 0 {
			continue
		}
		ra := UpgradeRolloutAgent{AgentID: a.ID, Name: a.Name, FromVersion: a.Version, State: rolloutPending}
		if err := c.eligibility(a, target, selfUpdate[a.ID]); err != nil {
			ra.State, ra.Error = rolloutSkipped, err.Error()
		}
		r.Agents = append(r.Agents, ra)
	}
	pending := 0
	for _, ra := range r.Agents {
		if ra.State == rolloutPending {
			pending++
		}
	}
	if pending == 0 {
		return nil, refuse(http.StatusConflict, "no connected agent that can self-update is older than %s", target)
	}
	if !c.tryAcquire() {
		return nil, refuse(http.StatusConflict, "another rollout or automatic upgrade is running")
	}
	c.mu.Lock()
	c.rollout = r
	c.mu.Unlock()
	c.systemAudit(actor, "")("upgrade_rollout_started", fmt.Sprintf("rollout %s to %s over %d agent(s)", r.ID, target, pending))
	go func() {
		defer c.release()
		c.runRollout(ctx, r.ID, target, actor)
	}()
	return c.snapshot(), nil
}

func (c *upgradeCoordinator) runRollout(ctx context.Context, rolloutID, target, actor string) {
	finish := func(state, errMsg string) {
		now := c.now().UTC()
		c.update(func(r *UpgradeRollout) {
			r.State, r.Error, r.FinishedAt, r.CurrentAgentID = state, errMsg, &now, ""
			if state == "failed" {
				for i := range r.Agents {
					if r.Agents[i].State == rolloutPending {
						r.Agents[i].State, r.Agents[i].Error = rolloutSkipped, "rollout stopped"
					}
				}
			}
		})
		details := fmt.Sprintf("rollout %s to %s: %s", rolloutID, target, state)
		if errMsg != "" {
			details += ": " + errMsg
		}
		c.systemAudit(actor, "")("upgrade_rollout_"+state, details)
	}
	plan := c.snapshot()
	for i, ra := range plan.Agents {
		if ra.State != rolloutPending {
			continue
		}
		setAgent := func(state, upgradeID, errMsg string) {
			c.update(func(r *UpgradeRollout) {
				r.Agents[i].State, r.Agents[i].Error = state, errMsg
				if upgradeID != "" {
					r.Agents[i].UpgradeID = upgradeID
				}
				r.CurrentAgentID = ra.AgentID
			})
		}
		setAgent(rolloutUpgrading, "", "")
		agent, err := c.s.db.GetAgent(ra.AgentID)
		if err != nil {
			setAgent(rolloutFailed, "", "agent disappeared")
			finish("failed", fmt.Sprintf("agent %s disappeared", ra.Name))
			return
		}
		up, err := c.start(agent, target, models.UpgradeTriggerRollout, rolloutID, actor, c.systemAudit(actor, agent.ID))
		if err != nil {
			setAgent(rolloutFailed, "", err.Error())
			finish("failed", fmt.Sprintf("agent %s: %v", agentLabel(agent), err))
			return
		}
		setAgent(rolloutUpgrading, up.ID, "")
		if err := c.waitHealthy(ctx, up.ID, agent.ID, target); err != nil {
			setAgent(rolloutFailed, up.ID, err.Error())
			finish("failed", fmt.Sprintf("agent %s: %v", agentLabel(agent), err))
			return
		}
		setAgent(rolloutDone, up.ID, "")
	}
	finish("done", "")
}

func agentLabel(a *models.Agent) string {
	if a.Name != "" {
		return a.Name
	}
	return a.FQDN
}

// waitHealthy waits until the upgrade finished and the agent is back online
// on the target version with a live stream.
func (c *upgradeCoordinator) waitHealthy(ctx context.Context, upgradeID, agentID, target string) error {
	ticker := time.NewTicker(c.poll)
	defer ticker.Stop()
	var settleDeadline time.Time
	for {
		up, err := c.s.db.GetAgentUpgrade(upgradeID)
		if err != nil {
			return err
		}
		switch up.State {
		case models.UpgradeFailed, models.UpgradeRolledBack:
			if up.Error != "" {
				return fmt.Errorf("upgrade %s: %s", up.State, up.Error)
			}
			return fmt.Errorf("upgrade %s", up.State)
		case models.UpgradeDone:
			if settleDeadline.IsZero() {
				settleDeadline = c.now().Add(c.settleTimeout)
			}
			agent, err := c.s.db.GetAgent(agentID)
			if err == nil && agent.Status == models.AgentStatusAdopted && c.s.hub.Connected(agentID) {
				if v, ok := models.NormalizeReleaseVersion(agent.Version); ok && v == target {
					return nil
				}
			}
			if c.now().After(settleDeadline) {
				return fmt.Errorf("agent did not come back online on %s within %s", target, c.settleTimeout)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// autoUpgradeOnce starts at most one automatic upgrade for an agent that
// opted in, is older than the orchestrator and has not already failed to reach
// this version.
func (c *upgradeCoordinator) autoUpgradeOnce(ctx context.Context) {
	target, ok := models.NormalizeReleaseVersion(c.s.version)
	if !ok || c.s.hub == nil {
		return
	}
	settings, err := c.s.db.ListAgentSelfUpdate()
	if err != nil {
		log.Printf("auto-upgrade: %v", err)
		return
	}
	for agentID, su := range settings {
		if !su.AutoUpgrade {
			continue
		}
		agent, err := c.s.db.GetAgent(agentID)
		if err != nil {
			continue
		}
		if c.eligibility(agent, target, su) != nil {
			continue
		}
		if active, _ := c.s.db.ActiveAgentUpgrade(agentID); active != nil {
			continue
		}
		if failed, err := c.s.db.HasUnsuccessfulUpgrade(agentID, target); err != nil || failed {
			continue
		}
		if !c.tryAcquire() {
			return
		}
		up, err := c.start(agent, target, models.UpgradeTriggerAuto, "", "auto-upgrade", c.systemAudit("auto-upgrade", agentID))
		if err != nil {
			c.release()
			log.Printf("auto-upgrade of agent %s: %v", agentID, err)
			continue
		}
		go func() {
			defer c.release()
			if err := c.waitHealthy(ctx, up.ID, agentID, target); err != nil {
				log.Printf("auto-upgrade of agent %s: %v", agentID, err)
			}
		}()
		return
	}
}

// StartUpgradeLoop runs the upgrade sweeper and the opt-in automatic upgrades
// until ctx ends.
func (s *Server) StartUpgradeLoop(ctx context.Context) {
	s.lifetime = ctx
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		tick := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			s.upgrades.sweep()
			tick++
			if tick%4 == 0 {
				s.upgrades.autoUpgradeOnce(ctx)
			}
		}
	}()
}

func writeUpgradeError(w http.ResponseWriter, err error) {
	var ue *upgradeError
	if errors.As(err, &ue) {
		writeError(w, ue.status, ue.msg)
		return
	}
	log.Printf("agent upgrade: %v", err)
	writeError(w, http.StatusInternalServerError, "upgrade failed")
}

// readOptionalVersion decodes {"version": "..."} from an optional body.
func readOptionalVersion(r *http.Request) (string, error) {
	var req struct {
		Version string `json:"version"`
	}
	if r.Body == nil {
		return "", nil
	}
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 4096))
	if err != nil {
		return "", fmt.Errorf("reading request body: %w", err)
	}
	if strings.TrimSpace(string(body)) == "" {
		return "", nil
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return "", fmt.Errorf("invalid JSON body: %w", err)
	}
	return req.Version, nil
}

// POST /api/v1/agents/{id}/upgrade
func (s *Server) handleUpgradeAgent(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	requested, err := readOptionalVersion(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	agent, err := s.db.GetAgent(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	target, err := s.upgrades.resolveTarget(requested)
	if err != nil {
		writeUpgradeError(w, err)
		return
	}
	actor, _ := r.Context().Value(ctxActor).(string)
	up, err := s.upgrades.start(agent, target, models.UpgradeTriggerManual, "", actor, func(action, details string) {
		s.audit(r, "agent", id, action, details)
	})
	if err != nil {
		writeUpgradeError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, up)
}

// GET /api/v1/agents/{id}/upgrades
func (s *Server) handleListAgentUpgrades(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	if _, err := s.db.GetAgent(id); err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	ups, err := s.db.ListAgentUpgrades(id, 20)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list upgrades")
		return
	}
	writeJSON(w, http.StatusOK, ups)
}

// PUT /api/v1/agents/{id}/auto-upgrade
func (s *Server) handleSetAutoUpgrade(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil || req.Enabled == nil {
		writeError(w, http.StatusBadRequest, `body must be {"enabled": true|false}`)
		return
	}
	if _, err := s.db.GetAgent(id); err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if err := s.db.SetAgentAutoUpgrade(id, *req.Enabled); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update auto-upgrade")
		return
	}
	s.audit(r, "agent", id, "auto_upgrade", fmt.Sprintf("auto_upgrade=%t", *req.Enabled))
	writeJSON(w, http.StatusOK, map[string]bool{"auto_upgrade": *req.Enabled})
}

// POST /api/v1/agents/upgrade-outdated
func (s *Server) handleUpgradeOutdated(w http.ResponseWriter, r *http.Request) {
	requested, err := readOptionalVersion(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	target, err := s.upgrades.resolveTarget(requested)
	if err != nil {
		writeUpgradeError(w, err)
		return
	}
	actor, _ := r.Context().Value(ctxActor).(string)
	// The rollout outlives this request, so it runs on the server's lifetime
	// context rather than the request's.
	rollout, err := s.upgrades.startRollout(s.lifetimeContext(), target, actor)
	if err != nil {
		writeUpgradeError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, rollout)
}

// GET /api/v1/agents/upgrade-rollout
func (s *Server) handleGetUpgradeRollout(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]*UpgradeRollout{"rollout": s.upgrades.snapshot()})
}

// POST /api/v1/agents/{id}/upgrade/report  (agent auth)
func (s *Server) handleAgentUpgradeReport(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	if callerID, _ := r.Context().Value(ctxAgentID).(string); callerID != id {
		writeError(w, http.StatusForbidden, "agent can only report its own upgrades")
		return
	}
	var rep models.UpgradeReport
	if err := readJSON(r, &rep); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !models.ValidUpgradeID(rep.UpgradeID) || !rep.State.Valid() || rep.State == models.UpgradeRequested {
		writeError(w, http.StatusBadRequest, "invalid upgrade report")
		return
	}
	up, err := s.db.GetAgentUpgrade(rep.UpgradeID)
	if err != nil || up.AgentID != id {
		writeError(w, http.StatusNotFound, "upgrade not found")
		return
	}
	// The final word on success is the version the agent runs: a "done" from a
	// binary that is not the target is recorded as a failure.
	state, errMsg := rep.State, rep.Error
	if state == models.UpgradeDone {
		if v, ok := models.NormalizeReleaseVersion(rep.Version); !ok || v != up.TargetVersion {
			state, errMsg = models.UpgradeFailed, fmt.Sprintf("agent reported done but runs %q", rep.Version)
		}
	}
	after, err := s.upgrades.apply(up.ID, state, errMsg, func(action, details string) {
		s.audit(r, "agent", id, action, details)
	})
	if errors.Is(err, db.ErrUpgradeTransition) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to record upgrade report")
		return
	}
	writeJSON(w, http.StatusOK, after)
}

// attachUpgradeInfo adds the self-update fields to listed agents.
func (s *Server) attachUpgradeInfo(agents []models.Agent) {
	latest, err := s.db.LatestAgentUpgrades()
	if err != nil {
		log.Printf("listing agent upgrades: %v", err)
	}
	settings, err := s.db.ListAgentSelfUpdate()
	if err != nil {
		log.Printf("listing agent self-update settings: %v", err)
	}
	for i := range agents {
		a := &agents[i]
		a.Upgrade = latest[a.ID]
		if su, ok := settings[a.ID]; ok {
			a.AutoUpgrade = su.AutoUpgrade
			a.SelfUpdate = su.Capability
		}
	}
}

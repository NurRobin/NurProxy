package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/failover"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// ErrInvalidBackups marks a backup server list that SetDomainBackups refuses;
// the API maps it to 400.
var ErrInvalidBackups = errors.New("invalid backup servers")

// StandbyArtifactID is the artifact and managed resource identity of a
// domain's standby route on a backup agent. Artifacts belong to one agent, so
// the standby copy cannot share the primary's "dom-<id>". The agent id is
// hashed to keep the id short and inside the helper's id alphabet.
func StandbyArtifactID(domainID int64, agentID string) string {
	sum := sha256.Sum256([]byte(agentID))
	return domainArtifactID(domainID) + "-sb-" + hex.EncodeToString(sum[:6])
}

// standbyRenamedResourceID names the tombstone of a standby vhost left behind
// by a rename, for the same reason as renamedRouteResourceID.
func standbyRenamedResourceID(domainID int64, agentID, oldHost string) string {
	sum := sha256.Sum256([]byte(oldHost))
	return StandbyArtifactID(domainID, agentID) + "-was-" + hex.EncodeToString(sum[:8])
}

// DomainBackup is one backup server of a domain.
type DomainBackup struct {
	ServerID string
	AgentID  string
	Priority int
}

// ListDomainBackups returns a domain's backup servers, most preferred first.
func (d *DB) ListDomainBackups(domainID int64) ([]DomainBackup, error) {
	rows, err := d.read.Query(`
		SELECT b.server_id, s.agent_id, b.priority
		FROM domain_backups b JOIN servers s ON s.id = b.server_id
		WHERE b.domain_id = ?
		ORDER BY b.priority, b.server_id`, domainID)
	if err != nil {
		return nil, fmt.Errorf("listing backups of domain %d: %w", domainID, err)
	}
	defer rows.Close()
	var out []DomainBackup
	for rows.Next() {
		var b DomainBackup
		if err := rows.Scan(&b.ServerID, &b.AgentID, &b.Priority); err != nil {
			return nil, fmt.Errorf("scanning backup: %w", err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// StandbyDomain is a domain an agent holds as warm standby, with the backup
// server on that agent its route proxies to.
type StandbyDomain struct {
	Domain models.Domain
	Server models.Server
}

// ListStandbyDomains returns the domains for which one of agentID's servers is
// a backup. Domains being deleted are included; callers skip them like their
// primary domains.
func (d *DB) ListStandbyDomains(agentID string) ([]StandbyDomain, error) {
	rows, err := d.read.Query(`
		SELECT b.domain_id, b.server_id
		FROM domain_backups b
		JOIN servers s ON s.id = b.server_id
		JOIN domains dm ON dm.id = b.domain_id
		WHERE s.agent_id = ?
		ORDER BY dm.created_at, dm.id`, agentID)
	if err != nil {
		return nil, fmt.Errorf("listing standby domains of agent %s: %w", agentID, err)
	}
	type pair struct {
		domainID int64
		serverID string
	}
	var pairs []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.domainID, &p.serverID); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scanning standby domain: %w", err)
		}
		pairs = append(pairs, p)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]StandbyDomain, 0, len(pairs))
	for _, p := range pairs {
		dom, err := d.GetDomain(p.domainID)
		if errors.Is(err, ErrDomainNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		srv, err := d.GetServer(p.serverID)
		if err != nil {
			continue
		}
		out = append(out, StandbyDomain{Domain: *dom, Server: *srv})
	}
	return out, nil
}

// DomainCandidate is a server that may serve a domain, with its agent.
type DomainCandidate struct {
	Server  models.Server
	Agent   models.Agent
	Primary bool
	// Priority is 0 for the primary, then the backup's position.
	Priority int
	// ServesZone reports whether the agent serves the domain's zone. The
	// primary always counts as serving it: it was bound before backups
	// existed and nothing ever required it.
	ServesZone bool
	// Ready: the agent acknowledged the standby route with its certificate
	// in place. Always true for the primary. NotReady says why not.
	Ready    bool
	NotReady string
}

// DomainCandidates returns the primary server of dom followed by its backups,
// most preferred first. A backup whose server or agent no longer resolves is
// left out; an unresolvable primary is an error.
func (d *DB) DomainCandidates(dom *models.Domain) ([]DomainCandidate, error) {
	srv, err := d.GetServer(dom.ServerID)
	if err != nil {
		return nil, fmt.Errorf("resolving primary server %s: %w", dom.ServerID, err)
	}
	agent, err := d.GetAgent(srv.AgentID)
	if err != nil {
		return nil, fmt.Errorf("resolving agent %s: %w", srv.AgentID, err)
	}
	out := []DomainCandidate{{Server: *srv, Agent: *agent, Primary: true, ServesZone: true, Ready: true}}
	backups, err := d.ListDomainBackups(dom.ID)
	if err != nil {
		return nil, err
	}
	standby, err := d.standbyStatus(dom.ID)
	if err != nil {
		return nil, err
	}
	for _, b := range backups {
		bs, err := d.GetServer(b.ServerID)
		if err != nil {
			continue
		}
		ba, err := d.GetAgent(bs.AgentID)
		if err != nil {
			continue
		}
		serves, err := d.agentServesZone(ba.ID, dom.ZoneID)
		if err != nil {
			return nil, err
		}
		c := DomainCandidate{Server: *bs, Agent: *ba, Priority: b.Priority, ServesZone: serves}
		if s, ok := standby[ba.ID]; !ok {
			c.NotReady = "standby route not applied yet"
		} else if !s.ready {
			c.NotReady = s.reason
		} else {
			c.Ready = true
		}
		out = append(out, c)
	}
	return out, nil
}

func (d *DB) agentServesZone(agentID, zoneID string) (bool, error) {
	var one int
	err := d.read.QueryRow(`SELECT 1 FROM agent_zones WHERE agent_id = ? AND zone_id = ?`, agentID, zoneID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checking zone %s of agent %s: %w", zoneID, agentID, err)
	}
	return true, nil
}

// SetDomainBackups replaces a domain's backup servers with serverIDs, most
// preferred first, and returns the agents that lost their standby route (to
// be pushed so they drop it). Each backup must sit on its own agent, other
// than the primary's, and a newly added one on an agent that serves the
// domain's zone; cert-only and deleting domains take no new backups. Keeping
// or dropping existing backups is always allowed, so a backup whose agent
// left the zone never blocks removing another one. A standby route an
// nginx/apache agent loses gets a route tombstone, like a domain moved away
// (#148); an empty list also drops the stored failover state, so the record
// returns to the primary.
func (d *DB) SetDomainBackups(domainID int64, serverIDs []string, at time.Time) ([]string, error) {
	dom, err := d.GetDomain(domainID)
	if err != nil {
		return nil, err
	}
	current, err := d.ListDomainBackups(domainID)
	if err != nil {
		return nil, err
	}
	existing := make(map[string]bool, len(current))
	for _, b := range current {
		existing[b.ServerID] = true
	}
	adding := false
	for _, id := range serverIDs {
		adding = adding || !existing[id]
	}
	if adding {
		if dom.CertOnly {
			return nil, fmt.Errorf("%w: a cert-only domain has no DNS record to switch", ErrInvalidBackups)
		}
		if dom.Status == models.DomainStatusDeleting {
			return nil, fmt.Errorf("%w: the domain is being deleted", ErrInvalidBackups)
		}
	}
	if len(serverIDs) > failover.MaxBackups {
		return nil, fmt.Errorf("%w: at most %d backup servers", ErrInvalidBackups, failover.MaxBackups)
	}
	primary, err := d.GetServer(dom.ServerID)
	if err != nil {
		return nil, fmt.Errorf("resolving primary server %s: %w", dom.ServerID, err)
	}
	newAgents := make(map[string]string, len(serverIDs)) // agent -> server
	for _, id := range serverIDs {
		srv, err := d.GetServer(id)
		if err != nil {
			return nil, fmt.Errorf("%w: server %s not found", ErrInvalidBackups, id)
		}
		if srv.ID == primary.ID {
			return nil, fmt.Errorf("%w: server %s is the domain's primary server", ErrInvalidBackups, srv.Name)
		}
		if srv.AgentID == primary.AgentID {
			return nil, fmt.Errorf("%w: server %s is on the primary's agent; a backup must run on another agent", ErrInvalidBackups, srv.Name)
		}
		if other, dup := newAgents[srv.AgentID]; dup {
			return nil, fmt.Errorf("%w: servers %s and %s are on the same agent; use one backup per agent", ErrInvalidBackups, other, srv.ID)
		}
		if !existing[srv.ID] {
			serves, err := d.agentServesZone(srv.AgentID, dom.ZoneID)
			if err != nil {
				return nil, err
			}
			if !serves {
				return nil, fmt.Errorf("%w: the agent of server %s does not serve this domain's zone", ErrInvalidBackups, srv.Name)
			}
		}
		newAgents[srv.AgentID] = srv.ID
	}

	var removed []string
	for _, b := range current {
		if _, kept := newAgents[b.AgentID]; !kept {
			removed = append(removed, b.AgentID)
		}
	}
	if err := d.checkActiveBackupKept(dom, current, newAgents, at); err != nil {
		return nil, err
	}
	zone, err := d.GetZone(dom.ZoneID)
	if err != nil {
		return nil, fmt.Errorf("resolving zone %s: %w", dom.ZoneID, err)
	}
	host := dom.FQDN(zone.Name)
	if !dom.CertOnly {
		for _, agentID := range removed {
			if err := d.tombstoneStandby(agentID, StandbyArtifactID(domainID, agentID), host, at); err != nil {
				return nil, err
			}
		}
		for agentID := range newAgents {
			if err := d.claimRouteOnAgent(agentID, StandbyArtifactID(domainID, agentID), host); err != nil {
				return nil, err
			}
		}
	}

	tx, err := d.sql.Begin()
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`DELETE FROM domain_backups WHERE domain_id = ?`, domainID); err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("clearing backups of domain %d: %w", domainID, err)
	}
	for i, id := range serverIDs {
		if _, err := tx.Exec(`INSERT INTO domain_backups (domain_id, server_id, priority) VALUES (?, ?, ?)`, domainID, id, i+1); err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("storing backup %s of domain %d: %w", id, domainID, err)
		}
	}
	// The standby status of an agent that lost the route no longer says
	// anything; a later re-add starts from "not applied yet".
	for _, agentID := range removed {
		if _, err := tx.Exec(`DELETE FROM domain_standby_status WHERE domain_id = ? AND agent_id = ?`, domainID, agentID); err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("clearing standby status of domain %d: %w", domainID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	// The standby artifact rows are keyed to the agent that lost the route;
	// that agent no longer reports them.
	for _, agentID := range removed {
		id := StandbyArtifactID(domainID, agentID)
		if _, err := d.GetConfigArtifact(id); err == nil {
			if err := d.DeleteConfigArtifact(id); err != nil {
				return removed, fmt.Errorf("removing standby artifact %s: %w", id, err)
			}
		}
	}
	return removed, nil
}

// ErrActiveBackupInUse refuses removing the backup the domain's record points
// at while no remaining candidate could take over; the API maps it to 409.
var ErrActiveBackupInUse = errors.New("backup server is serving the domain")

// checkActiveBackupKept refuses a backup list that drops the server the
// record currently points at when no other candidate that stays (primary or
// kept backup) is healthy and ready: the record would have to move to a down
// agent. The record is never moved by a list edit itself; the next DNS pass
// moves it to the first healthy candidate.
func (d *DB) checkActiveBackupKept(dom *models.Domain, current []DomainBackup, kept map[string]string, now time.Time) error {
	st, err := d.GetDomainFailover(dom.ID)
	if err != nil || st.ActiveServerID == "" || st.ActiveServerID == dom.ServerID {
		return err
	}
	var activeAgent string
	for _, b := range current {
		if b.ServerID == st.ActiveServerID {
			activeAgent = b.AgentID
		}
	}
	if activeAgent == "" {
		return nil
	}
	if srv, ok := kept[activeAgent]; ok && srv == st.ActiveServerID {
		return nil
	}
	status, err := d.DomainFailoverStatus(dom, now)
	if err != nil {
		return err
	}
	for _, c := range status.Candidates {
		if c.ServerID == st.ActiveServerID || !c.Healthy {
			continue
		}
		if c.Primary || kept[c.AgentID] == c.ServerID {
			return nil
		}
	}
	return fmt.Errorf("%w: the DNS record points at backup server %s and no other server that stays is healthy; keep it until the primary or another backup is back", ErrActiveBackupInUse, st.ActiveServerID)
}

// tombstoneStandby persists a route deletion on an nginx/apache agent; Caddy
// agents drop a route by leaving it out of the full sync.
func (d *DB) tombstoneStandby(agentID, resourceID, host string, at time.Time) error {
	agent, err := d.GetAgent(agentID)
	if err != nil {
		return nil // agent gone: nothing left to clean up on it
	}
	backend := managedBackendForAgent(agent)
	if backend != "nginx" && backend != "apache" {
		return nil
	}
	deletion := helperprotocol.ManagedDeletion{ResourceID: resourceID, Host: host, Backend: backend}
	if err := d.UpsertManagedRouteTombstone(agentID, deletion, at); err != nil {
		return fmt.Errorf("persisting standby route deletion on agent %s: %w", agentID, err)
	}
	return nil
}

// claimRouteOnAgent drops pending tombstones on agentID that a route with
// resourceID for host would collide with (see ClaimDomainRoute).
func (d *DB) claimRouteOnAgent(agentID, resourceID, host string) error {
	if !validRecoverySemanticID(agentID) {
		return nil
	}
	pending, err := d.ListManagedRouteTombstones(agentID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	file := helperprotocol.ManagedVhostKey(host)
	stale := make([]helperprotocol.ManagedDeletion, 0)
	for _, deletion := range pending {
		if deletion.ResourceID == resourceID || helperprotocol.ManagedVhostKey(deletion.Host) == file {
			stale = append(stale, deletion)
		}
	}
	return d.DeleteManagedRouteTombstones(agentID, stale)
}

// TombstoneStandbyRoutes persists the deletion of dom's standby routes on its
// nginx/apache backup agents, for a domain that is being deleted. It returns
// every backup agent, so the caller can push them. Idempotent.
func (d *DB) TombstoneStandbyRoutes(dom *models.Domain, at time.Time) ([]string, error) {
	backups, err := d.ListDomainBackups(dom.ID)
	if err != nil || len(backups) == 0 {
		return nil, err
	}
	agents := make([]string, 0, len(backups))
	for _, b := range backups {
		agents = append(agents, b.AgentID)
	}
	if dom.CertOnly {
		return agents, nil
	}
	zone, err := d.GetZone(dom.ZoneID)
	if err != nil {
		return agents, fmt.Errorf("resolving zone %s: %w", dom.ZoneID, err)
	}
	host := dom.FQDN(zone.Name)
	for _, agentID := range agents {
		if err := d.tombstoneStandby(agentID, StandbyArtifactID(dom.ID, agentID), host, at); err != nil {
			return agents, err
		}
	}
	return agents, nil
}

// DomainsBackedByServer lists the ids of the domains that use serverID as a
// backup.
func (d *DB) DomainsBackedByServer(serverID string) ([]int64, error) {
	rows, err := d.read.Query(`SELECT domain_id FROM domain_backups WHERE server_id = ? ORDER BY domain_id`, serverID)
	if err != nil {
		return nil, fmt.Errorf("listing domains backed by server %s: %w", serverID, err)
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// RemoveServerFromBackups drops serverID from every backup list it is on,
// through SetDomainBackups so the standby routes get their tombstones. It
// returns the agents to push.
func (d *DB) RemoveServerFromBackups(serverID string, at time.Time) ([]string, error) {
	ids, err := d.DomainsBackedByServer(serverID)
	if err != nil {
		return nil, err
	}
	var agents []string
	for _, id := range ids {
		backups, err := d.ListDomainBackups(id)
		if err != nil {
			return agents, err
		}
		keep := make([]string, 0, len(backups))
		for _, b := range backups {
			if b.ServerID != serverID {
				keep = append(keep, b.ServerID)
			}
		}
		removed, err := d.SetDomainBackups(id, keep, at)
		if err != nil {
			return agents, err
		}
		agents = append(agents, removed...)
	}
	return agents, nil
}

// GetDomainFailover returns the stored failover state of a domain, or a zero
// state (with DomainID set) when none is stored.
func (d *DB) GetDomainFailover(domainID int64) (models.DomainFailoverState, error) {
	st := models.DomainFailoverState{DomainID: domainID}
	var pendingSince, switchedAt, evaluatedAt, settleSince sql.NullString
	var allDown int
	err := d.read.QueryRow(`
		SELECT active_server_id, pending_server_id, pending_since, all_down, switched_at, switches, evaluated_at, settle_since
		FROM domain_failover WHERE domain_id = ?`, domainID).Scan(
		&st.ActiveServerID, &st.PendingServerID, &pendingSince, &allDown, &switchedAt, &st.Switches, &evaluatedAt, &settleSince)
	if errors.Is(err, sql.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("reading failover state of domain %d: %w", domainID, err)
	}
	st.AllDown = allDown != 0
	st.PendingSince = parseNullTime(pendingSince)
	st.SwitchedAt = parseNullTime(switchedAt)
	st.EvaluatedAt = parseNullTime(evaluatedAt)
	st.SettleSince = parseNullTime(settleSince)
	return st, nil
}

// SaveDomainFailover stores a domain's failover state. A domain that was
// deleted meanwhile is skipped.
func (d *DB) SaveDomainFailover(st models.DomainFailoverState) error {
	_, err := d.sql.Exec(`
		INSERT INTO domain_failover (domain_id, active_server_id, pending_server_id, pending_since, all_down, switched_at, switches, evaluated_at, settle_since)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM domains WHERE id = ?)
		ON CONFLICT(domain_id) DO UPDATE SET
			active_server_id = excluded.active_server_id,
			pending_server_id = excluded.pending_server_id,
			pending_since = excluded.pending_since,
			all_down = excluded.all_down,
			switched_at = excluded.switched_at,
			switches = excluded.switches,
			evaluated_at = excluded.evaluated_at,
			settle_since = excluded.settle_since`,
		st.DomainID, st.ActiveServerID, st.PendingServerID, formatNullTime(st.PendingSince),
		boolToInt(st.AllDown), formatNullTime(st.SwitchedAt), st.Switches,
		formatNullTime(st.EvaluatedAt), formatNullTime(st.SettleSince), st.DomainID)
	if err != nil {
		return fmt.Errorf("storing failover state of domain %d: %w", st.DomainID, err)
	}
	return nil
}

// DeleteDomainFailover drops a domain's stored failover state, for a domain
// that has no backups any more. Callers hold the domain's DNS lock.
func (d *DB) DeleteDomainFailover(domainID int64) error {
	if _, err := d.sql.Exec(`DELETE FROM domain_failover WHERE domain_id = ?`, domainID); err != nil {
		return fmt.Errorf("clearing failover state of domain %d: %w", domainID, err)
	}
	return nil
}

type standbyState struct {
	ready  bool
	reason string
}

func (d *DB) standbyStatus(domainID int64) (map[string]standbyState, error) {
	rows, err := d.read.Query(`SELECT agent_id, ready, reason FROM domain_standby_status WHERE domain_id = ?`, domainID)
	if err != nil {
		return nil, fmt.Errorf("reading standby status of domain %d: %w", domainID, err)
	}
	defer rows.Close()
	out := make(map[string]standbyState)
	for rows.Next() {
		var agentID string
		var ready int
		var s standbyState
		if err := rows.Scan(&agentID, &ready, &s.reason); err != nil {
			return nil, err
		}
		s.ready = ready != 0
		out[agentID] = s
	}
	return out, rows.Err()
}

// RecordStandbyApply stores the outcome of a backup agent's last standby
// apply for a domain: ready, or the reason it is not (apply error, missing
// certificate). Only a backup agent of the domain is recorded.
func (d *DB) RecordStandbyApply(domainID int64, agentID string, ready bool, reason string) error {
	_, err := d.sql.Exec(`
		INSERT INTO domain_standby_status (domain_id, agent_id, ready, reason, updated_at)
		SELECT ?, ?, ?, ?, ? WHERE EXISTS (
			SELECT 1 FROM domain_backups b JOIN servers s ON s.id = b.server_id
			WHERE b.domain_id = ? AND s.agent_id = ?)
		ON CONFLICT(domain_id, agent_id) DO UPDATE SET
			ready = excluded.ready, reason = excluded.reason, updated_at = excluded.updated_at`,
		domainID, agentID, boolToInt(ready), reason, time.Now().UTC().Format(time.RFC3339Nano), domainID, agentID)
	if err != nil {
		return fmt.Errorf("storing standby status of domain %d on agent %s: %w", domainID, agentID, err)
	}
	return nil
}

// ListDomainFailoverStates returns every stored failover state, keyed by
// domain id.
func (d *DB) ListDomainFailoverStates() (map[int64]models.DomainFailoverState, error) {
	rows, err := d.read.Query(`
		SELECT domain_id, active_server_id, pending_server_id, pending_since, all_down, switched_at, switches, evaluated_at, settle_since
		FROM domain_failover`)
	if err != nil {
		return nil, fmt.Errorf("listing failover states: %w", err)
	}
	defer rows.Close()
	out := make(map[int64]models.DomainFailoverState)
	for rows.Next() {
		var st models.DomainFailoverState
		var pendingSince, switchedAt, evaluatedAt, settleSince sql.NullString
		var allDown int
		if err := rows.Scan(&st.DomainID, &st.ActiveServerID, &st.PendingServerID, &pendingSince, &allDown, &switchedAt, &st.Switches, &evaluatedAt, &settleSince); err != nil {
			return nil, err
		}
		st.EvaluatedAt = parseNullTime(evaluatedAt)
		st.SettleSince = parseNullTime(settleSince)
		st.AllDown = allDown != 0
		st.PendingSince = parseNullTime(pendingSince)
		st.SwitchedAt = parseNullTime(switchedAt)
		out[st.DomainID] = st
	}
	return out, rows.Err()
}

// FillDomainFailover sets BackupServerIDs and ActiveServerID on each domain.
// A domain without backups is active on its primary.
func (d *DB) FillDomainFailover(doms []models.Domain) error {
	if len(doms) == 0 {
		return nil
	}
	rows, err := d.read.Query(`SELECT domain_id, server_id FROM domain_backups ORDER BY domain_id, priority, server_id`)
	if err != nil {
		return fmt.Errorf("listing domain backups: %w", err)
	}
	backups := make(map[int64][]string)
	for rows.Next() {
		var id int64
		var srv string
		if err := rows.Scan(&id, &srv); err != nil {
			_ = rows.Close()
			return err
		}
		backups[id] = append(backups[id], srv)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	states, err := d.ListDomainFailoverStates()
	if err != nil {
		return err
	}
	for i := range doms {
		dom := &doms[i]
		dom.BackupServerIDs = backups[dom.ID]
		dom.ActiveServerID = dom.ServerID
		if len(dom.BackupServerIDs) == 0 {
			continue
		}
		if st, ok := states[dom.ID]; ok && st.ActiveServerID != "" {
			for _, id := range dom.BackupServerIDs {
				if id == st.ActiveServerID {
					dom.ActiveServerID = id
				}
			}
		}
	}
	return nil
}

func parseNullTime(s sql.NullString) *time.Time {
	if !s.Valid || s.String == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, s.String)
	if err != nil {
		return nil
	}
	return &t
}

func formatNullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// CheckPrimaryServer refuses a new primary server for domainID that sits on
// the agent of one of the domain's backups: one agent cannot be primary and
// standby for the same domain. Remove that backup first.
func (d *DB) CheckPrimaryServer(domainID int64, serverID string) error {
	srv, err := d.GetServer(serverID)
	if err != nil {
		return nil // the caller reports an unknown server
	}
	backups, err := d.ListDomainBackups(domainID)
	if err != nil {
		return err
	}
	for _, b := range backups {
		if b.AgentID == srv.AgentID {
			return fmt.Errorf("%w: server %s is on the agent of backup server %s; remove that backup first", ErrInvalidBackups, srv.Name, b.ServerID)
		}
	}
	return nil
}

// Eligible reports whether the candidate's agent may ever be the DNS target:
// adopted (or merely offline), with an FQDN to point the CNAME at, and, for a
// backup, still serving the domain's zone. The reason says why not.
func (c *DomainCandidate) Eligible() (bool, string) {
	switch {
	case c.Agent.Status != models.AgentStatusAdopted && c.Agent.Status != models.AgentStatusOffline:
		return false, fmt.Sprintf("agent is %s", c.Agent.Status)
	case c.Agent.FQDN == "":
		return false, "agent has no FQDN"
	case !c.ServesZone:
		return false, "agent no longer serves the zone"
	case !c.Ready:
		return false, c.NotReady
	}
	return true, ""
}

// FailoverCandidates converts candidates to the failover package's input,
// keeping their order.
func FailoverCandidates(cands []DomainCandidate) []failover.Candidate {
	out := make([]failover.Candidate, len(cands))
	for i := range cands {
		ok, _ := cands[i].Eligible()
		out[i] = failover.Candidate{ServerID: cands[i].Server.ID, Eligible: ok, LastSeen: cands[i].Agent.LastSeen}
	}
	return out
}

// DomainFailoverStatus describes which servers may serve dom, their agents'
// health as the reconciler judges it at now, and the stored decision. It only
// reads; the decision itself moves on the reconcile cycle.
func (d *DB) DomainFailoverStatus(dom *models.Domain, now time.Time) (*models.DomainFailoverStatus, error) {
	cands, err := d.DomainCandidates(dom)
	if err != nil {
		return nil, err
	}
	st, err := d.GetDomainFailover(dom.ID)
	if err != nil {
		return nil, err
	}
	known := false
	for i := range cands {
		known = known || cands[i].Server.ID == st.ActiveServerID
	}
	if !known {
		st.ActiveServerID = dom.ServerID
	}
	policy := failover.LoadPolicy(d)
	fc := FailoverCandidates(cands)
	out := &models.DomainFailoverStatus{DomainFailoverState: st, Candidates: make([]models.FailoverCandidate, 0, len(cands))}
	if len(cands) > 1 {
		out.Settling = failover.Decide(fc, st, policy, now).Settling
	}
	for i := range cands {
		c := &cands[i]
		_, reason := c.Eligible()
		healthy := policy.Healthy(fc[i], now)
		if reason == "" && !healthy {
			reason = "no heartbeat"
		}
		out.Candidates = append(out.Candidates, models.FailoverCandidate{
			ServerID: c.Server.ID, ServerName: c.Server.Name,
			AgentID: c.Agent.ID, AgentName: c.Agent.Name, AgentFQDN: c.Agent.FQDN,
			Primary: c.Primary, Priority: c.Priority,
			Eligible: fc[i].Eligible, Healthy: healthy, Active: c.Server.ID == st.ActiveServerID,
			LastSeen: c.Agent.LastSeen, Reason: reason,
		})
	}
	return out, nil
}

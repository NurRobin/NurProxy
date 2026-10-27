package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// DomainMove is a server change that crosses agents. The REST API and the MCP
// tools both route such a change through BeginDomainMove / CompleteDomainMove
// so the old agent always gets its route tombstone (#148).
type DomainMove struct {
	OldAgentID string
	NewAgentID string
	ArtifactID string
	// Tombstone is the deletion persisted on the old agent; nil when the old
	// agent renders through Caddy or the domain is cert-only.
	Tombstone *helperprotocol.ManagedDeletion
}

// managedBackendForAgent mirrors the reconciler's backendForAgent: the
// detected host proxy in existing mode, else the bundled Caddy.
func managedBackendForAgent(agent *models.Agent) string {
	if agent.ProxyMode == "existing" && agent.ProxyDetection != nil && agent.ProxyDetection.Kind != "" {
		return agent.ProxyDetection.Kind
	}
	return "caddy"
}

func domainArtifactID(domainID int64) string {
	return "dom-" + strconv.FormatInt(domainID, 10)
}

// BeginDomainMove prepares moving before (the domain as stored, before any
// field of the update is applied) to newServerID. It returns nil when the move
// stays on one agent or the old server no longer resolves. For a cross-agent
// move whose old agent renders nginx/apache, it persists a route tombstone for
// the OLD host on the OLD agent. Call it before the domain row is updated so no
// push can stop retaining the certificate while the vhost is still listed
// nowhere.
func (d *DB) BeginDomainMove(before *models.Domain, newServerID string, at time.Time) (*DomainMove, error) {
	oldSrv, err := d.GetServer(before.ServerID)
	if err != nil {
		return nil, nil
	}
	newSrv, err := d.GetServer(newServerID)
	if err != nil {
		return nil, fmt.Errorf("resolve target server: %w", err)
	}
	if oldSrv.AgentID == newSrv.AgentID {
		return nil, nil
	}
	move := &DomainMove{OldAgentID: oldSrv.AgentID, NewAgentID: newSrv.AgentID, ArtifactID: domainArtifactID(before.ID)}
	if before.CertOnly {
		return move, nil
	}
	oldAgent, err := d.GetAgent(oldSrv.AgentID)
	if err != nil {
		return nil, fmt.Errorf("resolve old agent: %w", err)
	}
	backend := managedBackendForAgent(oldAgent)
	if backend != "nginx" && backend != "apache" {
		return move, nil
	}
	zone, err := d.GetZone(before.ZoneID)
	if err != nil {
		return nil, fmt.Errorf("resolve old zone: %w", err)
	}
	deletion := helperprotocol.ManagedDeletion{ResourceID: move.ArtifactID, Host: before.FQDN(zone.Name), Backend: backend}
	if err := d.UpsertManagedRouteTombstone(oldAgent.ID, deletion, at); err != nil {
		return nil, err
	}
	move.Tombstone = &deletion
	return move, nil
}

// AbortDomainMove removes the tombstone BeginDomainMove persisted, for when the
// domain row update itself failed. Best-effort.
func (d *DB) AbortDomainMove(move *DomainMove) {
	if move == nil || move.Tombstone == nil {
		return
	}
	_ = d.DeleteManagedRouteTombstones(move.OldAgentID, []helperprotocol.ManagedDeletion{*move.Tombstone})
}

// CompleteDomainMove drops the stale artifact row, which is keyed to the old
// agent; the new agent reports a fresh one in its apply-ACK. It reports whether
// a row was removed.
func (d *DB) CompleteDomainMove(move *DomainMove) (bool, error) {
	if move == nil {
		return false, nil
	}
	if _, err := d.GetConfigArtifact(move.ArtifactID); err != nil {
		return false, nil
	}
	if err := d.DeleteConfigArtifact(move.ArtifactID); err != nil {
		return false, err
	}
	return true, nil
}

// ClaimDomainRoute drops any pending route tombstone on dom's agent that the
// domain's own route would collide with: one for the same resource (a domain
// moved away and back) or for the same host (a new domain reusing the host of
// a deleted or moved one). Both would otherwise put a retained and a deleted
// target for one vhost into the same signed apply. Cert-only domains render
// no vhost and claim nothing.
func (d *DB) ClaimDomainRoute(dom *models.Domain) error {
	if dom.CertOnly {
		return nil
	}
	srv, err := d.GetServer(dom.ServerID)
	if err != nil {
		return err
	}
	zone, err := d.GetZone(dom.ZoneID)
	if err != nil {
		return err
	}
	pending, err := d.ListManagedRouteTombstones(srv.AgentID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	resourceID, file := domainArtifactID(dom.ID), helperprotocol.ManagedVhostKey(dom.FQDN(zone.Name))
	stale := make([]helperprotocol.ManagedDeletion, 0)
	for _, deletion := range pending {
		if deletion.ResourceID == resourceID || helperprotocol.ManagedVhostKey(deletion.Host) == file {
			stale = append(stale, deletion)
		}
	}
	return d.DeleteManagedRouteTombstones(srv.AgentID, stale)
}

package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
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

// DomainRename is an update that changes a domain's host (subdomain or zone).
// The REST API and the MCP tools both route it through BeginDomainRename /
// FinishDomainRename (#151). The old DNS record is released by UpdateDomain
// itself.
type DomainRename struct {
	OldHost string
	NewHost string
	// AgentID / Tombstone: the deletion persisted for the old vhost when the
	// domain stays on an nginx/apache agent. A rename that also moves to another
	// agent is covered by the DomainMove tombstone instead.
	AgentID   string
	Tombstone *helperprotocol.ManagedDeletion
}

// renamedRouteResourceID names the tombstone of a vhost a domain left behind by
// a rename on the same agent. The domain's own "dom-<id>" stays in the signed
// apply as a retained resource, and one resource cannot be both retained and
// deleted; the helper deletes by host, so the tombstone gets its own identity
// derived from the old host.
func renamedRouteResourceID(domainID int64, oldHost string) string {
	sum := sha256.Sum256([]byte(oldHost))
	return domainArtifactID(domainID) + "-was-" + hex.EncodeToString(sum[:8])
}

// BeginDomainRename prepares an update from before (the stored domain) to after.
// It returns nil when the host does not change or cannot be resolved. When the
// domain stays on the same agent and that agent renders nginx/apache, it
// persists a route tombstone for the old host, so the next signed apply removes
// the old vhost file in the same transaction that writes the new one. Call it
// before the domain row is updated.
func (d *DB) BeginDomainRename(before, after *models.Domain, at time.Time) (*DomainRename, error) {
	if before.Subdomain == after.Subdomain && before.ZoneID == after.ZoneID {
		return nil, nil
	}
	oldZone, err := d.GetZone(before.ZoneID)
	if errors.Is(err, ErrZoneNotFound) {
		return nil, nil // the old host cannot be named; nothing to tombstone
	}
	if err != nil {
		return nil, fmt.Errorf("resolve old zone: %w", err)
	}
	newZone, err := d.GetZone(after.ZoneID)
	if err != nil {
		return nil, fmt.Errorf("resolve new zone: %w", err)
	}
	rename := &DomainRename{OldHost: before.FQDN(oldZone.Name), NewHost: after.FQDN(newZone.Name)}
	if rename.OldHost == rename.NewHost || before.CertOnly ||
		helperprotocol.ManagedVhostKey(rename.OldHost) == helperprotocol.ManagedVhostKey(rename.NewHost) {
		return rename, nil
	}
	oldSrv, err := d.GetServer(before.ServerID)
	if err != nil {
		return rename, nil
	}
	newSrv, err := d.GetServer(after.ServerID)
	if err != nil {
		return nil, fmt.Errorf("resolve target server: %w", err)
	}
	if oldSrv.AgentID != newSrv.AgentID {
		return rename, nil // BeginDomainMove tombstones the old host on the old agent
	}
	agent, err := d.GetAgent(oldSrv.AgentID)
	if err != nil {
		return nil, fmt.Errorf("resolve agent: %w", err)
	}
	backend := managedBackendForAgent(agent)
	if backend != "nginx" && backend != "apache" {
		return rename, nil
	}
	deletion := helperprotocol.ManagedDeletion{
		ResourceID: renamedRouteResourceID(before.ID, rename.OldHost),
		Host:       rename.OldHost, Backend: backend,
	}
	if err := d.UpsertManagedRouteTombstone(agent.ID, deletion, at); err != nil {
		return nil, err
	}
	rename.AgentID, rename.Tombstone = agent.ID, &deletion
	return rename, nil
}

// AbortDomainRename removes the tombstone BeginDomainRename persisted, for when
// the domain row update itself failed. Best-effort.
func (d *DB) AbortDomainRename(rename *DomainRename) {
	if rename == nil || rename.Tombstone == nil {
		return
	}
	_ = d.DeleteManagedRouteTombstones(rename.AgentID, []helperprotocol.ManagedDeletion{*rename.Tombstone})
}

// FinishDomainRename runs after the renamed row is stored. It deletes the
// central certificate of the old host unless another domain still serves that
// host (certificates are keyed by host and can be shared). It reports whether
// a certificate was deleted.
func (d *DB) FinishDomainRename(rename *DomainRename) (bool, error) {
	if rename == nil || rename.OldHost == rename.NewHost {
		return false, nil
	}
	cert, err := d.GetCertificate(rename.OldHost)
	if err != nil {
		if errors.Is(err, ErrCertNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("look up certificate for %s: %w", rename.OldHost, err)
	}
	if cert.IsWildcard || cert.Source == models.CertSourceImported {
		// A wildcard covers more than the one host, and an imported bundle is
		// the operator's to remove; NurProxy could not issue it again.
		return false, nil
	}
	served, err := d.HostServed(rename.OldHost)
	if err != nil || served {
		return false, err
	}
	if err := d.DeleteCertificate(rename.OldHost); err != nil {
		return false, err
	}
	return true, nil
}

// HostServed reports whether any domain that is not being deleted resolves to
// host. A zone that cannot be resolved fails the check, so a caller never
// deletes a certificate on a false "not served".
func (d *DB) HostServed(host string) (bool, error) {
	domains, err := d.ListDomains(DomainFilter{})
	if err != nil {
		return false, fmt.Errorf("listing domains to resolve host %q: %w", host, err)
	}
	zoneNames := make(map[string]string)
	for i := range domains {
		dom := &domains[i]
		if dom.Status == models.DomainStatusDeleting {
			continue
		}
		zoneName, ok := zoneNames[dom.ZoneID]
		if !ok {
			zone, zErr := d.GetZone(dom.ZoneID)
			if zErr != nil {
				return false, fmt.Errorf("resolving zone %s for domain %d: %w", dom.ZoneID, dom.ID, zErr)
			}
			zoneName = zone.Name
			zoneNames[dom.ZoneID] = zoneName
		}
		if dom.FQDN(zoneName) == host {
			return true, nil
		}
	}
	return false, nil
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

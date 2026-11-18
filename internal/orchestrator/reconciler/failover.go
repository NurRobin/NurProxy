package reconciler

import (
	"fmt"
	"log"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/orchestrator/failover"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// failoverPolicy is the stored policy plus what only the running
// reconciler knows: when it started, and after how long a gap a pass counts
// as stale (at least three cycles, so a long reconcile interval never makes
// every pass look stale).
func (r *Reconciler) failoverPolicy() failover.Policy {
	p := failover.LoadPolicy(r.db)
	p.StartedAt = r.startedAt
	p.StaleAfter = max(p.DownAfter, 3*r.currentInterval())
	return p
}

// dnsTarget is the outcome of a failover evaluation for one domain.
type dnsTarget struct {
	agent *models.Agent
	cands []db.DomainCandidate
	dec   failover.Decision
	// failover is false for a domain without backups.
	failover bool
}

// decideDNSTarget works out the agent dom's CNAME should point at without
// changing anything: the primary server's agent without backups, otherwise
// the failover decision (failover.Decide). The takeover preview uses it as
// is; selectDNSTarget stores and audits the decision.
func (r *Reconciler) decideDNSTarget(dom *models.Domain) (*dnsTarget, error) {
	cands, err := r.db.DomainCandidates(dom)
	if err != nil {
		return nil, err
	}
	if len(cands) == 1 {
		return &dnsTarget{agent: &cands[0].Agent, cands: cands}, nil
	}
	st, err := r.db.GetDomainFailover(dom.ID)
	if err != nil {
		return nil, err
	}
	dec := failover.Decide(db.FailoverCandidates(cands), st, r.failoverPolicy(), r.clock().UTC())
	return &dnsTarget{agent: &cands[dec.Active].Agent, cands: cands, dec: dec, failover: true}, nil
}

// selectDNSTarget is decideDNSTarget that also stores the decision and
// audits every switch before the target is returned, so DNS never moves
// without a record of why. A domain without backups drops leftover state, so
// backups added later start from the primary. Callers hold the domain's DNS
// lock (domainDNSLock): the state and the record it describes change
// together.
func (r *Reconciler) selectDNSTarget(dom *models.Domain) (*models.Agent, error) {
	t, err := r.decideDNSTarget(dom)
	if err != nil {
		return nil, err
	}
	if !t.failover {
		if st, err := r.db.GetDomainFailover(dom.ID); err != nil {
			return nil, err
		} else if st.EvaluatedAt != nil || st.ActiveServerID != "" {
			if err := r.db.DeleteDomainFailover(dom.ID); err != nil {
				return nil, err
			}
		}
		return t.agent, nil
	}
	if err := r.db.SaveDomainFailover(t.dec.State); err != nil {
		return nil, err
	}
	var prev *db.DomainCandidate
	if t.dec.Previous >= 0 {
		prev = &t.cands[t.dec.Previous]
	}
	next := &t.cands[t.dec.Active]
	for _, ev := range t.dec.Events {
		r.audit("domain", fmt.Sprintf("%d", dom.ID), string(ev), failoverDetail(ev, dom, prev, next))
	}
	return t.agent, nil
}

func agentLabel(c *db.DomainCandidate) string {
	return fmt.Sprintf("%s (%s, server %s)", c.Agent.Name, c.Agent.FQDN, c.Server.Name)
}

func failoverDetail(ev failover.Event, dom *models.Domain, prev, next *db.DomainCandidate) string {
	prevLabel := "a server that is no longer a candidate"
	if prev != nil {
		prevLabel = agentLabel(prev)
	}
	switch ev {
	case failover.EventFailover:
		return fmt.Sprintf("domain %s: agent %s is down; DNS now points at %s", dom.Subdomain, prevLabel, agentLabel(next))
	case failover.EventFailback:
		return fmt.Sprintf("domain %s: %s was healthy for the failback delay; DNS moves back from %s", dom.Subdomain, agentLabel(next), prevLabel)
	case failover.EventAllDown:
		return fmt.Sprintf("domain %s: every agent that can serve it is down; DNS stays on %s", dom.Subdomain, agentLabel(next))
	case failover.EventRecovered:
		return fmt.Sprintf("domain %s: %s is healthy again", dom.Subdomain, agentLabel(next))
	case failover.EventTargetRemoved:
		return fmt.Sprintf("domain %s: the server DNS pointed at was removed from the candidates; DNS now points at %s", dom.Subdomain, agentLabel(next))
	}
	return string(ev)
}

// markInboundApplied records a successful inbound route push on the domain.
// A standby route's push leaves the status alone: it follows the primary.
func (r *Reconciler) markInboundApplied(d desiredRoute, fqdn string) error {
	if d.standby {
		return nil
	}
	return r.markDomainApplied(d, fqdn)
}

// markInboundError records a failed inbound route push on the domain; for a
// standby route it is logged only.
func (r *Reconciler) markInboundError(d desiredRoute, msg string) error {
	if d.standby {
		log.Printf("reconciler: standby route %s of domain %d: %s", d.artifactID, d.domain.ID, msg)
		return nil
	}
	return r.db.UpdateDomainStatus(d.domain.ID, models.DomainStatusError, msg)
}

// standbyHosts returns the hosts agent holds as warm standby, for the cert
// keep list: a standby certificate must survive pruning (#148) like the
// primary's.
func (r *Reconciler) standbyHosts(agent *models.Agent) []string {
	standby, err := r.db.ListStandbyDomains(agent.ID)
	if err != nil {
		log.Printf("reconciler: cannot list standby domains for agent %s: %v", agent.ID, err)
		return nil
	}
	hosts := make([]string, 0, len(standby))
	for i := range standby {
		dom := &standby[i].Domain
		if dom.Status == models.DomainStatusDeleting {
			continue
		}
		zone, err := r.db.GetZone(dom.ZoneID)
		if err != nil {
			continue
		}
		hosts = append(hosts, dom.FQDN(zone.Name))
	}
	return hosts
}

// tearDownStandby removes a deleted domain's standby routes: a tombstone on
// each nginx/apache backup agent and the standby artifact rows. It returns the
// backup agents, which must be pushed.
func (r *Reconciler) tearDownStandby(dom *models.Domain) ([]string, error) {
	agents, err := r.db.TombstoneStandbyRoutes(dom, r.clock().UTC())
	if err != nil {
		return nil, err
	}
	for _, agentID := range agents {
		id := db.StandbyArtifactID(dom.ID, agentID)
		if _, aErr := r.db.GetConfigArtifact(id); aErr != nil {
			continue
		}
		if dErr := r.db.DeleteConfigArtifact(id); dErr != nil {
			log.Printf("reconciler: failed to delete standby artifact %s for domain %d: %v", id, dom.ID, dErr)
			continue
		}
		r.audit("config_artifact", id, "remove", "domain deleted")
	}
	return agents, nil
}

// agentsServingHost resolves an FQDN to every agent that serves it: the
// primary agent of each matching domain and its backup agents. Returns nil
// (no error) when no domain matches.
func (r *Reconciler) agentsServingHost(host string) ([]string, error) {
	domains, err := r.db.ListDomains(db.DomainFilter{})
	if err != nil {
		return nil, fmt.Errorf("listing domains to resolve host %q: %w", host, err)
	}
	var agents []string
	seen := make(map[string]bool)
	add := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			agents = append(agents, id)
		}
	}
	for i := range domains {
		dom := &domains[i]
		zone, zErr := r.db.GetZone(dom.ZoneID)
		if zErr != nil || dom.FQDN(zone.Name) != host {
			continue
		}
		srv, sErr := r.db.GetServer(dom.ServerID)
		if sErr != nil {
			return nil, fmt.Errorf("resolving server for host %q: %w", host, sErr)
		}
		add(srv.AgentID)
		backups, bErr := r.db.ListDomainBackups(dom.ID)
		if bErr != nil {
			return nil, fmt.Errorf("resolving backups for host %q: %w", host, bErr)
		}
		for _, b := range backups {
			add(b.AgentID)
		}
	}
	return agents, nil
}

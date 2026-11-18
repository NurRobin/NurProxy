# Multi-agent failover per domain (design)

> **Issue:** #74 · **Request:** REQ-218 · **Decision:** option B, health-aware DNS

## Problem

`agent_zones` lets several agents serve one zone, but a domain is bound to one
server and therefore one agent. Its CNAME points at that agent's FQDN. When the
agent dies, the domain is down until someone moves it by hand. A second agent
in the zone does nothing for the domain.

## Decision

Active/passive failover by switching the domain's single CNAME.

- A domain keeps its **primary** server (`domains.server_id`) and gets an
  ordered list of **backup** servers on other agents.
- Every candidate agent (primary and backups) holds the route and the
  certificate at all times (warm standby). Failover is only a DNS change.
- The reconciler picks the **active** candidate from agent health and points
  the CNAME at that agent's FQDN. With no backups nothing changes: the CNAME
  points at the primary agent, as before.

### Why a CNAME switch and not several A/AAAA records

- A CNAME has exactly one target, and every NurProxy domain record already is a
  CNAME to an agent FQDN. The agent anchor records (A/AAAA with DDNS) stay the
  single place where IPs live. Per-domain A records would copy every agent IP
  into every domain record and need a DDNS update per domain.
- Round-robin A records (option A) send part of the traffic to a dead agent
  until someone removes the record. Removing records on failure is option B
  anyway, so we may as well keep one record and move it.
- It works the same with Cloudflare proxied records, with apex flattening, with
  adoption and with takeover, because the record shape does not change.
- Cost: no load sharing between healthy agents. That is a non-goal here.

## Data model (migration 38)

- `domain_backups(domain_id, server_id, priority)`, PK `(domain_id, server_id)`,
  FK cascade on both sides. Lower priority value = preferred. The primary is
  always priority 0 implicitly and is not stored here.
- `domain_failover(domain_id PK, active_server_id, pending_server_id,
  pending_since, all_down, switched_at, switches, evaluated_at,
  settle_since)`: the reconciler's decision state. It is only written in a
  DNS pass under the domain's DNS lock; a domain without backups has its row
  dropped there.
- `domain_standby_status(domain_id, agent_id, ready, reason)`: the last
  standby apply each backup agent acknowledged.
- Settings: `failover_grace` (seconds, default 30), `failover_failback`
  (`true`), `failover_failback_delay` (seconds, default 300),
  `failover_settle` (seconds, default 90).

Validation when backups are set (API, CLI, MCP share one DB function): the
domain is not cert-only and not being deleted; each server exists, is not the
primary, sits on an agent other than the primary's and other than every other
backup's, and that agent serves the domain's zone (`agent_zones`). At most 3
backups. Changing the primary to a server on a backup agent is refused.

## Failure detection and hysteresis

Health is the existing liveness signal: an agent is up while its last heartbeat
(POST heartbeat, stream keepalive or apply ACK) is fresh.

- **Down:** no heartbeat for `agent_offline_timeout + failover_grace` (default
  90 s + 30 s). One missed heartbeat (30 s interval) never triggers anything.
- **Failover:** when the active agent is down, switch at once to the first
  healthy candidate in priority order.
- **Failback:** when a more preferred candidate is healthy again, it must stay
  healthy for `failover_failback_delay` before the record moves back. The
  "healthy since" mark (`pending_server_id`, `pending_since`) is persisted, so
  an orchestrator restart cannot shorten the delay. With `failover_failback`
  off the record stays on the backup until that one fails.
- **Settle period:** for `failover_settle` after the orchestrator starts,
  after a pass that comes later than max(down time, three reconcile
  intervals) after the previous one, and after an all-down state ends, a
  down target is held. Agents reconnect with up to 30 s of backoff and
  heartbeat every 30 s; without the hold the agent that reports first would
  win and a failback would follow minutes later.
- **Readiness:** a backup is only selected once its agent acknowledged the
  standby route without error and, for central TLS, with the certificate in
  the store (each push installs it before the apply). A failed standby apply
  makes it ineligible until a later apply succeeds; a rename resets it.
- An agent that is pending, rejected, has no FQDN, or (for backups) no longer
  serves the zone is never selected.

Every switch writes an audit entry (`failover`, `failback`, `failover_all_down`,
`failover_recovered`, `failover_target_removed`) and bumps `domain_failover.switches`. `/metrics` exports
`nurproxy_domain_failover_switches_total{domain}` and
`nurproxy_domain_on_backup{domain}`.

## All agents offline

Never delete the last record. When no candidate is healthy, the CNAME stays on
the last active agent (a record pointing at a dead host is better than NXDOMAIN,
which resolvers cache negatively). One `failover_all_down` audit entry is
written; the next healthy candidate is selected as soon as it reports.

## Split brain

Only the orchestrator decides; agents never touch DNS. If the orchestrator loses
the primary while users can still reach it, it fails over anyway and both
agents serve the domain correctly (same route, same certificate). Clients follow
DNS as caches expire. The upstreams behind primary and backup are the
operator's business: a shared backend just works, separate replicas must be
able to take the traffic. If the orchestrator itself is down, nothing switches;
the record keeps its last target.

## TLS on backup agents

Central certificates are stored per host, not per agent, and issued with DNS-01,
so issuance does not depend on where the CNAME points. The standby route makes
the host part of the backup agent's desired set, so the same certificate rides
every push to that agent. The renewal hook (`RepushCertForHost`) pushes to the
primary and every standby agent, and the cert keep list (#148) includes standby
hosts, so pruning never removes a standby certificate. Limit: a domain on
`self-acme` gets its certificate on the backup only after DNS points there.

## Routes on backup agents

The standby route is rendered from the same domain settings with the backup
server's address as upstream. It gets its own artifact identity,
`dom-<id>-sb-<hash(agent)>`, because artifacts are owned by one agent. Drift
review, raw edits and apply errors work per artifact as usual. A standby apply
error is visible on the artifact and in the audit log; it does not change the
domain status, which stays the primary's.

nginx/apache standby routes are removed with route tombstones on the backup
agent when the backup is removed, when the domain is deleted, and when the
domain is renamed (#151, the old host gets a tombstone like on the primary).

## Interactions

- **Cloudflare proxied (#126):** only the record content changes; the proxy bit
  is kept. Proxied records switch for visitors almost at once; DNS-only records
  follow the TTL (auto, 300 s at Cloudflare).
- **Apex:** unchanged; the apex CNAME needs a provider with CNAME flattening.
- **Cert-only hosts:** no backups. NurProxy does not manage their DNS, so there
  is nothing to switch.
- **Takeover:** writes the CNAME for the currently active target, under the
  domain's DNS lock (#173). The takeover preview computes the same decision
  without storing it or writing audit entries.
- **Removing backups:** removing the backup the record points at is refused
  (409) while no server that stays is healthy, so a list edit never sends the
  record to a down agent. If the target disappears another way (agent
  deleted), the next pass moves the record to the first healthy candidate, or
  the primary, and audits `failover_target_removed`.
- **Rename (#151):** the old record is released as before; the new record is
  created for the active target; standby vhosts get rename tombstones.
- **Cascade delete:** deleting a server that is a backup is refused with 409;
  `cascade=true` drops it from the backup lists first. Deleting an agent drops
  its servers and with them its backup entries; a domain whose active server is
  gone falls back to the primary on the next pass.

## Limits

- Health means "the agent process can reach the orchestrator", not "the site
  answers". Upstream health checks are out of scope.
- Resolvers that cached the old target keep using it until the TTL expires.
- Failover needs the orchestrator to be running and the DNS provider reachable.
- One record per domain, no load sharing, at most 3 backups.

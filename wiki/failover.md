# Failover to a second agent

A domain normally runs on one agent: its DNS record is a CNAME to that
agent's FQDN. If the agent goes down, so does the domain. With **backup
servers** a domain can move to another agent on its own.

## How it works

- The domain keeps its **primary** server. You add up to three **backup
  servers**, each on a different agent, most preferred first.
- Every one of these agents gets the domain's route and certificate right away
  (warm standby). A failover only changes DNS; nothing has to be installed at
  that moment.
- NurProxy watches the agents' heartbeats. When the agent the record points at
  stays silent for the offline timeout plus a grace period, the CNAME moves to
  the first backup that is online.
- When a more preferred agent is back, NurProxy waits for the failback delay
  and then moves the record back. A primary that keeps dropping out does not
  pull the record back and forth.
- If every agent is down, the record stays where it is. NurProxy never deletes
  the last record of a domain.
- After the orchestrator starts, after it was away for a while, and after
  every agent was down, the record is held for a settle period, so agents
  that reconnect a little later are not passed over.
- A backup only takes over once its agent has applied the route with the
  certificate. A backup whose last apply failed is skipped.

Each switch is in the activity log (`failover`, `failback`,
`failover_all_down`, `failover_recovered`) and in Prometheus
(`nurproxy_domain_on_backup`, `nurproxy_domain_failover_switches_total`).

## Requirements

- The backup's agent must serve the domain's zone (pick the zone when you
  approve the agent, or later on the Agents page).
- The backup server must be reachable from its agent and able to answer like
  the primary (a shared backend, or a replica of the app).
- Use central TLS (the default). A domain on `self-acme` only gets its
  certificate on the backup after DNS points there.
- Cert-only domains cannot have backups: NurProxy does not manage their DNS.

## Setting it up

Dashboard: **Domains → Edit → Failover**. Add backup servers, order them with
the arrow, save. The tab shows which agents can serve the domain, whether
they are online, and which one is active. The domain list marks a domain that
currently runs on a backup.

CLI:

```bash
nurproxy domain backups 12 --set srv-b,srv-c   # set, most preferred first
nurproxy domain backups 12 --clear             # back to a single agent
nurproxy domain failover 12                    # show candidates and the active agent
```

API: `PUT /api/v1/domains/{id}/backups` with `{"server_ids": [...]}`, and
`GET /api/v1/domains/{id}/failover`. MCP: `set_domain_backups`,
`get_domain_failover`.

## Settings

Set these through the settings API (`PUT /api/v1/settings/<key>` with `{"value": "..."}`):

- `agent_offline_timeout` (default 90): seconds without a heartbeat before an
  agent counts as offline.
- `failover_grace` (default 30): extra seconds on top of that before the
  record moves.
- `failover_failback` (default `true`): move back to a more preferred agent
  once it is healthy again.
- `failover_failback_delay` (default 300): seconds that agent must stay
  healthy before the record moves back.
- `failover_settle` (default 90): seconds the record is held after a
  restart, an orchestrator outage or all agents being down.

With the defaults a failover happens about two minutes after the agent's last
heartbeat.

## Things to know

- Health means "the agent talks to the orchestrator". NurProxy does not check
  whether your app answers.
- Clients that cached the old DNS answer keep using it until the TTL runs
  out. With the Cloudflare proxy on, visitors are switched almost at once;
  without it, expect up to the record's TTL (300 s with Cloudflare's "auto").
- Failover needs a running orchestrator and a reachable DNS provider. While
  the orchestrator is down, the record stays where it is.
- A server that is a backup cannot be deleted until it is removed from the
  backup lists (or delete it with cascade, which does that for you).
- The backup the record currently points at cannot be removed while no other
  server of the domain is healthy (409).
- A domain cannot be moved onto an agent that is one of its backups; remove
  that backup first.

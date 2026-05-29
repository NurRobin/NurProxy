# Agents

An **agent** is the NurProxy daemon running on one of your edge servers. It runs
Caddy locally and applies the proxy and DNS configuration you set in this
dashboard.

## Lifecycle

1. **Register** — after install, the agent contacts the orchestrator and appears
   as **Pending**.
2. **Approve (adopt)** — you confirm the agent, give it a name, pick its DNS zones,
   and choose a [DNS mode](dns-modes). Approving means NurProxy now trusts this
   server and manages it. (Older wording called this "adoption".)
3. **Active** — the agent heartbeats regularly. If it stops, it goes **Offline**.

Reject a pending agent you don't recognize — only approve servers you installed.

## DNS anchor (FQDN)

Each agent has an **FQDN** — its anchor hostname. NurProxy creates an **A record**
at that name pointing to the server's IP. Every domain you add for the agent is
then a **CNAME** back to the FQDN, so if the server's address changes you only
update one record.

The FQDN **must be a hostname inside one of the agent's assigned zones** (e.g.
`edge1.example.com` when the zone is `example.com`). If it isn't — for example if
the agent registered with a bare hostname like `edge1.local` — NurProxy can't
create the A record, every CNAME pointing at it dangles, and the agent shows a
**DNS problem** explaining this. Set the anchor at **approval** time, or later via
**Edit** on the agent, to a name within an assigned zone.

## Connection model

The agent **dials out** to the orchestrator and holds a connection open; the
orchestrator pushes configuration down it. This means the orchestrator never needs
to reach the agent — only the agent needs outbound access to the orchestrator, so
agents work behind NAT and firewalls. Liveness is judged by the agent's heartbeats,
not by reaching it inbound.

## Health and errors

An agent reports its own health on every heartbeat. If something is wrong but the
agent itself is alive — most commonly its embedded Caddy can't bind ports 80/443
because another service (nginx, Apache) already holds them — the agent **stays
connected and online** and surfaces the problem on its detail page (**Agent
problem** / **Local proxy: not running**), instead of silently failing to start.

## Servers (upstreams)

Each agent has one or more **servers**: backend addresses it proxies to, like
`192.168.1.10`. Domains point at a server + port. Add servers from the agent's
expanded row.

## Deleting an agent

Deleting an agent also removes its servers and the domains that depend on them.
The DNS records and proxy config are cleaned up.

## Troubleshooting

- Agent never appears → [Agent can't connect](agent-reachability).
- Agent went **Offline** → its heartbeats stopped arriving. Check the server is up
  and can still reach the orchestrator (outbound).
- Agent **online** but showing an error → read the message on its detail page. A
  **Local proxy: not running** with a bind error means ports 80/443 are taken on
  the edge server; free them (or stop the conflicting service) and the agent
  recovers on its own.
- **DNS problem** about the FQDN → the anchor isn't inside an assigned zone; fix it
  via **Edit** (see [DNS anchor](#dns-anchor-fqdn)).

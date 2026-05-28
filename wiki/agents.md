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
update one record. Override the FQDN at approval time only if you want a different
anchor than the server's own hostname.

## Servers (upstreams)

Each agent has one or more **servers**: backend addresses it proxies to, like
`192.168.1.10`. Domains point at a server + port. Add servers from the agent's
expanded row.

## Deleting an agent

Deleting an agent also removes its servers and the domains that depend on them.
The DNS records and proxy config are cleaned up.

## Troubleshooting

- Agent never appears → [Agent can't connect](agent-reachability).
- Agent went **Offline** → check the server is up and can still reach the
  orchestrator.

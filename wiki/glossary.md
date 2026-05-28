# Glossary

Short definitions for the terms you'll see around NurProxy.

**Orchestrator** — this dashboard and its API. It stores your desired
configuration and tells agents what to do.

**Agent** — the NurProxy daemon on an edge server. It runs Caddy and applies the
config the orchestrator sends. See [Agents](agents).

**Edge server** — the machine that actually receives and serves public traffic,
where an agent runs.

**Server (upstream)** — a backend address an agent proxies to, like
`192.168.1.10`. Domains point at a server + port.

**Zone** — a domain you control at your DNS provider, like `example.com`.
NurProxy creates subdomain records inside zones you grant it.

**FQDN** — Fully Qualified Domain Name: the complete address of a host, like
`edge1.example.com`. When you connect an agent, NurProxy creates an **A record**
at its FQDN pointing to the server's IP, and every domain (subdomain) you add for
that agent becomes a **CNAME** pointing back to the FQDN. Set a custom FQDN only
if you want a different anchor hostname than the server's own.

**Domain (in NurProxy)** — a subdomain proxied to a server, e.g. `app.example.com`.
See [Domains](domains).

**Provider** — a DNS service NurProxy talks to via API (currently Cloudflare).

**Approval / Adoption** — confirming a pending agent so NurProxy trusts and
manages it.

**DNS mode** — Static (fixed IP) or DDNS (agent updates its record as its IP
changes). See [DNS modes](dns-modes).

**Reconciler** — the background loop that keeps live DNS records and proxy configs
matching your desired settings. Its interval is set in Settings.

**Force HTTPS** — automatically redirect `http://` to `https://`.

**Orchestrator URL** — the address an agent uses to reach the orchestrator. Must be
reachable *from the agent's server*. See [Agent can't connect](agent-reachability).

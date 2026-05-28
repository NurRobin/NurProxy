# NurProxy

Reverse proxy and DNS management for people who run servers in more than one place.

If you have a homelab, a VPS or two, and a handful of domains, you know the pain: every time you spin up a new service, you log into your DNS provider, create a record, SSH into the right server, edit the proxy config, request a certificate, and hope you didn't fat-finger anything. Multiply that by a few servers across different networks and it gets old fast.

NurProxy puts all of that into one dashboard. You tell it which DNS provider you use, point it at your servers, and from then on, creating a new subdomain is one click. DNS record, reverse proxy route, TLS certificate, done. No more jumping between Cloudflare tabs and SSH sessions.

## How it works

NurProxy has two parts:

**The Orchestrator** is where you log in. It runs the dashboard, stores your configuration in a local SQLite database, talks to your DNS provider, and tells your agents what to do. It is a single binary with the web UI baked in. No Node.js runtime, no external database, no dependencies.

**Agents** run on each server that should act as a reverse proxy. An agent is a lightweight binary that manages a local Caddy instance. You start it, point it at your orchestrator, and adopt it through the dashboard. Once adopted, the orchestrator pushes routes to it and the agent takes care of TLS certificates automatically.

The split is intentional. Your DNS credentials never leave the orchestrator. Agents don't need API keys for anything. They just receive routes and serve traffic.

```
                     Internet
                       |
          *.example.com DNS records
              |                |
              v                v
        +-----------+   +-----------+
        |  Agent A  |   |  Agent B  |
        |  (VPS)    |   |  (Home)   |
        |  Caddy    |   |  Caddy    |
        +-----+-----+   +--+----+--+
              |             |    |
         localhost:3000   LAN   LAN
                           |    |
                         vm1  vm2
                              
        +-------------------+
        |   Orchestrator    |
        |   Dashboard + API |
        |   SQLite + DNS    |
        +-------------------+
```

Each agent gets an A record at your DNS provider (pointing to the server's public IP). All subdomains that run through that agent get a CNAME pointing to the agent's FQDN. That way, if a server's IP changes (common with home connections), only one A record needs updating and all subdomains follow automatically. The agent can handle this itself with built-in DDNS support.

## The typical flow

1. **Setup**: You install the orchestrator, open the dashboard, and run through the setup wizard. You enter your DNS provider credentials (Cloudflare to start, more planned), and it auto-detects your zones.

2. **Add an agent**: On a server that should proxy traffic, you install the agent binary and point it at the orchestrator. It shows up in the dashboard as "pending". You adopt it, give it a name, and assign which DNS zones it should handle.

3. **Add servers**: You tell the agent which backend servers it can reach. For a homelab, that might be a Proxmox host and a few VMs. You enter the IP addresses as they are reachable from the agent's perspective (this matters when your agent is in the same LAN as the backends, but you are accessing the dashboard through Tailscale or a VPN).

4. **Create a domain**: You click "New Domain", pick a zone like `example.com`, type a subdomain like `jellyfin`, pick the target server and port. Optionally you toggle WebSocket support, set a max body size, or add custom headers. Hit save. The orchestrator creates a CNAME record at your DNS provider, pushes the route to the agent, and Caddy grabs a TLS certificate. The subdomain is live within seconds.

5. **Edit anytime**: Every route is fully editable through the dashboard. Simple settings like WebSocket and body size have their own toggles. For advanced use cases, you can edit the raw Caddy JSON directly. If you customize the config manually, NurProxy marks it as manually configured and won't overwrite it during sync.

## Features

- **One dashboard for everything**: See all your agents, servers, and domains in one place. Create, edit, and delete from the UI.
- **DNS provider integration**: Cloudflare ships first. The provider system is pluggable, so adding Hetzner DNS, deSEC, Route53, or others is straightforward.
- **Automatic TLS**: Agents run Caddy, which handles Let's Encrypt certificates through HTTP-01 challenges. No certificate management on your end.
- **DDNS built in**: Agents behind dynamic IPs can automatically keep their DNS A record up to date. Configurable interval per agent.
- **CNAME chain architecture**: Subdomains point to agent FQDNs via CNAME, agents publish their own A records. One IP change updates one record, all subdomains follow.
- **Full route control**: Toggle common settings through simple UI controls or drop into raw Caddy JSON for full flexibility.
- **Reconciler**: A background sync loop ensures that what the dashboard says matches what is actually configured on agents and at the DNS provider. Drift gets corrected automatically.
- **Audit log**: Every change is logged with who did what and when.
- **MCP server (opt-in)**: Expose an MCP endpoint so AI tools like Claude can create and manage domains programmatically. Disabled by default, enable it in settings when you want it.
- **Minimal footprint**: The orchestrator is a single binary (~20 MB) serving its own dashboard. Agents are a single binary (~30-50 MB) with Caddy. No runtime dependencies.

## Installation

### Orchestrator

```bash
# Download the latest release
curl -fsSL https://github.com/NurRobin/NurProxy/releases/latest/download/nurproxy-linux-amd64 -o nurproxy
chmod +x nurproxy

# Run it
./nurproxy --port 8080 --data-dir /var/lib/nurproxy
```

Or with Docker:

```bash
docker run -d \
  -p 8080:8080 \
  -v nurproxy-data:/data \
  ghcr.io/nurrobin/nurproxy
```

Open `http://your-server:8080` in your browser to start the setup wizard.

### Agent

```bash
# Download the latest release
curl -fsSL https://github.com/NurRobin/NurProxy/releases/latest/download/nurproxy-agent-linux-amd64 -o nurproxy-agent
chmod +x nurproxy-agent

# Run it (the orchestrator URL must be reachable from this machine)
./nurproxy-agent \
  --orchestrator http://orchestrator-ip:8080 \
  --fqdn edge1.example.com
```

Or with Docker:

```bash
docker run -d \
  -p 80:80 -p 443:443 \
  -v nurproxy-agent-data:/data \
  -e NP_ORCHESTRATOR=http://orchestrator-ip:8080 \
  -e NP_FQDN=edge1.example.com \
  ghcr.io/nurrobin/nurproxy-agent
```

The agent registers itself with the orchestrator. Go to the dashboard and adopt it.

> **A note on IP addresses and URLs**: When setting up an agent, the orchestrator URL must be reachable from the agent's machine, not from your browser. If you access the dashboard through Tailscale but the agent is in the same LAN as the orchestrator, use the LAN address. The same applies when adding backend servers to an agent: enter IP addresses as the agent sees them.

## Tech stack

- **Backend**: Go, SQLite (embedded, no CGo), single binary
- **Frontend**: React, TypeScript, Tailwind CSS, built with Vite, embedded via `go:embed`
- **Proxy**: Caddy (managed by agents, runtime config via Admin API)
- **DNS**: Provider plugin system (Cloudflare implemented)
- **Builds**: Multi-arch (amd64, arm64, armv7) via GoReleaser

## Project structure

```
cmd/nurproxy/          Orchestrator entry point
cmd/nurproxy-agent/    Agent entry point
internal/orchestrator/ Orchestrator logic (API, database, reconciler)
internal/agent/        Agent logic (Caddy management, adoption, heartbeat)
internal/provider/     DNS provider plugin system
internal/shared/       Shared code (models, auth, crypto, route generation)
web/                   Dashboard (Vite + React + Tailwind)
```

## Contributing

NurProxy is open source and contributions are welcome. The DNS provider interface and notification system are designed as plugin points where new implementations can be added without touching core logic.

See [CLAUDE.md](CLAUDE.md) for development setup, build commands, and conventions.

## License

MIT

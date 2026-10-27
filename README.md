# NurProxy

Reverse proxy and DNS management for people who run servers in more than one place.

If you have a homelab, a VPS or two, and a handful of domains, you know the drill: every time you spin up a new service, you log into your DNS provider, create a record, SSH into the right server, edit the proxy config, request a certificate, and hope you didn't fat-finger anything. Multiply that by a few servers across different networks and it gets old fast.

NurProxy puts all of that into one dashboard. You tell it which DNS provider you use, point it at your servers, and from then on, creating a new subdomain is one click. DNS record, reverse proxy route, TLS certificate, done.

## How it works

NurProxy has two parts:

**The Orchestrator** is where you log in. It runs the dashboard, stores your configuration in a local SQLite database, talks to your DNS provider, issues TLS certificates centrally via DNS-01, and tells your agents what to do. Single binary with the web UI baked in, no runtime dependencies, no external database.

**Agents** run on each server that should act as a reverse proxy. An agent has two modes:

- **Built-in** (default): The agent runs its own bundled **Caddy** instance. Nothing else to install. It owns the proxy process end to end.
- **Existing**: The agent manages an **already-installed nginx or Apache** on the host. It writes that proxy's config files and reloads the service, but leaves the process under your control. Your existing vhosts stay untouched.

You start an agent, point it at your orchestrator, and adopt it through the dashboard. Once adopted, the orchestrator pushes routes and TLS certificates to it, and the agent configures whichever proxy backend it uses.

The split is intentional. Your DNS credentials never leave the orchestrator. Agents don't need API keys for anything. They receive routes and serve traffic.

```
                     Internet
                       |
          *.example.com DNS records
              |                |
              v                v
        +-----------+   +-----------+
        |  Agent A  |   |  Agent B  |
        |  (VPS)    |   |  (Home)   |
        |  Caddy    |   |  nginx    |
        +-----+-----+   +--+----+--+
              |             |    |
         localhost:3000   LAN   LAN
                           |    |
                         vm1  vm2
                              
        +-------------------+
        |   Orchestrator    |
        |   Dashboard + API |
        |   SQLite + DNS    |
        |   TLS issuance    |
        +-------------------+
```

Each agent gets an A record at your DNS provider (pointing to the server's public IP). All subdomains that run through that agent get a CNAME pointing to the agent's FQDN. If a server's IP changes (common with home connections), only one A record needs updating and all subdomains follow automatically. The agent can handle this itself with built-in DDNS support.

## Already have nginx or Apache?

NurProxy **manages your existing proxy directly**. You do not need to replace it, remove it, or put another proxy in front of it. If the agent detects nginx or Apache on the host, the dashboard offers a guided "Manage existing proxy" flow:

1. The dashboard shows what it found (proxy type, config directory, test/reload commands).
2. You confirm and get a one-time confirmation code.
3. On the host, you run `nurproxy-agent apply <CODE>`. The agent switches from its bundled Caddy to your installed proxy live, without a restart.

From that point on, the agent writes `nurproxy-*.conf` files into your proxy's config directory (e.g. `/etc/nginx/sites-available/`) and reloads the service when routes change. Your hand-written vhosts are left alone. If you edit a NurProxy-generated config on disk, the dashboard detects the drift and lets you accept or revert the change.

The agent needs exactly two permissions: write access to the config directory (via group ownership) and a scoped sudoers entry for the test + reload commands. It tells you which grants are missing and prints the commands to fix them. See [Managing existing proxies](wiki/existing-proxies.md) for the full guide.

```
Internet :80/:443
       |
   nginx / Apache (your existing install, managed by NurProxy agent)
       |
   your services
```

There is no extra proxy layer, no port conflict, and no TLS delegation chain. The agent drives your existing proxy the same way you would, just centrally managed.

## The typical flow

1. **Setup**: Install the orchestrator, open the dashboard, and run through the setup wizard. Enter your DNS provider credentials (Cloudflare to start, more planned), and it auto-detects your zones. Optionally set a Let's Encrypt contact email for central TLS issuance.

2. **Add an agent**: On a server that should proxy traffic, install the agent binary and point it at the orchestrator. It shows up in the dashboard as "pending". Adopt it, give it a name, and assign which DNS zones it should handle. If the agent detects an existing nginx or Apache, the dashboard offers to switch to managing it; otherwise it uses its bundled Caddy.

3. **Add servers**: Tell the agent which backend servers it can reach. For a homelab, that might be a Proxmox host and a few VMs. Enter the IP addresses as they are reachable from the agent's perspective (this matters when your agent is in the same LAN as the backends, but you access the dashboard through Tailscale or a VPN).

4. **Create a domain**: Click "New Domain", pick a zone like `example.com`, type a subdomain like `jellyfin`, pick the target server and port. Optionally toggle WebSocket support, basic auth, max body size, or custom headers. Hit save. The orchestrator creates a CNAME record at your DNS provider, issues a TLS certificate, pushes the route and cert to the agent, and the agent configures the proxy. The subdomain is live within seconds.

5. **Edit anytime**: Every route is fully editable through the dashboard. Simple settings like WebSocket and body size have their own toggles. For advanced use cases, you can edit the raw config directly in the proxy's native format (Caddy JSON, nginx config, or Apache VirtualHost, depending on what the agent runs). If you customize the config manually, NurProxy marks it as manually configured and won't overwrite it during sync.

## Features

### Core

- **One dashboard for everything**: All agents, servers, and domains in one place. Create, edit, and delete from the UI.
- **DNS provider integration**: Cloudflare ships first. The provider system is pluggable, so adding Hetzner DNS, deSEC, Route53, or others is straightforward.
- **DDNS built in**: Agents behind dynamic IPs can automatically keep their DNS A record up to date. Configurable interval per agent.
- **CNAME chain architecture**: Subdomains point to agent FQDNs via CNAME, agents publish their own A records. One IP change updates one record, all subdomains follow.
- **Full route control**: Toggle common settings through simple UI controls, or drop into the proxy's native config format for full flexibility. The dashboard greys out options the backend can't handle.
- **Basic auth**: Per-route username/password protection in the route model and API. The dashboard currently only shows whether it is enabled; editing credentials from the UI is not wired up yet.
- **MCP server (opt-in)**: Exposes an MCP endpoint so AI tools like Claude can create and manage domains programmatically. Disabled by default.
- **Headless + CLI**: Run the orchestrator without the dashboard and manage everything via the built-in CLI client. Every command supports `--json` for scripting.
- **Minimal footprint**: The orchestrator is a single binary (~20 MB) serving its own dashboard. Agents weigh ~30-50 MB with Caddy built in. Neither has runtime dependencies.

### Proxy management

- **Multi-backend support**: Agents support three proxy backends: **Caddy** (built-in, zero config), **nginx**, and **Apache**. Each agent reports its backend and capabilities; the dashboard adapts the UI accordingly.
- **Existing proxy management**: An agent can manage an already-installed nginx or Apache instead of running its own Caddy. Existing vhosts are adopted into the central store (versioned, visible in the dashboard) but never modified unless you say so. See [Managing existing proxies](wiki/existing-proxies.md).
- **Port-conflict detection**: On Linux, the agent detects when another process holds `:80`/`:443`, identifies it by name, and offers to switch to managing it instead of fighting for the ports.
- **Guided setup**: `nurproxy-agent setup` prompts for the orchestrator URL and FQDN, probes connectivity, writes the env file, and starts the service. One command after package install.

### TLS

- **Central TLS issuance**: The orchestrator issues Let's Encrypt certificates via DNS-01, using the DNS provider credentials it already has. Certificates are stored encrypted at rest and pushed to agents, so you don't need port-80 challenge traffic.
- **Automatic renewal**: A background loop renews certificates before expiry and re-pushes them to the serving agent.
- **Backend-aware**: Built-in Caddy agents can also use self-managed ACME as fallback. Existing nginx/Apache agents receive centrally issued certificates with paths that match their config conventions.
- **ACME email setup**: Configurable in the setup wizard or settings. Issuance stays inactive until an email is set, and the dashboard warns when central-TLS domains exist without one.

### Config lifecycle

- **Version history**: Every config artifact (generated and adopted) is versioned. The dashboard shows the full history with diffs.
- **Drift detection**: The agent checksums on-disk config each heartbeat. If someone edits a file outside the dashboard, the change appears as drift with the actual diff.
- **Drift review**: Accept an on-disk edit (it becomes the new baseline), reject it (the agent reverts to the last known-good version), or roll back to any previous version.
- **Reconciler**: A background sync loop ensures that what the dashboard says matches what is actually configured on agents and at the DNS provider. Generated config that drifts is corrected automatically; manually edited config is left alone.
- **Audit log**: Every change is logged with who did what and when.

### Observability

- **Permission self-test**: Existing-mode agents probe their permissions each heartbeat and report a structured result: can it write config? Can it reload the service? The dashboard shows which grant is missing and the commands to fix it.
- **Degraded state**: An agent that can read config but not reload the service is marked "degraded". It stays connected and visible, but the dashboard makes clear it can't push changes live yet.
- **Agent capabilities**: Each agent reports what its proxy backend supports (WebSocket, headers, body size, etc.). The dashboard disables controls the backend can't handle.
- **Log tailing**: On-demand log streaming from the orchestrator in the dashboard.

## Installation

The fastest path on Linux, macOS, and FreeBSD is the one-line installer. It
downloads the right binary for your OS and architecture, installs it, and
registers a hardened service (systemd, OpenRC, launchd, or rc.d, auto-detected)
in one step.

**Orchestrator** (on the host you log into):

```bash
curl -fsSL https://raw.githubusercontent.com/NurRobin/NurProxy/main/scripts/install.sh \
  | sh -s -- orchestrator --port 8080
```

Then open `http://your-server:8080` to run the setup wizard.

**Agent** (on each server that should serve traffic):

```bash
curl -fsSL https://raw.githubusercontent.com/NurRobin/NurProxy/main/scripts/install.sh \
  | sh -s -- agent --orchestrator http://orchestrator-ip:8080 --fqdn edge1.example.com
```

The agent registers itself with the orchestrator; adopt it from the dashboard.
Any flag after the component name is passed straight to the service install, so
`--data-dir`, `--user`, etc. work too. Add `--no-service` (or use the `binary`
component) to install just the binary without registering a service. Remove a
component with `sudo nurproxy uninstall` / `sudo nurproxy-agent uninstall`
(add `--purge` to delete its data).

### Docker

```bash
# Orchestrator
docker run -d -p 8080:8080 -v nurproxy-data:/data ghcr.io/nurrobin/nurproxy

# Agent (host networking so Caddy can bind :80/:443)
docker run -d --network host \
  -v nurproxy-agent-data:/data \
  -e NP_ORCHESTRATOR=http://orchestrator-ip:8080 \
  -e NP_FQDN=edge1.example.com \
  ghcr.io/nurrobin/nurproxy-agent
```

Or use [`deploy/docker-compose.yml`](deploy/docker-compose.yml): `docker compose -f deploy/docker-compose.yml up -d`.

### Debian / Ubuntu / RHEL packages

Download the `.deb` or `.rpm` for your component and architecture from the
[latest release](https://github.com/NurRobin/NurProxy/releases/latest):

```bash
# Debian/Ubuntu
sudo dpkg -i nurproxy_*_linux_amd64.deb           # or nurproxy-agent_*.deb
# RHEL/Fedora
sudo rpm -i  nurproxy-*.x86_64.rpm
```

The orchestrator package starts automatically. The agent package installs the
service disabled; finish it with the guided setup, which asks for the
orchestrator URL and this agent's FQDN, then starts the service:

```bash
sudo nurproxy-agent setup
```

(Non-interactive: `sudo nurproxy-agent setup --orchestrator <URL> --fqdn <host.zone>`. Or edit `/etc/nurproxy-agent/agent.env` by hand and run `sudo systemctl enable --now nurproxy-agent`.)

For automatic updates via `apt`/`dnf`, add the signed package repository (setup
commands are at [nurrobin.github.io/NurProxy](https://nurrobin.github.io/NurProxy)),
then `apt install nurproxy` / `dnf install nurproxy`.

### Homebrew (macOS)

```bash
brew install NurRobin/tap/nurproxy          # or: nurproxy-agent
```

### Arch Linux

```bash
yay -S nurproxy-bin                          # or: nurproxy-agent-bin
```

### Manual binary

Prefer to place the binary yourself? Grab the tarball for your platform from
the [releases page](https://github.com/NurRobin/NurProxy/releases/latest),
extract it, and run `./nurproxy --port 8080` or
`./nurproxy-agent --orchestrator <URL> --fqdn <host.zone>` directly.

### Supported platforms

| OS | amd64 | arm64 | armv7 | Notes |
|---|:---:|:---:|:---:|---|
| Linux | ✅ | ✅ | ✅ | full support; `.deb`/`.rpm` for systemd distros, OpenRC on Alpine |
| macOS (darwin) | ✅ | ✅ | - | launchd; agent is experimental (see below) |
| FreeBSD | ✅ | ✅ | - | rc.d (incl. OPNsense/pfSense/TrueNAS); agent is experimental |

> Windows is not supported. Production reverse proxies don't run on bare Windows;
> use WSL2, a Linux VM, or Docker instead. The orchestrator runs on every
> platform above; the **agent** is Linux-first because a few host probes
> (port-conflict detection, existing-proxy discovery) are Linux-only and degrade
> gracefully elsewhere, so macOS/FreeBSD agents are experimental for now.

> **IP addresses and URLs**: When setting up an agent, the orchestrator URL must be reachable from the agent's machine, not from your browser. If you access the dashboard through Tailscale but the agent is in the same LAN as the orchestrator, use the LAN address. The same applies when adding backend servers to an agent: enter IP addresses as the agent sees them.

## Headless & CLI

For servers and CI you can run a **headless orchestrator**, the same API without the embedded dashboard:

```bash
make build-headless    # produces ./nurproxy-headless (no embedded web/dist)
```

Everything the dashboard does is reachable from the built-in management CLI, which is a thin client over the REST API. It works against any orchestrator (headless or not):

```bash
export NP_API_URL=http://localhost:8080

# Bootstrap a fresh install with nothing but the binary:
nurproxy auth setup --password 'choose-a-strong-one'
nurproxy apikey create --password 'choose-a-strong-one'   # prints the key once

export NP_API_KEY=np_ak_...   # the key from above

nurproxy provider add --type cloudflare --name "CF" --config '{"api_token":"..."}'
nurproxy zone add --provider <provider-id> --name example.com
nurproxy agent list
nurproxy agent adopt <agent-id> --name edge1 --zones <zone-id>
nurproxy server add <agent-id> --name app --address 10.0.0.5:8080
nurproxy domain add --subdomain api --zone <zone-id> --server <server-id> --port 8080
```

Auth comes from `NP_API_KEY` (Bearer) or `NP_API_PASSWORD` (the CLI logs in for you). Add `--json` to any command for script-friendly output. See [wiki/cli.md](wiki/cli.md) for the full command reference.

## Backup & restore

`nurproxy backup` archives everything the orchestrator needs to come back up: a consistent snapshot of the SQLite database (safe to take while the orchestrator is running) plus `encryption.key` and `acme-account.key`.

```bash
nurproxy backup [--data-dir DIR] [-o OUTFILE]        # default output: nurproxy-backup-<timestamp>.tar.gz
nurproxy restore [--data-dir DIR] [--force] ARCHIVE
```

`--data-dir` defaults to `$NP_DATA_DIR` or `./data`, matching the server's own resolution order. Restore refuses to overwrite an existing database unless `--force` is given, and clears stale SQLite `-wal`/`-shm` sidecars so an old journal can't replay over the restored snapshot. If the orchestrator is running, stop it before restoring into its data dir.

The archive contains the plaintext `encryption.key` — store it as a secret. Anyone holding it can decrypt every provider config and TLS private key in the database.

## Sandbox / dry-run mode

For local development and CI you can run the orchestrator in **dry-run mode**: it runs the full control plane — reconciler, DNS state machine, certificate issuance and renewal — but **simulates every DNS and ACME call instead of executing it**. No live Cloudflare zone, no Let's Encrypt round trips, and no rate-limit risk. DNS mutations land in an in-memory store that reads back correctly (so `create CNAME → present TXT challenge → clean up TXT` sequences behave realistically), and ACME issuance returns a self-signed certificate with a 90-day validity.

```bash
# Mock everything (DNS + ACME):
NP_DRY_RUN=true ./nurproxy

# Or per subsystem, for partial testing:
NP_DNS_DRY_RUN=true ./nurproxy     # mock DNS, real ACME (DNS-01 cannot complete — see note)
NP_ACME_DRY_RUN=true ./nurproxy    # real DNS, mock ACME

# Exercise issuance error paths without waiting for a real failure:
NP_ACME_DRY_RUN=true NP_DRY_RUN_FAIL=ratelimit ./nurproxy   # ratelimit | challenge | propagation
```

Note that `NP_DNS_DRY_RUN` (mock DNS) combined with **real** ACME cannot complete a DNS-01 challenge: the challenge TXT record only lands in the in-memory DNS store and is never published to a resolvable zone, so Let's Encrypt can't validate it. Use that combination for non-issuance DNS testing only; for full TLS flows use `NP_DRY_RUN` (mock both) or `NP_ACME_DRY_RUN` (real DNS, mock ACME).

The `-dry-run` CLI flag is equivalent to `NP_DRY_RUN=true`. Every simulated call is logged and tagged in the audit log with `source: dryrun`, the dashboard shows a persistent **"Dry-run mode"** banner, and `/api/v1/health` reports `dry_run`, `dns_dry_run`, and `acme_dry_run` so there's no confusion with a live instance. Provider setup (validate + list zones) is mocked too, so you can wire up a Cloudflare provider with a dummy token and run the whole flow end-to-end without provisioning anything.

### The agent runs dry too

The agent has its own sandbox mode (`-dry-run` / `NP_DRY_RUN`): the reverse proxy is simulated entirely in-memory — no Caddy subprocess, no `:80`/`:443` binding, no privileged file ops — while registration, adoption, heartbeat, the push stream, and route rendering all run for real. Because nothing binds a port, you can run many agents on one machine. Route rendering still goes through the real renderer, so the artifacts match production built-in Caddy exactly.

```bash
nurproxy-agent -dry-run -orchestrator http://localhost:8080 -fqdn edge1.example.com
```

### One command for the whole stack

`make dev-sandbox` builds and launches a dry-run orchestrator plus one or more dry-run agents and seeds a working topology (provider with a dummy token, zone, adopted agents, servers, and central-TLS domains) — a fully populated, "live"-looking environment with zero external calls and zero privileges. Knobs: `AGENTS=3`, `PORT=9000`, `KEEP=0` (tear down after seeding). The launcher lives at [`scripts/dev-sandbox.sh`](scripts/dev-sandbox.sh).

`make test-sandbox` runs the same flow as a self-contained end-to-end test (`test/sandbox`, behind the `sandbox` build tag): it boots both binaries in dry-run, drives the REST API to stand up a central-TLS domain, and asserts the control plane converges (domain active, certificate issued, DNS records simulated, audit tagged `dryrun`) — no secrets, no external dependencies. It also runs in CI.

## Tech stack

- **Backend**: Go, SQLite (embedded, no CGo), single binary
- **Frontend**: React, TypeScript, Tailwind CSS, built with Vite, embedded via `go:embed`
- **Proxy backends**: Caddy (built-in), nginx, Apache, pluggable via the `proxy.Proxy` interface
- **TLS**: Central DNS-01 issuance via [lego](https://github.com/go-acme/lego), encrypted cert store; Caddy self-ACME as fallback
- **DNS**: Provider plugin system (Cloudflare implemented)
- **Builds**: Multi-arch (amd64, arm64, armv7) via GoReleaser; signed releases with SBOMs

## Project structure

```
cmd/nurproxy/          Orchestrator entry point
cmd/nurproxy-agent/    Agent entry point
internal/orchestrator/ Orchestrator logic (API, database, reconciler)
internal/agent/        Agent logic (proxy management, adoption, heartbeat)
internal/agent/proxy/  Proxy backend interface + Caddy, nginx, Apache implementations
internal/provider/     DNS provider plugin system
internal/shared/       Shared code (models, auth, crypto, route generation)
web/                   Dashboard (Vite + React + Tailwind)
```

## Contributing

NurProxy is open source and contributions are welcome. The DNS provider interface, proxy backend interface, and notification system are designed as plugin points where new implementations can be added without touching core logic.

See [CLAUDE.md](CLAUDE.md) for development setup, build commands, and conventions.

## License

MIT

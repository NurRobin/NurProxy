# Getting started

NurProxy gives you one place to manage reverse proxies and DNS across your own
servers. You run a small **agent** on each edge server; this dashboard (the
**orchestrator**) tells those agents what to serve and keeps DNS in sync.

The whole setup is two steps.

## 1. Connect a DNS provider

NurProxy creates and updates DNS records for you, so it needs an API token from
your DNS provider. Today that's **Cloudflare**.

- Paste a scoped API token.
- NurProxy detects the domains (**zones**) the token can manage.
- Pick which zones you want NurProxy to control.

See [Creating a Cloudflare API token](cloudflare-token) for the exact clicks and
permissions.

## 2. Connect an agent

Install the agent on the server that will actually serve your traffic:

```
curl -fsSL https://get.nurproxy.dev | sh -s -- agent \
  --orchestrator https://your-dashboard-url \
  --fqdn edge1.example.com
```

The agent registers itself and shows up here for **approval** (we also call this
"adoption"). Approving it lets NurProxy manage its proxy and DNS.

> The `--orchestrator` address must be reachable **from the edge server** — it is
> often different from the URL you use in your browser. If your agent never shows
> up, that's almost always why. See [Agent can't connect](agent-reachability).

## Run it as a service (systemd)

Install the binaries from the latest release, then register each component as a
hardened systemd service:

```
# Download nurproxy + nurproxy-agent into /usr/local/bin
curl -fsSL https://raw.githubusercontent.com/NurRobin/NurProxy/main/scripts/install.sh | bash

# Orchestrator (on the dashboard host)
sudo nurproxy install --port 8080

# Agent (on each edge server)
sudo nurproxy-agent install \
  --orchestrator https://your-dashboard-url \
  --fqdn edge1.example.com
```

Each `install` writes config + a systemd unit (auto-restart, `NoNewPrivileges`,
`ProtectSystem=strict`), then enables and starts the service. Follow logs with
`journalctl -u nurproxy -f` (or `-u nurproxy-agent`). Remove a component with
`sudo nurproxy uninstall` (add `--purge` to also delete its data).

## After setup

- **Domains** — point a subdomain at a server and port. NurProxy creates the DNS
  record and configures the proxy.
- **Agents** — add backend servers, review status, change DNS mode.
- **Settings** — add more providers, change the admin password, manage API keys.

New terms? Every unfamiliar word in the UI has a small **?** you can hover, and
the [Glossary](glossary) explains them all in one place.

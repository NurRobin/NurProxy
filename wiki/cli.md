# Command-line interface

The `nurproxy` binary doubles as a management CLI. Everything the dashboard does
is reachable here, so a **headless** orchestrator (built with `make
build-headless`, no embedded dashboard) is fully usable on its own — handy for
servers, CI, and automation.

The CLI is a thin client over the orchestrator's REST API. It does not touch the
database directly, so it works against a local *or* remote orchestrator, and
every change still lands in the audit log.

## Connecting

The CLI needs to know where the orchestrator is and how to authenticate.

| Setting   | Env var            | Flag         | Default                 |
| --------- | ------------------ | ------------ | ----------------------- |
| Base URL  | `NP_API_URL`       | `--url`      | `http://localhost:8080` |
| API key   | `NP_API_KEY`       | `--key`      | —                       |
| Password  | `NP_API_PASSWORD`  | `--password` | —                       |

Authentication resolves in this order:

1. An **API key** (`NP_API_KEY` / `--key`) is sent as `Authorization: Bearer …`.
2. Otherwise a **password** (`NP_API_PASSWORD` / `--password`) is used to log in,
   and the CLI rides the returned session cookie for that command.

Add `--json` to any command to print the raw API response instead of a table —
useful for piping into `jq`.

## Bootstrapping a fresh install

A brand-new headless orchestrator has no password and no API key yet. You can set
both up with nothing but the binary:

```bash
export NP_API_URL=http://localhost:8080

nurproxy auth setup --password 'choose-a-strong-one'    # sets the admin password
nurproxy apikey create --password 'choose-a-strong-one' # prints the API key ONCE

export NP_API_KEY=np_ak_...   # paste the key from the previous command
```

From here on, the exported `NP_API_KEY` authenticates every command.

## Command reference

### auth

```bash
nurproxy auth status                       # is setup required? are we authed?
nurproxy auth setup --password <pw>        # one-time admin password bootstrap
```

### apikey

```bash
nurproxy apikey show                        # whether a key exists (masked)
nurproxy apikey create                      # (re)generate — shown once
nurproxy apikey revoke
```

### provider

```bash
nurproxy provider list
nurproxy provider add --type cloudflare --name "CF" --config '{"api_token":"..."}'
nurproxy provider add --type cloudflare --name "CF" --config-file ./cf.json   # or - for stdin
nurproxy provider zones <provider-id>       # zones the provider can manage
nurproxy provider delete <provider-id>
```

### zone

```bash
nurproxy zone list
nurproxy zone add --provider <provider-id> --name example.com [--external-id <id>]
nurproxy zone delete <zone-id>
```

### agent

```bash
nurproxy agent list
nurproxy agent status <agent-id>
nurproxy agent adopt  <agent-id> [--name n] [--fqdn f] [--zones id,id] [--dns-mode m] [--ddns-interval s]
nurproxy agent update <agent-id> [--name n] [--fqdn f] [--zones id,id] [--dns-mode m] [--ddns-interval s]
nurproxy agent reject <agent-id>            # only while pending
nurproxy agent delete <agent-id>
```

### server

Backend servers are scoped to an agent. Addresses are written from the agent's
point of view.

```bash
nurproxy server list   <agent-id>
nurproxy server add    <agent-id> --name app --address 10.0.0.5:8080 [--notes "..."]
nurproxy server update <server-id> [--name n] [--address a] [--notes "..."]
nurproxy server delete <server-id>
```

### domain

```bash
nurproxy domain list [--agent <id>] [--server <id>] [--status <s>]
nurproxy domain add --subdomain api --zone <zone-id> --server <server-id> --port 8080 \
                    [--websocket] [--force-https] [--ssl-mode auto] \
                    [--proxy-config-file ./proxy.json]
nurproxy domain update <domain-id> [--subdomain s] [--port n] [--websocket] [--force-https] [--ssl-mode m]
nurproxy domain delete <domain-id>          # marks for deletion; reconciler cleans up
```

For advanced per-domain proxy options (custom headers, timeouts, basic auth, IP
allow/block lists, path rewriting), pass a `ProxyConfig` JSON document via
`--proxy-config-file`.

## End-to-end example

```bash
export NP_API_URL=http://localhost:8080
export NP_API_KEY=np_ak_...

# 1. DNS provider + a zone it manages
PID=$(nurproxy provider add --type cloudflare --name CF \
        --config '{"api_token":"..."}' --json | jq -r .id)
ZID=$(nurproxy zone add --provider "$PID" --name example.com --json | jq -r .id)

# 2. Adopt the edge agent and give it a backend
AID=$(nurproxy agent list --json | jq -r '.[0].id')
nurproxy agent adopt "$AID" --name edge1 --zones "$ZID"
SID=$(nurproxy server add "$AID" --name app --address 10.0.0.5:8080 --json | jq -r .id)

# 3. Publish a domain
nurproxy domain add --subdomain api --zone "$ZID" --server "$SID" --port 8080
```

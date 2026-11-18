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
nurproxy agent upgrade <agent-id> [--version X] [--allow-prerelease] [--wait]   # default: the orchestrator's version
nurproxy agent upgrade --all-outdated [--version X] [--allow-prerelease] [--wait]
nurproxy agent upgrades <agent-id>          # upgrade history
nurproxy agent auto-upgrade <agent-id> --enabled=true|false
```

Upgrades are covered in [Agent upgrades](agent-upgrades).

### server

Backend servers are scoped to an agent. Addresses are written from the agent's
point of view.

```bash
nurproxy server list   <agent-id>
nurproxy server add    <agent-id> --name app --address 10.0.0.5:8080 [--notes "..."]
nurproxy server update <server-id> [--name n] [--address a] [--notes "..."]
nurproxy server delete <server-id>
```

### discovery

Server discovery sources (Proxmox VE). Runs on the orchestrator; imported
machines become ordinary servers under the agent you name. See
[Server discovery](server-discovery) for the token setup.

```bash
nurproxy discovery types
nurproxy discovery list
nurproxy discovery add --name homelab --config '{"url":"https://pve1.lan:8006","token_id":"nurproxy@pve!discovery","token_secret":"...","fingerprint":"AB:CD:..."}' \
                       [--sync-interval 3600] [--skip-test]
nurproxy discovery update <source-id> [--name n] [--config '{"verify_tls":true}'] [--sync-interval s]
nurproxy discovery run <source-id>          # query the cluster now and print the machines
nurproxy discovery candidates <source-id>   # last stored result
nurproxy discovery import <source-id> --agent <agent-id> (--id <external-id> ... | --all) \
                       [--address <external-id>=<address> ...]
nurproxy discovery delete <source-id>       # imported servers are kept
```

### domain

```bash
nurproxy domain list [--agent <id>] [--server <id>] [--status <s>]
nurproxy domain add --subdomain api --zone <zone-id> --server <server-id> --port 8080 \
                    [--websocket] [--force-https] [--ssl-mode auto] \
                    [--access-log off] [--error-log-level crit] [--tls-wildcard] \
                    [--proxy-config-file ./proxy.json]
nurproxy domain update <domain-id> [--subdomain s] [--port n] [--websocket] [--force-https] [--ssl-mode m] \
                    [--access-log off|default] [--error-log-level <level>|default] [--tls-wildcard[=false]]
nurproxy domain delete <domain-id>          # marks for deletion; reconciler cleans up
nurproxy domain backups <domain-id> [--set <server-id>,<server-id> | --clear]
nurproxy domain failover <domain-id>        # candidates, their health, the active agent
```

`domain backups` without flags shows the same view as `domain failover`. With
`--set` it replaces the backup servers (most preferred first, each on its own
agent that serves the zone); `--clear` removes them. See
[Failover to a second agent](failover).

`--access-log off` stops writing an access log for the domain, so client IPs of
its visitors don't end up in the host-wide log. `--error-log-level` (`info`,
`notice`, `warn`, `error`, `crit`, `alert`, `emerg`) raises the domain's error
log threshold; `crit` keeps routine upstream errors with client IPs out of the
log. `default` puts either setting back to the host default. Apache supports
both. nginx supports `--access-log` everywhere, but `--error-log-level` only
when the host's nginx error log is `/var/log/nginx/error.log` (the stock path
of distribution packages): the agent checks `nginx -V` and the error_log lines
of the main nginx.conf, and otherwise doesn't offer it, so source builds and
OpenResty keep their own log. The built-in Caddy writes no access log anyway
and has no per-domain error level. The orchestrator refuses a setting the
domain's agent doesn't offer.

Path routes send some request paths to other servers of the same agent (see
[Domains](domains.md#path-routes) for the matching rules):

```bash
nurproxy domain route list   <domain-id>
nurproxy domain route add    <domain-id> --path /api/world --server <server-id> --port 80 --match exact
nurproxy domain route add    <domain-id> --path /media --server <server-id> --port 9000 \
                             [--match prefix] [--scheme https] [--websocket] [--strip-prefix]
nurproxy domain route remove <domain-id> --path /media [--match prefix|exact]
```

`--match` defaults to `prefix`. `remove` needs `--match` only when a prefix and
an exact route share the path.
`--tls-wildcard` serves the domain from its zone's shared `*.<zone>`
certificate instead of a per-host one; `--tls-wildcard=false` on `update` turns
it off again. Only a single label directly below the zone with central TLS can
use it, and the private key is then shared by every agent serving a wildcard
domain of the zone. See [Domains](domains.md#zone-wildcard-certificate).

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

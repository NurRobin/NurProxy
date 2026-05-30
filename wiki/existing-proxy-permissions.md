# Existing-mode permissions (least privilege)

When an agent runs in **Existing** mode it manages an already-installed
nginx/Apache by editing files on disk and reloading the service. That needs two
privileges the built-in Caddy path never did:

1. **Write** the proxy's config files.
2. **Reload** the service after a validated change.

NurProxy is built so neither of these needs blanket `sudo`. The agent runs as an
ordinary user; you grant exactly the two privileges above and nothing more.

The agent **probes both at startup**. If it cannot write or cannot reload, it
does **not** crash — it stays connected and shows a clear, actionable error on
the agent's health card in the dashboard, telling you which grant is missing.
Fix the grant and the error clears on the next heartbeat. (This mirrors the
built-in Caddy behavior when ports 80/443 are already taken: report, don't die.)

## 1. Write access — via group/ownership, not sudo

Add the agent's user to the group that owns the proxy's config directory, or
point the agent at a NurProxy-owned include directory it owns outright. The agent
only ever writes its own `nurproxy-*.conf` files plus the matching
`sites-enabled` symlink (Debian) — it never rewrites your hand-written vhosts
without an explicit **Accept** in the drift-review flow.

Example (Debian/Ubuntu nginx, agent user `nurproxy-agent`):

```bash
# Make the config dirs group-writable by a dedicated group, add the agent to it.
sudo groupadd --system nurproxy
sudo usermod -aG nurproxy nurproxy-agent

sudo chgrp -R nurproxy /etc/nginx/sites-available /etc/nginx/sites-enabled
sudo chmod -R g+w      /etc/nginx/sites-available /etc/nginx/sites-enabled
# Keep the group sticky so new files stay group-writable:
sudo chmod g+s /etc/nginx/sites-available /etc/nginx/sites-enabled
```

RHEL/Fedora nginx uses a single flat `conf.d` (no `sites-enabled`):

```bash
sudo chgrp -R nurproxy /etc/nginx/conf.d
sudo chmod -R g+w /etc/nginx/conf.d
sudo chmod g+s    /etc/nginx/conf.d
```

Apache is the same idea on `/etc/apache2/sites-available` +
`/etc/apache2/sites-enabled` (Debian) or `/etc/httpd/conf.d` (RHEL).

## 2. Reload access — a narrowly-scoped sudoers entry

The only privileged action is reloading the service. Grant a `NOPASSWD` sudoers
entry for **exactly** the test and reload commands — not blanket `sudo`, not a
shell.

Create `/etc/sudoers.d/nurproxy-agent` (validate it with `visudo -c` after):

```sudoers
# nginx (Debian/Ubuntu). Replace the user and binary path to match your host.
nurproxy-agent ALL=(root) NOPASSWD: /usr/sbin/nginx -t
nurproxy-agent ALL=(root) NOPASSWD: /usr/sbin/nginx -s reload
```

```sudoers
# Apache (Debian/Ubuntu):
nurproxy-agent ALL=(root) NOPASSWD: /usr/sbin/apachectl configtest
nurproxy-agent ALL=(root) NOPASSWD: /usr/sbin/apachectl graceful
```

```sudoers
# systemd-managed reload (works for either, if you prefer it over -s reload):
nurproxy-agent ALL=(root) NOPASSWD: /usr/bin/systemctl reload nginx
nurproxy-agent ALL=(root) NOPASSWD: /usr/bin/systemctl reload apache2
```

Then point the agent at the privileged commands so it uses `sudo` for the reload
and test steps:

```yaml
# agent.yaml (in the agent data dir)
proxy_mode: existing
proxy_type: nginx
proxy_test_cmd:   "sudo /usr/sbin/nginx -t"
proxy_reload_cmd: "sudo /usr/sbin/nginx -s reload"
```

The exact command the agent wants allowed is echoed back in the health error when
the reload probe fails, so you can copy it straight into the sudoers file.

> Tip: pin absolute binary paths in both the sudoers line and `proxy_reload_cmd`
> / `proxy_test_cmd`. A bare `nginx` resolved off `$PATH` will not match a
> sudoers rule that names `/usr/sbin/nginx`.

## Alternatives

- **A dedicated systemd unit** the agent may `systemctl reload` (with a scoped
  Polkit rule) instead of a sudoers line.
- **Linux capabilities** if your proxy supports a non-root reload path.

The scoped sudoers line is the most portable and the easiest to audit, so it is
the documented default.

## Threat model

Existing mode raises the agent's privilege from "talks to a local admin API" to
"can write proxy config files and reload the service," and central TLS means
**cert private keys now live on the agent**. Know what that means:

- **Elevated file/reload rights.** A compromised agent can rewrite the proxy
  config and reload it — i.e. redirect traffic for the domains that proxy serves.
  Keep the grants minimal: group-write on the config dir (not world-write), and a
  sudoers line scoped to the two exact commands (no wildcards, no shell). Never
  give the agent blanket `sudo`.
- **Private keys on the agent.** Central TLS pushes cert + key down the
  agent-initiated stream; the agent writes them under its data dir and encrypts
  the key at rest (AES-256-GCM) with an agent-local key. A host compromise still
  exposes the keys for that host's certs — the same blast radius as any reverse
  proxy that terminates TLS. Prefer **per-host certs** (the default); a
  **wildcard** is opt-in precisely because it puts one private key on every agent
  that serves the wildcard.
- **The orchestrator stays the crown jewels.** DNS provider tokens never leave
  the orchestrator. The agent only ever dials out; the orchestrator never opens a
  connection to the agent (including cert push). A reachable-from-the-internet
  agent is not required and not recommended.
- **Drift is review, not bulldoze.** NurProxy never overwrites a config you
  changed on disk without an explicit Accept, so a stray manual edit can't be
  silently clobbered — and a surprising change shows up as drift you can inspect.

See also: [Security notes](security), [Agent reachability](agent-reachability).

# Managing existing proxies

Every agent serves traffic through a **proxy backend**. There are two:

- **Built-in** (default) — the agent runs its own bundled **Caddy**. Nothing else
  to install; the agent owns the process and the config end to end.
- **Existing** — the agent manages an **already-installed nginx or Apache** on the
  host. It writes that proxy's config files on disk and reloads the service, but
  leaves the process itself under your control (systemd, your package manager).

Pick **Existing** when the edge server already runs nginx/Apache for other things
and you want NurProxy to drive it rather than replace it. Otherwise stay on
**Built-in** — it's the simpler, lower-privilege path.

## Switching an agent to Existing

Switching is deliberately a two-touch action: configure it in the dashboard, then
confirm it once on the host. The privileged jump — from "talks to a local admin
API" to "can write `/etc/nginx` and reload the service" — only ever happens with a
shell present on the machine. The orchestrator can never flip an agent into a
host-file mutator on its own; see [Why a code, not a toggle](#why-a-code-not-a-toggle).

### In the dashboard

1. Open the agent and choose **Manage existing proxy**.
2. Confirm the detected proxy type and paths (config dir, test/reload commands).
   NurProxy fills these in from what it found on the host; adjust if your layout
   differs.
3. Click **Prepare**. You get a one-time **confirmation code** (`XXXX-XXXX`, valid
   ~15 minutes) and two ready-to-run commands.

### On the host

Run **one** of the two commands, matching how the agent is installed:

```bash
# binary / systemd install:
nurproxy-agent apply <CODE>

# docker install:
docker exec <container> nurproxy-agent apply <CODE>
```

The agent authenticates with its **local identity** (the token in its data dir)
plus the code, pulls the change you prepared, writes it into `agent.yaml`, and
**hot-applies** it. There is **no agent restart** and no dropped connection — the
backend swaps live, the bundled Caddy is stopped cleanly if you're leaving
Built-in, and the dashboard reflects the new mode and health on the next
heartbeat.

### Why a code, not a toggle

The code binds *one* dashboard intent to *one* local apply. A remote "flip this
agent to Existing" button would let the orchestrator unilaterally turn any agent
into something that edits host files and reloads services — a privilege
escalation we don't want to exist. Keeping the apply on the host preserves the
control-plane trust boundary (the agent only ever dials out; the orchestrator
never reaches in) while still letting you configure everything from the
dashboard.

## Granting the required permissions

Existing mode needs exactly two privileges, and **neither is blanket `sudo`**:

1. **Write** the proxy's config directory — via group ownership, no sudo at
   runtime.
2. **Reload** the service — via a sudoers entry scoped to *exactly* the test +
   reload commands.

The agent probes both on apply (and at startup). A missing grant is **non-fatal**:
the agent stays connected and online, and the dashboard health card tells you
which grant is still missing. `nurproxy-agent apply` also **prints the exact
commands for your host** — with the detected agent user and absolute binary
paths — whenever a permission is missing, so you can copy them straight off the
terminal.

### 1. Write the config dir via group ownership

Add the agent user to a dedicated group that owns the config dir. No sudo is
needed by the agent at runtime once this is set.

```bash
sudo groupadd -f nurproxy
sudo usermod -aG nurproxy <agent-user>
sudo chgrp -R nurproxy <config-dir>
sudo chmod -R g+w <config-dir>
sudo chmod g+s <config-dir>     # new files inherit the group
```

The agent only ever writes its own `nurproxy-*.conf` files (plus the matching
`sites-enabled` symlink on Debian). It never rewrites your hand-written vhosts
without an explicit **Accept** in the drift-review flow.

### 2. Reload via a scoped sudoers entry

The reload is the only privileged command. Grant `NOPASSWD` for **exactly** the
test and reload commands — no wildcards, no shell.

```bash
# nginx:
echo '<agent-user> ALL=(root) NOPASSWD: /usr/sbin/nginx -t, /usr/sbin/nginx -s reload' | sudo tee /etc/sudoers.d/nurproxy-agent
sudo chmod 0440 /etc/sudoers.d/nurproxy-agent
sudo visudo -c
```

For Apache, use the configtest + graceful-reload pair instead:

```bash
# apache:
echo '<agent-user> ALL=(root) NOPASSWD: /usr/sbin/apachectl configtest, /usr/sbin/apachectl graceful' | sudo tee /etc/sudoers.d/nurproxy-agent
sudo chmod 0440 /etc/sudoers.d/nurproxy-agent
sudo visudo -c
```

> Pin **absolute** binary paths in both the sudoers line and the agent's
> test/reload commands. A bare `nginx` resolved off `$PATH` won't match a sudoers
> rule that names `/usr/sbin/nginx`.

For the full permission model — distro-specific config-dir paths, the
`agent.yaml` keys, systemd/Polkit and capabilities alternatives, and how the
agent surfaces a missing grant — see
[Existing-mode permissions](existing-proxy-permissions).

## What you're trading

Switching to Existing grants the agent **file-write + service-reload** rights on
the host, and — with central TLS — certificate **private keys live on the agent**.
That is the cost of letting NurProxy manage an already-installed proxy. It stays
**least privilege** (group ownership + a sudoers line scoped to two exact
commands), never blanket sudo. For the full threat-model note, read
[Existing-mode permissions → Threat model](existing-proxy-permissions) and the
[Security notes](security).

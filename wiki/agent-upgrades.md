# Agent upgrades

Agents report their version on every heartbeat, and the dashboard marks an agent
**outdated** when it runs an older release than the orchestrator. From there you
can upgrade it without logging in to the host: the agent downloads the signed
release, checks it, swaps its own binary, restarts, and goes back to the old
binary if the new one doesn't come up.

Nothing upgrades on its own. Every upgrade starts with an operator action, unless
you switch on **Upgrade automatically** for a specific agent (off by default).

## Agents older than 0.6.0

Self-update arrived with 0.6.0, so an agent on 0.5.x or older cannot take a
remote upgrade: install 0.6.0 on its host by hand once, the same way you
installed it. From then on the agent reports whether it can self-update, and
the orchestrator refuses an upgrade (409) for agents that never reported it.
**Upgrade all outdated** skips them.

## Before the first upgrade: enable it on the host

Self-update needs one-time consent on each edge server, because the agent runs as
an unprivileged user and can't replace its own binary. Run this once, as root:

```bash
sudo nurproxy-agent self-update-enable
# custom data dir or unit name:
sudo nurproxy-agent self-update-enable --data-dir /var/lib/nurproxy-agent --unit nurproxy-agent.service
```

On **systemd** this installs two units:

- `nurproxy-agent-update.path` watches `<data-dir>/self-update/request.json`.
- `nurproxy-agent-update.service` is a root oneshot that runs
  `nurproxy-agent self-update-apply` when that file appears.

On **macOS (launchd)** it installs a `de.nurrobin.nurproxy-agent-update` job that
watches the same directory. **OpenRC** has no path trigger, so there an agent can
only self-update when it runs as root. `sudo nurproxy-agent self-update-disable`
removes the trigger again.

Until the trigger exists, the agent reports why it can't self-update, and the
**Upgrade** button stays disabled with that reason as its tooltip.

### Ownership requirements

The trigger runs the agent binary as root on behalf of an unprivileged agent, so
`self-update-enable` and the applier both refuse unless:

- the agent binary (`/usr/local/bin/nurproxy-agent` with `install.sh`) and every
  directory above it are **owned by root and not group- or world-writable**,
  and none of them is a symlink. Otherwise the agent user could replace the file
  and get its own code run as root. Fix it with
  `sudo chown root:root /usr/local/bin/nurproxy-agent && sudo chmod 0755 /usr/local/bin/nurproxy-agent`
  (and the same for any parent directory the error names);
- every directory above the data dir is root-owned and not group- or
  world-writable, and the data dir itself is not group- or world-writable.

`self-update-enable` also creates `<data-dir>.selfupdate` (for example
`/var/lib/nurproxy-agent.selfupdate`, root:root, 0755) next to the data dir. The
applier keeps its state there; the agent can only read it. If that directory
exists but belongs to someone else, the applier refuses until you remove it.

If the agent's directory fails these checks, the applier refuses, removes the
request where that is safe, and leaves a failure with the reason that the agent
reports for the upgrade it was waiting on. When it cannot remove the request it
waits 30 seconds before exiting, so the path trigger does not spin.

### Hosts that refuse

Self-update refuses, and says so on the agent page, when:

| Install | Why | Upgrade instead with |
|---|---|---|
| `.deb` / `.rpm` package | overwriting a package-owned file breaks the package database | `apt upgrade` / `dnf upgrade` |
| AUR (`nurproxy-agent-bin`) | same | your AUR helper |
| Homebrew | same | `brew upgrade nurproxy-agent` |
| Any binary in `/usr/bin` | that directory belongs to the package manager | the package manager |
| Docker / Podman / Kubernetes | the container image is the unit of deployment | pull the new tag, recreate the container |
| Development builds (`dev`) | no release version to compare against | a release build |
| No systemd, launchd or OpenRC | nothing could restart the agent | a manual upgrade |

So self-update is for agents installed with `install.sh` (binary in
`/usr/local/bin`, service registered by `nurproxy-agent install`).

## Upgrading

- **One agent:** open the agent and press **Upgrade agent**. Leave the version
  empty to move to the orchestrator's version, or name a newer release.
- **All outdated agents:** **Upgrade all outdated** on the Agents page. The
  rollout runs **one agent at a time**: it waits until each agent is back online
  on the new version before it touches the next one, and **stops at the first
  failure**. Agents that are offline or can't self-update are skipped and listed
  with the reason.
- **Pre-releases** (`-rc`, `-beta`, ...) are refused unless you allow them
  explicitly: tick **Allow a pre-release** in the dialog, pass
  `--allow-prerelease` on the CLI or `"allow_prerelease": true` in the API body.
  This applies to the orchestrator's own version as the default target too; the
  rollout dialog names a pre-release target before you confirm it. Automatic
  upgrades never install a pre-release.
- **Automatic:** **Upgrade automatically** on an agent upgrades it to the
  orchestrator's version once it notices the agent is behind (after you upgrade
  the orchestrator). A target that failed once is not retried automatically.

CLI:

```bash
nurproxy agent upgrade <agent-id> [--version 0.6.0] [--allow-prerelease] [--wait]
nurproxy agent upgrade --all-outdated [--version 0.6.0] [--allow-prerelease] [--wait]
nurproxy agent upgrades <agent-id>            # history
nurproxy agent auto-upgrade <agent-id> --enabled=true
```

Self-update only ever moves **forward**: an older release, or the version the
agent already runs, is refused. To go back, see [Rolling back by hand](#rolling-back-by-hand).

## What happens

| State | Meaning |
|---|---|
| `requested` | The orchestrator recorded the upgrade and pushed it down the agent's stream. |
| `downloading` | The agent fetches `checksums.txt`, its signature and certificate, and the archive for its OS/architecture. |
| `installed` | The download passed verification and was handed to the root applier. |
| `restarting` | The applier swapped the binary and restarted the service; it waits for the new agent. |
| `done` | The new agent reached the orchestrator and reports the target version. |
| `failed` | Stopped before anything was replaced (download, verification, precondition), or the agent stopped reporting. The old binary is untouched. |
| `rolled_back` | The new binary did not come up healthy; the previous one is back in place. |

Every transition is written to the audit log (`upgrade_requested`,
`upgrade_downloading`, …, `upgrade_rollout_started`/`_done`/`_failed`).

Step by step on the host:

1. The agent checks the preconditions above and that the target is newer.
2. It downloads the release and verifies it (see [Trust model](#trust-model)).
   On failure it reports `failed` and nothing changes.
3. It stages the files under `<data-dir>/self-update/staged/` and writes
   `request.json`. The trigger starts the root applier.
4. The applier reads the request and the staged files into its own memory,
   treating them as hostile (see [Root/agent boundary](#rootagent-boundary)), and
   **verifies that copy again** with its own trust roots. It extracts the binary,
   writes it next to the current one as `root:root` mode `0755`, fsyncs it, and
   runs it with `-version` to make sure it starts on this machine and is the
   expected version.
5. It keeps the current binary as `nurproxy-agent.prev`, renames the new one into
   place, re-pins the root helper's build identity if the host has one, and
   restarts the service (on systemd also the root helper).
6. The new agent writes a health proof after its first heartbeat the orchestrator
   accepted. If that doesn't happen within **3 minutes**, or the restart command
   fails, the applier copies `.prev` back, restarts again and records
   `rolled_back` with the reason. The agent that starts next reports the result.

An upgrade counts as `done` when the agent relays the applier's committed
result. A heartbeat on the target version alone completes it only after the
upgrade sat in `restarting` for 5 minutes (longer than the applier's health
window), in case that report got lost; a `rolled_back` report still overrides
such a `done`.

If the applier dies while it waits for the health proof (power loss, OOM,
`kill -9`), its pending record stays behind. The agent reports that upgrade once
the window has passed (`done` if it runs the target version, `failed`
otherwise) and is free to start the next one. The next applier run settles the
record first: it commits on a health proof, waits out what is left of the
window, or restores `.prev`.

The orchestrator gives up on an upgrade that stops making progress (2 min in
`requested`, 15 min `downloading`, 5 min `installed`, 10 min `restarting`) and
marks it `failed`.

## Trust model

A release is installed only if all of this holds:

1. `checksums.txt` carries a **cosign keyless signature** (`checksums.txt.sig` +
   `checksums.txt.pem`) whose certificate chains to the **Sigstore Fulcio CA
   built into the agent binary**.
2. The certificate was issued to **this repository's release workflow for exactly
   the requested tag**: its identity must be
   `https://github.com/NurRobin/NurProxy/.github/workflows/release.yml@refs/tags/v<version>`,
   issued by `https://token.actions.githubusercontent.com`. A signature from
   another workflow, fork, or tag does not count, so an older release can't be
   passed off as a newer one.
3. The archive's SHA-256 matches its line in that `checksums.txt`, and the archive
   name matches the agent's OS and architecture.

Because the signature is checked, the download location doesn't need to be
trusted. Set `update_mirror` in `agent.yaml` (or `NP_UPDATE_MIRROR`) to an
`https://` mirror serving `<mirror>/v<version>/<file>` if hosts can't reach
GitHub.

Limits, stated plainly:

- The Rekor transparency log is not consulted (that would need network access
  and a large dependency). The certificate chain is checked at the time the
  certificate was issued instead of "now". Forging a release would therefore
  still need a Fulcio certificate for this repository's release workflow and tag,
  which means control over the repository's GitHub Actions.
- The Fulcio CA is pinned in the binary (valid until 2031). If Sigstore rotates
  it, upgrades fail verification until you install a newer agent by hand. They
  fail closed, never open.
- A compromised agent process can ask the applier to install any **genuine,
  newer** release, but nothing else: the applier re-verifies everything, takes
  the binary path from its own executable, and never downgrades.

## Root/agent boundary

The agent and the root applier share two directories:

| Directory | Owner | Holds |
|---|---|---|
| `self-update/` | agent user | `request.json`, `staged/*`, `healthy.json` (written by the agent) |
| `<data-dir>.selfupdate/` (next to the data dir) | root, `0755` | `pending.json`, `result.json` (written by the applier) |

Root never creates, writes or renames anything in a directory the agent can
write, because there the agent could swap an entry for a symlink and redirect
root's write anywhere on the host. Root's directory sits next to the data dir, not
inside it: the agent owns the data dir and could move a root-owned directory
from elsewhere into it, while the data dir's parent only root can change. In `self-update/` the applier only reads and
unlinks. It opens every directory relative to its parent without following
symlinks and checks owner and mode on the opened descriptor, so nothing can be
swapped between check and use. Files it reads from the agent must be regular
files (no symlinks, FIFOs or hard links) owned by the agent user and below a size
limit; JSON is decoded strictly (unknown fields or trailing data are refused).
Anything off and the applier discards the request and installs nothing.

## Rolling back by hand

The previous binary stays next to the current one:

```bash
sudo install -m 0755 /usr/local/bin/nurproxy-agent.prev /usr/local/bin/nurproxy-agent
sudo nurproxy-agent helper-refresh-build    # only if the root helper is in use
sudo systemctl restart nurproxy-agent
```

If the host reboots while the applier waits for the new agent (the 3-minute
window), the automatic rollback doesn't happen; the `.prev` binary is still there
for the steps above.

## Sandbox

A dry-run agent (`NP_DRY_RUN=true`) reports self-update as supported and
simulates the whole flow without downloading or restarting: it walks through the
states and then reports the target version. `NP_DRY_RUN_UPDATE_FAIL=verify` or
`=rollback` makes it fail at that step, for testing rollouts.

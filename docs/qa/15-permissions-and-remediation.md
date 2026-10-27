# Permission Probing & Remediation (existing mode)

> **Scope:** how an existing-mode agent self-tests whether it can WRITE the host proxy's config dir and RELOAD the service, reports a structured result + targeted least-privilege remediation on every heartbeat, and clears the warning on its own once the operator grants the right.
> **Code:** `internal/agent/proxy/permcheck/permcheck.go` (probe), `internal/agent/proxy/permcheck/remediation.go` (remediation builder), `internal/agent/runtimeenv/runtimeenv.go` (env detection), `internal/agent/proxy/holder.go` (`ProbePermissions`/`probeExisting`, lines 458-529), `internal/agent/proxy/nginx/nginx.go` (`ProbeDirs`, lines 577-582), `internal/agent/proxy/apache/apache.go` (`ProbeDirs`, lines 601-606), `internal/agent/ddns/ddns.go` (`SetPermissionsFn`/per-beat send, lines 104-110, 199-202), `cmd/nurproxy-agent/main.go` (`SetPermissionsFn`/`toProxyPermissions`/`toRuntimeEnv`, lines 428-526), `internal/shared/models/models.go` (`ProxyPermissions`/`RuntimeEnv`/`Remediation`, lines 149-225), `web/src/pages/Agents.tsx` + `web/src/lib/types.ts` + `web/src/lib/status.ts` (dashboard panel).
> **Coverage legend:** D = coverable dry, R = needs a real run.

## Prerequisites

- Both binaries built: `make build-all` (produces `./nurproxy` and `./nurproxy-agent`).
- For the probe-logic unit suite: a Go toolchain (`make test`).
- For the live-probe walk-throughs: a host with a real nginx **or** apache layout on
  disk (an `/etc/nginx/sites-available[+sites-enabled]` Debian layout, or a
  `conf.d` RHEL layout), or any directory you point the agent's resolved config dir
  at. You do **not** need root, real serving, or a real zone to exercise the probe
  and reporting — only the dirs and (for the reload probe) the proxy binary to be
  invokable.
- A way to read the heartbeat result: the dashboard Agents page, or
  `GET /api/v1/agents` against the orchestrator.
- The actual *effect* of a remediation step (group/setgid, sudoers.d, systemd
  ReadWritePaths/CAP_DAC_OVERRIDE drop-in) only proves out on a real systemd host
  with the proxy installed — that is the R part.

> **Why the sandbox does not cover this on its own:** `make dev-sandbox` /
> `NP_DRY_RUN=true ./nurproxy-agent` run the agent with the **in-memory mock Caddy
> backend** (`cmd/nurproxy-agent/main.go:212-238`), i.e. built-in mode. The mock is
> not a `fileBackend`, so `Holder.ProbePermissions` returns `checked=false` and the
> heartbeat carries **no** `proxy_permissions` block (`holder.go:471-476`,
> `main.go:489-491`). To exercise the live probe you must run the agent in
> **existing** mode (`-proxy-mode existing -proxy-type nginx|apache`). The probe
> itself is still cheap and unprivileged (it writes one throwaway file and runs a
> validate command), so most of this file is **D**.

## Features covered

- [ ] `ProxyPermissions` reported only in existing mode (`checked` true), nil/absent in built-in mode.
- [ ] Re-probed on **every heartbeat**; a granted right clears the warning on the next beat with no restart.
- [ ] Write probe: throwaway `.nurproxy-permcheck` file created + removed in **each** `ProbeDir`.
- [ ] `ProbeDirs` set: nginx/apache report `sites-available` always, plus `sites-enabled` on the Debian layout; RHEL `conf.d` layout reports the one dir only.
- [ ] Write-probe error classes: missing dir, path-not-a-dir, cannot-write (group/ownership), cannot-remove.
- [ ] Reload probe via injected validate command (`nginx -t` / `apachectl configtest`) over `sudo -n`; permission-denial vs benign config-invalid distinction.
- [ ] `isPermissionDenied` needle matching (password/tty/not-in-sudoers/not-allowed/command-not-found) and the deliberate non-match of bare "no such file".
- [ ] `RuntimeEnv` detection: OS, distro, init system (systemd/openrc/launchd/windows-service), managed, unit, sandboxed, user, is_root. (ID_LIKE family is parsed internally — `runtimeenv.Env.DistroLike` — but is **not** carried on the wire: `toRuntimeEnv` and `models.RuntimeEnv` drop it, so the REST/dashboard `runtime_env` has no `distro_like`.)
- [ ] Runtime-aware health messages: unprivileged (group + scoped sudoers), root-under-systemd (sandbox + CAP_DAC_OVERRIDE), root-no-systemd.
- [ ] Remediation outputs: systemd ReadWritePaths drop-in (+ CAP_DAC_OVERRIDE for root), group-ownership + setgid step, scoped `/etc/sudoers.d/nurproxy-agent` NOPASSWD line, only-missing-grant steps.
- [ ] `OK()`/`HealthError()`: both grants present → OK + empty health error; combined message when both fail.
- [ ] Health/last_error kept in sync with the live structured report each beat.
- [ ] Dashboard Agents detail: permissions panel with copy-paste remediation + runtime context.

## Tests

### 15.1 Probe runs only in existing mode; nil in built-in

- **Must:** A built-in-mode agent (bundled Caddy / admin-API backend) reports **no**
  `proxy_permissions` (the field is omitted / nil). An existing-mode agent
  (nginx/apache `fileBackend`) reports `proxy_permissions` with `checked: true`.
- **Access:**
  - Flag/env: `nurproxy-agent -proxy-mode existing -proxy-type nginx|apache`
    (`cmd/nurproxy-agent/main.go:53`; constants `built-in`/`existing` in
    `internal/agent/config/config.go:19-22`).
  - REST: `GET /api/v1/agents` → each agent's `proxy_permissions` field.
  - Dashboard: Agents page, agent detail — the permissions panel only appears for
    an existing-mode agent.
- **Prerequisites:** an orchestrator the agent can adopt against; a real nginx or
  apache config layout for the existing-mode case.
- **Steps:**
  ```bash
  # built-in (dry) — expect NO proxy_permissions:
  NP_DRY_RUN=true ./nurproxy -port 18080 -data-dir /tmp/np-perm-orch &
  NP_DRY_RUN=true ./nurproxy-agent -orchestrator http://localhost:18080 -fqdn edge1.example.com &
  # ...adopt the agent, then:
  curl -s http://localhost:18080/api/v1/agents | jq '.[] | {fqdn, proxy_permissions}'

  # existing (live probe) — expect proxy_permissions.checked == true:
  ./nurproxy-agent -orchestrator http://localhost:18080 -fqdn edge2.example.com \
      -proxy-mode existing -proxy-type nginx &
  curl -s http://localhost:18080/api/v1/agents | jq '.[] | {fqdn, proxy_permissions}'
  ```
- **Pass:** built-in agent shows `proxy_permissions: null`; existing-mode agent
  shows `proxy_permissions.checked == true` with `can_write`/`can_reload` booleans
  and a `runtime_env`.
- **Coverage:** D (built-in via dry; existing needs a real config layout but no root).
- **Pitfalls:** Adoption must complete first or the agent never heartbeats. The mock
  Caddy path in dry-run is built-in, so you can **not** prove the existing-mode probe
  with `NP_DRY_RUN=true` on the agent — drop the flag and supply `-proxy-mode existing`.

### 15.2 Re-probed every heartbeat; grant clears without a restart

- **Must:** `ProxyPermissions` is recomputed on each beat (`SetPermissionsFn` called
  per beat, `ddns.go:104-110`, `199-202`). Granting a missing right makes the next
  beat report `ok: true` and clears the dashboard warning — no agent restart.
- **Access:** REST `GET /api/v1/agents` (poll); Dashboard Agents panel.
- **Prerequisites:** an existing-mode agent against a config dir you can toggle
  writability on.
- **Steps:**
  ```bash
  # Make the config dir non-writable for the agent user, observe the warning, then
  # restore write and watch it clear on the NEXT beat (do not restart the agent):
  chmod a-w /path/to/sites-available
  sleep <one heartbeat interval>; curl -s .../api/v1/agents | jq '.[].proxy_permissions.can_write'   # false
  chmod u+w /path/to/sites-available
  sleep <one heartbeat interval>; curl -s .../api/v1/agents | jq '.[].proxy_permissions.can_write'   # true
  ```
- **Pass:** `can_write` flips false→true across two beats with the agent process
  untouched; `ok` becomes true; `remediation` goes nil; `last_error` clears.
- **Coverage:** D (no root needed — file-bit toggle on a temp dir owned by the test
  user); R for the same flow against a real `/etc/nginx`.
- **Pitfalls:** `main.go:431-436` deliberately re-syncs `health.SetError(res.HealthError())`
  each beat so the generic `last_error` channel does not lag the structured report —
  if `last_error` stays stale after a grant, that wiring regressed.

### 15.3 Write probe — throwaway file in each ProbeDir

- **Must:** For each (deduped, non-empty) `ProbeDir` the probe creates
  `.nurproxy-permcheck` (mode 0644, content "nurproxy permission probe\n"), then
  **removes** it. Nothing in the live config is touched. The suffix has **no
  `.conf`** so a stray file is never auto-included by nginx/apache `conf.d` globbing
  (`permcheck.go:34-38`, `160-195`).
- **Access:** internal — driven by `Holder.ProbePermissions` per beat; assert via
  the unit suite and by inspecting the probe dir during a beat.
- **Prerequisites:** a Go toolchain (`make test`). No root, no proxy, no orchestrator.
- **Steps:**
  ```bash
  make test                                   # whole suite
  go test ./internal/agent/proxy/permcheck/   # just the probe
  ```
- **Pass:** `TestProbe_writableDirAndNoRunner_ok` and the degenerate-input tests
  pass; no `.nurproxy-permcheck` file lingers in the probe dir after a beat.
- **Coverage:** D.
- **Pitfalls:** If removal fails, that is itself surfaced as a permission problem
  ("cannot remove files in config directory", `permcheck.go:190-192`) — do not treat
  a leftover probe file as benign.

### 15.4 ProbeDirs set per backend + layout

- **Must:** nginx/apache `ProbeDirs()` return `sites-available` **always**, plus
  `sites-enabled` on the **Debian** layout (the symlink/a2ensite activation dir);
  the **RHEL `conf.d`** layout has no separate enable dir, so exactly **one** dir is
  returned (`nginx.go:577-582`, `apache.go:601-606`).
- **Access:** REST `GET /api/v1/agents` → `proxy_permissions.dirs`; Dashboard panel
  lists the checked dirs.
- **Prerequisites:** an existing-mode agent run against each layout (a Debian
  `sites-available`+`sites-enabled` tree and a RHEL `conf.d` tree), or the
  backend/holder unit tests for the deterministic path. No root.
- **Steps:**
  ```bash
  # per layout (existing-mode agent already adopted), read the checked dirs:
  curl -s http://localhost:18080/api/v1/agents | jq '.[] | {fqdn, dirs: .proxy_permissions.dirs}'
  ```
- **Pass:** Debian layout → two dirs (available + enabled); RHEL `conf.d` layout →
  one dir.
- **Coverage:** D (layout resolution is deterministic from the on-disk shape; cover
  both via the backend/holder tests) / R to confirm against a real distro install.
- **Pitfalls:** Which layout is chosen comes from detection, not a flag — if a
  Debian box reports one dir (or RHEL reports two) the layout resolver picked wrong;
  that is a §9 detection issue, not a permcheck bug.

### 15.5 Write-probe error classes

- **Must:** Distinct, actionable messages for: directory does **not exist**, path
  **is not a directory**, **cannot write** (the canonical group/ownership case),
  **cannot remove**. Missing dir is reported as its own message, never a raw
  `os.ErrNotExist` (`permcheck.go:171-192`).
- **Access:** REST `proxy_permissions.write_error`; Dashboard panel.
- **Prerequisites:** a Go toolchain. Do **not** run as root (root bypasses the DAC
  bits, so the read-only-dir case will not trip — see Pitfalls).
- **Steps:**
  ```bash
  go test -run 'TestProbe_(missingDir|pathIsFileNotDir|readOnlyDir)' ./internal/agent/proxy/permcheck/
  ```
- **Pass:** `TestProbe_missingDir_reportsActionableWriteError`,
  `TestProbe_pathIsFileNotDir_reportsWriteError`,
  `TestProbe_readOnlyDir_reportsWriteError` pass; each message names the dir and the
  fix class.
- **Coverage:** D.
- **Pitfalls:** `TestProbe_readOnlyDir` will **not** trip when the test runs as
  root (root ignores the DAC bits) — the unit test guards this; do not run the probe
  suite as root expecting a write failure.

### 15.6 Reload probe — validate command via scoped sudo; permission vs config-invalid

- **Must:** The reload probe runs the backend's validate command (`nginx -t` /
  `apachectl configtest`, invoked under `sudo -n` on a real host). A **permission
  denial** ⇒ `can_reload: false`. A merely **config-invalid** result ⇒
  `can_reload: true` (the command ran, the privilege is present; the config error is
  the Apply/Validate path's problem, §10). The proxy's own output is carried into
  the message so the operator sees which key/log failed, capped at 600 chars
  (`permcheck.go:197-218`, `291-335`).
- **Access:** REST `proxy_permissions.can_reload` + `reload_error`; Dashboard panel.
- **Prerequisites:** a Go toolchain (the table uses an injected `fakeRunner`, no real
  proxy/sudo); for the R confirmation, an installed nginx/apache reachable via
  `sudo -n`.
- **Steps:**
  ```bash
  go test -run 'TestProbe_reload_table' ./internal/agent/proxy/permcheck/
  ```
- **Pass:** the table cases pass — "syntax is ok" → CanReload true; unknown-directive
  config error → CanReload **true** (benign); "a password is required" /
  "is not allowed to execute" / `os.ErrPermission` / `exec.ErrNotFound` →
  CanReload false.
- **Coverage:** D (injected `fakeRunner`); R to confirm the real `sudo -n nginx -t`
  path against an installed proxy.
- **Pitfalls:** A nil `Runner` **skips** the reload probe and reports
  `can_reload: true` — that is the admin-API caddy path which needs no service
  reload (`permcheck.go:145`, `TestProbe_nilRunner_skipsReloadProbe`). Do not read a
  built-in agent's absent reload check as "reload OK".

### 15.7 `isPermissionDenied` needle matching

- **Must:** Treated as a privilege denial: `os.ErrPermission`, and output/error
  containing any of "permission denied", "operation not permitted", "a password is
  required", "a terminal is required", "sudo: no tty present", "is not allowed to
  execute", "not in the sudoers file", "command not found", "executable file not
  found". A **bare** "no such file or directory" is deliberately **not** matched
  (far more often a config error than a missing binary) — matching stays
  conservative so it never over-reports (`permcheck.go:230-251`).
- **Access:** internal — covered by the reload table + dedicated assertions.
- **Prerequisites:** a Go toolchain.
- **Steps:** `go test ./internal/agent/proxy/permcheck/`
- **Pass:** the needle set above all classify as denials; a "no such file" config
  error classifies as benign (CanReload true).
- **Coverage:** D.
- **Pitfalls:** This is the homelab **passwordless-sudo** gotcha in code form: a host
  whose sudoers prompts for a password yields "a password is required" / "a terminal
  is required" under `sudo -n`, which is **correctly** reported as `can_reload:
  false`. The fix is the scoped NOPASSWD sudoers line (15.10), not blanket sudo. See
  RELEASE-QA "sudo: apps-vm is NOPASSWD; durox needed a passwordless-sudo config".

### 15.8 RuntimeEnv detection

- **Must:** `runtime_env` reports `os` (GOOS), `distro`,
  `init_system` (one of `systemd`/`openrc`/`launchd`/`windows-service` or empty when
  run directly), `managed`, `unit`, `sandboxed`, `user`, `is_root`. Detection is
  read-only, best-effort, never fails; unknowns stay at zero value
  (`runtimeenv.go:37-102`). The internal `runtimeenv.Env` also parses the os-release
  `ID_LIKE` family (`DistroLike`), but the wire model (`models.RuntimeEnv`) and
  `toRuntimeEnv` (`main.go:515-526`) **omit** it — there is no `distro_like` JSON
  field, so it is not surfaced over REST or in the dashboard.
  - init system is classified from env vars children inherit: systemd
    (`INVOCATION_ID`/`JOURNAL_STREAM`), OpenRC (`RC_SVCNAME`), launchd
    (`XPC_SERVICE_NAME` ≠ "0") — `runtimeenv.go:128-143`.
  - unit name comes from env (OpenRC's `RC_SVCNAME` / launchd's `XPC_SERVICE_NAME`);
    for systemd it is parsed from `/proc/self/cgroup` — the first path segment ending
    in `.service` or `.scope` (`runtimeenv.go:87-91`, `148-161`).
  - `sandboxed` is true when `/etc` is a **read-only mount** for the process
    (systemd `ProtectSystem=`), checked only under systemd via `/proc/self/mountinfo`
    (`runtimeenv.go:93-99`, `169-187`).
- **Access:** REST `proxy_permissions.runtime_env`; Dashboard shows e.g. "systemd
  service on Debian, running as root" next to the fix.
- **Prerequisites:** a Go toolchain for the parser tests; for the live comparison, an
  existing-mode agent run once foreground and once under a service manager (a
  `systemd-run` scope is enough — no real proxy needed).
- **Steps:**
  ```bash
  go test ./internal/agent/runtimeenv/        # parser unit tests
  # live: run an existing-mode agent under systemd vs foreground and compare:
  curl -s .../api/v1/agents | jq '.[].proxy_permissions.runtime_env'
  ```
- **Pass:** parser tests pass; a foreground run shows `init_system: ""`,
  `managed: false`; a systemd-managed run shows `init_system: "systemd"`,
  `managed: true`, a resolved `unit`, and `sandboxed: true` when the unit hardens
  `/etc`.
- **Coverage:** D (pure parser tests, and a foreground/`systemd-run` comparison
  needs no real proxy); R to confirm `sandboxed` against a production hardened unit.
- **Pitfalls:** launchd sets `XPC_SERVICE_NAME=0` for processes it did **not**
  launch as a service — only a non-"0" value counts (`runtimeenv.go:138`). On
  Windows `UID` is -1 and `is_root` is false. `sandboxed` is only probed under
  systemd, so it is always false off-systemd even if a mount is read-only.

### 15.9 Runtime-aware health messages

- **Must:** The same missing grant produces a **different** actionable message
  depending on `RuntimeEnv`:
  - **Unprivileged**, write-denied: "add the agent user to the group that owns the
    config dir (or point it at a NurProxy-owned include dir)" (`permcheck.go:276-279`).
  - **Read-only FS under systemd**, write-denied: explains this is the unit's
    `ProtectSystem=` sandbox (not file perms) and to add the dirs to
    `ReadWritePaths` in a `systemctl edit <unit>` drop-in (`permcheck.go:262-268`).
  - **Root** (no systemd), write-denied: "not a group/ownership problem … check the
    service sandbox or an immutable/read-only mount" (`permcheck.go:269-275`).
  - **Root under systemd**, reload-denied: "not a sudo problem" — names **both** a
    read-only mount (ReadWritePaths) **and** a dropped capability (add
    `CAP_DAC_OVERRIDE` so root may read TLS keys / write logs)
    (`permcheck.go:297-303`).
  - **Unprivileged**, reload-denied: "grant a narrowly-scoped sudoers entry (NOPASSWD
    for exactly … and the matching test command), not blanket sudo"
    (`permcheck.go:310-318`). The exact `ReloadHint` command is woven in when set
    (nginx default `nginx -s reload`, `nginx.go:589-601`).
  - Both failures are reported **together** in `HealthError()` so the operator fixes
    everything in one pass (`permcheck.go:85-97`).
- **Access:** REST `proxy_permissions.write_error` / `reload_error`; Dashboard panel
  message text.
- **Prerequisites:** a Go toolchain.
- **Steps:**
  ```bash
  go test -run 'TestWriteMessage_runtimeAware|TestReloadMessage_runtimeAware' \
      ./internal/agent/proxy/permcheck/
  ```
- **Pass:** both runtime-aware message tests pass; the message wording matches the
  runtime case.
- **Coverage:** D.
- **Pitfalls:** A root agent that gets a sudo-flavored message is a regression — for
  root the fix is **never** sudo (it is the sandbox / capability / file
  ownership). The read-only-FS branch keys on the literal "read-only file system"
  string (portable across OSes), not `syscall.EROFS` (`permcheck.go:341-343`).

### 15.10 Remediation outputs (BuildRemediation)

- **Must:** `BuildRemediation` is pure (builds strings only, never touches the host,
  never panics on empty input). Steps are ordered and **only the missing grants** are
  emitted (`holder.go:506-528` sets `Dirs` only when `!CanWrite`, the test/reload
  cmds only when `!CanReload`):
  - **systemd step (step 0):** a numbered drop-in
    `/etc/systemd/system/<unit>.d/10-nurproxy-writepaths.conf` with
    `ReadWritePaths=` covering the proxy's dirs (prefixed `-` so an absent path is
    ignored), then `daemon-reload` + `restart <unit>`. For a **root** agent it also
    adds `AmbientCapabilities`/`CapabilityBoundingSet` set to
    `CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE CAP_CHOWN` (the bind cap is retained alongside the
    restored DAC override), and that step is the **complete** fix (group/sudo do not
    apply to root) — the
    builder returns early (`remediation.go:119-145`, `204-241`,
    `DefaultSandboxWritePaths` lines 29-34).
  - **group/ownership step (step 1, non-root):** `groupadd -f nurproxy`,
    `usermod -aG nurproxy <user>`, then per dir `chgrp -R`, `chmod -R g+w`, and
    `chmod g+s` (setgid so new files inherit the group) — **no sudo for the agent
    itself** (`remediation.go:147-168`).
  - **scoped sudoers step (step 2, non-root):** the exact line
    `<user> ALL=(root) NOPASSWD: <test>, <reload>`, written to
    `/etc/sudoers.d/nurproxy-agent` (0440), validated with `visudo -c`; a note warns
    when a command path is not absolute (`remediation.go:170-199`, `sudoersPath`
    line 17). `SudoersLine` is also surfaced standalone.
- **Access:** REST `proxy_permissions.remediation` (`{steps:[{title,commands}],
  sudoers_line}`); Dashboard renders the copy-paste `CommandBlock`
  (`web/src/components/CommandBlock.tsx`).
- **Prerequisites:** a Go toolchain for the builder tests; for the live shape, an
  existing-mode agent with at least one grant denied. **R** for the effect: a real
  systemd host with the proxy installed.
- **Steps:**
  ```bash
  go test ./internal/agent/proxy/permcheck/   # remediation_test.go
  # live shape, against a real existing-mode agent with a missing grant:
  curl -s .../api/v1/agents | jq '.[].proxy_permissions.remediation'
  ```
- **Pass:** the remediation unit tests pass; a denied existing-mode agent returns a
  `remediation` whose steps/sudoers_line match the runtime case above; a fully-granted
  agent returns `remediation: null`.
- **Coverage:** D for building/reporting the commands; **R for the *effect*** —
  actually applying the drop-in / group / sudoers on a real systemd host and
  re-probing to `ok: true`.
- **Pitfalls:** The commands are **copy-paste for a human with local shell
  presence** — the agent never runs them (§19 trust boundary). The systemd drop-in
  body is rendered via a single-quoted `printf` with literal `\n`
  (`remediation.go:230-236`); paste it as-is. `ReadWritePaths` entries are `-`
  prefixed so a path absent on this host does not fail the unit's start.

### 15.11 OK() / HealthError() and health/last_error sync

- **Must:** `OK()` is true only when **both** `CanWrite && CanReload`; `HealthError()`
  is "" when OK and otherwise joins both failure messages with a space
  (`permcheck.go:78-97`). The agent feeds `HealthError()` into `health.SetError`
  each beat (`main.go:435`), and maps the result + remediation into the wire model
  (`toProxyPermissions`/`toRuntimeEnv`, `main.go:488-526`).
- **Access:** REST `proxy_permissions.ok` + `.../status` (`last_error`); Dashboard
  Wallboard treats a failed §12 probe as connected-but-degraded
  (`web/src/lib/status.ts:38-47`, `web/src/pages/Wallboard.tsx:34`).
- **Prerequisites:** a Go toolchain for the unit assertion; for the Wallboard check,
  an existing-mode agent with both grants denied feeding a (dry) orchestrator.
- **Steps:** `go test -run 'TestProbe_bothFail_healthErrorCombinesBoth' ./internal/agent/proxy/permcheck/`
- **Pass:** the combined-message test passes; a both-failed existing agent shows the
  agent as degraded (not down) on the Wallboard with a fixable reason.
- **Coverage:** D.
- **Pitfalls:** A failed permission probe must **not** mark the agent down/offline —
  it is a degraded-but-connected state, like a bind failure; the agent keeps
  heartbeating so the fix can be driven from the dashboard (`permcheck.go:14-18`).

### 15.12 Dashboard permissions panel

- **Must:** The Agents detail page shows, for an existing-mode agent, the §12
  permission self-test: write/reload status, the runtime context (e.g. "systemd
  service on Debian, running as root"), and the copy-paste remediation when a grant
  is missing.
- **Access:** Dashboard → Agents (`web/src/pages/Agents.tsx`,
  `PermissionSelfTest` component); types in `web/src/lib/types.ts`
  (`ProxyPermissions`, `Remediation`, `RemediationStep`, `RuntimeEnv`).
- **Prerequisites:** the dashboard served by an orchestrator that has at least one
  adopted existing-mode agent reporting a denied grant, plus (for the negative case)
  a built-in agent to confirm the panel is absent.
- **Steps:** open the dashboard, select an existing-mode agent with a denied grant,
  read the panel and the remediation block; then select a built-in agent and confirm
  no permissions panel renders.
- **Pass:** panel lists `can_write`/`can_reload`, the runtime env, and the exact
  copy-paste steps + `sudoers_line`; panel is absent for a built-in agent.
- **Coverage:** D (dry orchestrator + a real-config existing-mode agent feeding it)
  / R to confirm the end-to-end "apply the steps, panel goes green" loop.
- **Pitfalls:** The panel reflects the **last beat** — after applying a fix, wait one
  heartbeat for it to clear; do not refresh-spam expecting an instant flip.

## Acceptance checklist

**Dry (every RC):**
- [ ] `make test` green, including `./internal/agent/proxy/permcheck/` and `./internal/agent/runtimeenv/`.
- [ ] Built-in dry agent reports `proxy_permissions: null` (15.1).
- [ ] Existing-mode agent (real config layout, no root) reports `checked: true`, correct `dirs` per layout, and `runtime_env` (15.1, 15.4, 15.8).
- [ ] Toggle config-dir writability → `can_write`/`ok` flip across two beats with no restart; `last_error` tracks (15.2, 15.11).
- [ ] Reload table + needle classification + runtime-aware messages + remediation shape all pass in the unit suite (15.6-15.10).
- [ ] Failed probe shows the agent degraded-but-connected, never down (15.11).
- [ ] Dashboard panel renders status + runtime + copy-paste remediation for a denied existing agent; absent for built-in (15.12).

**Real run (before final):**
- [ ] On a real systemd host with the proxy installed: deny a grant, confirm the reported message/remediation matches the runtime (root-vs-unprivileged, sandboxed-vs-not).
- [ ] Apply the emitted remediation (group + setgid, `/etc/sudoers.d/nurproxy-agent`, or the `ReadWritePaths`/`CAP_DAC_OVERRIDE` drop-in) and confirm the next beat reports `ok: true` and the dashboard panel clears (15.10, 15.12).
- [ ] Confirm `sudo -n <test>`/`<reload>` succeeds after the scoped sudoers line on a password-prompting host (the homelab passwordless-sudo gotcha — 15.7).
- [ ] Confirm `runtime_env.sandboxed` is true under a real hardened unit and false foreground (15.8).

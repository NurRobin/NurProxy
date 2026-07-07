# Backend: Existing (host-installed) Caddy

> **Scope:** what actually happens when a user selects `-proxy-mode existing -proxy-type caddy` — i.e. asks NurProxy to manage an already-installed, host-owned Caddy rather than the bundled built-in Caddy.
> **Code:** `internal/agent/proxy/registry.go`, `internal/agent/proxy/caddy/caddy.go`, `internal/agent/proxy/holder.go`, `internal/agent/proxy/detect.go`, `internal/agent/proxy/parse.go`, `cmd/nurproxy-agent/main.go`, `internal/agent/config/config.go`, `internal/agent/caddy/caddy.go`.
> **Coverage legend:** D = coverable dry, R = needs a real run.

---

## TL;DR — the truth about "existing + caddy"

There is **no file-based / Caddyfile-on-disk Caddy backend**. Only **three** proxy
backends are registered in the agent's proxy registry, each via its package `init()`:

- `apache` — file backend (registered at `internal/agent/proxy/apache/apache.go:57`; `Info().Kind = apache` at `apache.go:163`, targets `TargetKindFile` at `apache.go:252`).
- `nginx` — file backend (registered at `internal/agent/proxy/nginx/nginx.go:51`; `Info().Kind = nginx` at `nginx.go:156`, targets `TargetKindFile` at `nginx.go:247`).
- `caddy` — **admin-API backend, NOT a file backend** (`internal/agent/proxy/caddy/caddy.go:42-50`). Its own package doc states it explicitly: *"The backend never writes config files: built-in Caddy is driven entirely through its localhost admin API"* (`caddy.go:6-9`).

`reconfigureExisting` resolves the backend by name with `Get(req.Type, ...)`
(`holder.go:392`). For `req.Type == "caddy"` the registry returns **the same
admin-API backend the built-in mode uses** (`registry.go:73-81` → the factory at
`caddy.go:43`). So:

**`-proxy-mode existing -proxy-type caddy` does NOT manage a host Caddyfile. It hands
the Holder the admin-API Caddy backend, then stops the bundled Caddy and points that
admin-API client at a Caddy admin port — but with `AdminPort` unset (zero) on the
existing-mode path. The net effect is a degenerate / effectively-unsupported config.**
See the detailed analysis in the test below. **This is a documented gap, not a
working mode.** The first-class ways to run Caddy are: **built-in** (bundled, admin-API,
the default and only properly-supported Caddy path — see `11`/`§2.5b` in RELEASE-QA.md),
and **existing nginx / existing apache** for host-installed file-based proxies.

---

## Prerequisites

- Both binaries built: `make build-all` (produces `./nurproxy`, `./nurproxy-agent`).
- For dry verification: nothing else — the agent's proxy is simulated in-memory
  (`NP_DRY_RUN=true`, see CLAUDE.md "Dry-run / Sandbox").
- For real verification of the gap: a Linux host with a host-installed `caddy` in
  `PATH` and (optionally) a running host Caddy with its admin API on some port.
- Detection (read-only) needs `caddy version` to succeed and, for port-conflict
  reporting, `ss` available.

---

## Features covered

- [ ] **Selection / flags:** `-proxy-mode existing` + `-proxy-type caddy` (and the
      `NP_*` env / `agent.yaml` equivalents) and how they validate.
- [ ] **Backend resolution:** what `Get("caddy", cfg)` actually returns (admin-API
      backend, no file backend exists).
- [ ] **Read-only detection** of a host-installed Caddy (`caddy version`, config dir,
      log paths, port conflicts) — independent of the management mode.
- [ ] **Startup honoring of existing+caddy** (`main.go` step 3b): bundled Caddy not
      started, Holder hot-switched, permission probe skipped, `AdminPort=0` defect.
- [ ] **Config write / reload model** — i.e. that there is none for caddy (no
      Caddyfile written, no `caddy reload`/`caddy validate` invoked).
- [ ] **Adoption** (`ReadManaged` → `ReportAdopted`) under existing+caddy.
- [ ] **TLS handling** under existing+caddy (cert store wiring vs. admin-API reality).
- [ ] **Permission probe / remediation** behaviour for an admin-API backend.
- [ ] **The gap itself:** exactly what a user sees if they select this, documented.

---

## Tests

### 1. Selection & flag validation (`-proxy-mode existing -proxy-type caddy`)

- **Must:** the agent accepts the selection without a hard error. `proxy_mode` is the
  only field validated against an allowed set; `proxy_type` is **not** range-checked.
- **Access:**
  - **Agent flags:** `-proxy-mode existing -proxy-type caddy`
    (`cmd/nurproxy-agent/main.go:53-54`). `-proxy-mode` help text: `built-in (default) | existing`;
    `-proxy-type` help text: `caddy | nginx | apache` (`main.go:53-54`).
  - **Env:** `NP_PROXY_MODE=existing NP_PROXY_TYPE=caddy` (full set:
    `NP_PROXY_{MODE,TYPE,BINARY,CONFIG_DIR,RELOAD_CMD,TEST_CMD,LOG_PATHS,SERVICE}`,
    `config.go:237-260`). Priority is **flags > env > config file > defaults**
    (`config.go:97`, applied in `mergeFile`→`mergeEnv`→`mergeFlags`,
    `config.go:131-140`). `agent.yaml` keys: `proxy_mode`, `proxy_type`, plus
    `proxy_binary` / `proxy_config_dir` / `proxy_reload_cmd` / `proxy_test_cmd` /
    `proxy_log_paths` / `proxy_service` (`config.go:35-52`).
  - **Dashboard / REST:** the orchestrator-driven set-proxy-mode payload carries
    `proxy_mode` + `proxy_type` (`internal/agent/api/api.go:348-349,401-402`); the
    agent local hot-switch endpoint `POST /admin/reconfigure` takes the same
    (`cmd/nurproxy-agent/apply.go:31-33,179-187,298-301`).
  - **No MCP tool** for this.
- **Prerequisites:** none beyond file-level.
- **Steps (dry):**
  ```bash
  make build-all
  NP_DRY_RUN=true ./nurproxy-agent \
    -orchestrator http://localhost:8080 \
    -fqdn caddyx.example.com \
    -proxy-mode existing -proxy-type caddy
  ```
  (No orchestrator needed to observe the startup log lines; it will fail to register,
  which is fine for this check.)
- **Pass:**
  - Startup log prints `Proxy mode:   existing` (`main.go:121`).
  - Config validation does **not** reject `proxy_type=caddy`: only `proxy_mode` is
    validated (`config.go:155-157`); there is no `proxy_type` allow-list anywhere.
  - The agent does **not** crash on the selection (fail-soft, `Reconfigure` never
    returns a fatal error — `holder.go:354-361`).
- **Coverage:** D.
- **Pitfalls:** because `proxy_type` is unvalidated, a typo or an unsupported value
  is only caught later at `Get(req.Type, ...)` — an unknown type yields the fail-soft
  health message `"%q is not a known proxy backend"` (`holder.go:406`), but `caddy`
  IS a known backend, so it silently resolves to the admin-API one (test 2).

### 2. Backend resolution — `caddy` resolves to the admin-API backend (the gap)

- **Must:** be honest that `existing + caddy` does not give a file-managed Caddy.
- **Access:** internal; observed via behaviour + logs from test 1's invocation, or
  by reading the code paths cited.
- **Prerequisites:** none.
- **What the code does, step by step:**
  1. `reconfigureExisting` requires a non-empty `Type` (`holder.go:383-390`) — `caddy` passes.
  2. It calls `Get("caddy", Config{Type:"caddy", Binary:…, ConfigDir:…, ReloadCmd:…,
     TestCmd:…, Service:…, LogPaths:…, CertDir:…, EncryptKey:…})` (`holder.go:392-404`).
     **Note `AdminPort` is NOT set here — it is the zero value `0`.**
  3. The registry returns the factory registered under `"caddy"`, which is the
     admin-API backend factory: `New(agentcaddy.NewClient(cfg.AdminPort))`
     (`caddy.go:43-49`). With `cfg.AdminPort == 0`, the client base URL becomes
     `http://localhost:0` (`internal/agent/caddy/caddy.go:149-151`).
  4. The permission probe is **skipped**: `probeExisting` only probes backends that
     implement the `fileBackend` interface (`ProbeDirs/ReloadHint/ResolvedCommands`)
     — the admin-API caddy backend does not, so the probe returns an all-clear
     `{CanWrite:true, CanReload:true}` with no remediation (`holder.go:484-489`).
  5. `StopCaddy` is invoked, stopping the **bundled** Caddy so "the host proxy can own
     :80/:443" (`holder.go:419-425`) — but nothing in this path actually drives the
     host Caddy's config.
  6. The Holder swaps `current` to the admin-API backend and sets `mode="existing"`
     (`holder.go:429-432`); `SetCaddyRunning(false)` (`holder.go:435-437`).
  7. Because the probe is all-clear, it reports `OK:true`, message
     `"switched to existing caddy — config is writable and reloadable"`
     (`holder.go:439-445`) — **a misleading success string**: nothing was made
     writable/reloadable; there is no file backend.
- **Pass (what to assert / accept as the documented truth):**
  - No separate Caddyfile/file caddy backend is registered (only the three in the
    TL;DR). Confirm: `grep -rn 'proxy.Register' internal/agent/proxy/*/*.go` returns
    exactly apache, caddy, nginx.
  - `existing + caddy` reaches the **admin-API** backend with `AdminPort=0`.
  - Route Apply on this backend talks to the admin API (`Apply` → EnsureServer /
    ClearRoutes / AddRoute, `caddy.go:237-250`) at `http://localhost:0`, which is not a
    real, reachable host-Caddy admin endpoint unless the host Caddy happens to be on a
    port the agent never passes here.
- **Coverage:** D (resolution + logs) / R (to observe that real route application to a
  host Caddy does not work).
- **Pitfalls:**
  - The success message at `holder.go:440` is the trap: a tester may see
    `"switched to existing caddy — config is writable and reloadable"` and conclude it
    works. It is the generic file-backend success string reached via the all-clear
    probe; it does **not** mean a host Caddy was configured.
  - There is no `AdminPort` plumbing on the existing path. The built-in path uses
    `cfg.CaddyAdminPort` (`main.go:211,237,346`), but `reconfigureExisting` never sets
    `Config.AdminPort` (`holder.go:392-404`), so the existing-mode admin client targets
    `:0`. **UNVERIFIED whether any code elsewhere repoints it** — grep showed none.

### 3. Read-only detection of a host-installed Caddy

- **Must:** independent of management mode, the agent's read-only detector recognizes
  an installed Caddy, parses its version, resolves its config dir + log paths, and
  reports who holds :80/:443. This is Phase-0 detection and **never mutates** host state
  (`detect.go:1-12`).
- **Access:** automatic — detection runs once at startup/adoption (`main.go:147`
  `detectProxy(ctx)` → `mgr.SetDetection`) and again on every heartbeat
  (`main.go:414` `hb.SetDetectionFn(func() … { return detectProxy(ctx) })`). Surfaced
  read-only on the agent row / dashboard.
- **Prerequisites (real):** a host with `caddy` in `PATH`.
- **Detection specifics from code:**
  - Probe order is nginx → apache → caddy (`detect.go:157-161`); caddy is probed with
    binary name `caddy` and version args `version` (`detect.go:160`). **First match
    wins** (`detect.go:188` `break`) — so on a host that has BOTH nginx and caddy,
    detection reports **nginx**, not caddy.
  - Config dir for caddy is always reported as `/etc/caddy` (`parse.go:85-91`): it
    is the sole candidate, and `firstExistingDir` falls back to the first candidate
    when none exist (`parse.go:173-183`) — so `config_dir=/etc/caddy` even on a host
    where that directory was never created.
  - Log path probed: `/var/log/caddy/access.log`, included only if it exists on disk
    (`existingFiles`, `parse.go:90`,`186-194`).
  - Port-conflict holders for :80/:443 are reported via `ss -ltnp` with a `/proc`
    fallback (`detect.go:216-250`).
- **Steps (real):** run a non-dry agent on a host with caddy installed and adopt it;
  inspect the agent's reported `ProxyDetection`.
- **Pass:** `installed=true`, `kind="caddy"` (only if nginx/apache absent),
  `version` parsed, `config_dir=/etc/caddy` (always — the canonical default), and any
  :443 holder named.
- **Coverage:** R (real host needed for true detection). Parsing helpers
  (`ParseVersion`, `ResolvePaths`, `ParseSSOutput`) are unit-tested — **D** for the
  pure logic (`detect_test.go`, `parse_test.go`).
- **Pitfalls:** detection is read-only and orthogonal to management; detecting a host
  Caddy does **not** imply existing+caddy management works (test 2). On a host with
  nginx present, caddy detection is masked by the first-match `break`.

### 4. Startup honoring of a persisted existing+caddy (`main.go` step 3b)

- **Must:** an agent started (or restarted) with `proxy_mode=existing, proxy_type=caddy`
  goes through the same `Reconfigure` path at boot, lands in mode `existing`, and never
  crashes. The bundled Caddy is NOT started.
- **Access:** agent flags / `agent.yaml` (test 1).
- **Steps (dry):**
  ```bash
  NP_DRY_RUN=true ./nurproxy-agent \
    -orchestrator http://localhost:8080 -fqdn caddyx.example.com \
    -proxy-mode existing -proxy-type caddy
  ```
- **Pass:**
  - Log: `Existing mode: not starting the bundled Caddy (the host proxy owns :80/:443)`
    (`main.go:215`) — but **note:** under `NP_DRY_RUN` the dry branch
    (`main.go:212-213`) takes precedence over the existing branch for the *subprocess*
    start; the `existingMode` flag still drives step 3b (`main.go:206,369-381`).
  - Log: `Existing mode honored at startup: …` (`main.go:380`) with the message from
    `Reconfigure` (for caddy: the misleading "config is writable and reloadable",
    test 2).
  - `holder.Mode()` is `existing`, reported on the next heartbeat
    (`ddns.go:49-52,216`).
- **Coverage:** D.
- **Pitfalls:** in dry-run the bundled Caddy is simulated regardless; this test proves
  the *control-plane* path honors the mode, not real serving. Real serving by a host
  Caddy is **not** exercised (test 2's gap).

### 5. Config write / reload model — there is none for caddy

- **Must:** be explicit that, unlike existing-nginx/apache (which write
  `nurproxy-*.conf` and run a reload/`-t` test), existing+caddy writes **no config
  file** and runs **no reload/validate command**.
- **Access:** internal behaviour.
- **Prerequisites:** none.
- **Code facts:**
  - The caddy backend's targets are `TargetKindCaddyRoute` (`caddy.go:199`), not
    `TargetKindFile` — so there is no on-disk vhost. `Prune` is a no-op (`caddy.go:291-293`).
  - `Apply` posts route JSON to the admin API (`caddy.go:237-250`); it never writes a
    Caddyfile and never shells out to `caddy reload`/`caddy validate`.
  - `Validate` round-trips the live config through the admin API (`caddy.go:312-322`),
    not via `caddy validate`.
  - The file backends are the contrast: nginx/apache implement `fileBackend`
    (`ProbeDirs/ReloadHint/ResolvedCommands`, used by `holder.go:484-528`) and write
    prefixed conf files (`nginx.go:247`, `apache.go:252`). The caddy backend implements
    none of these.
- **Pass:** confirm (by reading the cited lines, or by observing logs in test 2/4)
  that no `caddy reload`, no `nurproxy-*.conf`-equivalent, and no Caddyfile path is
  exercised in existing+caddy.
- **Coverage:** D.
- **Pitfalls:** RELEASE-QA.md §2.5a's "agent only manages the `nurproxy-` prefix" and
  the `nginx -t` reload expectation are **nginx/apache** facts. They do **not** apply
  to caddy — do not look for `nurproxy-*.conf` under `/etc/caddy`.

### 6. Adoption (`ReadManaged` → `ReportAdopted`) under existing+caddy

- **Must:** at startup in existing mode the agent reads its managed config and reports
  it to the central store (`main.go:399-407`). For the admin-API caddy backend,
  "managed config" is the **live admin-API route set**, not files on disk.
- **Access:** automatic at startup when `holder.Mode()=="existing"` (`main.go:399`).
- **Prerequisites:** an orchestrator to receive `ReportAdopted` (use the sandbox).
- **Code facts:** `ReadManaged` for caddy calls `client.ListRoutes` and wraps each as
  a `TargetKindCaddyRoute` artifact (`caddy.go:209-226`). With `AdminPort=0` (test 2)
  this call targets `http://localhost:0` and will error; the agent logs
  `WARNING: could not read existing config for the central store: …` (`main.go:401`) —
  **non-fatal** (best-effort, `main.go:396`).
- **Steps (dry):** bring up the sandbox and add a dry caddy-existing agent by hand:
  ```bash
  make build-all
  NP_DRY_RUN=true ./nurproxy -port 8080 -data-dir /tmp/np-orch &
  NP_DRY_RUN=true ./nurproxy-agent -orchestrator http://localhost:8080 \
    -fqdn caddyx.example.com -proxy-mode existing -proxy-type caddy
  ```
- **Pass:** agent connects and heartbeats; the adoption read either reports artifacts
  (dry mock client) or logs the non-fatal read warning — in neither case does the
  agent die.
- **Coverage:** D.
- **Pitfalls:** in dry-run the caddy client is the in-memory mock
  (`main.go:227-228`), so `ReadManaged` succeeds against the mock — this does NOT prove
  real host-Caddy adoption. Against a real host Caddy with `AdminPort=0`, expect the
  read warning.

### 7. TLS handling under existing+caddy

- **Must:** be clear how central TLS is (not) served. The cert store IS wired into the
  reconfigure deps (`CertDir`/`CertKey`, `main.go:343-344`, threaded into `Get` at
  `holder.go:400-403`), so the rebuilt backend gets a cert store
  (`caddy.go:44-47`). But the admin-API backend's TLS path (`EnsureServerTLS`,
  `InstallCerts`, `caddy.go:336-431`) drives the **Caddy admin API** — at `:0` on this
  path — not a host Caddyfile's `tls` directives.
- **Access:** automatic via the stream (certs ride the agent-initiated stream, then
  `InstallCerts` before `Apply`).
- **Code facts:**
  - `InstallCerts` writes bundles via the cert store and encrypts keys at rest
    (`caddy.go:336-360`); with no cert store it is a logged no-op with a self-ACME note
    (`caddy.go:340-344`).
  - `EnsureServerTLS` PUTs a TLS strategy to the admin API (`caddy.go:383-431`).
  - For built-in mode these are the real central-TLS mechanism. For existing+caddy
    they target the same admin-API client with `AdminPort=0`.
- **Steps:** dry sandbox + a central-TLS domain (see `make dev-sandbox`); observe that
  cert install logs run but admin-API TLS application targets the unreachable port on
  a real host.
- **Pass (documented truth):** central TLS for existing+caddy is **not** delivered to
  a host Caddy via Caddyfile; it goes through the admin-API path that built-in uses.
  On a real host with `AdminPort=0` it does not reach a host Caddy. Mark serving as
  **UNVERIFIED / unsupported** for this mode.
- **Coverage:** D (logic/logs) / R (to confirm no real serving).
- **Pitfalls:** RELEASE-QA.md §7-style "self-ACME fallback" notes assume the bundled
  Caddy; for existing+caddy there is no running bundled Caddy (it was stopped,
  `holder.go:419-425`), so self-ACME does not apply either.

### 8. Permission probe / remediation for an admin-API backend

- **Must:** the §12 permission probe is a no-op (all-clear) for an admin-API backend
  because there is no file-write or service-reload privilege to test.
- **Access:** `holder.ProbePermissions` runs on every heartbeat (`main.go` heartbeat
  wiring) and at hot-switch (`holder.go:417`).
- **Code facts:** `ProbePermissions` returns `{CanWrite:true, CanReload:true}, nil,
  nil, checked=false` when the current backend is not a `fileBackend`
  (`holder.go:469-477`); `probeExisting` likewise (`holder.go:484-489`). The caddy
  backend is not a `fileBackend`.
- **Pass:** no permission block / no remediation shown for existing+caddy; the
  dashboard shows no "grant these rights" prompt (unlike existing-nginx).
- **Coverage:** D.
- **Pitfalls:** the all-clear is **structural**, not a real privilege check — it does
  not mean the agent can actually configure a host Caddy. It feeds the misleading
  success string in test 2.

### 9. The gap, stated for the release notes

- **Must:** the release book records, in one place, what a user gets if they pick
  `-proxy-mode existing -proxy-type caddy`.
- **Observable outcome:** the agent starts, does not crash, reports mode `existing`,
  stops the bundled Caddy, and logs the success-sounding message
  `"switched to existing caddy — config is writable and reloadable"`. **But** it
  manages no host Caddyfile, runs no `caddy reload`/`validate`, and its admin-API
  client targets `:0` (`AdminPort` unset on this path) so it does not actually drive a
  host Caddy. There is no live serving via a host Caddy through NurProxy in this mode.
- **Recommended user guidance:** for Caddy, use **built-in** mode (the default,
  fully-supported admin-API path). For host-installed file-based proxies use
  **existing nginx** or **existing apache**. Treat **existing+caddy as unsupported**.
- **Coverage:** D (everything above is observable dry).
- **Pitfalls:** this is a real correctness/clarity gap, not just docs:
  - misleading success message (`holder.go:440`);
  - `AdminPort=0` on the existing path (`holder.go:392-404` vs. built-in `main.go:346`);
  - `proxy_type` unvalidated (`config.go:155-157`) so the bad combo is accepted silently.
  Consider filing/linking a tracking issue (parallels RELEASE-QA.md §4 gaps such as
  existing-apache / non-Linux not-yet-covered).

---

## Acceptance checklist

### Dry (every RC)
- [ ] Only three backends registered: `grep -rn 'proxy.Register' internal/agent/proxy/*/*.go` → apache, caddy, nginx (no separate file-caddy).
- [ ] `-proxy-mode existing -proxy-type caddy` is accepted (no validation error; `proxy_type` is unvalidated — `config.go:155-157`).
- [ ] Agent boots in existing+caddy, logs `Existing mode honored at startup: …`, reports mode `existing`, does not crash.
- [ ] Confirmed: `Get("caddy", …)` returns the admin-API backend (`caddy.go:43`), not a file backend; `AdminPort` is unset (`0`) on the existing path (`holder.go:392-404`).
- [ ] Confirmed: no Caddyfile written, no `caddy reload`/`validate` invoked; caddy targets are `TargetKindCaddyRoute` (`caddy.go:199`), `Prune` is a no-op (`caddy.go:291`).
- [ ] Permission probe is all-clear/no-op for the admin-API backend (`holder.go:484-489`); no remediation shown.
- [ ] Detection pure-logic (version/paths/ss parsing) green via `make test`.

### Real run (before final)
- [ ] On a host with `caddy` installed (and no nginx/apache), read-only detection reports `kind=caddy`, version, `/etc/caddy`, and :443 holder.
- [ ] Confirm the gap on a real host: existing+caddy does NOT serve real traffic via a host Caddy (admin-API client at `:0` cannot reach a host Caddy); route Apply / central TLS do not land. Record as a known limitation.
- [ ] Note in release notes: existing+caddy is unsupported; use built-in Caddy, or existing nginx/apache.

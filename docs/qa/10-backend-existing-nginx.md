# Backend: Existing nginx (apply / reload / adopt / drift / prune)

> **Scope:** managing a host-installed nginx as the agent's reverse-proxy backend — selection, layout resolution, the atomic apply dance, overridable test/reload commands + sudo elevation, adoption, prune, remove, basic-auth htpasswd sidecars, the permission probe, and central-TLS cert references.
> **Code:**
> - `internal/agent/proxy/nginx/nginx.go` — Backend (Detect/Capabilities/Render/ReadManaged/Apply/Remove/Prune/Validate/InstallCerts/ProbeDirs/ResolvedCommands), `execRunner`, sudo elevation.
> - `internal/agent/proxy/nginx/paths.go` — `Layout`, `ResolveLayout`, `ManagedFileName`, `IsManagedFile`, `sanitizeHostForFile`.
> - `internal/agent/proxy/nginx/fileops.go` — `stagedFile`, `snapshot`, `restoreSnapshot`, `ensureSymlink`, `activationPresent`.
> - `internal/agent/proxy/nginx/attribution.go` — `AttributeNginxTestError`, `ErrAttribution`.
> - `internal/shared/nginxgen/generate.go` — the pure renderer.
> - `internal/agent/proxy/detect.go` + `parse.go` — detection (`exec.LookPath nginx`, `nginx -v`, `ResolvePaths`).
> - `internal/agent/proxy/holder.go` + `internal/agent/proxy/permcheck/*` — permission probe / remediation.
> - `cmd/nurproxy-agent/main.go` — agent flags & wiring (`detectProxy`, existing-mode reconfigure at startup).
> **Coverage legend:** D = coverable dry, R = needs a real run.

> **Note on what is dry-coverable here.** The dry/sandbox stack (`make dev-sandbox`, `NP_DRY_RUN=true`) does **not** exercise the nginx backend: dry-run forces the in-memory Caddy **mock client** (`cmd/nurproxy-agent/main.go:227-228` — `cfg.DryRun || caddyProc.IsMock() || !caddyProc.Running()` → `caddy.NewMockClient()`), and the sandbox launcher never sets existing-mode, so the file backend is never wired. (Dry-run and existing-mode are independent flags: setting both `-dry-run` *and* `-proxy-mode existing` would still hot-switch the Holder onto the real nginx file backend at startup, `main.go:369-381` — the startup honor is gated only on `existingMode`, not on dry-run. The sandbox just never does this.) See the CLAUDE.md "Not covered" note ("nginx/apache existing-mode apply/reload is not exercised"). What *is* coverable without a real running nginx are the **pure functions**: the renderer (`nginxgen`), `ResolveLayout`, `ManagedFileName`/`IsManagedFile`, `ParseVersion`, `AttributeNginxTestError`, and the atomic-apply orchestration via an **injected fake `Runner`** (unit tests in `*_test.go`) or against a **real nginx in Docker** (`-tags integration`). Anything that needs a live `nginx -t` / `nginx -s reload` / serving is marked **R**.

## Prerequisites
- Both binaries built: `make build-all` (orchestrator `./nurproxy`, agent `./nurproxy-agent`).
- For the **pure / unit** tests (D): a Go toolchain only. `make test` runs the nginx backend unit tests (fake `Runner`, `t.TempDir`).
- For the **integration** tests (D, against a real nginx): Docker available; run `go test -tags integration ./internal/agent/proxy/nginx/...`. If Docker is absent every test in that file `t.Skip`s (`nginx_integration_test.go` header).
- For the **real-host** tests (R): a host with `nginx` installed and in `PATH`, owning `:80`/`:443`; a real orchestrator + a real zone the agent is adopted into. Homelab reference host: **durox** (existing-nginx), see `~/CLAUDE.md`.
- The agent must run with `-proxy-mode existing -proxy-type nginx` (or the persisted `agent.yaml` equivalent). In existing mode the bundled Caddy stays dormant so nginx keeps `:80`/`:443` (`main.go:202-215`).
- Mini backend fixture for behaviour tests: see `docs/RELEASE-QA.md` §5 (`/tmp/np-e2e-service.py` on `:18099`).

## Features covered
- [ ] Backend selection: `-proxy-mode existing -proxy-type nginx` (+ env `NP_PROXY_MODE`/`NP_PROXY_TYPE`, agent.yaml, dashboard reconfigure).
- [ ] Detection: `exec.LookPath("nginx")`, `nginx -v` version parse, `:80`/`:443` conflict reporting, OS-default path resolution.
- [ ] Layout resolution: Debian `sites-available`+`sites-enabled` symlinks vs RHEL flat `conf.d` (`ResolveLayout`, `IsConfD`).
- [ ] Managed file naming: `nurproxy-<host>.conf` (only the `nurproxy-` prefix is managed); host sanitization (`*.` → `_wildcard.`).
- [ ] Atomic apply dance: snapshot → `.nurproxy-tmp` → stage → ensure symlink → `nginx -t` → rename + `nginx -s reload`; rollback on failure.
- [ ] Error attribution: our generated config vs the operator's pre-broken config; permission-denied detection.
- [ ] Overridable commands: `-proxy-test-cmd` / `-proxy-reload-cmd`; sudo `-n` elevation when unprivileged; `NURPROXY_NO_SUDO=1`.
- [ ] Adoption (`ReadManaged`): reads ALL files, `nurproxy-*` → generated (drift-tracked), others → adopted (`Source: manual`); operator files never touched.
- [ ] Prune: removes stale `nurproxy-*` files + symlinks + htpasswd sidecars on the next push; operator files never pruned.
- [ ] Remove: deletes file + symlink + htpasswd sidecar, then reloads.
- [ ] basic_auth htpasswd sidecar (`.htpasswd`, bcrypt entry, skipped from adoption/prune as auxiliary).
- [ ] Permission probe: write to `sites-available`/`sites-enabled`, reload via scoped sudoers (cross-link to permissions spec).
- [ ] Central TLS: `ssl_certificate` / `ssl_certificate_key` reference installed bundle paths; missing cert → TLS listener dropped (warning).
- [ ] Capability matrix advertised by the nginx backend.

## Tests

### Backend selection (`-proxy-mode existing -proxy-type nginx`)
- **Must:** the agent runs the nginx file backend (not the bundled Caddy), keeps the host nginx owning `:80`/`:443`, and reports mode `existing` on every heartbeat.
- **Access:**
  - **CLI / flags:** `nurproxy-agent -proxy-mode existing -proxy-type nginx [-proxy-config-dir …] [-proxy-binary …] [-proxy-reload-cmd …] [-proxy-test-cmd …] [-proxy-log-paths a,b] [-proxy-service …]` (`main.go:53-60`).
  - **Env:** `NP_PROXY_MODE=existing NP_PROXY_TYPE=nginx` (and `NP_PROXY_CONFIG_DIR`, `NP_PROXY_BINARY`, `NP_PROXY_RELOAD_CMD`, `NP_PROXY_TEST_CMD`, `NP_PROXY_LOG_PATHS`, `NP_PROXY_SERVICE`) — `config.go:237-260`. Precedence: flags > env > agent.yaml > defaults.
  - **agent.yaml:** persisted `proxy_mode: existing`, `proxy_type: nginx`; honored at startup via `holder.Reconfigure` (`main.go:369-381`).
  - **Dashboard / REST:** the agent's `POST /admin/reconfigure` endpoint (agent API), Bearer-token auth via the same `authMiddleware` as the rest of the admin surface (the CLI presents the agent's local token after a confirmation-code claim); driven by the orchestrator's set-proxy-mode op (`op_type: set_proxy_mode`). Request body is snake_case `proxy_mode`/`proxy_type`/`proxy_config_dir`/`proxy_binary`/`proxy_reload_cmd`/`proxy_test_cmd`/`proxy_service`/`proxy_log_paths` (`reconfigureRequest`, `internal/agent/api/api.go:347-356`); handler `handleReconfigure` at `api.go:384-419`; the CLI side forwards the confirmed admin-op payload verbatim (`cmd/nurproxy-agent/apply.go`). Returns 503 when no holder is wired. Mode value must be exactly `existing`; type one of `nginx | apache | caddy`.
- **Prerequisites:** real nginx in PATH (R).
- **Steps (R):**
  ```bash
  ./nurproxy-agent -proxy-mode existing -proxy-type nginx \
    -orchestrator http://<orch>:8080 -fqdn edge1.example.com
  ```
  Watch startup logs for `Existing mode: not starting the bundled Caddy …` and `Existing mode honored at startup: switched to existing nginx …`.
- **Pass:** agent logs existing mode; bundled Caddy not started; dashboard agent detail shows mode `existing`; nginx still binds `:80`/`:443`.
- **Coverage:** R.
- **Pitfalls:**
  - an empty `-proxy-type` with `-proxy-mode existing` is rejected: `reconfigure: proxy mode existing requires a proxy type (nginx | apache | caddy)` (`holder.go:384`). Invalid `proxy_mode` fails config load with `invalid proxy_mode %q (must be %q or %q)` (`config.go:155-156`).
  - `-proxy-service` / `NP_PROXY_SERVICE` is parsed and threaded through `proxy.Config.Service`, but the **nginx backend ignores it**: reload is always `nginx -s reload` (or the `-proxy-reload-cmd` override), never `systemctl reload`. `New` reads only `Binary`/`ConfigDir`/`LogPaths`/`ReloadCmd`/`TestCmd`/`CertDir`/`EncryptKey` (`nginx.go:119-136`, `registry.go:13-39`). To reload via a service manager, set `-proxy-reload-cmd "systemctl reload nginx"` explicitly.

### Detection (LookPath nginx, version parse, port conflicts, paths)
- **Must:** detection finds nginx, parses its version, resolves its config dir + log paths, and — when `:80`/`:443` is occupied — names the holding process. Detection is read-only and never mutates host state.
- **Access:** runs automatically at agent startup and on every heartbeat (`main.go:147`, `:414`); the result is the `ProxyDetection` shown on the dashboard agent detail (detected proxy kind/version/config dir/log paths, port conflicts, discovered upstreams, networks). Pure helpers `ParseVersion` / `ResolvePaths` / `ParseSSOutput` are unit-tested.
- **Steps:**
  - **D (pure):** `make test` covers `ParseVersion(KindNginx, "nginx version: nginx/1.24.0 (Ubuntu)") == "1.24.0"` (`parse.go:18`, `versionRe` at `parse.go:12`), `ResolvePaths(KindNginx)` (`parse.go:54-69`), `ParseSSOutput` (`parse.go:214`).
  - **R:** on the real host, `./nurproxy-agent -version` is not detection; instead run the agent and read the startup line `Proxy detection: installed=true kind="nginx" version="…" config_dir="…"` (`main.go:149`).
- **Pass:**
  - Binary resolved via `exec.LookPath("nginx")`; candidate order is nginx, then apache, then caddy (`detect.go:157-161`).
  - Version comes from `nginx -v` (combined stdout+stderr — nginx prints to stderr, `detect.go:140-145,158`), parsed to the first dotted version.
  - Config dir resolved by first-existing: `/etc/nginx/sites-available` → `/etc/nginx/conf.d` → `/etc/nginx` (`parse.go:58-62`); log paths from `/var/log/nginx/error.log`, `/var/log/nginx/access.log` that exist (`parse.go:64-69`).
  - When nginx holds `:443`, the dashboard shows a port conflict naming `nginx` + pid (`detect.go:219-250`; unprivileged agents fall back to `/proc` walking, `detect.go:240-245`).
- **Coverage:** D (parse/paths/ss) + R (live detection).
- **Pitfalls:** `nginx -v` writes to **stderr** — detection merges both streams; a runner that reads only stdout would lose the version. A missing binary is **not** an error: `Detect` returns `(false, nil)` (`nginx.go:167-169`, `Backend.Detect`) and detection reports `Installed=false`.

### Layout resolution (Debian symlinks vs RHEL conf.d)
- **Must:** the backend writes managed files to the right directory and uses the right activation model: Debian symlinks `sites-available` → `sites-enabled`; RHEL/Fedora `conf.d` is flat (presence == enabled, no symlink step).
- **Access:** derived from the detected/overridden config dir (`-proxy-config-dir` / `NP_PROXY_CONFIG_DIR`) via `ResolveLayout` (`paths.go:56-75`). Pure, unit-tested.
- **Steps (D):** `make test` covers `ResolveLayout`:
  - ends in `sites-available` → Debian, `Enabled` = sibling `sites-enabled` (`paths.go:62-63`).
  - ends in `sites-enabled` → Debian, `Available` = sibling `sites-available` (`paths.go:64-65`).
  - ends in `conf.d` → RHEL flat, `Enabled` empty → `IsConfD()==true` (`paths.go:66-68`).
  - otherwise (e.g. `/etc/nginx`) → default Debian pair (`paths.go:69-74`).
- **Pass:** `Layout.IsConfD()` is true only when `Enabled` is empty (`paths.go:43`). In `Apply`/`Remove`/`Prune`/`ReadManaged`, the symlink steps are taken only when `!IsConfD()` (`nginx.go:325-329,375,421,476`).
- **Coverage:** D.
- **Pitfalls:** on conf.d, only `*.conf` files are auto-included by nginx's stock `include /etc/nginx/conf.d/*.conf;` — the `.conf` suffix is load-bearing there (`paths.go:15-17`). The `.htpasswd` sidecar is deliberately NOT `.conf` so the include glob never tries to parse it as config (`nginx.go:544-548`).

### Managed file naming (`nurproxy-<host>.conf`, sanitization)
- **Must:** a managed vhost lives at `<sites-available>/nurproxy-<sanitized-host>.conf`; only the `nurproxy-` prefix is "ours"; a crafted host can never escape the config dir.
- **Access:** `ManagedFileName(host)` / `Layout.AvailablePath(host)` are used by `Render` to set the artifact target; `IsManagedFile(name)` gates adoption + prune.
- **Steps (D):** `make test` covers `ManagedFileName` and `sanitizeHostForFile` (`paths.go:81-118`).
- **Pass:**
  - `ManagedFileName("app.example.com") == "nurproxy-app.example.com.conf"` (`paths.go:81-83`, prefix `nurproxy-` + `.conf`).
  - `sanitizeHostForFile` maps `*.` → `_wildcard.`, and strips `/`, `\`, `..` → `_` (`paths.go:111-118`) — so `*.example.com` → `nurproxy-_wildcard.example.com.conf`.
  - `IsManagedFile` requires BOTH the `nurproxy-` prefix AND the `.conf` suffix (`paths.go:103-105`).
- **Coverage:** D.
- **Pitfalls:** the sanitization mirrors the cert store's host sanitation so the file base and cert base stay consistent (`paths.go:108-110`). A non-`.conf` `nurproxy-…` file (e.g. the `.htpasswd` sidecar) is NOT a managed file and is left out of prune/adoption.

### Atomic apply dance (snapshot → temp → stage → symlink → `nginx -t` → rename + reload; rollback)
- **Must:** an apply either fully lands (all files written, validated, activated, reloaded) or fully rolls back to the exact pre-apply state — nginx is never left non-serving. The new content is validated by a real `nginx -t` **before** the reload.
- **Access:** `Backend.Apply(ctx, arts)` (`nginx.go:315-409`), driven by the agent's route-apply path over the dial-out stream. `nginx -t` runs via the injected `Runner.Test`; reload via `Runner.Reload`.
- **Prerequisites:** a `Runner` — a fake (D, unit), a docker-exec runner (D, integration), or the real `execRunner` (R).
- **Steps:**
  - **D (unit, fake Runner + `t.TempDir`):** `make test` runs `nginx_test.go` which asserts: temp file written with `.nurproxy-tmp` suffix, content staged at the live path, symlink ensured in `sites-enabled`, `Test` called once, `Reload` called once, temps removed on commit; and on a failing `Test`/`Reload` every file is restored and temps discarded.
  - **D (integration, real nginx in Docker):** `go test -tags integration ./internal/agent/proxy/nginx/...` (e.g. `TestIntegration_Apply_atomicWrite_realNginx`, `nginx_integration_test.go:227`). Host temp dirs are bind-mounted at the same `/etc/nginx/sites-available` + `sites-enabled` paths so absolute symlink targets resolve identically inside the container.
  - **R (real host):** apply a domain and capture `nginx -t` before and after.
- **Pass:**
  - On success: each `nurproxy-<host>.conf` is present in `sites-available` with the rendered content, a symlink exists in `sites-enabled` (Debian), `nginx -t` passes, nginx is reloaded, no `.nurproxy-tmp` files remain (`nginx.go:386-408`). Log line `nginx: applied config artifacts=N sites_available=… confd_layout=…` (`nginx.go:404-407`).
  - On a failing `nginx -t` or reload: every staged file is restored to its prior content (or removed if brand-new), every temp removed, brand-new symlinks removed (`nginx.go:387-396`, `fileops.go:56-67`); a re-run of `nginx -t` is clean and the prior config is still live.
- **Coverage:** D (unit + integration) / R (real reload + serving).
- **Pitfalls:**
  - The temp file lives in the SAME directory as the destination so the rename is atomic on one filesystem (`nginx.go:46-48`).
  - The staged file is registered in the rollback set **before** the live path is overwritten, so a later same-iteration failure (e.g. a symlink clash) still restores the prior content (`nginx.go:356-362`).
  - `ensureSymlink` refuses to replace a **regular file** at the sites-enabled path (an operator's copy-activation) and errors instead of clobbering (`fileops.go:69-84`) — this triggers rollback.
  - `restoreSnapshot` is best-effort: a restore error is swallowed and the resulting nginx state is reported via `Validate`/health (`fileops.go:52-67`).
  - Apply with zero artifacts is a no-op (`nginx.go:316-318`); a nil runner errors `nginx: no command runner configured`.

### Error attribution (our config vs operator's pre-broken config)
- **Must:** `nginx -t` validates the WHOLE config, so a pre-existing operator error can trip our apply. The agent must distinguish "we broke it" from "your existing config at X:N was already broken", and detect a permission-denied failure as a privilege problem, not a config error.
- **Access:** `AttributeNginxTestError(out, ourFiles...)` parses the backend output;
  the backend returns an `errors.As`-compatible `*proxy.Failure` into the apply
  error / health stream.
- **Steps (D):** `make test` covers `AttributeNginxTestError` against captured nginx `-t` output (`attribution_test.go`).
- **Pass:**
  - Fault in our file → `nginx -t failed in the generated config at <file>:<line>` (`Ours==true`, `nginx.go:75-76`).
  - Fault elsewhere → `nginx -t failed: error in your existing config at <file>:<line>` (`Ours==false`, `nginx.go:78`).
  - Permission denied and a missing proxy binary retain concise, distinct messages;
    unknown unlocated failures retain one short sanitized output line.
  - Exact clean paths match directly. A sites-enabled path may alias its
    sites-available sibling only when both have the same case-sensitive basename
    and parent layout; a foreign root or same basename elsewhere is not ours.
  - Batch apply compares the blamed path with every artifact staged in that batch,
    not only the first artifact.
  - Captured stdout/stderr and exposed evidence are bounded to 8 KiB. Locations
    are accepted only when absolute, clean, valid UTF-8, control-free, sanitized,
    and within the separate path-size limit.
  - When several `in file:line` clauses appear, the **last** (innermost) frame is used; `[warn]`/`[alert]` lines are skipped so a benign warning's line never gets blamed (`attribution.go:65-95`).
- **Coverage:** D.
- **Pitfalls:** standalone `Validate` supplies no managed artifact candidates, so
  a located error is never treated as generated-config evidence. `ManagedHint`
  remains evidence only; recovery must prove ownership separately.

### Overridable commands + sudo elevation
- **Must:** operators can override the test and reload commands; an unprivileged agent elevates exactly those two commands via `sudo -n` (scoped sudoers), not by running the whole agent as root.
- **Access:**
  - **Flags:** `-proxy-test-cmd "…"`, `-proxy-reload-cmd "…"` (`main.go:57-58`).
  - **Env:** `NP_PROXY_TEST_CMD`, `NP_PROXY_RELOAD_CMD` (`config.go:249-254`).
  - **Disable sudo:** `NURPROXY_NO_SUDO=1` (`nginx.go:714-718`).
- **Steps (D):** `make test` covers `execRunner.spec` / `ResolvedCommands`: an override is split on whitespace and a bare binary resolved to an absolute path; no override → resolved binary + default args (`-t`, `-s reload`).
- **Pass:**
  - Default test = `<binary> -t`, default reload = `<binary> -s reload` (`nginx.go:649,656`).
  - `ResolvedCommands()` returns the exact privileged strings with the binary as an absolute path (so a scoped sudoers entry matches) (`nginx.go:610-624`).
  - When the agent runs as a non-root POSIX user (`Geteuid()>0`) and the command is not already `sudo`, the runner prepends `sudo -n` (`nginx.go:670-677`, `elevateNeeded` `nginx.go:714-719`). As root (`euid 0`) or on Windows (`euid -1`) it runs directly. `NURPROXY_NO_SUDO=1` disables the wrapper.
- **Coverage:** D (command resolution) / R (actual sudo elevation on a host).
- **Pitfalls:** an override binary that is a bare name is resolved via `exec.LookPath` to an absolute path so it matches the sudoers entry (`nginx.go:685-696`); if `LookPath` fails the bare name is used (won't match an absolute-path sudoers rule). `nginx -t` must read every vhost's TLS **private key** (root-owned), which is why an unprivileged agent genuinely needs the elevation (`nginx.go:667-669`).

### Adoption (`ReadManaged`)
- **Must:** at startup the agent reads ALL files in `sites-available`, marks `nurproxy-*` files as generated (drift-tracked, `Adopted=false`) and every other file as an operator-authored config (`Adopted=true` → stored `Source: manual`, version 1). Operator files are never modified.
- **Access:** `Backend.ReadManaged(ctx)` (`nginx.go:265-305`), called once at startup in existing mode and reported via `streamClient.ReportAdopted(…)` (`main.go:399-407`). Visible under the dashboard's Config view.
- **Prerequisites:** existing mode; some files in `sites-available` (R), or a `t.TempDir` (D unit).
- **Steps:**
  - **D (unit):** `make test` covers `ReadManaged` reading a mix of `nurproxy-*.conf` and operator files.
  - **R:** drop a hand-written `zzz-manual.conf` and a `nurproxy-app.conf` into `sites-available`, start the agent, check the log `Reported N existing config artifact(s) to the central store` (`main.go:404-405`) and the dashboard Config view.
- **Pass:**
  - All non-dir files read (no whitelist), EXCEPT `.nurproxy-tmp` and `.htpasswd` files which are skipped (`nginx.go:280-283`).
  - `nurproxy-*.conf` → `Adopted=false`; everything else → `Adopted=true` (`nginx.go:300-302`, via `IsManagedFile`).
  - `Enabled` reflects sites-enabled presence on Debian (symlink **or** a copied regular file counts — `activationPresent`, `fileops.go:103-106`); on conf.d a read file is enabled by definition (`nginx.go:293-296`).
  - A missing `sites-available` directory returns `(nil, nil)` — not an error (`nginx.go:268-269`).
- **Coverage:** D (unit) / R (live startup report).
- **Pitfalls:** reading is independent of reload permission — a limited-permission agent still surfaces its config (`main.go:394-396`). Some operators activate by **copying** the file into sites-enabled rather than symlinking; treating only symlinks as enabled would mislabel those live vhosts (`fileops.go:97-106`).

### Prune (remove stale `nurproxy-*` on push)
- **Must:** when the desired route set shrinks (a domain deleted), the next push removes the orphaned `nurproxy-*` files + their symlinks + htpasswd sidecars and reloads once — no ghost vhosts. Operator files are never pruned.
- **Access:** `Backend.Prune(ctx, keep)` (`nginx.go:448-495`), called from the agent's apply path with the full desired target set (rides the dial-out stream — no inbound probe).
- **Steps (D unit / R):** apply two domains, then apply only one; the dropped domain's file disappears.
- **Pass:**
  - Only files matching `IsManagedFile` (and not `.nurproxy-tmp`) whose path is not in `keep` are removed; the symlink (Debian) and `.htpasswd` sidecar go with them (`nginx.go:463-487`).
  - Operator files (no `nurproxy-` prefix) are skipped entirely (`nginx.go:468-470`).
  - One reload happens only if something was removed (`nginx.go:489-493`). Returns the count removed.
  - A missing dir returns `(0, nil)` (`nginx.go:456-458`).
- **Coverage:** D (unit) / R (live reload).
- **Pitfalls:** prune does NOT run `nginx -t` before reloading (only removals) — removing files can't introduce a syntax error, but a reload failure is still surfaced (`nginx.go:490-492`).

### Remove (single managed vhost)
- **Must:** removing one managed vhost deletes its sites-available file, its sites-enabled symlink, and its htpasswd sidecar, then reloads so nginx drops the vhost promptly.
- **Access:** `Backend.Remove(ctx, target)` (`nginx.go:415-440`).
- **Steps (D unit / R):** delete a single domain.
- **Pass:** symlink removed first (Debian), then the `.conf` file, then the `.htpasswd` sidecar, then `nginx -s reload` (`nginx.go:419-438`). A missing file is not an error (`os.ErrNotExist` swallowed). Empty target path errors `nginx remove: empty target path`.
- **Coverage:** D (unit) / R (live reload).
- **Pitfalls:** reload runs only after the files are gone so the removed domain stops serving immediately (`nginx.go:414`).

### basic_auth htpasswd sidecar
- **Must:** a basic-auth route gets a `nurproxy-<host>.htpasswd` sidecar containing `user:<bcrypt-hash>`, and the rendered config references it with `auth_basic` + `auth_basic_user_file`. The plaintext password never travels — the intent already carries a bcrypt hash.
- **Access:** materialized in `Backend.Render` when `route.BasicAuth` has a username + password hash (`nginx.go:212-220`, `writeHtpasswd` `nginx.go:559-569`); rendered by `nginxgen` (`generate.go:191-198`).
- **Steps:**
  - **D:** `make test` (nginxgen) asserts `auth_basic "Restricted: <host>";` + `auth_basic_user_file <path>;` when `AuthFile` is set (`generate.go:191-198`, realm at `generate.go:343`).
  - **R:** create a domain with basic auth, `curl` without creds → `401`, with creds → backend body. The htpasswd file must contain a `$2y$`/`$2a$` bcrypt entry (`nginx.go:557-558`).
- **Pass:** sidecar file written `0644` as `<user>:<hash>\n` (`nginx.go:563-565`); config references it; nginx's `crypt()` validates the bcrypt entry. If the write fails, `AuthFile` stays empty and nginxgen DROPS basic auth with a warning rather than referencing a missing file (`nginx.go:214-219`, `generate.go:195-196`).
- **Coverage:** D (render) / R (behaviour).
- **Pitfalls:** the sidecar is NOT a `.conf` so nginx's include glob never loads it (`nginx.go:544-548`); ReadManaged/Prune treat it as auxiliary (skipped/removed-with-vhost). **Password is a bcrypt hash, not plaintext** (carry-over from RELEASE-QA §2.6).

### Permission probe (write + reload)
- **Must:** before going live in existing mode the agent self-tests that it can WRITE to the config dir(s) and RELOAD nginx; a missing grant is non-fatal (the backend still swaps in) but health reports the exact least-privilege remediation.
- **Access:** runs inside `holder.Reconfigure` → `probeExisting` (`holder.go:382-456,484-527`) at startup / on a hot-switch, and on every heartbeat via `ProbePermissions` (`holder.go:469-477`). Surfaced on the dashboard agent detail (permissions block + remediation). See the **permissions spec** (`docs/qa/` permissions file) for the full probe/remediation matrix.
- **Steps (R):** run an unprivileged agent in existing mode with no grants; observe the health error + remediation; apply the grants; confirm the next heartbeat clears it.
- **Pass:**
  - `ProbeDirs()` returns `sites-available` always, plus `sites-enabled` on Debian; only `Available` on conf.d (`nginx.go:577-582`).
  - A passing probe → `switched to existing nginx — config is writable and reloadable` and health cleared (`holder.go:439-445`).
  - A failing probe → backend still live, health carries `probe.HealthError()`, the `Remediation` carries copy-paste commands for ONLY the missing grants (group ownership for write, scoped `/etc/sudoers.d/nurproxy-agent` line for reload) (`holder.go:448-455,506-527`; `permcheck/remediation.go:9-34`).
- **Coverage:** R (real privilege state).
- **Pitfalls:** a root agent under a systemd sandbox needs a `ReadWritePaths` drop-in, not group+sudoers (`main.go:333-338`, `permcheck/remediation.go:60-74`); the probe reuses the backend's `Runner()`/`ReloadHint()`/`ResolvedCommands()` so the remediation names the exact commands the agent runs.

### Central TLS (provided-cert references)
- **Must:** for a central-TLS route the agent installs the orchestrator-issued bundle to its cert store BEFORE applying the config, and the rendered nginx references `ssl_certificate` / `ssl_certificate_key` pointing at those on-disk paths. A missing cert drops the TLS listener (plaintext) with a warning rather than emitting a broken listener.
- **Access:** `Backend.InstallCerts` (`nginx.go:516-536`) over the agent stream (preflight, before Apply); cert paths resolved in `Render` (`nginx.go:200-205`); listener emitted by `nginxgen.resolveTLS` (`generate.go:276-298`).
- **Prerequisites:** a cert store configured — the agent wires `CertDir`/`EncryptKey` into the file backend (`main.go:256-281,402-403`). Without it the backend's `Capabilities().CentralTLS` is false (`nginx.go:186`).
- **Steps:**
  - **D:** `make test` (nginxgen) — with both `CertPath` + `KeyPath` set, the server block emits `listen 443 ssl;` + `http2 on;` + `ssl_certificate` + `ssl_certificate_key` (`generate.go:153-167`); with either empty it drops the TLS listener and warns `tls: no provided certificate available; route served over plaintext HTTP` (`generate.go:287-291`).
  - **R:** create a central-TLS domain, then `curl --resolve host:443:<host-ip> https://host/` returns the backend body over TLS with the LE cert.
- **Pass:** cert + key installed (key encrypted at rest when a key is configured, `nginx.go:525-533`); config references the **absolute** installed paths (the cert dir is absolutized because nginx resolves a relative `ssl_certificate` against its own prefix, `main.go:259-268`). A wildcard cert emits a non-fatal `tls_wildcard` warning about the shared private key (`generate.go:292-295`).
- **Coverage:** D (render + install) / R (real TLS serving).
- **Pitfalls:** `self-acme` is a Caddy-only fallback — the nginx backend never does its own ACME; a self-acme TLS policy is dropped to plaintext with a warning (`generate.go:280-285`). An existing-mode agent with no cert store drops EVERY central-TLS listener (`main.go:252-255`) — verify the cert store is wired.

### Capability matrix
- **Must:** the nginx backend advertises exactly the options its renderer can express, so the orchestrator audits dropped options correctly.
- **Access:** `Backend.Capabilities()` (`nginx.go:176-188`), reported each heartbeat (`main.go:418`).
- **Steps (D):** `make test`.
- **Pass:** `ReverseProxy`, `WebSocket`, `ForceHTTPS`, `CustomHeaders`, `PathRewrite`, `BasicAuth`, `IPFilter`, `RateLimit` are all true; `CentralTLS` is true ONLY when a cert store is configured (`nginx.go:186`). RateLimit relies on the always-compiled-in `ngx_http_limit_req_module` (`nginx.go:171-175`).
- **Coverage:** D.
- **Pitfalls:** the renderer matrix (directives + behaviour) is covered in `docs/qa/08-proxy-config-matrix.md` / RELEASE-QA §2.6 — note nginx returns **503** when `limit_req` trips (not 429), and for IP allow/block tests drive the host directly via `--resolve` so the observed client IP is deterministic.

## Acceptance checklist

**Dry / pure (every RC):**
- [ ] `make test` green — nginx backend unit tests (fake `Runner`): apply atomic dance + rollback, ReadManaged adopt/generated split, Prune keeps operator files, Remove cleans symlink+sidecar.
- [ ] `make test` green — pure helpers: `ResolveLayout` (4 cases), `ManagedFileName`/`sanitizeHostForFile`, `IsManagedFile`, `ParseVersion`, `AttributeNginxTestError` (ours / operator / permission / last-frame).
- [ ] `make test` green — `nginxgen` render matrix: TLS listener emitted/dropped, basic_auth file referenced/dropped, force_https redirect, rate_limit, IP allow/deny, headers, timeouts, body size, path strip/rewrite, websocket.
- [ ] (Docker present) `go test -tags integration ./internal/agent/proxy/nginx/...` green — real nginx accepts the rendered config, symlink activation, live reload, real `nginx -t` error attribution.

**Real run (before final):**
- [ ] Agent in `-proxy-mode existing -proxy-type nginx` runs the nginx backend, bundled Caddy dormant, nginx owns `:80`/`:443`, dashboard shows mode `existing` + detected version/config dir.
- [ ] Apply a domain → `nginx -t` ok **before and after**, `nginx -s reload`, only `nurproxy-<host>.conf` written, sites-enabled symlink present.
- [ ] A hand-written non-`nurproxy` vhost survives untouched through apply / adopt / prune (RELEASE-QA §2.5a, §2.7).
- [ ] Drift healing: hand-edit a `nurproxy-*.conf`, add a `zzz-manual.conf`; after a heartbeat cycle (~30–60 s) the managed file is restored, the manual file is intact (RELEASE-QA §2.7).
- [ ] Central TLS: `curl --resolve host:443:<ip> https://host/` serves the backend body with the LE cert; `force_https` redirects on `:80`.
- [ ] basic_auth: no creds → 401, valid creds → backend body (htpasswd holds a bcrypt entry).
- [ ] Permission probe: unprivileged agent with missing grants reports the exact remediation (group ownership + scoped sudoers / systemd `ReadWritePaths`); applying it clears health on the next heartbeat.

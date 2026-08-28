# Backend: Existing Apache (apply / reload / adopt / drift)

> **Scope:** managing a host-installed Apache (httpd) as the agent's "existing"
> proxy backend — detection, directory layout, atomic apply/reload, adoption,
> prune/remove, drift, basic auth, central TLS, the permission probe, and the
> rate-limit divergence.
> **Code:** `internal/agent/proxy/apache/apache.go`, `paths.go`, `fileops.go`,
> `attribution.go`; `internal/shared/apachegen/generate.go`;
> `internal/agent/proxy/parse.go` (detection/version/paths);
> `internal/agent/proxy/holder.go` (hot-switch); `cmd/nurproxy-agent/main.go` +
> `internal/agent/config/config.go` (flags / env).
> **Coverage legend:** D = coverable dry, R = needs a real run.

> **!! KNOWN COVERAGE GAP:** the existing-Apache backend is **NOT YET exercised by a
> real run in the homelab** (RELEASE-QA.md §2.5c, "Existing apache … R, NOT YET
> COVERED"; §4 gaps: "Existing-apache apply/reload … NOT YET COVERED"). Everything
> marked **R** below is the procedure to run *when an Apache host is available*; it
> has not been signed off on real hardware. The atomic apply orchestration is
> covered by Docker-backed integration tests (`apache_integration_test.go`, skipped
> when Docker is absent) and the render is fully unit-tested
> (`apachegen/generate_test.go`).

## Prerequisites

- Both binaries built: `make build-all` (orchestrator `./nurproxy`, agent
  `./nurproxy-agent`).
- For dry control-plane checks: `make dev-sandbox` (orchestrator + dry agent up).
- For the render/path/attribution unit + integration suites: a Go toolchain
  (`make test`); Docker for the real-Apache integration tests — each gates on
  `dockerAvailable()` and `t.Skip`s when no Docker daemon is reachable
  (`apache_integration_test.go:80-90`, skips at `:226,258,285,336,359`).
- For **R** tests: a host with Apache installed (Debian/Ubuntu `apache2` or
  RHEL/Fedora `httpd`) reachable as a NurProxy agent, with `mod_proxy`,
  `mod_proxy_http`, `mod_proxy_wstunnel`, `mod_headers`, `mod_rewrite`,
  `mod_authz_host`, `mod_auth_basic`, `mod_authn_file`, `mod_ssl` loaded (the
  renderer assumes the operator's httpd already loads its modules — no `LoadModule`
  is emitted; `Result.Preamble` is empty for every current route, see
  `generate.go:67-79`).
- The agent must be able to write the config dir(s) and run `apachectl configtest`
  + a graceful reload (root, or a scoped passwordless sudoers entry — see the
  permission probe test).

## Features covered

- [ ] Backend selection: `-proxy-mode existing -proxy-type apache` (flags + env).
- [ ] Binary detection: `apachectl` → `apache2ctl` → `httpd` → `apache2` lookup order.
- [ ] Version parse from `Server version: Apache/2.4.x`.
- [ ] OS-default config-dir + log-path resolution (Debian vs RHEL).
- [ ] Directory layout: Debian `sites-available` + `sites-enabled` (symlink
      activation) vs RHEL `conf.d` (flat, presence == enabled).
- [ ] Managed file naming `nurproxy-<host>.conf` + host sanitation.
- [ ] Atomic apply: snapshot → temp → stage → (Debian) symlink →
      `apachectl configtest` → graceful reload; rollback on any failure.
- [ ] Error attribution: "ours" vs "your existing config at file:line".
- [ ] **Rate limit NOT supported** — `rate_limit` dropped with a warning (the key
      Apache divergence vs nginx/Caddy).
- [ ] Other render options: reverse proxy, websocket, force-https, custom req/resp
      headers, path strip/rewrite, max body size, IP allow/block, upstream scheme,
      timeouts.
- [ ] Basic auth via htpasswd sidecar (`<host>.htpasswd`).
- [ ] Central TLS via `SSLCertificateFile`/`SSLCertificateKeyFile` (provided certs).
- [ ] Adoption (`ReadManaged`): managed vs operator files.
- [ ] Prune (orphan managed vhosts on domain delete).
- [ ] Remove (single vhost + symlink + htpasswd).
- [ ] Drift detect/heal (re-checksum managed vhosts on heartbeat; operator files left alone).
- [ ] Permission probe (`ProbeDirs`, reload-grant probe, remediation/`ReloadHint`).
- [ ] Hot-switch into existing-apache (built-in ↔ existing, no restart).

## Tests

### Backend selection (`-proxy-mode existing -proxy-type apache`)

- **Must:** the agent manages the host's Apache instead of running bundled Caddy.
  `existing` mode requires a `-proxy-type`; an unknown type or a missing type is a
  clear, non-fatal error.
- **Access:**
  - Agent flags (`cmd/nurproxy-agent/main.go:53-60`): `-proxy-mode existing`,
    `-proxy-type apache`, plus optional `-proxy-binary`, `-proxy-config-dir`,
    `-proxy-reload-cmd`, `-proxy-test-cmd`, `-proxy-log-paths` (comma-separated),
    `-proxy-service`.
  - Env (`internal/agent/config/config.go:237-260`): `NP_PROXY_MODE=existing`,
    `NP_PROXY_TYPE=apache`, `NP_PROXY_BINARY`, `NP_PROXY_CONFIG_DIR`,
    `NP_PROXY_RELOAD_CMD`, `NP_PROXY_TEST_CMD`, `NP_PROXY_LOG_PATHS`,
    `NP_PROXY_SERVICE` (each mirrors its flag).
  - Dashboard / hot-switch: a reconfigure request with `Mode: "existing"`,
    `Type: "apache"` (`holder.go:246-264`, `ReconfigureRequest`).
  - Config file: `agent.yaml` keys `proxy_mode: existing`, `proxy_type: apache`
    (`config.go:35-38`).
- **Prerequisites:** Apache installed for a real run; for dry validation use the
  sandbox (mode/type validation runs without a host — the missing-type error is
  surfaced fail-soft, not at config load).
- **Steps (mode validation at config load, D):**
  ```bash
  # An invalid -proxy-mode is rejected by config.Load() (fatal at startup):
  NP_DRY_RUN=true ./nurproxy-agent -orchestrator http://localhost:8080 \
    -fqdn ap1.example.com -proxy-mode bogus
  # → fatal: invalid proxy_mode "bogus" (must be "built-in" or "existing")
  ```
- **Steps (missing/unknown type at startup, D):**
  ```bash
  # existing mode with NO -proxy-type: config.Load() accepts it, but the startup
  # Reconfigure logs a NON-FATAL warning and the agent stays connected (built-in
  # backend stays seeded — it does NOT exit):
  NP_DRY_RUN=true ./nurproxy-agent -orchestrator http://localhost:8080 \
    -fqdn ap1.example.com -proxy-mode existing
  # log: Existing mode honored at startup: reconfigure: proxy mode existing
  #      requires a proxy type (nginx | apache | caddy)
  # existing mode with an UNKNOWN -proxy-type (same fail-soft path):
  NP_DRY_RUN=true ./nurproxy-agent -orchestrator http://localhost:8080 \
    -fqdn ap1.example.com -proxy-mode existing -proxy-type httpdx
  # log: ... reconfigure: "httpdx" is not a known proxy backend — cannot switch to it: ...
  ```
- **Steps (R, on an Apache host):**
  ```bash
  ./nurproxy-agent -orchestrator https://<orch> -fqdn edge-apache.example.com \
    -proxy-mode existing -proxy-type apache
  ```
- **Pass:**
  - `config.Load()` accepts `proxy_mode` ONLY as `built-in` or `existing`; anything
    else is fatal: `invalid proxy_mode %q (must be "built-in" or "existing")`
    (`config.go:155-156`). It does NOT validate the proxy type — a missing/unknown
    type is caught later, by the startup `Reconfigure`.
  - `existing` with no proxy type → the startup `Reconfigure` returns
    `reconfigure: proxy mode existing requires a proxy type (nginx | apache | caddy)`
    (`holder.go:382-390`); logged as a WARNING + `Existing mode honored at startup: …`
    (`main.go:369-381`) — NON-FATAL, the agent keeps the seeded built-in backend and
    stays connected.
  - `existing` with an unknown type → `reconfigure: %q is not a known proxy backend
    — cannot switch to it: …` (`holder.go:405-411`), also non-fatal. (An unknown
    *mode* — only reachable via the local reconfigure API, not the CLI — yields
    `reconfigure: unknown proxy mode …`, `holder.go:367-368`.)
  - On a real host the agent logs `Proxy detection: installed=true kind="apache" …`
    (`main.go:149-153`).
- **Coverage:** D (validation, mode/type plumbing) / R (actually attaching to Apache).
- **Pitfalls:** `built-in` is the default proxy mode (`defaults()`, `config.go:91`).
  In
  existing mode the bundled Caddy stays dormant so the host's Apache owns `:80`/`:443`
  (`main.go:206-220`). The missing-type case is fail-soft (logged, agent up), NOT a
  config-load crash — do not expect the agent to exit.

### Binary detection & version parse

- **Must:** Detect resolves the first available Apache control binary; version is
  parsed from its `-v` output. A missing binary is "not present here", not an error.
- **Access:** automatic at agent start (`detectProxy`, `main.go:144-155`);
  override with `-proxy-binary` / `NP_PROXY_BINARY`.
- **Steps (D, unit):**
  ```bash
  go test ./internal/agent/proxy/ -run ParseVersion -v
  ```
- **Pass:**
  - Lookup order is exactly `apachectl`, `apache2ctl`, `httpd`, `apache2`
    (`apache.go:126`); first found on `$PATH` wins; a `-proxy-binary` override
    short-circuits the search (`apache.go:124-125`).
  - `Detect` returns `(true, nil)` when a binary resolved, `(false, nil)` when not —
    never an error (`apache.go:174-176`).
  - `ParseVersion(KindApache, "Server version: Apache/2.4.58 (Ubuntu)")` → `2.4.58`;
    `"Server version: Apache/2.4.57 (Red Hat ...)"` → `2.4.57` (`parse.go:19-20,33-38`).
    It grabs the first dotted version, so it works for both `apachectl -v` and
    `httpd -v`.
- **Coverage:** D.
- **Pitfalls:** version is informational (shown in `Info`/dashboard); empty when
  unparseable — not fatal.

### OS-default config dir & log paths

- **Must:** with no `-proxy-config-dir`, the agent picks the first existing default
  dir so one binary serves both Debian and RHEL.
- **Access:** automatic (`ResolvePaths(KindApache)`, `parse.go:70-84`); override
  with `-proxy-config-dir` / `NP_PROXY_CONFIG_DIR`.
- **Steps (D, unit):** `go test ./internal/agent/proxy/ -run ResolvePaths -v`.
- **Pass:** config-dir candidates in order: `/etc/apache2/sites-available`,
  `/etc/httpd/conf.d`, `/etc/apache2`, `/etc/httpd`; first existing wins, else the
  first candidate (`parse.go:71-77`). Log candidates probed:
  `/var/log/apache2/{error,access}.log`, `/var/log/httpd/{error_log,access_log}`
  (`parse.go:78-83`) — only existing files are surfaced.
- **Coverage:** D.
- **Pitfalls:** on a host where no default dir exists yet, detection still reports
  the canonical primary (`/etc/apache2/sites-available`) so the operator sees where
  files would go.

### Directory layout (Debian sites-available/enabled vs RHEL conf.d)

- **Must:** the layout the backend writes to is derived purely from the config dir.
  Debian uses real files in `sites-available` activated by a `sites-enabled`
  symlink (like `a2ensite`); RHEL `conf.d` is flat — every `*.conf` is
  auto-included, no enable step.
- **Access:** automatic via `ResolveLayout(cfg.ConfigDir)` (`apache.go:134`,
  `paths.go:56-78`); driven by whatever `-proxy-config-dir` resolves to.
- **Steps (D, unit):** `go test ./internal/agent/proxy/apache/ -run Layout -v`
  (`paths_test.go`).
- **Pass:** `ResolveLayout` mapping (`paths.go:61-77`):
  - dir ends `sites-available` → Debian; `Enabled` = sibling `sites-enabled`.
  - dir ends `sites-enabled` → Debian; `Available` = sibling `sites-available`.
  - dir ends `conf.d` → RHEL; `Enabled` empty.
  - dir is `httpd` root → RHEL; `Available` = `<dir>/conf.d`.
  - anything else (e.g. `apache2` root) → Debian `sites-available`/`sites-enabled`
    pair.
  - `Layout.IsConfD()` is true iff `Enabled == ""` (`paths.go:42`).
- **Coverage:** D.
- **Pitfalls:** the layout *decides symlink behaviour*: on conf.d (RHEL) NO symlink
  is ever created and presence == enabled (`apache.go:295-297,376`); on Debian the
  symlink is the activation.

### Managed file naming `nurproxy-<host>.conf`

- **Must:** a managed vhost lives at `<Available>/nurproxy-<host>.conf`; the host is
  sanitized so a crafted host can't escape the dir.
- **Access:** automatic (`Render` sets the target to `layout.AvailablePath(host)`,
  `apache.go:253`).
- **Steps (D, unit):** `go test ./internal/agent/proxy/apache/ -run ManagedFile -v`.
- **Pass:** file name = `nurproxy-` + sanitized host + `.conf` (`paths.go:84-86`).
  Sanitation (`paths.go:114-121`): `*.` → `_wildcard.`, `/`→`_`, `\`→`_`, `..`→`_`.
  `IsManagedFile` matches `nurproxy-` prefix AND `.conf` suffix (`paths.go:106-108`).
- **Coverage:** D.
- **Pitfalls:** on RHEL conf.d the `.conf` suffix is load-bearing (only `*.conf`
  auto-include) — the in-flight temp suffix `.nurproxy-tmp` deliberately does NOT
  end in `.conf` so a stray temp is never auto-included mid-apply
  (`apache.go:49-54`).

### Atomic apply + reload (snapshot → temp → stage → symlink → configtest → graceful)

- **Must:** an apply either fully lands (valid config, reloaded) or fully rolls back
  to exactly what was served before. The proxy is never left non-serving.
- **Access:**
  - Real flow: orchestrator pushes routes over the agent stream → agent's
    `applyIntents` → `Backend.Apply` (`apache.go:317-410`).
  - The reload runs `apachectl graceful` and the test runs `apachectl configtest`
    by default; override with `-proxy-reload-cmd` / `-proxy-test-cmd`
    (`apache.go:570-584,637-654`). NOTE: the apache backend ignores `-proxy-service`
    — `New()` wires only `binary`, `reloadCmd`, `testCmd` into the `execRunner`
    (`apache.go:137`); there is no built-in `systemctl reload`. To reload via systemd
    set `-proxy-reload-cmd "systemctl reload apache2"` (or `httpd`) explicitly.
  - When the agent is non-root, both commands run through `sudo -n` so a scoped
    passwordless sudoers entry grants exactly them (`apache.go:660-667`);
    `NURPROXY_NO_SUDO=1` disables the sudo wrapper (`apache.go:697-702`).
- **Prerequisites:** Apache + write access + reload privilege (R). The orchestration
  itself is unit/integration-tested without a real host.
- **Steps (D, integration logic):**
  ```bash
  go test ./internal/agent/proxy/apache/ -run Apply -v     # fake Runner, t.TempDir
  go test ./internal/shared/apachegen/ -v                  # pure render
  # Real-Apache integration (needs Docker, else skipped):
  go test ./internal/agent/proxy/apache/ -run Integration -v
  ```
- **Steps (R, on a host):** adopt the agent, add a server + domain pointing at an
  upstream, then before/after capture:
  ```bash
  apachectl configtest                 # BEFORE: note current state
  # ... let NurProxy push the domain ...
  ls -l <Available>/nurproxy-<host>.conf
  ls -l <Enabled>/nurproxy-<host>.conf # Debian only — a symlink
  apachectl configtest                 # AFTER: "Syntax OK"
  curl -I http://<host>/               # served via the new vhost
  ```
- **Pass (per `apache.go:317-410`):**
  1. config dir is ensured (`0o755`); on Debian `sites-enabled` is ensured too.
  2. per artifact: `snapshot(dest)` of prior content → write `dest+.nurproxy-tmp` →
     stage content at the live `dest` → (Debian, `art.Enabled`) ensure the
     sites-enabled symlink.
  3. `runner.Test(ctx)` (`apachectl configtest`) runs ONCE over the whole staged set.
  4. on pass: `runner.Reload(ctx)` (`apachectl graceful`); then temps removed and
     each staged file marked committed.
  5. on a failing test OR a failing reload: `rollback()` removes every temp and
     restores every snapshot (rewrites prior content, or removes a brand-new file,
     and removes a symlink this apply created but leaves a pre-existing one
     alone — `fileops.go:56-67`).
  - A graceful reload re-reads config without dropping active connections
    (`apache.go:645-647`).
- **Coverage:** D (orchestration via fakes + Docker integration) / R (real serving
  + reload — NOT YET COVERED on real hardware).
- **Pitfalls:**
  - The temp is staged at the LIVE path so configtest validates the *real* content;
    the snapshot is what makes rollback safe (`apache.go:369-374`).
  - On Debian, a staged file is registered in the rollback set BEFORE the symlink
    step, so a symlink clash still restores prior content (`apache.go:358-364`).
  - `ensureSymlink` refuses to replace a non-symlink (an operator's own copied
    activation) and surfaces an error rather than clobbering it (`fileops.go:72-84`).
  - A reload failure *after* a passing configtest is unexpected, rolls back, and
    surfaces as a typed `apache reload failed: …` failure.

### Error attribution (ours vs operator's existing config)

- **Must:** `apachectl configtest` validates the WHOLE config, so a pre-existing
  operator error elsewhere can trip our apply. The error must distinguish "we broke
  it" from "your existing config at file:line".
- **Access:** `AttributeConfigtestError(out, ourFiles...)` parses it; the backend
  surfaces an `errors.As`-compatible `*proxy.Failure` in the apply error / health
  message.
- **Steps (D, unit):** `go test ./internal/agent/proxy/apache/ -run Attribut -v`.
- **Pass:**
  - Located + ours → `apachectl configtest failed in the generated config at
    <file>:<line>` (`apache.go:76-77`).
  - Located + not ours → `apachectl configtest failed: error in your existing config
    at <file>:<line>` (`apache.go:79`).
  - Permission denied and a missing proxy binary retain concise, distinct
    messages; an unknown unlocated failure retains one short sanitized line.
  - Missing-binary evidence requires a typed process-start failure for one of the
    Apache executable names (`apachectl`, `apache2ctl`, `httpd`, `apache2`). A
    missing `sudo` or custom wrapper remains unknown.
  - Exact clean paths match directly. A sites-enabled path aliases its
    sites-available sibling only under the same parent layout with the same
    case-sensitive basename. Foreign roots and same basenames elsewhere do not
    count as ours.
  - Batch apply compares the blamed path with every staged artifact. The LAST `on
    line N of file` clause (innermost frame) wins.
  - Combined stdout/stderr and exposed evidence are bounded to 8 KiB. Locations
    must be absolute, clean, valid UTF-8, control-free, sanitized, and within the
    separate path-size limit.
- **Coverage:** D.
- **Pitfalls:** standalone `Validate` supplies no managed artifact candidates, so
  a located error is never treated as generated-config evidence. `ManagedHint`
  is evidence only, not an ownership decision.

### Rate limit NOT supported (the key Apache divergence)

- **Must:** Apache core has NO per-client request rate limiting — `mod_ratelimit`
  only throttles *bandwidth*, not request rate. So a route's `rate_limit` field is
  **dropped with a warning**, never an error. This is the headline difference from
  nginx (`limit_req` → 503) and Caddy.
- **Access:** the route's `RateLimit.RequestsPerSecond` (set via dashboard ProxyConfig
  / REST domain proxy config). Capability is advertised false:
  `Capabilities().RateLimit == false` (`apache.go:193`).
- **Steps (D, unit):**
  ```bash
  go test ./internal/shared/apachegen/ -run 'TestRender_structured/rate_limit' -v
  go test ./internal/agent/proxy/apache/ -run RateLimit -v   # TestRender_dropsUnsupportedRateLimit
  ```
- **Pass:**
  - `Capabilities.RateLimit` is `false` (`apache.go:184-196`).
  - A route with `RateLimit.RequestsPerSecond > 0` produces a warning
    `rate_limit: Apache core has no per-client request rate limiting; option
    dropped` (`generate.go:126-128`) and NO rate-limit directive in the vhost. (The
    "mod_ratelimit only throttles bandwidth" rationale is in the code comment
    `generate.go:123-125`, not the emitted warning text.)
  - The warning is logged + carried back in the apply-ACK for audit
    (`apache.go:231-238`) — render never fails on it.
- **Coverage:** D.
- **Pitfalls:** do NOT expect 429/503 throttling on an Apache backend — the limit is
  silently (but audibly, via warning + audit) absent. Document this in any test plan
  that compares backends side by side. Contrast: nginx returns **503** for
  `limit_req` (RELEASE-QA.md §2.6).

### Other render options (proxy / websocket / force-https / headers / path / body / IP / scheme / timeouts)

- **Must:** every supported `ProxyConfig` field renders to the right native Apache
  directive.
- **Access:** dashboard domain ProxyConfig / REST domain config → route → `Render`.
  Advertised capabilities: `ReverseProxy, WebSocket, ForceHTTPS, CustomHeaders,
  PathRewrite, BasicAuth, IPFilter` all true (`apache.go:184-196`).
- **Steps (D, unit):** `go test ./internal/shared/apachegen/ -v` (table-driven).
  For R, render a domain and `curl` it on the host.
- **Pass (`generate.go`):**
  - reverse proxy → `ProxyPass / <scheme>://<addr>:<port>/` + `ProxyPassReverse`
    + `ProxyPreserveHost On` + `RequestHeader set X-Forwarded-Proto <http|https>`
    (`generate.go:222-280`).
  - websocket → `RewriteCond %{HTTP:Upgrade} =websocket` + `RewriteRule … ws(s)://…
    [P,L]` before the plain `ProxyPass` (`generate.go:258-268`).
  - force-https → a dedicated `<VirtualHost *:80>` with `Redirect permanent /
    https://<host>/` — **only when TLS is enabled**; otherwise dropped with warning
    `force_https: …redirect dropped` (`generate.go:136-145`).
  - custom response headers → `Header always set …` (sorted, deterministic)
    (`generate.go:204-209`).
  - custom request headers → `RequestHeader set …` (`generate.go:213-218`).
  - max body size → `LimitRequestBody <bytes>`; `unlimited` → `0`; k/m/g parsed as
    1000-based; unparseable → dropped with `max_body_size` warning
    (`generate.go:162-165,321-335`).
  - IP allow/block → `<RequireAll>` with `Require ip …` (allowlist) or `Require all
    granted` + `Require not ip …` (blocklist) (`generate.go:171-183`).
  - upstream scheme https → `ProxyPass https://…` (`generate.go:234-238`).
  - timeouts → `ProxyPass … connectiontimeout=<write> timeout=<read>` (seconds)
    (`generate.go:270-277`).
  - path strip/rewrite → `RewriteEngine On` + `RewriteRule … [P]` + `ProxyPassReverse`
    (`generate.go:242-256`).
  - render errors (validation): missing host, missing upstream addr, port out of
    1-65535 (`generate.go:104-112`).
- **Coverage:** D.
- **Pitfalls:** for IP allow/block *behaviour* on a real host, drive the host
  directly (`--resolve host:443:<host-LAN>`) so the observed client IP is
  deterministic (RELEASE-QA.md §2.6). The renderer assumes the matching Apache
  modules are loaded.

### Basic auth (htpasswd sidecar)

- **Must:** a basic-auth route gets an `<Location />` with `AuthType Basic` +
  `AuthUserFile` pointing at a per-vhost htpasswd file the agent writes; without the
  file, basic auth is dropped with a warning rather than emitting a broken directive.
- **Access:** dashboard domain ProxyConfig basic-auth (username + password) / REST.
  The intent carries a **bcrypt password hash**, not plaintext.
- **Steps (D, unit + render):**
  ```bash
  go test ./internal/agent/proxy/apache/ -run Render_basicAuth -v   # writes htpasswd + references it
  go test ./internal/shared/apachegen/ -run 'TestRender_structured/basic_auth' -v
  ```
  For R: `curl -u user:pass https://<host>/` should 200; wrong creds 401.
- **Pass:**
  - The agent writes `<Available>/nurproxy-<host>.htpasswd` as `user:hash\n`
    (`apache.go:547-561`).
  - Render emits `<Location />` with `AuthType Basic`, `AuthName "Restricted:
    <host>"`, `AuthUserFile <path>`, `Require valid-user` (`generate.go:189-200`).
  - If `AuthFile` is empty (write failed) → warning `basic_auth: no htpasswd file
    path provided; basic auth dropped` (`generate.go:197-198`).
  - The `.htpasswd` sidecar is skipped by `ReadManaged` and removed by
    `Remove`/`Prune` (`apache.go:286,429-431,482`).
- **Coverage:** D (render + write) / R (actual 401/200 behaviour).
- **Pitfalls:** the htpasswd suffix `.htpasswd` is deliberately NOT `.conf` so
  Apache's Include glob never loads it (`apache.go:541-544`). The password stored is
  the **bcrypt hash**, never plaintext (mirrors nginx, RELEASE-QA.md §2.6).

### Central TLS (provided certs via `SSLCertificateFile`)

- **Must:** centrally-issued certs are written to the agent's cert store before any
  config that references them, and a TLS route renders `:443` + `SSLEngine on` +
  `SSLCertificateFile`/`SSLCertificateKeyFile`. No cert → TLS listener dropped with a
  warning (route served plaintext, never a dangling cert reference).
- **Access:** orchestrator pushes `CertBundle`s over the agent stream →
  `InstallCerts` (`apache.go:513-533`). Requires a cert store: `-proxy-cert-dir`
  wiring (`ReconfigureDeps.CertDir`, `holder.go:295-302`); `Capabilities.CentralTLS`
  is true only when a cert store is configured (`apache.go:194`).
- **Steps (D, unit + sandbox):**
  ```bash
  # TLS render cases are subtests of the structured table (tls_central_*,
  # self_acme_*, wildcard_cert_*, force_https_with_cert_*):
  go test ./internal/shared/apachegen/ -run 'TestRender_structured/(tls|self_acme|wildcard|force_https)' -v
  ```
  The sandbox issues self-signed certs (`source=dryrun`) and pushes them.
- **Pass:**
  - `InstallCerts` writes each bundle to the cert store (key encrypted at rest when
    an encrypt key is set) (`apache.go:522-531`); with no store it is a logged
    no-op and TLS listeners are dropped (`apache.go:517-521`).
  - TLS route renders the `:443` vhost with `SSLEngine on`, `SSLCertificateFile
    <cert>`, `SSLCertificateKeyFile <key>` (`generate.go:155-160`).
  - `TLSPolicyOff` → plaintext `:80`; `TLSPolicySelfACME` → dropped to plaintext
    with warning `tls: self-acme is not supported by the apache backend…` (Apache
    never does its own ACME) (`generate.go:294-302`).
  - Missing cert/key path on a central-TLS route → warning `tls: no provided
    certificate available; route served over plaintext HTTP` (`generate.go:304-308`).
  - Wildcard cert → non-dropping warning `tls_wildcard: wildcard certificate shares
    one private key across hosts` (`generate.go:309-312`).
- **Coverage:** D (install + render) / R (real chain serving — self-acme is
  Caddy-only, so Apache TLS is always central/provided).
- **Pitfalls:** without a configured cert dir an existing-mode agent silently drops
  every central TLS listener (`holder.go:295-299`) — make sure the cert dir is wired
  before testing TLS. Sandbox certs are self-signed (no real chain).

### Adoption (`ReadManaged`: managed vs operator files)

- **Must:** on adoption the agent uploads ALL vhost files in the Available dir. Files
  NurProxy generated (`nurproxy-` prefix) come back as `Adopted=false` (for drift
  comparison); every operator-authored file comes back as `Adopted=true` (stored as
  manual, version 1). `Enabled` reflects activation.
- **Access:** automatic at existing-mode startup (`main.go:399-405` reports existing
  config to the central store) and on adopt.
- **Steps (D, unit):** `go test ./internal/agent/proxy/apache/ -run ReadManaged -v`.
  For R: hand-write a `zzz-manual.conf` in the dir, adopt, confirm it appears as a
  manual config.
- **Pass (`apache.go:271-306`):**
  - reads all files except `*.nurproxy-tmp` and `*.htpasswd` sidecars.
  - `Adopted = !IsManagedFile(name)` (operator files adopted; ours not).
  - `Enabled`: Debian → `activationPresent(sites-enabled/<name>)` (symlink OR a
    copied regular file both count, `fileops.go:106-112`); RHEL conf.d → always true
    (presence == enabled).
  - missing dir → `(nil, nil)`, not an error (`apache.go:274-276`).
- **Coverage:** D (logic) / R (real adopt round-trip).
- **Pitfalls:** ReadManaged is NOT whitelisted — operator vhosts are tracked too
  (NurProxy never overwrites a file without an explicit Accept). Some operators
  activate by copying into sites-enabled instead of symlinking; that still counts as
  enabled (`fileops.go:100-112`).

### Prune (orphan managed vhosts on domain delete)

- **Must:** on each push the agent removes every `nurproxy-`-prefixed vhost not in
  the desired set, then reloads once — so a deleted domain's file is gone on the next
  push with no inbound probe. Operator files are never touched.
- **Access:** automatic in `applyIntents` with the full desired set (`Prune`,
  `apache.go:446-491`).
- **Steps (D, unit):** `go test ./internal/agent/proxy/apache/ -run Prune -v`.
- **Pass:** only `IsManagedFile` files (skip `*.nurproxy-tmp`) not in `keep` are
  removed, with their Debian symlink and `.htpasswd` sidecar; a single reload runs
  iff anything was removed (`apache.go:460-490`). Returns the count removed.
- **Coverage:** D / R.
- **Pitfalls:** see the known DNS-leak bug on server delete (MEMORY: deleting a
  server cascade-deletes its domains and orphans managed DNS records/certs) — that
  is an orchestrator-side issue, separate from this vhost prune.

### Remove (single managed vhost)

- **Must:** removing a domain deletes its vhost file (+ Debian symlink + htpasswd)
  and reloads so Apache drops the vhost — no ghosts. A missing file is not an error.
- **Access:** orchestrator → agent stream → `Remove` (`apache.go:416-438`).
- **Steps (D, unit):** `go test ./internal/agent/proxy/apache/ -run Remove -v`. For R:
  delete a domain, confirm the file and (Debian) the symlink are gone and the host no
  longer serves it.
- **Pass:** Debian symlink removed, config removed (both tolerate `ErrNotExist`),
  `.htpasswd` removed best-effort, then `apachectl graceful` reload
  (`apache.go:420-437`).
- **Coverage:** D / R.
- **Pitfalls:** the reload runs only after the files are gone, so a removed domain
  stops serving promptly.

### Drift detection & heal (manual edit to a managed vhost)

- **Must:** a hand-edit to a managed `nurproxy-<host>.conf` is detected and reported
  so the orchestrator can re-push the rendered content; an operator's own
  (non-`nurproxy-`) vhost is never reported as drift and never overwritten.
- **Access:** automatic on every heartbeat. For a file backend the agent re-reads
  the on-disk file and re-checksums it (`ManagedChecksums`,
  `internal/agent/stream/stream.go:141-175`) — the drift signal is the on-disk
  content, NOT the apply-time in-memory checksum (that path is for the admin-API
  built-in Caddy). The mechanism is identical for nginx and apache.
- **Prerequisites:** an adopted Apache host with at least one managed vhost (R); the
  re-checksum logic itself is unit-tested in the stream package (D).
- **Steps (D, unit):**
  ```bash
  go test ./internal/agent/stream/ -run Drift -v   # TestApplyIntents_keepRetainsDriftedArtifactInManaged
  ```
- **Steps (R, on a host):**
  ```bash
  # 1. let NurProxy push a domain → nurproxy-<host>.conf written + served
  # 2. hand-edit the managed file out from under it:
  sudo sh -c 'echo "# tampered" >> <Available>/nurproxy-<host>.conf'
  # 3. wait one heartbeat cycle; the orchestrator flags drift and re-pushes,
  #    restoring the rendered content; confirm the edit is gone:
  apachectl configtest && grep -c "# tampered" <Available>/nurproxy-<host>.conf  # → 0
  # 4. a manual operator vhost is untouched:
  sudo sh -c 'cat > <Available>/zzz-manual.conf <<EOF
  <VirtualHost *:80>
      ServerName manual.example.com
  </VirtualHost>
  EOF'
  # adopt/heartbeat → zzz-manual.conf still present and unmodified
  ```
- **Pass:** on a file backend `ManagedChecksums` re-reads each managed artifact and
  re-checksums it; a changed checksum vs the accepted one makes the orchestrator
  flag drift and capture the drifted content (`stream.go:154-175`); a read error
  falls back to the last-applied checksum. Operator (`Adopted=true`) files are
  stored as manual, never re-rendered or pruned.
- **Coverage:** D (re-checksum logic) / R (real heal round-trip — NOT YET COVERED).
- **Pitfalls:** healing is orchestrator-driven (the agent reports, the orchestrator
  re-pushes) — there is no agent-side auto-rewrite. The `.htpasswd` sidecar is not a
  `.conf` and is excluded from the managed-vhost checksum set.

### Permission probe (writable dirs + reload grant + remediation)

- **Must:** at startup / hot-switch, the agent probes that it can write the config
  dir(s) and run the reload; a failing probe is NON-FATAL — the agent stays
  connected and surfaces an actionable remediation (the scoped sudoers grant).
- **Access:** automatic (`permcheck`); the backend exposes `ProbeDirs()`,
  `Runner()`, `ReloadHint()`, `ResolvedCommands()` (`apache.go:595-625,570-584`).
- **Steps (D, unit):** `go test ./internal/agent/proxy/apache/ -run ProbeDirs -v`
  and the `permcheck` suite. For R: run the agent as a non-root user without the
  sudoers grant, confirm the health message names the exact commands.
- **Pass:**
  - `ProbeDirs()` returns `[Available, Enabled]` on Debian, `[Available]` on RHEL
    conf.d (`apache.go:601-606`).
  - `ResolvedCommands()` returns the absolute `… configtest` / `… graceful` strings
    (or per-agent overrides) for the sudoers remediation (`apache.go:570-584`).
  - `ReloadHint()` is the per-agent reload override or `apachectl graceful`
    (`apache.go:616-625`).
  - The probe writes a throwaway file in each dir to confirm the group/ownership
    grant before any real apply.
- **Coverage:** D / R.
- **Pitfalls:** when the agent is non-root, configtest+reload run via `sudo -n`, so
  the scoped sudoers entry must name the ABSOLUTE binary that matches what the agent
  invokes (`apache.go:660-691`); `NURPROXY_NO_SUDO=1` disables the wrapper when the
  agent is already privileged.

### Hot-switch into existing-apache (no process restart)

- **Must:** the agent can switch built-in ↔ existing-apache live, under a write lock,
  fail-soft (a failing probe never crashes the agent), reporting mode `existing` on
  the next heartbeat.
- **Access:** `ReconfigureRequest{Mode:"existing", Type:"apache", …}` via the agent
  local API (dashboard reconfigure) (`holder.go:246-264,354-451`).
- **Steps (R):** with the agent in built-in mode and Apache installed, send a
  reconfigure to `existing`/`apache`; watch the heartbeat flip to `existing`.
- **Pass:** on success `switched to existing apache — config is writable and
  reloadable` (`holder.go:440`); on a failing probe the backend is still swapped but
  a WARNING + remediation is surfaced (`holder.go:451`, applied-with-warnings).
  Mode reported as `existing` on the next beat (`main.go:399-421`,
  `holder.go:428-431`).
- **Coverage:** R (NOT YET COVERED on real hardware).
- **Pitfalls:** leaving built-in stops the bundled Caddy so Apache can own
  `:80`/`:443` (`holder.go:283-287`). The cert dir/key must be passed in
  `ReconfigureDeps` or central TLS is dropped (`holder.go:295-302`).

## Acceptance checklist

### Dry (every RC)
- [ ] `go test ./internal/shared/apachegen/ -v` passes (render matrix).
- [ ] `go test ./internal/agent/proxy/apache/ -v` passes (Apply/rollback,
      ReadManaged, Prune, Remove, Attribution, Layout, ProbeDirs — Docker
      integration tests skip cleanly when Docker absent).
- [ ] `go test ./internal/agent/proxy/ -run "ParseVersion|ResolvePaths" -v` passes.
- [ ] `rate_limit` on an Apache route → dropped with the documented warning, no
      directive, audited (the key divergence).
- [ ] `self-acme` on an Apache route → dropped to plaintext with warning.
- [ ] No-cert central-TLS route → plaintext + warning (no dangling SSLCertificateFile).
- [ ] Layout resolves correctly for `sites-available`, `sites-enabled`, `conf.d`,
      `httpd`, and bare-root inputs.
- [ ] Error attribution distinguishes "generated config" vs "your existing config".
- [ ] `existing` mode with no `-proxy-type` errors clearly; invalid mode rejected.

### Real run (before final) — NOT YET COVERED (known gap, RELEASE-QA §2.5c / §4)
- [ ] Adopt an agent on a Debian `apache2` host: `nurproxy-<host>.conf` written to
      `sites-available`, symlinked into `sites-enabled`, `apachectl configtest`
      Syntax OK, graceful reload, `curl` served.
- [ ] Same on a RHEL `httpd` host: file in `conf.d` (no symlink), served.
- [ ] Force-broken config (e.g. point at an unreachable file, or corrupt an operator
      vhost) → apply rolls back, prior config restored, attribution message correct.
- [ ] Basic auth: 401 without creds, 200 with creds.
- [ ] Central TLS: `:443` served with the provided cert; `force_https` redirect from
      `:80` works.
- [ ] IP allow/block: blocked client gets 403 (drive the host directly via
      `--resolve` for a deterministic source IP).
- [ ] Domain delete → vhost file + symlink + htpasswd gone, no ghost vhost.
- [ ] Drift: hand-edit a managed conf → healed on the next heartbeat cycle; a manual
      `zzz-*.conf` left untouched.
- [ ] Non-root agent + scoped sudoers: permission probe passes; remediation names
      the exact absolute `configtest`/`graceful` commands when missing.
- [ ] Hot-switch built-in → existing-apache reported as `existing` on next beat.

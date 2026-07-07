# Backend: Built-in (Bundled) Caddy — DEFAULT mode, HIGH RISK

> **Scope:** the default proxy mode (`-proxy-mode built-in`) that serves real HTTPS by driving a bundled Caddy through its localhost admin API — selection/mock-fallback, the apply sequence (InstallCerts → EnsureServer → ClearRoutes → EnsureServerTLS → AddRoute), real `:443` TLS termination on provided certs, `force_https` redirect, and the #106 regression guards.
> **Code:**
> - `internal/agent/proxy/caddy/caddy.go` — the `Backend` (proxy.Proxy impl): Render/Apply/EnsureServer/EnsureServerTLS/InstallCerts, the `caddy:route:<@id>` target, module probing.
> - `internal/agent/caddy/caddy.go` — the admin-API `Client` + `Process` (the `exec.LookPath("caddy")` / mock-mode decision, `EnsureServer` srv0 with `listen [":443",":80"]`, `ApplyTLS`).
> - `internal/shared/caddygen/generate.go` — `GenerateRoute` (route JSON: subroute, reverse_proxy, force_https redirect).
> - `internal/shared/caddygen/servertls.go` — `GenerateServerTLS` (`load_files` + `automatic_https`).
> - `internal/shared/caddygen/types.go` — the route JSON struct shapes (admin-API tied).
> - `internal/agent/proxy/holder.go` — backend swap; built-in primitives forwarded only when the backend implements them.
> - `internal/agent/stream/stream.go` — `applyIntents` apply ordering + per-artifact checksum.
> - `cmd/nurproxy-agent/main.go` — flags `-proxy-mode`, `-caddy-admin-port`, `-dry-run`, cert-dir wiring.
> **Coverage legend:** D = coverable dry, R = needs a real run.

## Prerequisites
- Both binaries built: `make build-all` (produces `./nurproxy` + `./nurproxy-agent`).
- Dry stack option: `make dev-sandbox` brings up a dry orchestrator + dry agent(s) with a seeded topology (provider, zone, adopted agents, central-TLS domains). The dry agent **never** binds `:80`/`:443` and runs the proxy in-memory.
- **Real serving (the high-risk part) needs:** a real `caddy` binary in `PATH` on the agent host, the agent running as a user that may bind `:80`/`:443` (root or `CAP_NET_BIND_SERVICE`), a real orchestrator + a real DNS provider/zone so a central-TLS domain gets a real LE cert, and outside reach to the agent IP for the curl probe.
- `curl`, `openssl`, and `jq` on the box you run the verification from.
- The agent's localhost admin API is on `-caddy-admin-port` (default **2019**); the verification GETs hit `http://localhost:2019/config/...`.

## Features covered
- [ ] Mode selection: `-proxy-mode built-in` is the default (empty `-proxy-mode` ⇒ built-in).
- [ ] Caddy binary discovery: agent does NOT embed Caddy — `exec.LookPath("caddy")`; missing binary ⇒ **mock mode** (no `:443`).
- [ ] Mock-mode behaviour: in-memory config, admin-API calls become no-ops/in-memory; `IsMock()` true.
- [ ] Bootstrap: Caddy started with admin-only config (`admin.listen localhost:<port>`); `:80`/`:443` added by EnsureServer afterwards.
- [ ] EnsureServer: creates `srv0` with `listen [":443",":80"]` and an empty `routes` array, never clobbering sibling apps/servers.
- [ ] Apply sequence (admin API): InstallCerts (preflight) → EnsureServer → ClearRoutes → EnsureServerTLS → AddRoute per route.
- [ ] EnsureServerTLS / central TLS: `load_files` for provided-cert hosts + `automatic_https.disable` (all-provided) or `automatic_https.skip` (mixed self-ACME).
- [ ] Real HTTPS end-to-end: `:443` terminates TLS with the provided LE cert and proxies to the upstream.
- [ ] `force_https`: a plaintext `:80` request gets a 302 redirect to `https://`.
- [ ] Route rendering shape: `caddy:route:<@id>` target, `@id = domain-<slug(host)>`, subroute + reverse_proxy, X-Forwarded-Proto / X-Real-IP defaults.
- [ ] Per-route admin-API ops: AddRoute / RemoveRoute by `@id` / ClearRoutes / ListRoutes / GetConfig / Validate (round-trip).
- [ ] Capabilities + rate-limit module probe (`caddy list-modules` → `http.handlers.rate_limit`).
- [ ] Regression guards (#106): `routes ≥ 1` AND `tls_connection_policies ≥ 1` on srv0 AND `sslverify=0`.
- [ ] Caddy-version coupling: caddygen emits raw admin-API JSON for the **bundled** Caddy; newer Caddy can reject the route JSON (`cannot unmarshal … RouteList`).
- [ ] Artifact target kind `caddy-route` + apply-time/in-memory checksum (no on-disk file).
- [ ] Raw escape-hatch: a domain `RawConfig` tagged for the `caddy` backend is emitted verbatim as the route JSON (any other backend tag is rejected at render).

## Tests

### 9.1 Mode selection — built-in is the default
- **Must:** with no `-proxy-mode` (or `-proxy-mode built-in`) the agent runs the bundled-Caddy admin-API backend. `existing` switches to the file/process backend instead.
- **Access:**
  - CLI: `nurproxy-agent -proxy-mode built-in`. The flag default is the empty string (`main.go:53`); an empty `-proxy-mode` resolves to `ProxyModeBuiltIn = "built-in"` because the config default is built-in (`internal/agent/config/config.go:91`) and an empty flag is not applied over it (`config.go:330`). Valid values are `built-in` and `existing`; anything else is rejected at load (`config.go:155-156`).
  - Env / config: `NP_PROXY_MODE` env and `proxy_mode` in `agent.yaml` (priority flags > env > file > defaults; merge order in `config.go:Load`, env mapping at `config.go:237-238`). `main.go:94-110` only builds the `Flags` struct and calls `agentconfig.Load`.
  - Admin port: `-caddy-admin-port` (flag default 2019 — `main.go:46`; config default 2019 — `config.go:90`; YAML key `caddy_admin_port`). There is **no** `NP_CADDY*` env var — the admin port is flag / `agent.yaml` / default only.
- **Prerequisites:** none beyond file-level.
- **Steps (dry):**
  ```bash
  # Dry agent, default mode (no -proxy-mode):
  NP_DRY_RUN=true ./nurproxy-agent -orchestrator http://localhost:8080 -fqdn edge1.example.com
  # Watch the startup banner — it logs the proxy mode and the Caddy admin port.
  ```
- **Pass:** the agent comes up in built-in mode; startup logs the Caddy admin port (`main.go:120`). No `:80`/`:443` bound in dry mode.
- **Coverage:** D.
- **Pitfalls:** `existing` mode is a different file (see 02.5a). This file is only about `built-in`.

### 9.2 Caddy binary discovery and mock-mode fallback
- **Must:** the agent binary does **not** bundle Caddy. At startup `Process.Start` does `exec.LookPath("caddy")`; if there is no `caddy` in `PATH` it logs `WARNING: caddy binary not found, running in mock mode`, sets `mock=true`/`running=true`, and **does not bind any port**. The package install ships a `caddy`; a bare `make build` dev binary does not.
- **Access:** automatic at agent startup (`internal/agent/caddy/caddy.go:35-45`). `Process.IsMock()` reports the decision (`caddy.go:133`). `-dry-run` forces the in-memory mock path regardless of a present binary (`main.go:48`).
- **Prerequisites:** to see mock-mode, run with no `caddy` in `PATH` (or use `-dry-run`).
- **Steps (dry / no-real-caddy):**
  ```bash
  # Force a PATH without caddy to observe the mock-mode log line:
  env PATH=/usr/bin:/bin ./nurproxy-agent -orchestrator http://localhost:8080 -fqdn m1.example.com 2>&1 | grep -i "mock mode"
  ```
- **Pass (mock):** log shows `running in mock mode`; nothing listens on `:443`/`:80`; the agent still registers and reports state (admin-API calls are in-memory no-ops — `caddy.go:181-190,331-341,416-424`).
- **Pass (real):** with a real `caddy` in `PATH`, the log shows `Caddy started (PID …, admin on localhost:<port>)` (`caddy.go:70`) and there is **no** "mock mode" line.
- **Coverage:** D (mock observed dry); R (confirming a real binary starts and binds).
- **Pitfalls (real bug class):** the single most common false failure — a dev/`make build` agent with no `caddy` in `PATH` silently serves **nothing on `:443`**, then the operator blames TLS. Always confirm `which caddy` on the agent host and grep the log for the mock-mode warning before debugging anything else.

### 9.3 Bootstrap + EnsureServer (srv0 with :443/:80 and a routes array)
- **Must:** Caddy is launched with an **admin-only** initial config (`admin.listen localhost:<port>`, no HTTP server) so it starts even when `:80`/`:443` are taken (`caddy.go:47-56`). EnsureServer then creates `srv0` with `"listen":[":443",":80"]` and an **empty `routes` array**, building from the deepest existing ancestor down so it never clobbers other apps/servers (`caddy.go:179-253`).
- **Access:** called by the agent stream during apply (`stream.go:411`), and once at agent startup (`cmd/nurproxy-agent/main.go:301` region). Direct backend method `Backend.EnsureServer` (`internal/agent/proxy/caddy/caddy.go:258`).
- **Prerequisites:** a real `caddy` for the live-config assertion.
- **Steps (real):**
  ```bash
  # After the agent is up with a real caddy:
  curl -s http://localhost:2019/config/apps/http/servers/srv0 | jq '{listen, routes: (.routes|length)}'
  ```
- **Pass:** `listen` contains `:443` and `:80`; `routes` is an array (≥0 before any domain; **≥1** after a domain is applied — see 9.8 regression guard).
- **Coverage:** R (live admin-API assert). The path logic is exercised dry via `caddy_test.go`.
- **Pitfalls:** EnsureServer error == the classic "ports 80/443 already in use"; the stream surfaces it via health as `Caddy could not start its HTTP server (ports 80/443 in use?)` (`stream.go:415`). A fresh `srv0` **must** be created with the `routes` array present — historically (#106) srv0 was created without it, so the first `AddRoute` 500'd. See 9.8.

### 9.4 Apply sequence over the admin API (the ordering invariant)
- **Must:** for each push the agent runs, in order:
  1. **InstallCerts** (preflight) — write provided cert bundles to disk first (`stream.go:396` → `installCerts`).
  2. **EnsureServer** — create/confirm srv0 (`stream.go:411`).
  3. **ClearRoutes** — DELETE all live routes (non-fatal on error — `stream.go:422`).
  4. **EnsureServerTLS** — set `load_files` + `automatic_https` (`stream.go:433` → `applyServerTLS`).
  5. **Render + AddRoute per route** — the render loop renders each intent (`Backend.Render`) and, for a `caddy-route` artifact, POSTs it straight to `srv0/routes` via `c.caddy.AddRoute` (`stream.go:487`). `Backend.Apply` (`internal/agent/proxy/caddy/caddy.go:237-250`) is the *batch* mirror of the same EnsureServer→ClearRoutes→AddRoute sequence; it is used by the stream **only for file-backed artifacts** (nginx/apache/external caddy), not the built-in admin-API path.
  The admin API is transactional per call — there is no temp-file rollback (that is only for file backends).
- **Access:** automatic via the agent↔orchestrator stream on every intent push. Individual primitives are exposed on the backend: `EnsureServer`, `ClearRoutes`, `AddRoute`, `RemoveRoute`, `GetConfig`, `Validate` (`internal/agent/proxy/caddy/caddy.go:258-322`).
- **Prerequisites:** a stack (dry or real) + at least one central-TLS domain on the agent.
- **Steps (dry):** bring up `make dev-sandbox`, then drive a domain create via the dashboard/REST and watch the agent log emit the apply sequence. The dry agent applies routes in-memory; `GetConfig` returns the in-memory mockConfig.
- **Steps (real):** create a central-TLS domain, then:
  ```bash
  curl -s http://localhost:2019/config/ | jq '.apps.http.servers.srv0.routes | length'
  ```
- **Pass:** routes count goes to ≥1 after the domain converges; no apply error in the agent log; the apply-ACK reports each artifact with a checksum.
- **Coverage:** D (ordering + per-artifact ACK); R (the AddRoute actually landing in a live Caddy).
- **Pitfalls:** EnsureServer failure does **not** abort the apply — it is logged + health-flagged and the rest proceeds (`stream.go:411-421`). ClearRoutes failure is **non-fatal** by design. A failed AddRoute **aborts the remaining routes for that artifact** with an error naming the host (`internal/agent/proxy/caddy/caddy.go:245-247`). InstallCerts failure is surfaced via health but the built-in path still applies (self-ACME fallback, §7 — `stream.go:388-394`).

### 9.5 Central TLS strategy — EnsureServerTLS (load_files + automatic_https)
- **Must:** `EnsureServerTLS` resolves each central-policy host's installed cert/key paths and PUTs:
  - `apps/tls/certificates/load_files` — one `{certificate,key}` entry per provided-cert host.
  - `apps/http/servers/srv0/automatic_https` — `{"disable":true}` when **every** TLS host is on provided certs/off; `{"skip":[...]}` (Disable false) when at least one host is `self-acme`, listing the provided/off hosts so Caddy does not ACME them (`internal/shared/caddygen/servertls.go:93-136`; PUT in `internal/agent/caddy/caddy.go:269-326`).
  A central host whose cert is not yet installed is **dropped from `load_files`** with an audited warning but still kept out of automatic_https (the orchestrator owns it) — apply continues (`internal/agent/proxy/caddy/caddy.go:401-408`).
- **Access:** automatic via stream (call at `stream.go:433`; helper `applyServerTLS` at `stream.go:633`). Backend method `Backend.EnsureServerTLS` takes `[]proxy.TLSIntent` (Host + Policy). Policy values: `central` (default), `self-acme`, `off` (`internal/agent/proxy/caddy/caddy.go:383-431`). Per-domain selection: domain `ProxyConfig.TLSPolicy` / `SSLMode` (`internal/shared/caddygen/generate.go:83-97`).
- **Prerequisites:** a central-TLS domain with an installed cert (real run) for the load_files assertion.
- **Steps (real):**
  ```bash
  curl -s http://localhost:2019/config/apps/tls/certificates/load_files | jq 'length'
  curl -s http://localhost:2019/config/apps/http/servers/srv0/automatic_https | jq .
  ```
- **Pass:** `load_files` length ≥ the number of provided-cert hosts; `automatic_https.disable == true` for an all-central agent (or `skip` lists the central hosts in a mixed fleet).
- **Coverage:** D (the pure `GenerateServerTLS` decision is fully table-tested — `servertls_test.go`); R (the PUT landing + cert files existing).
- **Pitfalls:**
  - This step runs **after** InstallCerts and **after** EnsureServer but **before** routes (`stream.go:426-433`) — a provided cert referenced before it is installed would make Caddy fail to load the file.
  - No cert store configured (`-data-dir` certs dir empty) ⇒ no `load_files`; the host falls through to Caddy self-ACME (`internal/agent/proxy/caddy/caddy.go:392-400`). That is a *fallback*, not a failure — but on a host with no DNS provider it means the cert is whatever Caddy ACMEs itself.

### 9.6 Real HTTPS end-to-end — :443 terminates TLS on the provided LE cert
- **Must:** with a route applied and the provided LE cert loaded, `:443` terminates TLS using the **LE leaf for the host** and reverse-proxies to the upstream. This is the whole point of the default mode.
- **Access:** observed externally — there is no NurProxy CLI for it. Verify via `curl --resolve` + `openssl s_client` against the agent IP, and the admin-API config GET.
- **Prerequisites:** real `caddy`, real LE cert issued (central DNS-01), agent bound on `:443`, reachable agent IP.
- **Steps (real):**
  ```bash
  HOST=app.example.com
  AGENT_IP=<agent-ip>           # e.g. 127.0.0.1 if testing on the agent host
  # 1) Does HTTPS serve the backend body with a trusted (LE) cert?
  curl --resolve $HOST:443:$AGENT_IP https://$HOST/ \
       -w "\nhttp=%{http_code} sslverify=%{ssl_verify_result}\n"
  # 2) Is the served leaf an LE cert for this host?
  echo | openssl s_client -connect $AGENT_IP:443 -servername $HOST 2>/dev/null \
       | openssl x509 -noout -issuer -subject -dates
  ```
- **Pass:** `http=200` (backend body returned), `sslverify=0` (chain verified, real LE), issuer is `Let's Encrypt`, subject CN/SAN matches `$HOST`.
- **Coverage:** R only. The dry agent does **not** bind a listener and certs are self-signed — real serving is uncovered dry (see CLAUDE.md "Not covered").
- **Pitfalls:**
  - `sslverify` is curl's `%{ssl_verify_result}` — **0 means verified**. A non-zero value means the served cert is self-signed/wrong (e.g. you hit a dry agent, or Caddy fell back to self-ACME and produced a staging/self cert).
  - `--resolve` is mandatory if DNS doesn't yet point at the agent (the central CNAME is created a reconcile cycle late — see 05/02.2). Without it you may hit the old target.

### 9.7 force_https — :80 → :443 redirect
- **Must:** when the domain has `force_https`, the rendered route prepends a subroute matched on `protocol == http`, marked **terminal**, returning a **302** with `Location: https://{http.request.host}{http.request.uri}` so only plaintext requests redirect (no HTTPS loop) (`internal/shared/caddygen/generate.go:308-327`).
- **Access:** per-domain `ForceHTTPS` (domain field or `ProxyConfig.ForceHTTPS` — `generate.go:33`). Capability advertised as `ForceHTTPS: true` (`internal/agent/proxy/caddy/caddy.go:118`).
- **Prerequisites:** a `force_https` central-TLS domain on a real agent bound on `:80`.
- **Steps (real):**
  ```bash
  HOST=app.example.com; AGENT_IP=<agent-ip>
  curl -s -o /dev/null --resolve $HOST:80:$AGENT_IP "http://$HOST/path?q=1" \
       -w "code=%{http_code} loc=%{redirect_url}\n"
  ```
- **Pass:** `code=302` and `loc=https://app.example.com/path?q=1` (host + URI preserved).
- **Coverage:** R for the live redirect; the rendered JSON shape is unit-tested (`generate_test.go`) so D for the render.
- **Pitfalls:** the redirect route must be **terminal and matched on `protocol:http`** — without that an HTTPS request would also match and loop. Regression-guard the rendered JSON, not just the live behaviour.

### 9.8 Regression guards (#106) — the three checks that must all hold
- **Must:** on a converged central-TLS agent, **all three** hold simultaneously:
  1. `srv0.routes` length **≥ 1** (the route actually landed).
  2. `srv0.tls_connection_policies` length **≥ 1** (Caddy is actually terminating TLS, not serving plaintext on `:443`).
  3. `sslverify=0` from the external curl (real chain served).
- **Access:** admin-API config GET + the curl from 9.6.
- **Prerequisites:** real `caddy`, converged central-TLS domain.
- **Steps (real):**
  ```bash
  curl -s http://localhost:2019/config/apps/http/servers/srv0 \
    | jq '{routes:(.routes|length), tls_policies:((.tls_connection_policies // [])|length)}'
  # plus the curl --resolve … -w "sslverify=%{ssl_verify_result}" from 9.7/9.6
  ```
- **Pass:** `routes ≥ 1`, `tls_connection_policies ≥ 1`, `sslverify = 0`.
- **Coverage:** R.
- **Pitfalls (these are the actual #106 bugs — guard against regressing them):**
  - **`routes ≥ 1`:** historically srv0 was created **without** a `routes` array, so the first `AddRoute` 500'd. NurProxy now seeds `"routes":[]` in EnsureServer (`internal/agent/caddy/caddy.go:185,202`) — verify the array exists pre-apply and grows post-apply.
  - **`tls_connection_policies ≥ 1`:** historically `automatic_https.disable` was set with **no TLS connection policy**, so Caddy served **plaintext on :443**. NOTE: NurProxy itself does **not** emit `tls_connection_policies` — it disables automatic_https and loads `load_files`; Caddy **synthesizes** the connection policy at runtime when it has certs to serve. So this check reads the **live Caddy-generated** config, not a NurProxy field. If it is 0 while `automatic_https.disable` is true, Caddy is NOT terminating TLS — the bug is back. (Field absent in NurProxy source — confirmed via grep; it is a runtime/observed assertion.)
  - **`sslverify=0`:** if 1+, Caddy fell back to self-ACME / self-signed or isn't serving the provided cert — re-check 9.5 `load_files` and that the cert files exist on disk.

### 9.9 Caddy version coupling — test with the bundled version, NOT latest
- **Must:** caddygen emits **raw admin-API JSON** (the structs in `internal/shared/caddygen/types.go`) tied to the schema of the **bundled (Alpine package) Caddy** version. A newer Caddy can reject this route JSON — typically `cannot unmarshal … into … RouteList`.
- **Access:** N/A — this is a test-discipline rule for the QA runner.
- **Prerequisites:** the exact Caddy that the package install ships (not a hand-installed `latest`).
- **Steps (real):**
  ```bash
  caddy version   # confirm it matches the version shipped by the NurProxy agent package
  # Then apply a domain; if AddRoute fails, capture the admin-API error body:
  #   "caddy API returned 400/500: … cannot unmarshal … RouteList"
  ```
- **Pass:** `AddRoute` returns 2xx; no `RouteList`/unmarshal error in the agent log or admin-API response.
- **Coverage:** R (it depends on the real binary's JSON schema).
- **Pitfalls:** do **not** validate the built-in path against a `latest` Caddy you happened to have in `PATH` — the result is meaningless (a pass hides a schema break against the shipped version; a fail may be a false alarm). The admin-API error surfaces as `caddy API returned <code>: <body>` (`internal/agent/caddy/caddy.go:459-461`).

### 9.10 Route render shape + per-route admin-API operations
- **Must:** `Render` turns a `proxymodel.Route` into an Artifact whose target is `Kind: caddy-route` and `Path: caddy:route:<@id>`, with `@id = "domain-" + slugify(host)` and content = the route JSON (top-level subroute → reverse_proxy with `X-Forwarded-Proto`/`X-Real-IP` defaults) (`internal/agent/proxy/caddy/caddy.go:189-205,433-461`; `internal/shared/caddygen/generate.go:121-343`). `Remove` deletes by the `@id` recovered from the target handle; `RemoveRoute` hits `/id/<routeID>` (`internal/agent/caddy/caddy.go:352-366`). `Validate` round-trips `GET /config/` through the admin API (`internal/agent/proxy/caddy/caddy.go:312-322`).
- **Access:** automatic via stream apply/remove; backend methods `Render`, `ReadManaged`, `Remove`, `RemoveRoute`, `ListRoutes`, `GetConfig`, `Validate`.
- **Prerequisites:** none for the render shape (dry); real Caddy for the live ops.
- **Steps (dry):** create a domain in `make dev-sandbox` and inspect the apply-ACK / agent log for the artifact `TargetKind: caddy-route` and `TargetPath: caddy:route:domain-<slug>`.
- **Steps (real):**
  ```bash
  curl -s http://localhost:2019/config/apps/http/servers/srv0/routes \
    | jq '.[]."@id"'        # expect "domain-app-example-com" style ids
  # delete a domain, then confirm the route id is gone:
  curl -s http://localhost:2019/config/apps/http/servers/srv0/routes | jq '.[]."@id"'
  ```
- **Pass:** `@id` is `domain-<slug>`; deleting the domain removes exactly that route; ListRoutes/GetConfig succeed; `Validate` returns no error.
- **Coverage:** D (render shape, slug, id recovery — `generate_test.go`, `caddy_test.go`); R (live add/remove).
- **Pitfalls:**
  - `Prune` is a **no-op** for built-in Caddy — `applyIntents` ClearRoutes-then-re-add replaces the whole set, so a dropped route is already gone; there is no orphaned on-disk vhost (`internal/agent/proxy/caddy/caddy.go:287-293`). Don't expect a `Prune` count > 0 here.
  - **Raw escape hatch:** when the domain carries a `ProxyConfig.RawConfig`, `GenerateRoute` short-circuits the structured render and returns the operator's raw JSON verbatim — but only after asserting `Raw.Backend == "caddy"` (an empty backend defaults to `caddy`); a payload tagged for `nginx`/`apache` errors with `raw config targets backend %q, not "caddy"`, and malformed JSON errors with `invalid raw Caddy JSON` (`internal/shared/caddygen/generate.go:124-138`). The raw blob must carry its own `@id` or the route lands under the bare `caddy:route:` handle (no slug). Verify the raw JSON is admin-API-valid for the **bundled** Caddy (9.9) — there is no structural validation beyond well-formed JSON.

### 9.11 Capabilities + rate-limit module probe
- **Must:** the backend advertises ReverseProxy/WebSocket/ForceHTTPS/CustomHeaders/PathRewrite/BasicAuth/IPFilter/CentralTLS = true always; **RateLimit is true only if `http.handlers.rate_limit` is compiled into the live binary**, probed via `caddy list-modules` (`internal/agent/proxy/caddy/caddy.go:113-187`). A missing binary / mock / probe error ⇒ RateLimit=false (no guessing).
- **Access:** reported at registration in the capability matrix (heartbeat / register — `cmd/nurproxy-agent/main.go:157` region); dashboard greys out unsupported options.
- **Prerequisites:** real `caddy` for an accurate RateLimit probe.
- **Steps (real):**
  ```bash
  caddy list-modules | grep -x http.handlers.rate_limit && echo "ratelimit compiled in" || echo "no ratelimit module"
  ```
- **Pass:** the agent's reported `RateLimit` matches whether that module line is present.
- **Coverage:** D (the parse `parseListModules` + `moduleListHas` are unit-tested); R (the real binary's module set).
- **Pitfalls:** the stock Caddy / a `make build` agent without the caddy-ratelimit plugin reports `RateLimit=false`; a rate-limited domain then renders **without** the limit and the orchestrator audits the drop (invariant #4). Don't expect rate limiting to "just work" unless the module is actually compiled in.

### 9.12 Artifact target kind `caddy-route` + apply-time/in-memory checksum
- **Must:** the built-in path uses target kind `caddy-route` (`internal/agent/proxy/proxy.go:154`), not `file`. There is **no on-disk config file** — the route lives only in Caddy's admin-API config. The artifact checksum is computed at apply time from the rendered content (`sha256` of the route JSON), reported in the apply-ACK and used for drift, never read back from a file (set in the report at `stream.go:469`; `checksum` helper — `sha256` of the content — at `stream.go:656-659`, matching `db.ChecksumContent` on the orchestrator).
- **Access:** internal; observable in the apply-ACK / `ManagedChecksums` snapshot the heartbeat carries.
- **Prerequisites:** a stack (dry suffices).
- **Steps (dry):** `make dev-sandbox`, create a domain, and confirm the agent reports a `caddy-route` artifact with a non-empty checksum and no file path on disk.
- **Pass:** the artifact report shows `TargetKind: caddy-route`, `TargetPath: caddy:route:domain-<slug>`, a stable `Checksum`, and `Enabled: true`; nothing is written under the proxy config dir.
- **Coverage:** D.
- **Pitfalls:** drift for built-in Caddy is checksum-of-rendered-content vs the live route, not a file mtime/content compare — a manual edit via the admin API would show as drift on the next compare, but there is no atomic-file rollback dance (that's file backends only).

## Acceptance checklist

### Dry (every RC)
- [ ] Default `-proxy-mode` (empty) selects built-in; startup logs the Caddy admin port (9.1).
- [ ] No `caddy` in PATH ⇒ `running in mock mode`; nothing binds `:443` (9.2).
- [ ] Apply ordering observed: InstallCerts → EnsureServer → ClearRoutes → EnsureServerTLS → AddRoute (9.4).
- [ ] `GenerateServerTLS` decisions correct (disable vs skip) per policy mix — unit tests green (9.5).
- [ ] `force_https` renders a terminal `protocol:http` 302 subroute (9.7 render half).
- [ ] Route artifact is `caddy-route` / `caddy:route:domain-<slug>` with a checksum and no file on disk (9.10, 9.12).
- [ ] RateLimit capability reflects the module probe; parse helpers unit-tested (9.11).

### Real run (before final)
- [ ] Real `caddy` (the **bundled** version) in PATH; `caddy version` matches the shipped package (9.9).
- [ ] `srv0.listen` contains `:443` and `:80`; `routes` array present (9.3).
- [ ] After a central-TLS domain converges: `srv0.routes ≥ 1` (9.8).
- [ ] `apps/tls/certificates/load_files` has the provided cert(s); `automatic_https.disable=true` (all-central) (9.5).
- [ ] `srv0.tls_connection_policies ≥ 1` in the live (Caddy-generated) config (9.8).
- [ ] `curl --resolve $HOST:443:$IP https://$HOST/` returns the backend body with `http=200` and `sslverify=0`; served leaf is an LE cert for the host (9.6, 9.8).
- [ ] Plaintext `:80` request gets a 302 to `https://` with host+URI preserved (9.7).
- [ ] `AddRoute` succeeds with no `RouteList`/unmarshal error against the bundled Caddy (9.9).
- [ ] Deleting a domain removes exactly its `domain-<slug>` route from srv0 (9.10).

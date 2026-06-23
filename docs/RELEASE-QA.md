# NurProxy Release QA / Acceptance Book

A living checklist for signing off a release. For each capability it records **what
it must do**, **how to test it**, **what can be covered dry vs. what needs a real
run**, the **pass criteria**, and the **pitfalls** that have actually bitten us.

> How to use this before a release: run the dry suite (cheap, every RC), then the
> real-run suite on a throwaway domain/agent (per RC or at least before the final
> tag), tick the [Acceptance checklist](#acceptance-checklist), and note any
> deviations in the release notes. New capabilities **must** land here with a test
> before they ship.

---

## 1. Test environments

| Env | What it is | Covers | Does NOT cover |
|---|---|---|---|
| **Dry / sandbox** | `make dev-sandbox` or `NP_DRY_RUN=true` binaries. Mocks DNS + ACME + the agent proxy. | Whole control plane: API/CLI/dashboard, DNS state machine, TLS issuance/renewal-window logic, agent protocol (register/adopt/heartbeat/stream/ack), route rendering, migrations, security hardening, backup/restore of a dry DB. | Real serving, real LE chain, resolvable DNS, real nginx/apache/caddy apply+reload. |
| **Single real host** | One real agent (built-in Caddy or existing nginx) + a real orchestrator + a real zone. | Real DNS-01 issuance, real serving on `:443`, proxy directives, the chosen backend's apply/reload. | Multi-agent, cross-host topology, platform matrix. |
| **Homelab (multi-host)** | apps-vm orchestrator + durox (existing-nginx) + optional extra agents. | In-place upgrades, multi-agent, real traffic continuity, IPv6 reachability. | Non-Linux platforms (macOS/FreeBSD), bundled-Caddy on a fresh public host. |

**Golden rule:** dry proves the *logic*; only a real run proves *serving, certs, and
DNS*. Anything in the "Real" column below cannot be signed off from dry alone.

---

## 2. Capabilities & acceptance tests

Legend: **D** = coverable in dry, **R** = needs a real run.

### 2.1 Agent lifecycle (register → adopt → heartbeat → stream) — D
- **Must:** an agent registers, shows pending, can be adopted, then heartbeats and
  holds the dial-out stream; re-register of an adopted agent returns 409 and it
  continues via heartbeat.
- **Steps:** start agent → `GET /agents` shows pending → `PUT /agents/{id}/adopt`
  (body `{"name":..,"dns_mode":"static"}`) → orchestrator logs `heartbeat 200`,
  `routes/ack 200`.
- **Pass:** status `adopted`; heartbeat/ack 200s recur.
- **Pitfalls:** adopt **requires a JSON body** (empty body → 400). There is **no
  `GET /agents/{id}`** (405) — list and filter. A restarted-but-already-adopted
  agent logs `registration failed 409` — that is expected, not an error.

### 2.2 DNS lifecycle & ownership — D (logic) / R (resolvable records)
- **Must:** creating a domain creates a CNAME `sub → agentFQDN`; NurProxy adopts an
  identical pre-existing record (`dns_managed=false`) and never overwrites a
  conflicting one; on teardown it deletes only records it created (`dns_managed=true`).
- **Steps (real):** create domain → `dig +short <sub> @<zone NS>` resolves → delete
  domain → record gone (managed) or kept (adopted). Check audit `dns_created` /
  `dns_deleted` / `dns_adopted` / `dns_left_adopted`.
- **Pass:** record appears on create, is removed on delete for managed records, audit
  matches.
- **Pitfalls:**
  - The CNAME is created **asynchronously a reconcile cycle AFTER** the domain goes
    `active` (~30–50 s later). A `dns_managed=false` read right after create is a
    **timing artifact**, not the final state — confirm via the audit log.
  - A **wildcard `*.zone`** makes any subdomain resolve even without a dedicated
    record; don't conclude "created" from a public-resolver `dig` alone — query the
    **authoritative NS** and compare proxied (orange) vs grey answers.
  - Teardown DNS deletion runs in the **reconciler**, not the delete handler — see 2.4.

### 2.3 TLS — central DNS-01 issuance, renewal, fallbacks — D (issuance logic) / R (real cert + serving)
- **Must:** a central-TLS domain gets a real LE cert via DNS-01 and the agent serves
  it; transient failures retry with backoff; a rate-limit is parsed into a typed
  `RateLimitError`; renewal happens inside the window; `self-acme` is the fallback for
  zones without a DNS provider.
- **Steps (real):** create central-TLS domain → orchestrator log shows DNS-01 solve →
  "Server responded with a certificate"; verify the served leaf is LE and matches the
  host. Inject failures dry with `NP_DRY_RUN_FAIL=ratelimit|challenge|propagation`.
- **Pass:** real LE cert served; `sslverify=0` against the agent; dry failure injection
  surfaces the right typed error and retry.
- **Pitfalls:**
  - `NP_DNS_DRY_RUN` + real ACME **always fails DNS-01** (mock DNS never publishes the
    challenge TXT). Use full `NP_DRY_RUN` or `NP_ACME_DRY_RUN` instead.
  - **Renewal-in-window** and **self-acme** are still only logic-tested (dry). Renewal
    needs LE-staging or a soak; self-acme needs a public host with open `:80/:443`.

### 2.4 Teardown & the parent-delete guard — D
- **Must:** deleting a domain tears down its route + managed DNS + cert via the
  reconciler. Deleting a **server / agent / zone that still has domains is refused
  with 409** (body lists the domains).
- **Steps:** create domain → `DELETE /domains/{id}` (202/200, async) → record + vhost
  gone, audit `dns_deleted`. Then create another and try `DELETE /servers/{id}` while
  the domain exists → **409** with `{"domains":[...]}`.
- **Pass:** clean teardown, no leak; parent delete blocked while children exist.
- **Pitfalls:**
  - Domain delete is **soft** (`status=deleting`); the reconciler does the real DNS/row
    cleanup a cycle later. The guard counts `deleting` rows too, so a `DELETE server`
    **right after** a `DELETE domain` correctly 409s until the reconciler finishes.
  - The FK is still `ON DELETE CASCADE`; the 409 guard is what prevents the cascade
    from bypassing teardown. A direct DB delete would still leak — see issues for the
    `RESTRICT` follow-up.

### 2.5 Backends

#### 2.5a Existing nginx (apply / reload / adopt / drift) — R
- **Must:** the agent writes only `nurproxy-*.conf`, reloads nginx, adopts existing
  tracked artifacts without duplication, and never touches operator files.
- **Steps:** see 2.7 (drift). Confirm `nginx -t` ok before/after every apply.
- **Pitfalls:** agent only manages the `nurproxy-` prefix; a hand-written non-prefixed
  vhost must survive untouched.

#### 2.5b Built-in Caddy (central TLS serving) — R — HIGH RISK, the DEFAULT mode
- **Must:** a fresh agent with no nginx/apache runs bundled Caddy and **serves real
  HTTPS** on central TLS: route applied, provided cert loaded, `:443` terminates TLS
  with the LE cert, proxies to the backend; `force_https` redirects on `:80`.
- **Steps (real):** run agent (`-proxy-mode built-in` is default) with a real `caddy`
  in PATH → adopt → create central-TLS domain → `curl --resolve host:443:127.0.0.1
  https://host/` returns the backend body with `sslverify=0` and an LE cert;
  `tls_connection_policies` count on `srv0` is ≥1; `routes` ≥1.
- **Pass:** real HTTPS served by Caddy end to end.
- **Pitfalls (all real bugs we hit — guard against regressions):**
  - The agent does **not** bundle Caddy in its own binary — it `exec.LookPath("caddy")`.
    No caddy in PATH ⇒ **"running in mock mode"** (no `:443`). The package install ships
    a caddy; a bare dev build does not.
  - **Caddy version matters:** caddygen emits raw admin-API JSON for the bundled
    (Alpine) Caddy. Test with that version — newer Caddy can reject the route JSON
    (`cannot unmarshal … RouteList`). Don't test bundled Caddy with `latest`.
  - Historically broken until rc.3 (#106): srv0 created without a `routes` array →
    AddRoute 500; and `automatic_https.disable` with no `tls_connection_policies` →
    **plaintext on :443**. Regression-guard: `routes ≥1` AND `tls_connection_policies ≥1`
    AND `sslverify=0`.

#### 2.5c Existing apache / other init systems / macOS / FreeBSD — R, NOT YET COVERED
- Tracked as gaps (§4).

### 2.6 Proxy directives (`ProxyConfig`) — R (behaviour) / D (render is unit-tested)
- **Must:** each structured field renders to the right native directive and behaves.
- **Matrix (verify rendered conf + behaviour):**
  - `custom_response_headers` → `add_header … always` (visible in `curl -I`).
  - `custom_request_headers` → `proxy_set_header` (backend echoes it).
  - `max_body_size` → `client_max_body_size`.
  - `path_strip` / `path_rewrite` → `rewrite …` (backend sees rewritten path).
  - `websocket:true` → `proxy_http_version 1.1` + Upgrade/Connection headers.
  - `timeout_*` → `proxy_*_timeout`.
  - `upstream_scheme:https` → `proxy_pass https://…`.
  - `rate_limit` → `limit_req` (nginx returns **503** when tripped, not 429).
  - `ip_allowlist`/`ip_blocklist` → `allow`/`deny` (blocked client → 403).
  - `basic_auth` → `auth_basic` + htpasswd; **password is a bcrypt hash**, not plaintext.
- **Pitfalls:** for IP allow/block tests, drive durox directly via `--resolve
  host:443:<durox-LAN>` so the observed client IP is deterministic (the public
  hairpin path mangles the source IP). nginx uses **503** for `limit_req`.

### 2.7 Drift healing — R
- **Must:** a hand-edited managed conf is restored; a manual non-`nurproxy` file is left
  alone; managed DNS drift is corrected.
- **Steps:** append a marker to `nurproxy-<host>.conf`; create a `zzz-manual.conf`;
  wait ~30–60 s. Marker gone (healed via heartbeat checksum → re-push), manual file
  intact.
- **Pass:** managed restored to the generated model, operator file untouched.
- **Pitfalls:** healing is **heartbeat-driven** (the agent reports file checksums; the
  orchestrator detects drift and re-pushes) — allow a cycle. DNS-drift correction needs
  write access to the provider outside NurProxy, so it's hard to self-test.

### 2.8 Security hardening — D
- **Must / steps / pass:**
  - **Brute-force login lockout:** 5 wrong passwords → **429 + `Retry-After: 900`**.
  - **Per-IP register rate limit:** ~10 `/agents/register` → **429**.
  - **Body cap:** a `>4 MiB` body → **400**.
  - **Global session revocation:** change password → old cookie → **401** on a protected route.
  - **Agent/admin token separation:** agent bearer on an admin route → **401**; on its own agent route → **200**.
  - **Secure cookie scheme:** `Secure` only when the request is HTTPS (`r.TLS` or
    `X-Forwarded-Proto: https`); plain-HTTP-by-IP keeps working.
- **Pitfalls:** run lockout tests on a **dry instance**, not prod — they lock the real
  login/register for 15 min. The secure-cookie default once **locked out** plain-HTTP
  dashboards (fixed pre-rc.2); regression-guard a plain-HTTP login still works.

### 2.9 Backup & restore — R (against a real DB) / D (dry DB)
- **Must:** `nurproxy backup` snapshots db + `encryption.key` + `acme-account.key` (with
  a plaintext-key warning); `nurproxy restore` reconstitutes them losslessly; a fresh
  orchestrator boots on the restored dir with all entities and decrypting providers.
- **Steps:** `nurproxy backup -o f.tgz` → restore into a temp dir → **key checksums
  match** the originals → boot **`NP_DRY_RUN`** on the restored dir → `/health`
  `database:ok`, `auth/status` `setup_required:false`, reconciler loads domains/agents
  and reaches the provider (= decryption works).
- **Pass:** checksums match, dry boot clean, entities present.
- **Pitfalls:** **never** boot the restored REAL data with a NON-dry orchestrator on
  the same tailnet — a second live orchestrator would fight prod over the same
  Cloudflare zone + agents. Always restore-verify in **dry**. (Live-DB backup with WAL
  active is fine for the test; for a guaranteed-consistent snapshot, stop the service.)

### 2.10 Ops signals — D
- **Health DB check:** `/api/v1/health` → `503` when the DB is down (unit-tested;
  hard to reproduce live because the running process holds the DB handle open).
- **Structured logging:** `NP_LOG_FORMAT=json` → valid JSON lines; `NP_LOG_LEVEL` filters.
- **Version-skew detection:** an agent older than the orchestrator is flagged in the
  dashboard.
- **Audit log:** every DNS/cert/route/security action is recorded; `source` is
  `ui|api|agent|system`, dry events tagged `source=dryrun`.

### 2.11 Resilience & upgrade — R
- **In-place upgrade:** stop → back up the data dir → swap binary → start; migrations
  run cleanly on the real DB; agents reconnect; **no traffic interruption** (the agent
  keeps serving while the orchestrator restarts).
- **Reconnect:** orchestrator restart → agent re-adopts artifacts, heartbeats, acks.
- **Pass:** health ok, version bumped, agent reconnected, live sites unaffected.
- **Pitfall:** the orchestrator logs a **one-time** `…:8780/routes … context deadline
  exceeded` per agent reconnect when it can't reach the agent at its advertised
  address — cosmetic, routes are delivered by push.

### 2.12 Interfaces — D
- **Dashboard / REST API / CLI** over the same surface; `--json` for scripts. Server
  subnet suggestions and nginx-inferred backends appear in the add-Server dialog.
- **MCP server** (optional, off by default) for AI-driven domain management.

---

## 3. Acceptance checklist (condensed)

Run before tagging a final release (and ideally per RC):

**Dry (every RC):**
- [ ] `make test` + `make test-sandbox` green.
- [ ] Security battery: login lockout, register ratelimit, body cap, session
      revocation, token separation (§2.8).
- [ ] Backup → restore → dry-boot round-trip; key checksums match (§2.9).
- [ ] JSON logging, health-503 unit tests (§2.10).

**Real run (before final, on a throwaway domain/agent):**
- [ ] Domain create → real DNS-01 LE cert → serve over **IPv4 and IPv6** (§2.3, §2.2).
- [ ] Proxy-directive matrix (§2.6).
- [ ] **Built-in Caddy** serves real HTTPS (`routes≥1`, `tls_connection_policies≥1`,
      `sslverify=0`) with the **bundled Caddy version** (§2.5b).
- [ ] Existing-nginx apply/reload + **drift healing** (§2.5a, §2.7).
- [ ] Teardown leaves **no leak**; parent-delete **409** guard works (§2.4).
- [ ] In-place upgrade on a real DB: migrations clean, agent reconnects, **no traffic
      drop** (§2.11).

**Always:**
- [ ] Stable channels untouched on a `-rc` (latest non-pre tag stays the last final).
- [ ] CHANGELOG updated; upgrade notes cover any breaking default.

---

## 4. Known gaps (not yet covered by a real run)

- **Cert renewal inside the window** — logic only; needs LE-staging or a soak.
- **`self-acme` fallback serving** — needs a public host with open `:80/:443`.
- **Existing-apache** apply/reload, **OpenRC/launchd/rc.d**, **macOS/FreeBSD** agents.
- **DNS-drift correction** end to end (needs external provider write access).
- **Large topology / many domains** reconciler performance.
- **Provider failure handling** (revoked CF token) — clear errors, no state corruption.

---

## 5. Reusable fixtures

**Mini backend** (echoes a marker + request headers; for proxy/header/path tests):
```python
# /tmp/np-e2e-service.py — python3, binds 0.0.0.0:18099
import http.server, socketserver, socket
M = "NURPROXY-E2E-PROOF"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s):
        hdrs = "".join(f"  {k}: {v}\n" for k, v in s.headers.items())
        b = f"{M}\nserved-by={socket.gethostname()}\npath={s.path}\n{hdrs}".encode()
        s.send_response(200); s.send_header("Content-Length", str(len(b))); s.end_headers(); s.wfile.write(b)
    def log_message(s, *a): pass
socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(("0.0.0.0", 18099), H).serve_forever()
```

**Serve-direct (bypass DNS/edge, deterministic client IP):**
```
curl --resolve <host>:443:<agent-ip> https://<host>/ -w "http=%{http_code} sslverify=%{ssl_verify_result}\n"
echo | openssl s_client -servername <host> -connect <agent-ip>:443 2>/dev/null | openssl x509 -noout -subject -issuer
```

**Dry instance for the security/ops battery (no prod risk):**
```
NP_LOG_FORMAT=json NP_DRY_RUN=true ./nurproxy -port 18081 -data-dir /tmp/np-sec
```

**bcrypt for basic_auth:** `python3 -c 'import bcrypt;print(bcrypt.hashpw(b"pw",bcrypt.gensalt()).decode())'`

---

## 6. Environment gotchas (homelab specifics — generalise as needed)

- **Tailscale ACL ports:** the orchestrator API (`:8080`) must be allowed in the ACL
  for a node to reach it over Tailscale (the default grants 22/80/443 only). LAN
  (same `/24`) bypasses the ACL. Symptom: `curl … :8080` → `HTTP 000`.
- **Clock skew in logs:** the orchestrator (apps-vm) logs **UTC (`…Z`)**; agents may log
  **local (+02:00)**. Convert before grepping `--since`, or you'll get empty windows.
- **sudo:** apps-vm is NOPASSWD; durox needed a passwordless-sudo config (now set). A
  password-prompting host can't be driven non-interactively — run the privileged block
  via `! ssh -t … sudo …`.
- **IPv6 self-tests are flaky from inside:** a host curling its **own** public v6
  (hairpin) often fails, and `systemd-resolved` can hand back a v4-mapped address for an
  AAAA. Prove external v6 from a **different** v6-capable host with `--resolve` to the
  real AAAA, and trust the authoritative DNS, not the local resolver.
- **Don't run two live orchestrators on one tailnet/zone** (e.g. a restore test) — they
  fight over the same Cloudflare records and agents.
- **API keys** used for a test are revocable — generate, use, `DELETE /api/v1/api-key`
  when done (they end up in transcripts).

# Security Hardening

> **Scope:** Every authentication/authorization and anti-abuse control in the orchestrator API and MCP endpoint, with exact thresholds, response codes and crypto parameters read from source.
> **Code:** `internal/orchestrator/api/server.go`, `internal/orchestrator/api/auth.go`, `internal/orchestrator/api/middleware.go`, `internal/orchestrator/api/helpers.go`, `internal/orchestrator/api/agents.go`, `internal/orchestrator/mcp/server.go`, `internal/shared/ratelimit/ratelimit.go`, `internal/shared/auth/{password,session,token}.go`, `internal/shared/crypto/crypto.go`.
> **Coverage legend:** D = coverable dry, R = needs a real run.

> **IMPORTANT — read before testing.** Three controls that the legacy `docs/RELEASE-QA.md` §2.8 lists are **NOT present in the current `dev` code** (verified by reading the source and `git log -S`). They are flagged **NOT IMPLEMENTED** in the relevant subsections below with the file evidence. Do **not** tick them green off the old checklist; either the control was never merged or was removed. File the discrepancy. The controls that *do* exist are documented exactly as the code behaves.

## Prerequisites
- Both binaries built: `make build-all` (produces `./nurproxy` and `./nurproxy-agent`).
- A **dry** orchestrator instance you can hammer. NEVER run the lockout tests against prod — a triggered lockout blocks the real admin login for 15 minutes per IP.
  ```bash
  # Minimal standalone dry orchestrator on :8080 (fresh temp DB):
  NP_DRY_RUN=true NP_DB_PATH="$(mktemp -d)/np.db" ./nurproxy &
  # or the full seeded stack:
  make dev-sandbox            # orchestrator + 1 agent, dashboard up
  ```
- `curl` and `jq` available.
- For the brute-force/lockout cases you want a *fresh* limiter: the limiter is per-process in-memory (`internal/shared/ratelimit/ratelimit.go`), so **restart the orchestrator** to clear all lockouts (there is no reset endpoint).
- First-run setup must be done before login tests:
  ```bash
  curl -s -X POST localhost:8080/api/v1/auth/setup -d '{"password":"correcthorse"}'
  ```

## Features covered
- [ ] Login brute-force lockout — threshold, window, lockout, `429` + `Retry-After` (`auth.go`, `server.go`).
- [ ] MCP admin-API-key brute-force lockout — 10 / 15 min / 15 min, `429` + `Retry-After` (`mcp/server.go`).
- [ ] **Per-IP `/agents/register` rate limit** — claimed by §2.8; **NOT IMPLEMENTED** in code (regression/discrepancy guard).
- [ ] MCP request body cap — `io.LimitReader(r.Body, 1<<20)` = 1 MiB (`mcp/server.go`).
- [ ] **REST API request body cap (>4 MiB → 400)** — claimed by §2.8; **NOT IMPLEMENTED** in code (`helpers.go` has no limit).
- [ ] Global session revocation on password change — re-hash invalidates? (verify actual behaviour) (`auth.go`).
- [ ] Session-secret model — persistent per-install HMAC key, forge resistance (`server.go` `loadOrCreateSessionKey`).
- [ ] Agent/admin token separation — agent bearer on admin route vs its own agent route (`middleware.go`).
- [ ] **Secure cookie scheme (`Secure` only on HTTPS; plain-HTTP keeps working)** — claimed by §2.8; **NOT IMPLEMENTED** in code (`auth.go` cookies set no `Secure` flag at all).
- [ ] `clientIP` anti-spoof — keyed on `RemoteAddr`, not `X-Forwarded-For` (`helpers.go`, `mcp/server.go`).
- [ ] Crypto parameters — bcrypt cost 12, AES-256-GCM, token prefixes `np_ag_`/`np_ak_`, HMAC-SHA256 sessions, constant-time compares.

## Tests

### Login brute-force lockout
- **Must:** After **5** failed logins from one client IP within a **15-minute** window, that IP is locked out for **15 minutes**; further attempts (even with the *correct* password) return `429 Too Many Requests` with a `Retry-After` header of **901** seconds. A successful login resets the counter.
  - Threshold/window/lockout: `server.go:92` → `loginLimiter: ratelimit.New(5, 15*time.Minute, 15*time.Minute)`.
  - `429` path and `Retry-After`: `auth.go:99-103`. `Retry-After` is `int(retryAfter.Seconds())+1` (`auth.go:100`) — i.e. `900+1 = 901` on a fresh lockout, NOT exactly 900. (RELEASE-QA §2.8 says "`Retry-After: 900`"; the code emits 901. Treat ≥900 as pass; note the off-by-one.)
  - A failed attempt calls `s.loginLimiter.Fail(ip)` (`auth.go:119,125`); a success calls `Reset(ip)` (`auth.go:130`).
  - The limiter arms the lockout when `failures >= max` and then resets the counter so post-lockout attempts get the full allowance again (`ratelimit.go:92-98`).
- **Access:**
  - REST: `POST /api/v1/auth/login`, body `{"password":"..."}` (`server.go:138`, `auth.go:97`).
  - Dashboard: the login page password field (same endpoint).
  - CLI: `nurproxy` auto-logs-in via `NP_API_PASSWORD`/`--password` (`cmd/nurproxy/cli.go:22`) — also hits this endpoint, so a bad CLI password counts toward lockout.
- **Prerequisites:** setup completed (an `admin_password_hash` exists); fresh process for a clean limiter.
- **Steps:**
  ```bash
  base=localhost:8080
  for i in 1 2 3 4 5; do
    curl -s -o /dev/null -w "fail $i -> %{http_code}\n" \
      -X POST $base/api/v1/auth/login -d '{"password":"wrong"}'
  done
  # 6th attempt — even with the CORRECT password — must be locked out:
  curl -s -D - -o /dev/null -X POST $base/api/v1/auth/login \
    -d '{"password":"correcthorse"}' | grep -iE 'HTTP/|retry-after'
  ```
- **Pass:** attempts 1–5 return `401`; the 6th returns `429` with `Retry-After: 901` (≥900). Verified pattern matches `login_ratelimit_test.go:29-33`.
- **Coverage:** D.
- **Pitfalls:** Per-IP and in-memory — run on a dry instance, never prod (locks the real login 15 min). `clientIP` keys on `RemoteAddr`, so all loopback curls share one key. To re-test, **restart the process** (no reset API). The window only resets the *count* on a fresh attempt after the window elapses (`ratelimit.go:87-90`); to simulate time passing in unit tests use the injectable `now` clock (`ratelimit_test.go:9`), but over HTTP you must wait or restart.

### MCP admin-API-key brute-force lockout
- **Must:** When MCP is enabled, **10** failed `Authorization: Bearer` attempts from one IP within **15 minutes** lock that IP out for **15 minutes** → `429` + `Retry-After` (≈`int(secs)+1`). A successful auth resets it.
  - Threshold: `mcp/server.go:44` → `ratelimit.New(10, 15*time.Minute, 15*time.Minute)`.
  - Order of checks: enabled gate first → method gate (`POST` only) → limiter `Allow` (`mcp/server.go:90-95`) → `authorized` (`:96`); on auth failure it calls `limiter.Fail` and returns `401` + `WWW-Authenticate: Bearer` (`:96-100`); on success `limiter.Reset` (`:102`).
  - MCP is **disabled by default**: unless setting `mcp_enabled == "true"`, the endpoint **404s** (`mcp/server.go:49-52,80-84`) — a probe never reveals the limiter.
  - Auth uses `subtle.ConstantTimeCompare` against `admin_api_key` (`mcp/server.go:67`); empty/missing key ⇒ unauthorized (`:57-60`).
- **Access:**
  - REST/JSON-RPC: `POST /mcp` (and `/mcp/`), `Authorization: Bearer <admin_api_key>`, body is JSON-RPC 2.0 (`mcp/server.go:30,79`).
  - Enable: `PUT /api/v1/settings/mcp_enabled` value `true`; generate the key via `POST /api/v1/api-key`.
- **Prerequisites:** `mcp_enabled=true`; an admin API key generated (otherwise every request is `401` regardless of token, `mcp/server.go:57-60`).
- **Steps:**
  ```bash
  base=localhost:8080
  # enable MCP + create a key (needs an admin session/cookie or admin api key):
  COOKIE=$(curl -s -i -X POST $base/api/v1/auth/login -d '{"password":"correcthorse"}' \
    | awk -F'[=;]' '/nurproxy_session/{print $2}')
  curl -s -X PUT  $base/api/v1/settings/mcp_enabled -b "nurproxy_session=$COOKIE" -d '{"value":"true"}'
  curl -s -X POST $base/api/v1/api-key             -b "nurproxy_session=$COOKIE"
  # hammer with a WRONG bearer 10x, then look for 429:
  for i in $(seq 1 10); do
    curl -s -o /dev/null -w "fail $i -> %{http_code}\n" \
      -X POST $base/mcp -H 'Authorization: Bearer np_ak_wrong' \
      -d '{"jsonrpc":"2.0","id":1,"method":"ping"}'
  done
  curl -s -D - -o /dev/null -X POST $base/mcp -H 'Authorization: Bearer np_ak_wrong' \
    -d '{"jsonrpc":"2.0","id":1,"method":"ping"}' | grep -iE 'HTTP/|retry-after'
  ```
- **Pass:** first 10 wrong attempts → `401` (with `WWW-Authenticate: Bearer`); 11th → `429` + `Retry-After`. With MCP disabled, every request → `404`.
- **Coverage:** D.
- **Pitfalls:** Disabled-by-default — if you forget to flip `mcp_enabled` you'll see `404` and wrongly conclude the limiter is broken. A *correct* bearer resets the IP, so don't interleave good/bad. Restart to clear lockout.

### Per-IP `/agents/register` rate limit — NOT IMPLEMENTED
- **Must (claimed by RELEASE-QA §2.8):** "~10 `/agents/register` → 429".
- **Reality (code):** `handleRegisterAgent` (`agents.go:51`) has **no rate limiter**. The only `ratelimit.Limiter` instances in the API are `loginLimiter` (`server.go:92`) and the MCP `limiter` (`mcp/server.go:44`); grep for `registerLimiter`/any limiter use in `internal/orchestrator/api/` returns only the login limiter. `git log -S registerLimiter` is empty.
- **Access:** `POST /api/v1/agents/register`, no auth (`server.go:143`), body `{"id","fqdn","token",...}` (`agents.go:52-62`).
- **Steps (to demonstrate the absence):**
  ```bash
  base=localhost:8080
  for i in $(seq 1 30); do
    curl -s -o /dev/null -w "%{http_code} " -X POST $base/api/v1/agents/register \
      -d "{\"id\":\"a$i\",\"fqdn\":\"e$i.example.com\",\"token\":\"np_ag_x\"}"
  done; echo
  ```
- **Pass / observation:** Responses are `201` (created) or `409` (duplicate FQDN, `agents.go:74-77,108-110`) — **never `429`**. This confirms the control is absent. **Mark the §2.8 line as a discrepancy / open issue, not a pass.**
- **Coverage:** D.
- **Pitfalls:** Don't assume it works because the login limiter does — they are separate. Registration is unauthenticated *and* unthrottled today; this is the finding to record.

### MCP request body cap (1 MiB)
- **Must:** The MCP handler reads at most **1 MiB** of the request body via `io.ReadAll(io.LimitReader(r.Body, 1<<20))` (`mcp/server.go:104`). Bodies larger than 1 MiB are silently **truncated** at 1 MiB, then JSON-parsed; an oversized body that no longer parses as JSON returns a JSON-RPC parse error (`writeError(..., parseError, "invalid JSON")`, `mcp/server.go:111-113`) over HTTP 200 (JSON-RPC errors are in-body, not HTTP status).
- **Access:** `POST /mcp` (MCP enabled + valid bearer required *before* the read — limiter/auth run first, `mcp/server.go:90-104`).
- **Prerequisites:** `mcp_enabled=true`, valid admin API key (else `404`/`401` before the body is read).
- **Steps:**
  ```bash
  base=localhost:8080; KEY=<admin_api_key>
  # ~2 MiB of junk after a valid-looking prefix:
  python3 - <<'PY' > /tmp/big.json
  print('{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"' + "A"*2000000 + '"}}')
  PY
  curl -s -o /dev/null -w "%{http_code}\n" -X POST $base/mcp \
    -H "Authorization: Bearer $KEY" --data-binary @/tmp/big.json
  ```
- **Pass:** Request completes (HTTP `200`) but the body was truncated at 1 MiB; because the truncated bytes are not valid JSON the JSON-RPC response carries a parse error. (Verify the response is a `parseError`, not a normal `ping` result.) Note: 1 MiB = `1<<20`, **not** the "4 MiB" figure RELEASE-QA §2.8 attributes generally — that 4 MiB is the *agent stream* line cap (`internal/agent/stream/stream.go:33` `maxLine = 4 << 20`), a different subsystem entirely.
- **Coverage:** D.
- **Pitfalls:** The cap applies to MCP only. The agent-stream 4 MiB and the MCP 1 MiB are unrelated; don't conflate them.

### REST API request body cap (>4 MiB → 400) — NOT IMPLEMENTED
- **Must (claimed by §2.8):** "a `>4 MiB` body → 400".
- **Reality (code):** REST handlers decode via `readJSON` (`helpers.go:19-29`) using a plain `json.NewDecoder(r.Body)` with **no `http.MaxBytesReader` and no `io.LimitReader`**. Grep for `MaxBytesReader` across `internal/` returns only the MCP `LimitReader`; `git log -S MaxBytesReader` is empty. There is no global body-cap middleware (`middleware.go` has only CORS + logging).
- **Access:** Any `POST`/`PUT` REST endpoint with a JSON body.
- **Steps (to demonstrate absence):**
  ```bash
  base=localhost:8080
  python3 -c 'print("{\"password\":\"" + "A"*5000000 + "\"}")' > /tmp/huge.json   # ~5 MiB
  curl -s -o /dev/null -w "%{http_code}\n" -X POST $base/api/v1/auth/setup \
    --data-binary @/tmp/huge.json
  ```
- **Pass / observation:** The server accepts and decodes the full body (no `400` due to size; you'll get a normal `200/409/400-for-content` based on handler logic, not a size rejection). This confirms the cap is absent. **Record as a discrepancy.** A `400` may still occur from malformed JSON — distinguish "invalid JSON" (handler-level, `helpers.go:25`) from a true size cap (which does not exist).
- **Coverage:** D.
- **Pitfalls:** Run against the unauthenticated `setup`/`login` endpoints so you don't need a session. Note that a `400 invalid JSON` is NOT evidence of a body cap.

### Global session revocation on password change
- **Must (claimed by §2.8):** Changing the password invalidates existing session cookies (old cookie → `401`).
- **Reality (code):** `handleChangePassword` (`auth.go:138-178`) **only** re-hashes and stores `admin_password_hash`; it does **NOT** rotate `session_secret`. Sessions are validated purely by HMAC signature over a random token using the persistent `session_secret` key (`middleware.go:28-34`, `auth/session.go:31-51`) — the signing key is unchanged by a password change, so a previously issued cookie **still verifies and remains valid**. There is no session store / revocation list and no per-user "password changed at" check.
- **Access:** `POST /api/v1/auth/change-password`, requires auth, body `{"current_password","new_password"}` (`server.go:140`, `auth.go:138`). Dashboard: change-password form. New password must be ≥8 chars (`auth.go:151`).
- **Steps:**
  ```bash
  base=localhost:8080
  # 1) log in, capture cookie:
  C=$(curl -s -i -X POST $base/api/v1/auth/login -d '{"password":"correcthorse"}' \
      | awk -F'[=;]' '/nurproxy_session/{print $2}')
  # 2) confirm it works:
  curl -s -o /dev/null -w "before change: %{http_code}\n" $base/api/v1/providers -b "nurproxy_session=$C"
  # 3) change password using that session:
  curl -s -X POST $base/api/v1/auth/change-password -b "nurproxy_session=$C" \
      -d '{"current_password":"correcthorse","new_password":"newpassword1"}'
  # 4) is the OLD cookie still accepted?
  curl -s -o /dev/null -w "after change:  %{http_code}\n" $base/api/v1/providers -b "nurproxy_session=$C"
  ```
- **Pass (per §2.8 expectation):** step 4 returns `401`. **Per current code it will return `200`** — the old cookie is still valid. Record the actual result; if it is `200`, the "global session revocation" control is **not implemented** and §2.8 is a discrepancy. (The only thing that invalidates all sessions today is the `session_secret` changing, which happens only if the stored secret is missing/malformed and is regenerated on restart — `server.go:107-124`.)
- **Coverage:** D.
- **Pitfalls:** Do not confuse logout (clears the cookie client-side, `auth.go:181-191`) with revocation — logout does not invalidate the token server-side either. Test on a dry instance.

### Session-secret model (forge resistance)
- **Must:** Session cookies are signed with a **persistent, per-install 32-byte random HMAC key** stored under the `session_secret` setting (base64), generated once via `crypto.GenerateKey()` and reused across restarts (`server.go:99-124`). This replaced an earlier key derived from a public constant + version string, which let anyone forge a cookie (see the explanatory comment `server.go:99-106`). The key never leaves the box: `GET /api/v1/settings` **omits it entirely** (along with `admin_password_hash` and `admin_api_key`) — it is filtered out, not masked (`system.go:118-129`), and `PUT /api/v1/settings/session_secret` is rejected with `403` (`system.go:151-153`). If `crypto/rand` fails, the process `log.Fatal`s (`server.go:117-119`); if persistence fails, an ephemeral key is used and sessions reset on restart (`server.go:120-122`).
- **Access:** Internal; observable via cookie behaviour and the masked settings entry.
- **Steps:**
  ```bash
  base=localhost:8080
  # session_secret must be present but masked in the settings listing:
  curl -s $base/api/v1/settings -b "nurproxy_session=$C" | jq '.[] | select(.key=="session_secret")'
  # forged/garbage cookie must be rejected:
  curl -s -o /dev/null -w "forged cookie: %{http_code}\n" $base/api/v1/providers \
      -b "nurproxy_session=deadbeef.deadbeef"
  ```
- **Pass:** `session_secret` is **absent** from the `/settings` listing (filtered out, `system.go:121`) — never the raw base64 key; a forged/garbage cookie → `401` (`middleware.go:28-34` Verify fails → falls through to `writeError 401`). `PUT /api/v1/settings/session_secret` → `403`. After an orchestrator restart with the SAME DB, a previously issued valid cookie still works (key persisted). Unit coverage: `session_secret_test.go`.
- **Coverage:** D.
- **Pitfalls:** The key is removed from the listing, not masked — if the raw key (or any value) appears for `session_secret` in `/settings` that is a leak; record it. The same filter hides `admin_password_hash` and `admin_api_key`.

### Agent / admin token separation
- **Must:** An **agent** bearer token is accepted on agent-scoped routes but **rejected on admin routes** unless it also happens to match the admin API key (it never does — different prefix/storage).
  - `requireAuth` accepts: (1) a valid session cookie, (2) the admin API key via constant-time compare against setting `admin_api_key` (`middleware.go:38-45`), (3) **any** registered agent token (matched by `auth.HashToken` against stored `TokenHash`, `middleware.go:47-60`). NOTE: per the code, an agent token *is* accepted by `requireAuth` — admin REST routes are guarded by `requireAuth`, so a valid agent token currently **passes** admin routes too (actor recorded as `agent:<id>`, source `agent`). This is broader than "agent bearer on admin route → 401". Verify and record.
  - `requireAgentAuth` (`middleware.go:68-95`) accepts only a bearer that hashes to a known agent `TokenHash`; a session cookie or the admin API key is **rejected** here (no cookie path) → `401`.
- **Access:**
  - Admin routes (`requireAuth`): e.g. `GET /api/v1/providers`, `GET /api/v1/agents` (`server.go:146,161`).
  - Agent routes (`requireAgentAuth`): e.g. `POST /api/v1/agents/{id}/heartbeat`, `GET /api/v1/agents/{id}/stream` (`server.go:168,171`).
- **Prerequisites:** A registered agent and its plaintext token. Easiest via `make dev-sandbox` (it seeds adopted agents); or register one and keep the token you sent.
- **Steps:**
  ```bash
  base=localhost:8080; AGENT_TOKEN=np_ag_...; AGENT_ID=<id>
  # agent token on an AGENT route (its own heartbeat) — expect 2xx/handler result:
  curl -s -o /dev/null -w "agent->agent route: %{http_code}\n" \
      -X POST $base/api/v1/agents/$AGENT_ID/heartbeat \
      -H "Authorization: Bearer $AGENT_TOKEN" -d '{}'
  # admin API key on an AGENT route — expect 401 (no cookie/api-key path in requireAgentAuth):
  curl -s -o /dev/null -w "apikey->agent route: %{http_code}\n" \
      -X POST $base/api/v1/agents/$AGENT_ID/heartbeat \
      -H "Authorization: Bearer <admin_api_key>" -d '{}'
  # agent token on an ADMIN route:
  curl -s -o /dev/null -w "agent->admin route: %{http_code}\n" \
      $base/api/v1/providers -H "Authorization: Bearer $AGENT_TOKEN"
  ```
- **Pass:**
  - Agent token on its own agent route → handler result (`200`/`202`, not `401`).
  - Admin API key on an agent route → `401` (`requireAgentAuth` has no api-key path).
  - Agent token on an admin route → per current code, **`200`** (agent tokens are accepted by `requireAuth`, `middleware.go:47-60`). The §2.8 expectation "agent bearer on admin route → 401" is therefore **not** what the code does — **record this as a discrepancy / potential privilege issue.**
- **Coverage:** D.
- **Pitfalls:** `requireAgentAuth` looks the token up across ALL agents (`middleware.go:76-91`); it does not (here) scope to `{id}` — any valid agent token authenticates against any agent's heartbeat route. The per-op scoping to `{id}` exists only in specific handlers (e.g. admin-ops claim/ack). Note both behaviours.

### Secure cookie scheme — NOT IMPLEMENTED
- **Must (claimed by §2.8):** Set cookie `Secure` only when the request is HTTPS (`r.TLS != nil` or `X-Forwarded-Proto: https`), so plain-HTTP-by-IP dashboards keep working (this once locked out plain-HTTP dashboards).
- **Reality (code):** Both `Set-Cookie` calls (`auth.go:182-189` logout, `auth.go:193-206` setSessionCookie) set `HttpOnly: true` and `SameSite: http.SameSiteLaxMode` but **no `Secure` field** at all, and `setSessionCookie(w)` takes only the `ResponseWriter` — it has no access to `*http.Request`, so it cannot inspect `r.TLS`/`X-Forwarded-Proto`. There is no conditional-Secure logic anywhere in the cookie path (`git log -S X-Forwarded-Proto` shows only nginx/apache config-rendering and agent-stream code, not the cookie).
- **Effect:** Cookie is **never** marked `Secure` ⇒ plain-HTTP-by-IP works (the regression that "once locked out plain-HTTP dashboards" cannot recur because Secure is never set), but a cookie over HTTPS is also not hardened with `Secure`. The *outcome* §2.8 cares about (plain HTTP keeps working) holds, but via "never Secure", not via the described conditional scheme.
- **Access:** Login/setup set the cookie; logout clears it.
- **Steps:**
  ```bash
  base=localhost:8080
  curl -s -i -X POST $base/api/v1/auth/login -d '{"password":"correcthorse"}' \
      | grep -i 'set-cookie'
  ```
- **Pass / observation:** The `Set-Cookie` line shows `HttpOnly` and `SameSite=Lax` but **no `Secure`** attribute. This confirms plain-HTTP still works. **The conditional-Secure scheme described in §2.8 is not present — record it.** If you reach the dashboard over plain HTTP by IP and log in successfully, that is the regression guard passing (no lockout).
- **Coverage:** D.
- **Pitfalls:** Don't expect `Secure` to appear over HTTPS — it won't in this code. The regression to guard against is the *opposite*: a `Secure` cookie over plain HTTP would silently never be sent back, locking out the dashboard. Confirm login over plain HTTP by IP works end to end.

### clientIP anti-spoof
- **Must:** Rate-limit keys derive from the transport-level `RemoteAddr` (host part), **never** from the client-controllable `X-Forwarded-For` header — otherwise an attacker rotates XFF to dodge per-IP lockout.
  - REST: `clientIP` uses `net.SplitHostPort(r.RemoteAddr)` only (`helpers.go:43-52`), with the explanatory comment at `helpers.go:43-46`.
  - MCP: `mcpClientIP` is identical, same rationale (`mcp/server.go:70-77`).
- **Access:** Internal; observable via the login limiter ignoring XFF.
- **Steps:**
  ```bash
  base=localhost:8080
  # 5 fails, each with a DIFFERENT spoofed XFF — must STILL lock out (keyed on RemoteAddr):
  for ip in 1.1.1.1 2.2.2.2 3.3.3.3 4.4.4.4 5.5.5.5; do
    curl -s -o /dev/null -X POST $base/api/v1/auth/login \
        -H "X-Forwarded-For: $ip" -d '{"password":"wrong"}'
  done
  curl -s -D - -o /dev/null -X POST $base/api/v1/auth/login \
      -H "X-Forwarded-For: 6.6.6.6" -d '{"password":"wrong"}' | grep -i 'HTTP/'
  ```
- **Pass:** The 6th attempt is `429` despite each request carrying a distinct `X-Forwarded-For` — proves the limiter keyed on the shared `RemoteAddr` (loopback) and ignored XFF.
- **Coverage:** D.
- **Pitfalls:** Operators terminating TLS at a trusted reverse proxy accept that the limiter keys on the *proxy's* address (documented tradeoff, `helpers.go:44-46`) — i.e. behind a shared proxy all clients share one lockout key. Do not "fix" this by trusting XFF.

### Crypto parameters
- **Must:** All exactly as in source.
  - **bcrypt cost 12** for the admin password (`auth/password.go:5` `bcryptCost = 12`, used in `HashPassword`/`CheckPassword`).
  - **AES-256-GCM** for secrets at rest: 32-byte key (`crypto/crypto.go:14` `keySize = 32`), random nonce prepended to ciphertext (`crypto.go:79-85`); used for provider configs and cert private keys (package doc `crypto.go:1`). Decrypt rejects ciphertext shorter than the nonce (`crypto.go:101-103`).
  - **Token prefixes:** agent tokens `np_ag_`, admin API keys `np_ak_`, both 32 random bytes hex; session tokens 32 random bytes hex, no prefix (`auth/token.go:11-27`). Tokens are stored only as SHA-256 hex digests (`HashToken`, `auth/token.go:37-41`); the plaintext is shown once at generation.
  - **Sessions:** HMAC-SHA256 over the token, `token.signature` format, base64url signature, compared with `hmac.Equal` (constant-time) (`auth/session.go:23-51`).
  - **Constant-time compares:** admin API key (`middleware.go:40` `subtle.ConstantTimeCompare`), MCP key (`mcp/server.go:67`), session signature (`hmac.Equal`).
  - **Credential-store write guard:** the generic `PUT /api/v1/settings/{key}` refuses the three sensitive keys with `403` — `admin_password_hash` ("cannot update password via settings endpoint"), `admin_api_key` ("use the /api/v1/api-key endpoint"), and `session_secret` ("managed internally") (`system.go:143-154`). The password is changeable only via `change-password`, the API key only via the `/api-key` endpoints.
- **Access:** Internal; partly observable.
- **Steps:**
  ```bash
  base=localhost:8080
  # token prefixes — agent token starts np_ag_ (from a register payload you control),
  # admin API key starts np_ak_:
  curl -s -X POST $base/api/v1/api-key -b "nurproxy_session=$C" | jq -r '.key // .api_key' | head -c 6; echo
  # password is bcrypt cost 12 — inspect the stored hash prefix ($2a$12$ / $2b$12$):
  # (read it from settings if exposed, or from the DB on a dry instance)
  ```
  Source-level verification (no run needed): open the files above and confirm the constants.
- **Pass:** Generated admin API key begins `np_ak_`; agent tokens begin `np_ag_`; stored password hash uses `$2?$12$` (cost 12); these match the constants in source. Unit coverage exists in `internal/shared/auth/auth_test.go` and `internal/shared/crypto/crypto_test.go` — `make test` passes.
- **Coverage:** D.
- **Pitfalls:** The plaintext admin API key is returned **only once**, by `POST /api/v1/api-key` (`{"api_key":"np_ak_..."}`, `201`, `system.go:86-98`). `GET /api/v1/api-key` does **NOT** return the key — only `{"exists":true,"masked":"np_a…last4"}` (`system.go:69-82`); the full key is never re-derivable from the stored value. `DELETE /api/v1/api-key` revokes it (sets the setting to `""`, `system.go:100-108`). Never log plaintext tokens.

## Acceptance checklist

### Dry (every RC)
- [ ] Login lockout: 5 fails → 6th is `429` + `Retry-After` ≥900 (note 901 off-by-one) — restart to reset.
- [ ] Login limiter ignores `X-Forwarded-For` (5 spoofed XFF still lock out the shared RemoteAddr).
- [ ] MCP disabled by default returns `404`; when enabled, 10 bad bearers → 11th `429`; constant-time key compare.
- [ ] MCP body read capped at 1 MiB (`1<<20`) — oversized body truncated → parse error.
- [ ] Admin API key on an agent route (`requireAgentAuth`) → `401`.
- [ ] Agent token on its own agent route → handler result (not `401`).
- [ ] Session cookie is `HttpOnly`, `SameSite=Lax`, **no `Secure`** — plain-HTTP-by-IP login works.
- [ ] Forged/garbage session cookie → `401`; valid cookie survives an orchestrator restart (persistent `session_secret`).
- [ ] `session_secret` is **absent** (filtered out, not masked) in `/api/v1/settings`; `PUT /settings/session_secret` → `403`.
- [ ] Crypto constants confirmed in source: bcrypt 12, AES-256 (32B), `np_ag_`/`np_ak_` prefixes, HMAC-SHA256 sessions, `subtle.ConstantTimeCompare`/`hmac.Equal`.

### Discrepancies to FILE (claimed by RELEASE-QA §2.8 but NOT in current code)
- [ ] Per-IP `/agents/register` rate limit — absent (`agents.go:51` has no limiter). Register returns `201`/`409`, never `429`.
- [ ] REST request body cap (>4 MiB → 400) — absent (`helpers.go` plain `json.NewDecoder`, no `MaxBytesReader`).
- [ ] Global session revocation on password change — absent (`auth.go:138-178` does not rotate `session_secret`; old cookie stays valid).
- [ ] Conditional `Secure` cookie scheme (`r.TLS`/`X-Forwarded-Proto`) — absent (`auth.go` cookies set no `Secure` and `setSessionCookie` has no `*http.Request`).
- [ ] Agent tokens are accepted by `requireAuth` (`middleware.go:47-60`), so an agent bearer reaches admin REST routes (`200`), contrary to "agent bearer on admin route → 401".

### Real run (before final)
- [ ] Over real HTTPS, confirm the dashboard login + cookie round-trips (and decide whether the missing `Secure` flag is acceptable for the release, given the §2.8 discrepancy).

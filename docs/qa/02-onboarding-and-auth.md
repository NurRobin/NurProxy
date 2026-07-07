# Onboarding, Authentication & Sessions
> **Scope:** first-run setup (the dashboard setup wizard + CLI bootstrap) and every authentication path — session cookie, admin API key, agent token — plus password change and API-key management.
> **Code:** `internal/orchestrator/api/auth.go`, `internal/orchestrator/api/middleware.go`, `internal/orchestrator/api/system.go`, `internal/orchestrator/api/server.go`, `internal/shared/auth/{session,password,token}.go`, `internal/shared/ratelimit/ratelimit.go`, `cmd/nurproxy/cli.go`, `cmd/nurproxy/cli_commands.go`, `web/src/pages/{Login,SetupWizard,Settings}.tsx`, `web/src/lib/{api,clipboard}.ts`.
> **Coverage legend:** D = coverable dry, R = needs a real run.

## Prerequisites
- Both binaries built: `make build-all` (produces `./nurproxy` + `./nurproxy-agent`).
- A running orchestrator. Easiest is a dry instance with an empty/fresh DB so you can exercise *first-run* setup:
  ```bash
  # fresh, isolated dry orchestrator on :8080 with a throwaway data dir
  NP_DRY_RUN=true NP_DATA_DIR=$(mktemp -d) ./nurproxy &
  export NP_API_URL=http://localhost:8080
  ```
  Note `make dev-sandbox` *pre-seeds* an admin password + API key, so it is **not** suitable for testing first-run `auth/setup` / setup-wizard from scratch — use a hand-booted dry instance with a clean data dir for those.
- `curl` and `jq` available for the REST steps.
- For the dashboard steps: the web bundle served by the orchestrator (open `http://localhost:8080/`).
- An admin password length of **at least 8 characters** is enforced server-side (`auth.go:60`, `auth.go:151`) and client-side (`Login.tsx:28`, `Settings.tsx:167`). Pick e.g. `hunter2!` (8 chars).

## Features covered
- [ ] Setup wizard flow: provider test → zone batch-create → ACME contact email → agent adopt → done (`SetupWizard.tsx`).
- [ ] `GET /api/v1/auth/status` — setup-required / authenticated reporting.
- [ ] `POST /api/v1/auth/setup` — first-run admin password (min length, single-use / 409 once configured).
- [ ] `POST /api/v1/auth/login` — password login, sets session cookie, per-IP lockout.
- [ ] `POST /api/v1/auth/logout` — clears session cookie.
- [ ] `POST /api/v1/auth/change-password` — current+new password, min length, session revocation effect.
- [ ] Session cookie scheme: `nurproxy_session`, HttpOnly, SameSite=Lax, HMAC-signed, lifetime from `session_expiry_hours`.
- [ ] Admin API key auth (`Bearer np_ak_…`) and which endpoints accept it.
- [ ] Agent token auth (`Bearer np_ag_…`) and the admin/agent route separation.
- [ ] API key management: `GET`/`POST`/`DELETE /api/v1/api-key` (plaintext shown once, masked otherwise).
- [ ] CLI `nurproxy apikey show|create|revoke`.
- [ ] CLI `nurproxy auth setup|status`.
- [ ] CLI auth flags `-url`/`-key`/`-password`/`-json` and env `NP_API_URL`/`NP_API_KEY`/`NP_API_PASSWORD`.
- [ ] Audit source tagging (`ui`/`api`/`agent`) derived from the auth path.

## Tests

### Setup wizard (dashboard first-run flow)
- **Must:** on a fresh install the dashboard lands on the setup wizard with four steps — `provider` → `tls` → `agent` → `done` (`SetupWizard.tsx:22-27`). Each step is optional/skippable; finishing persists `setup_complete=true` (`SetupWizard.tsx:176`).
  - Step 1 (provider): enter a Cloudflare API token → "Connect" calls `POST /api/v1/providers/test`; on `valid` it lists zones; selecting zones + "Add" calls `POST /api/v1/providers` then `POST /api/v1/zones/batch` (`SetupWizard.tsx:98-122`).
  - Step 2 (tls): an ACME contact email saved via `PUT /api/v1/settings/acme_email` (empty allowed — issuance just stays off until set) (`SetupWizard.tsx:131-138`).
  - Step 3 (agent): shows the agent install command for the entered orchestrator URL + FQDN, polls `GET /api/v1/agents` every 3 s, and lets you adopt a pending agent via `PUT /api/v1/agents/{id}/adopt` with `name`/`zone_ids`/`dns_mode` (the wizard radio offers `static` or `ddns`, default `static` — `SetupWizard.tsx:64,455-461`) (`SetupWizard.tsx:75-91,154-164`).
  - Step 4 (done): summary + "Go to dashboard" which writes `setup_complete=true`.
- **Access:**
  - Dashboard: the wizard page itself (auto-shown when setup not complete). Fields per step as above.
  - The wizard is pure UI orchestration over existing REST endpoints — there is no dedicated `/setup-wizard` REST call. (Note: the **admin password** is NOT set in the wizard; it is set on the Login page when `setup_required` is true — see the auth/setup test.)
- **Prerequisites:** a fresh DB where neither admin password nor `setup_complete` is set. The provider step needs the dry provider mock (any dummy token validates dry — see CLAUDE.md "Provider setup … is mocked too"); for a real token use a real zone (R).
- **Steps (dry, drive the underlying calls directly to prove the flow):**
  ```bash
  # must be authenticated first (set the admin password — see auth/setup test), then:
  KEY=... # an admin API key, or use -password via the CLI
  curl -s -X POST $NP_API_URL/api/v1/providers/test -H "Authorization: Bearer $KEY" \
    -H 'Content-Type: application/json' -d '{"type":"cloudflare","config":{"api_token":"dummy"}}' | jq .
  # → {"valid":true,"zones":[...]} in dry mode
  ```
- **Pass:** wizard advances step-by-step; provider test returns `valid:true` (dry); zones created; `acme_email` persisted; a started dry agent appears as `pending` within ~3 s and can be adopted; "Go to dashboard" leaves you logged into the main app and the wizard does not reappear on reload.
- **Coverage:** D (full flow with the dry provider + dry agent). R only if you want a real Cloudflare token / real zone listing.
- **Pitfalls:** the wizard does **not** create the admin password — a brand-new browser hits the Login page first (which switches to "create password" mode when `auth/status` says `setup_required:true`). Adopt **requires a JSON body** server-side; the wizard always sends one, but if you drive `/adopt` by hand an empty body is a 400 (see file 01 / RELEASE-QA §2.1). The clipboard copy of the install command falls back to `execCommand('copy')` on insecure (plain-HTTP-by-IP) origins where `navigator.clipboard` is undefined — the wizard calls `copyText` (`SetupWizard.tsx:186-193`), whose fallback lives in `web/src/lib/clipboard.ts:10-34`.

### `GET /api/v1/auth/status`
- **Must:** reports `{setup_required, authenticated}`. `setup_required:true` when no `admin_password_hash` setting exists (`auth.go:16-23`); otherwise `false`, and `authenticated` is `true` only if the request carries a valid `nurproxy_session` cookie (`auth.go:26-36`). No auth required to call it (`server.go:136`).
- **Access:**
  - Dashboard: called on Login page mount (`Login.tsx:21`).
  - REST: `GET /api/v1/auth/status`.
  - CLI: `nurproxy auth status` (unauthenticated GET, `cli_commands.go:502-508`).
- **Steps:**
  ```bash
  curl -s $NP_API_URL/api/v1/auth/status | jq .       # fresh: {"setup_required":true,"authenticated":false}
  ./nurproxy auth status -url $NP_API_URL
  ```
- **Pass:** fresh instance → `setup_required:true`. After setup, called without a cookie → `setup_required:false, authenticated:false`. With a valid session cookie → `authenticated:true`.
- **Coverage:** D.
- **Pitfalls:** `authenticated` only ever reflects the **session cookie** — passing a Bearer API key to `auth/status` will still report `authenticated:false` (the endpoint deliberately only checks the cookie).

### `POST /api/v1/auth/setup` (first-run admin password)
- **Must:** sets `admin_password_hash` (bcrypt, cost 12 — `password.go:5,9`) **only** when none exists; if one exists returns **409** `admin password already configured` (`auth.go:43-47`). Body `{"password": "..."}`; empty → 400 `password is required`; `< 8` chars → 400 `password must be at least 8 characters` (`auth.go:56-63`). On success it sets a session cookie (`auth.go:77`) and writes an audit entry with `source=ui`, `action=setup` (`auth.go:80-89`). Returns `{"message":"setup complete"}`.
- **Access:**
  - Dashboard: Login page "create password" mode (when `setup_required`), needs matching confirm field ≥8 (`Login.tsx:27-33`).
  - REST: `POST /api/v1/auth/setup` body `{"password":"..."}`.
  - CLI: `nurproxy auth setup --password <pw>` (or `NP_API_PASSWORD`); bypasses auth (`cli_commands.go:488-500`).
- **Steps:**
  ```bash
  curl -si -X POST $NP_API_URL/api/v1/auth/setup -H 'Content-Type: application/json' -d '{"password":"short"}'   # 400, min length
  curl -si -X POST $NP_API_URL/api/v1/auth/setup -H 'Content-Type: application/json' -d '{"password":"hunter2!"}' # 200 + Set-Cookie
  curl -si -X POST $NP_API_URL/api/v1/auth/setup -H 'Content-Type: application/json' -d '{"password":"hunter2!"}' # 409 second time
  # via CLI on a fresh instance:
  ./nurproxy auth setup --password 'hunter2!' -url $NP_API_URL
  ```
- **Pass:** first call 200 with a `Set-Cookie: nurproxy_session=...`; `<8` chars 400; second call 409. Audit log shows `setup` with `source=ui`.
- **Coverage:** D.
- **Pitfalls:** the audit `source` is hard-coded `ui` regardless of caller (CLI bootstrap also logs as `ui`) — that is intentional (`auth.go:79-86`). The CLI hint after success points you to `nurproxy apikey create --password <pw>` (`cli_commands.go:500`).

### `POST /api/v1/auth/login`
- **Must:** body `{"password":"..."}`; empty → 400; wrong password → 401 `invalid credentials`; correct → 200 `{"message":"logged in"}` + `Set-Cookie: nurproxy_session`. Failed attempts are rate-limited **per client IP**: limiter is `New(5, 15*time.Minute, 15*time.Minute)` — `New(max, window, lockout)` (`server.go:92`, `internal/shared/ratelimit/ratelimit.go:40`). The limiter is checked *before* the password is verified, and a 5th wrong password arms a 15m lockout, so the **6th** attempt is the first to be rejected with **429** `too many failed login attempts; try again later` plus a `Retry-After` header set to `int(retryAfter.Seconds())+1` (i.e. truncated-seconds + 1, ≈901 right after the lockout arms) (`auth.go:99-103`). A successful login resets the IP's counter (`auth.go:130`).
- **Access:**
  - Dashboard: Login page sign-in (`Login.tsx:34`).
  - REST: `POST /api/v1/auth/login`.
  - CLI: implicitly via `-password`/`NP_API_PASSWORD` — `ensureAuth` logs in once and caches the cookie (`cli.go:85-118`).
- **Steps:**
  ```bash
  curl -si -X POST $NP_API_URL/api/v1/auth/login -H 'Content-Type: application/json' -d '{"password":"wrong"}'    # 401
  curl -si -X POST $NP_API_URL/api/v1/auth/login -H 'Content-Type: application/json' -d '{"password":"hunter2!"}' # 200 + Set-Cookie
  # lockout: fire 6 wrong attempts, expect a 429 on the 6th
  for i in $(seq 1 6); do curl -s -o /dev/null -w "%{http_code} " -X POST $NP_API_URL/api/v1/auth/login \
    -H 'Content-Type: application/json' -d '{"password":"wrong"}'; done; echo
  ```
- **Pass:** wrong → 401; correct → 200 + cookie; the 6th wrong attempt → 429 with a `Retry-After` header (≈901).
- **Coverage:** D.
- **Pitfalls:** run lockout on a **dry/throwaway instance** — it locks that client IP's login for **15 min** (RELEASE-QA §2.8). The limiter keys on `clientIP(r)`, so all of localhost shares one bucket.

### `POST /api/v1/auth/logout`
- **Must:** clears the cookie by sending `nurproxy_session=""` with `MaxAge:-1`, `HttpOnly`, `SameSite=Lax` (`auth.go:181-190`). Always 200 `{"message":"logged out"}` (no auth gate on the route — `server.go:139`).
- **Access:** Dashboard logout action (`api.logout`, `api.ts:58`); REST `POST /api/v1/auth/logout`.
- **Steps:**
  ```bash
  curl -si -X POST $NP_API_URL/api/v1/auth/logout | grep -i set-cookie   # nurproxy_session=; Max-Age=0
  ```
- **Pass:** response sets an expiring/empty `nurproxy_session` cookie; a subsequent protected request with the cleared cookie is 401.
- **Coverage:** D.
- **Pitfalls:** logout is **client-side cookie clearing only** — there is no server-side session blacklist. The signed token stays valid until expiry; true global revocation comes from rotating the password (see below).

### `POST /api/v1/auth/change-password`
- **Must:** **requires auth** (`requireAuth`, `server.go:140`). Body `{"current_password","new_password"}`; either empty → 400; `new_password < 8` → 400 `new password must be at least 8 characters`; wrong current → 401 `current password is incorrect`; success → 200 `{"message":"password changed"}` and writes audit `action=change_password` (`auth.go:138-178`).
- **Access:**
  - Dashboard: Settings page "Change password" (current + new, client-side min 8 — `Settings.tsx:167,171,296`).
  - REST: `POST /api/v1/auth/change-password`.
  - CLI: none (no `nurproxy` subcommand wraps this).
- **Steps:**
  ```bash
  curl -si -X POST $NP_API_URL/api/v1/auth/change-password -H "Authorization: Bearer $KEY" \
    -H 'Content-Type: application/json' -d '{"current_password":"hunter2!","new_password":"newpass12"}'
  ```
- **Pass:** wrong current → 401; short new → 400; valid → 200. Old password no longer logs in; new one does.
- **Coverage:** D.
- **Pitfalls — session revocation:** changing the password does NOT touch the session-signing HMAC secret, so existing **cookies remain valid** by signature. RELEASE-QA §2.8 lists "change password → old cookie → 401" as a regression guard; verify this behaviour explicitly on the candidate build and flag it **UNVERIFIED** if an old cookie still passes `requireAuth` after a password change — the code in `auth.go`/`middleware.go` shows no cookie invalidation on password change.

### Session cookie scheme (`nurproxy_session`)
- **Must:** cookie name `nurproxy_session`; value is `token.signature` where signature is base64url HMAC-SHA256 of a 32-byte random token (`session.go:23-27`, `token.go:21-27`). Attributes set by `setSessionCookie` (`auth.go:193-206`): `Path=/`, `HttpOnly=true`, `SameSite=Lax`, `MaxAge`=session seconds, `Expires`=now+duration. Lifetime from `session_expiry_hours` setting; default **168h (7 days)**, ignoring non-numeric or `<=0` values (`auth.go:208-221`). The HMAC key is a per-install 32-byte secret persisted in the `session_secret` setting, surviving restarts (`server.go:99-124`).
- **Access:** set on `auth/setup` and `auth/login`; consumed by `requireAuth` step 1 (`middleware.go:28-34`).
- **Steps:**
  ```bash
  curl -si -X POST $NP_API_URL/api/v1/auth/login -H 'Content-Type: application/json' -d '{"password":"hunter2!"}' \
    | grep -i 'set-cookie'   # inspect HttpOnly; SameSite=Lax; Max-Age; Expires
  # change session_expiry_hours then log in again and re-check Max-Age:
  curl -s -X PUT $NP_API_URL/api/v1/settings/session_expiry_hours -H "Authorization: Bearer $KEY" \
    -H 'Content-Type: application/json' -d '{"value":"1"}'
  ```
- **Pass:** `Set-Cookie` shows `HttpOnly`, `SameSite=Lax`, and a `Max-Age`/`Expires` matching the configured hours (default 604800 s = 7 d; 1 → 3600 s). A tampered signature → next request 401.
- **Coverage:** D.
- **Pitfalls:** the cookie has **no `Secure` attribute** in the current code (`setSessionCookie`, `auth.go:193-206`, sets only HttpOnly/SameSite/MaxAge/Expires). RELEASE-QA §2.8 describes a conditional-`Secure`-on-HTTPS scheme — that note is **stale relative to this code**; do not expect a `Secure` flag. CORS deliberately does **not** send `Access-Control-Allow-Credentials`, so the cookie only works same-origin (`middleware.go:97-103`). If `session_secret` can't be persisted, an ephemeral key is used and all sessions reset on restart (`server.go:120-122`).

### Admin API key auth (`Bearer np_ak_…`)
- **Must:** `requireAuth` step 2 accepts a `Authorization: Bearer <key>` that constant-time-equals the `admin_api_key` setting (`middleware.go:38-45`); the request is tagged actor `api_key`, source `api`. Accepted on **all** `requireAuth`-guarded endpoints (providers, zones, agents admin routes, servers, domains, artifacts, settings, audit-log, api-key) — see `server.go:146-227`. **Not** accepted by `auth/status` (cookie-only) or the agent-only routes (`requireAgentAuth`).
- **Access:** REST via the `Authorization` header; CLI via `-key`/`NP_API_KEY` (`cli.go:66,143-144`).
- **Steps:**
  ```bash
  curl -s $NP_API_URL/api/v1/providers -H "Authorization: Bearer $KEY" | jq .       # 200
  curl -s -o /dev/null -w "%{http_code}\n" $NP_API_URL/api/v1/providers              # 401, no creds
  ```
- **Pass:** valid key → 200; missing/wrong → 401 `authentication required`. Audit entries for key-driven mutations show `source=api`.
- **Coverage:** D.
- **Pitfalls:** comparison is constant-time but only against a single stored key — there is exactly **one** admin API key at a time; regenerating overwrites the prior one. An empty/unset `admin_api_key` setting never matches (`middleware.go:40`).

### Agent token auth (`Bearer np_ag_…`) and admin/agent separation
- **Must:** an agent token is `np_ag_` + 32 hex bytes (`token.go:11,29-34`); only its **SHA-256 hash** is stored (`agent.TokenHash`, `token.go:38-41`). `requireAuth` step 3 falls through to match a Bearer token's hash against any adopted agent and tags actor `agent:<id>`, source `agent` (`middleware.go:47-60`). `requireAgentAuth` (the agent-only routes: heartbeat, stream, routes/ack, artifacts/adopt, logs/chunk, admin-ops claim/ack — `server.go:168-190`) requires a Bearer agent token and 401s anything else (`middleware.go:68-95`).
- **Access:** agent uses its token automatically; for QA you pass it as a Bearer header.
- **Steps (separation regression-guard):**
  ```bash
  AG=np_ag_...   # a real adopted agent's token (from a dry agent's data dir)
  # agent token on an ADMIN route — note both schemes are tried; an agent token DOES satisfy requireAuth:
  curl -s -o /dev/null -w "%{http_code}\n" $NP_API_URL/api/v1/providers -H "Authorization: Bearer $AG"
  # admin/agent route check per RELEASE-QA §2.8: agent bearer on its own agent route → 200
  ```
- **Pass:** `requireAgentAuth` routes reject a non-agent Bearer (e.g. the admin API key) with 401 `invalid agent token`; accept the matching agent token with 200. Audit shows `source=agent`, actor `agent:<id>`.
- **Coverage:** D (multi-agent dry stack provides real tokens).
- **Pitfalls:** note an **agent token also passes `requireAuth`** (step 3 of `middleware.go`), so an agent token is accepted on admin-read routes too — the separation that is strictly enforced is the reverse: admin/cookie creds are **rejected** on `requireAgentAuth` routes. RELEASE-QA §2.8's "agent bearer on an admin route → 401" claim is **inconsistent with this code path** — verify on the candidate and report the actual status code.

### API key management — `GET`/`POST`/`DELETE /api/v1/api-key` + `nurproxy apikey`
- **Must:**
  - `GET /api/v1/api-key`: never returns the key; `{"exists":false}` if unset, else `{"exists":true,"masked":"np_a…XXXX"}` (first 4 + `…` + last 4 when `len>8`) (`system.go:69-82`).
  - `POST /api/v1/api-key`: generates/regenerates and returns plaintext **once**: `201 {"api_key":"np_ak_..."}` (`system.go:86-98`); audit `generate_api_key`.
  - `DELETE /api/v1/api-key`: clears the setting, `200 {"message":"API key revoked"}` (`system.go:101-108`); audit `revoke_api_key`.
  - The key cannot be set via the settings endpoint — `PUT /api/v1/settings/admin_api_key` → **403** (`system.go:147-149`); and `admin_api_key`/`admin_password_hash`/`session_secret` are filtered out of `GET /api/v1/settings` (`system.go:121-123`).
- **Access:**
  - Dashboard: Settings → "Admin API key" section — generate (shows plaintext once, then masked) / revoke (handlers `Settings.tsx:181-195`, UI `Settings.tsx:300-314`; `api.ts:174-176`).
  - REST: the three verbs above.
  - CLI: `nurproxy apikey show` (`GET`), `create` (`POST`, prints "API key (shown once): …"), `revoke` (`DELETE`) — `cli_commands.go:451-481`.
- **Steps:**
  ```bash
  ./nurproxy apikey create --password 'hunter2!' -url $NP_API_URL   # prints np_ak_... once
  ./nurproxy apikey show -key $KEY -url $NP_API_URL                 # {"exists":true,"masked":"np_a…abcd"}
  curl -s -X PUT $NP_API_URL/api/v1/settings/admin_api_key -H "Authorization: Bearer $KEY" \
    -H 'Content-Type: application/json' -d '{"value":"x"}'          # 403
  ./nurproxy apikey revoke -key $KEY -url $NP_API_URL
  ```
- **Pass:** `create` returns the plaintext exactly once; `show` only ever returns the masked form; `revoke` makes `show` report `exists:false` and the old key 401s on protected routes; the settings endpoint refuses `admin_api_key` with 403.
- **Coverage:** D.
- **Pitfalls:** `apikey create` needs admin creds (`--password`/`NP_API_PASSWORD` or an existing `--key`); on a fresh box run `auth setup` first. Regenerating **invalidates** the previous key immediately (single stored value). API keys used in QA are revocable — generate, use, `DELETE` (RELEASE-QA "API keys" note).

### CLI auth flags & env vars
- **Must:** every subcommand shares four flags via `registerClientFlags` (`cli.go:62-69`): `-url` (default `NP_API_URL` or `http://localhost:8080`), `-key` (default `NP_API_KEY`), `-password` (default `NP_API_PASSWORD`), `-json` (raw JSON output). `ensureAuth` uses the API key directly if set, else logs in once with the password and caches the session cookie; with neither it errors `no credentials: set NP_API_KEY (or --key), or NP_API_PASSWORD (or --password)` (`cli.go:85-93`). `auth setup`/`auth status` bypass auth entirely (`cli_commands.go:488,502`).
- **Access:** CLI only.
- **Steps:**
  ```bash
  ./nurproxy provider list -url $NP_API_URL                 # → "no credentials" error
  ./nurproxy provider list -key $KEY -url $NP_API_URL        # → table
  NP_API_KEY=$KEY NP_API_URL=$NP_API_URL ./nurproxy provider list -json   # → raw JSON
  NP_API_PASSWORD='hunter2!' ./nurproxy zone list -url $NP_API_URL         # → logs in, then lists
  ```
- **Pass:** no-creds errors with the exact message; `-key` and `-password` both authenticate; `-json` emits raw JSON (no table); env vars are honoured as flag defaults.
- **Coverage:** D.
- **Pitfalls:** flag value beats env (flag default *is* the env value, but an explicit flag overrides). `-url` is right-trimmed of trailing `/` (`cli.go:74`). When using `-password`, the CLI hits `/auth/login` and must find a `nurproxy_session` cookie in the response or it errors `login succeeded but no session cookie returned` (`cli.go:111-117`).

### Audit source tagging
- **Must:** the auth middleware stamps the request context with the source: cookie → `ui`, admin API key → `api`, agent token → `agent` (`middleware.go:31,42,55`); `system` is the reconciler, `mcp` is MCP, `dryrun` tags simulated DNS/ACME calls in sandbox mode. The full enum lives in `models.AuditSource*` (`models/models.go:400-405`). `s.audit` derives the source from the request context for mutating endpoints (`server.go:232-235`); endpoints without the auth middleware use `auditAs` with an explicit source (`server.go:240`). Setup is force-tagged `ui` regardless of caller (`auth.go:85`).
- **Access:** `GET /api/v1/audit-log?source=ui|api|mcp|agent|system|dryrun` (filter — `system.go:52-54`), `requireAuth`-guarded (`server.go:222`).
- **Steps:**
  ```bash
  # do one mutation via API key and one via cookie, then:
  curl -s "$NP_API_URL/api/v1/audit-log?source=api" -H "Authorization: Bearer $KEY" | jq '.entries[].source' | sort -u
  ```
- **Pass:** an API-key-driven mutation shows `source=api`; a dashboard (cookie) mutation shows `source=ui`; filtering by `source` returns only matching entries.
- **Coverage:** D.
- **Pitfalls:** the source reflects the *auth path used*, not the tool name — a CLI run with `-key` logs as `api`, a CLI run with `-password` logs as `ui` (it rides a session cookie).

## Acceptance checklist

### Dry (every RC)
- [ ] Fresh instance: `auth/status` → `setup_required:true`; `auth/setup` sets the password (min 8 enforced; 409 on second call); cookie issued.
- [ ] Setup wizard walks provider(dry)→zones→acme_email→adopt(dry agent)→done; `setup_complete=true` persisted.
- [ ] Login: wrong→401, right→200+cookie; 6 wrong → 429 + `Retry-After` (on a throwaway instance only).
- [ ] Logout clears the cookie; cleared cookie → 401 on a protected route.
- [ ] Change-password: short→400, wrong-current→401, valid→200; old password rejected, new accepted. Verify whether an old cookie is invalidated (RELEASE-QA §2.8 regression guard) and record the result.
- [ ] Cookie attributes: `HttpOnly`, `SameSite=Lax`, `Max-Age` follows `session_expiry_hours` (default 604800). Confirm there is **no** `Secure` flag (matches current code).
- [ ] API key: `POST` returns plaintext once; `GET` masked only; `DELETE` revokes; `PUT /settings/admin_api_key`→403; key absent from `GET /settings`.
- [ ] CLI: `auth setup`/`auth status`; `apikey show|create|revoke`; `-url/-key/-password/-json` + `NP_API_*` env all behave; no-creds error message exact.
- [ ] Auth scheme matrix: cookie + admin key both pass `requireAuth`; admin key / cookie **rejected** on a `requireAgentAuth` route (401); agent token accepted on its agent route. Record the actual status when an agent token hits an admin route.
- [ ] Audit source tagging: `ui` vs `api` vs `agent` correct for each path; `?source=` filter works.

### Real run (before final)
- [ ] Setup wizard against a **real Cloudflare token**: provider test lists real zones; batch-create persists them.
- [ ] First-run from a real browser over the deployed origin (same-origin cookie works; confirm no cross-origin credential need).
- [ ] Adopt a **real agent** through the wizard (real `np_ag_` token issued, heartbeat begins).

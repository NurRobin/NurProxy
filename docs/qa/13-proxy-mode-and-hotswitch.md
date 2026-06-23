# Proxy Modes & Hot-Switch (admin-ops)

> **Scope:** switching an agent's live reverse-proxy backend between built-in (bundled Caddy) and existing (host nginx/apache/caddy) without a process restart, via a one-time-confirmation-code admin-op flow (§19).
> **Code:** `internal/orchestrator/api/admin_ops.go`, `internal/orchestrator/db/admin_ops.go`, `internal/orchestrator/db/confirmation_code.go`, `internal/agent/proxy/holder.go`, `internal/agent/api/api.go` (`handleReconfigure`), `cmd/nurproxy-agent/apply.go`, `internal/agent/config/persist.go`, `internal/shared/models/models.go` (`AgentAdminOp`, `SetProxyModePayload`, `AdminOp*`), route table in `internal/orchestrator/api/server.go:186-190`.
> **Coverage legend:** D = coverable dry, R = needs a real run.

## Prerequisites
- Both binaries built: `make build-all` (orchestrator `./nurproxy`, agent `./nurproxy-agent`).
- A control plane up with at least one adopted agent. Fastest path: `make dev-sandbox` (orchestrator + 1 dry agent, seeded). For multi-agent: `make dev-sandbox AGENTS=3`.
- An admin session cookie or API key for the orchestrator REST calls (the prepare/list/cancel endpoints are `requireAuth`). The sandbox launcher prints how to reach the dashboard/API.
- For the **claim/ack** calls you need an **agent token + agent id** (those endpoints are `requireAgentAuth`, scoped to the calling agent). A dry agent writes `token` and `agent-id` into its per-FQDN data dir.
- For the **real serving change** (R tests): a host with a real Caddy (built-in) and/or a real nginx/apache installed, plus the privileges (or the printed remediation applied) to write the config dir and reload the service.

## Features covered
- [ ] `proxy_mode` field per agent: enum `built-in` | `existing`, default `built-in`; reported by the agent on heartbeat (orchestrator/dashboard never assume it).
- [ ] Persistence: `apply` writes the `proxy_*` keys to `agent.yaml` so a restart honours the new mode (other keys preserved).
- [ ] Prepare admin-op: `POST /agents/{id}/admin-ops {op_type, payload}` mints a one-time confirmation code (shown once, hash stored, 15-min TTL).
- [ ] Op-type validation: only `set_proxy_mode` accepted; unknown op types rejected 400.
- [ ] List pending ops: `GET /agents/{id}/admin-ops` — never returns the code or its hash; lazily expires stale pending ops.
- [ ] Revoke pending op: `DELETE /agents/{id}/admin-ops/{opId}` (scoped to the agent).
- [ ] Claim: `POST /agents/{id}/admin-ops/claim {code}` — atomic single-use pending→applied; wrong/expired/already-used → 404.
- [ ] Ack: `POST /agents/{id}/admin-ops/{opId}/ack {ok,result}` — records the apply outcome.
- [ ] Agent CLI: `nurproxy-agent apply <CODE>` — claim → persist → hot-apply → ack, in one command.
- [ ] Confirmation code shape & hashing: Crockford base32 (no I/L/O/U), two groups of four (`XXXX-XXXX`), sha256 hex hash, case/whitespace-tolerant match.
- [ ] `holder.Reconfigure` transitions: existing→existing, built-in→existing (stop bundled Caddy, swap, re-probe perms), existing→built-in (rebuild bundled, may need subprocess restart).
- [ ] Fail-soft semantics: a failing permission probe is non-fatal (applied-with-warnings + remediation); the agent never crashes on a switch.
- [ ] Audit: prepare/cancel audit under the caller's source (`ui` for a dashboard session, `api` for an admin API key; an agent token hitting these `requireAuth` endpoints yields `agent`); claim & ack audit under `source=agent`. The admin-op endpoints are not exposed over MCP, so `mcp` never appears here.

## Tests

### `proxy_mode` field & heartbeat reporting
- **Must:** every agent has a `proxy_mode` of exactly `built-in` or `existing`, defaulting to `built-in`. The orchestrator stores what the agent reports on each heartbeat — it does not assume built-in. (`models.go:259-264`: "Owned by the agent via heartbeat … Defaults to built-in".) The agent feeds the live holder mode into the heartbeat: `hb.SetModeFn(holder.Mode)` (`cmd/nurproxy-agent/main.go:422`), and `Holder.Mode()` returns the current live mode, updated atomically on every `Reconfigure` (`holder.go:82-86, 431, 551`).
- **Access:**
  - Dashboard: Agents page → select an agent → detail drawer shows the **Proxy mode** row (`web/src/pages/Agents.tsx:314-321`); existing mode shows "managing existing", built-in shows the bundled-Caddy running indicator (`Agents.tsx:326-340`).
  - REST: `GET /api/v1/agents/{id}` → `proxy_mode` in the agent JSON.
  - Agent flag/env at startup: `-proxy-mode` (flag declared `cmd/nurproxy-agent/main.go:53`, fed into `agentconfig.Load` at `main.go:100-101`) / config key `proxy_mode` (type + field `config.go:13-35`). The holder is seeded with the configured mode at boot (`main.go:289`, `NewHolder` normalizes empty → `built-in`).
- **Prerequisites:** none beyond file-level.
- **Steps:**
  ```bash
  # With the sandbox up; grab the first agent id and read its mode.
  AID=$(curl -s -H "Authorization: Bearer $NP_API_KEY" \
        http://localhost:8080/api/v1/agents | python3 -c 'import sys,json;print(json.load(sys.stdin)["agents"][0]["id"])')
  curl -s -H "Authorization: Bearer $NP_API_KEY" \
        http://localhost:8080/api/v1/agents/$AID | python3 -c 'import sys,json;print(json.load(sys.stdin)["proxy_mode"])'
  ```
- **Pass:** a fresh agent reports `built-in`. After a successful hot-switch to existing (below), the **next heartbeat** flips it to `existing`.
- **Coverage:** D.
- **Pitfalls:** the value only changes on the *next* heartbeat after a live switch — poll, don't expect an instant flip. The dashboard agent model does not surface `proxy_mode` synchronously during the setup flow, so the ExistingSetup wizard polls the **pending-ops list** (not `proxy_mode`) to decide "applied" (`ExistingSetup.tsx:207-219`).

### Prepare admin-op (mint a one-time code)
- **Must:** `POST /agents/{id}/admin-ops` with `{op_type, payload}` validates the op type, mints a confirmation code, stores only its sha256 hash, persists a `pending` op with `expires_at = now + 15min`, audits `admin_op.prepare`, and returns the **plaintext code exactly once** plus `id` and `expires_at` (201). (`admin_ops.go:64-108`; TTL `adminOpTTL = 15 * time.Minute` at `admin_ops.go:16`.)
- **Access:**
  - Dashboard: the Existing-proxy setup wizard's prepare action calls `api.prepareAdminOp(agent.id, 'set_proxy_mode', {...})` (`web/src/pages/ExistingSetup.tsx:190-198`, `web/src/lib/api.ts:163-167`). The wizard is opened from the Agents card/detail (`setSetupOpen(true)`, `Agents.tsx:604,613,644`). **The dashboard only prepares the `existing` direction** — it hard-codes `proxy_mode: 'existing'` (`ExistingSetup.tsx:190-191`). Switching **back to built-in** has no dashboard control; do it via REST (prepare with `proxy_mode:"built-in"`) or the agent's local `/admin/reconfigure`.
  - REST: `POST /api/v1/agents/{id}/admin-ops` body `{"op_type":"set_proxy_mode","payload":{"proxy_mode":"existing","proxy_type":"nginx","proxy_config_dir":"...","proxy_reload_cmd":"...","proxy_test_cmd":"...","proxy_service":"...","proxy_log_paths":[...]}}`. Payload fields: `models.SetProxyModePayload` (`models.go:626-646`). Only `proxy_mode` is required for built-in; existing also needs `proxy_type`. Note `SetProxyModePayload` has **no `proxy_binary` field** — a binary-path override cannot ride the prepare→claim→apply path; it can only be set via the agent's local `/admin/reconfigure` body or the agent's startup `-proxy-binary` flag.
- **Prerequisites:** admin auth; a valid agent id.
- **Steps:**
  ```bash
  curl -s -X POST -H "Authorization: Bearer $NP_API_KEY" -H "Content-Type: application/json" \
    -d '{"op_type":"set_proxy_mode","payload":{"proxy_mode":"existing","proxy_type":"nginx"}}' \
    http://localhost:8080/api/v1/agents/$AID/admin-ops
  ```
- **Pass:** HTTP 201; body has `code` (shape `XXXX-XXXX`), `id` (UUID), and `expires_at` ~15 min out. The audit log has an `admin_op.prepare` entry (`details=op_type=set_proxy_mode`).
- **Coverage:** D.
- **Pitfalls:** the code is shown **once** here and never again — capture it. There is no plaintext stored; if lost, prepare a new op. `expires_at` is UTC.

### Op-type validation
- **Must:** only `set_proxy_mode` is accepted; any other `op_type` is rejected `400 unknown op_type "<x>"` so the channel stays a closed set. A malformed `set_proxy_mode` payload is `400 invalid set_proxy_mode payload`. (`admin_ops.go:44-60, 81-85`.)
- **Access:** REST `POST .../admin-ops`.
- **Steps:**
  ```bash
  curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "Authorization: Bearer $NP_API_KEY" \
    -H "Content-Type: application/json" -d '{"op_type":"reboot"}' \
    http://localhost:8080/api/v1/agents/$AID/admin-ops
  ```
- **Pass:** `400`. The TS type also pins this to a single value: `AdminOpType = 'set_proxy_mode'` (`web/src/lib/types.ts:236`).
- **Coverage:** D.
- **Pitfalls:** an empty/omitted `payload` is allowed (defaults to `{}` — `admin_ops.go:51-55`, `CreateAdminOp` backfills `"{}"` at `db/admin_ops.go:62-64`); it is only `proxy_mode`-empty that the agent later rejects on reconfigure, not the orchestrator at prepare time.

### List pending ops (code-free)
- **Must:** `GET /agents/{id}/admin-ops` returns the agent's `pending`, non-expired ops newest-first, projected through `adminOpView` which **omits `code_hash` and never carries the plaintext** (`admin_ops.go:18-42, 112-131`). Listing first lazily flips any pending op whose TTL elapsed to `expired` before returning, so the list reflects truth (`db/admin_ops.go:106-143`).
- **Access:** Dashboard wizard polls it (`api.listAdminOps`, `api.ts:168-169`); REST `GET /api/v1/agents/{id}/admin-ops`.
- **Steps:**
  ```bash
  curl -s -H "Authorization: Bearer $NP_API_KEY" \
    http://localhost:8080/api/v1/agents/$AID/admin-ops | python3 -m json.tool
  ```
- **Pass:** `ops[]` each has `id, op_type, status, created_at, expires_at` (and `applied_at`/`result` when present) — and **no `code` or `code_hash` key anywhere**.
- **Coverage:** D.
- **Pitfalls:** the list only ever shows `pending` ops; a claimed (`applied`), `canceled`, or `expired` op drops off the list. Use `GET .../agents/{id}` audit log or the op `id` to confirm a terminal state, not this list.

### Revoke a pending op
- **Must:** `DELETE /agents/{id}/admin-ops/{opId}` transitions the op to `canceled`, verifying it belongs to the agent (404 otherwise), and audits `admin_op.cancel` (`admin_ops.go:135-153`). After cancel, the code can no longer be claimed.
- **Access:** REST `DELETE /api/v1/agents/{id}/admin-ops/{opId}` (`api.ts:170-171`).
- **Steps:**
  ```bash
  # Prepare, capture id, then revoke.
  OPID=$(curl -s -X POST -H "Authorization: Bearer $NP_API_KEY" -H "Content-Type: application/json" \
    -d '{"op_type":"set_proxy_mode","payload":{"proxy_mode":"existing","proxy_type":"nginx"}}' \
    http://localhost:8080/api/v1/agents/$AID/admin-ops | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
  curl -s -o /dev/null -w "%{http_code}\n" -X DELETE -H "Authorization: Bearer $NP_API_KEY" \
    http://localhost:8080/api/v1/agents/$AID/admin-ops/$OPID
  ```
- **Pass:** `204`. The op disappears from the pending list, and a subsequent claim of its code returns 404.
- **Coverage:** D.
- **Pitfalls:** a DELETE for an op id that belongs to a different agent returns `404 admin op not found` (the handler checks `op.AgentID != id` — `admin_ops.go:140`).

### Claim (atomic, single-use)
- **Must:** `POST /agents/{id}/admin-ops/claim {code}` hashes the presented code, atomically flips a matching `pending`, non-expired op to `applied` (stamping `applied_at`), and returns `{id, op_type, payload}`. It is single-use: a second claim of the same code finds no pending row → `404 no matching pending change (wrong, expired, or already-used code)`. Wrong/expired codes also 404. The transition is a single guarded UPDATE inside a transaction (`db/admin_ops.go:145-194`: `WHERE … status=pending AND expires_at > now`, then `RowsAffected==0 → ErrAdminOpNotFound`). The endpoint is `requireAgentAuth` and refuses to claim for another agent (`callerID != id → 403`, `admin_ops.go:158-163`). Audits `admin_op.claim` (`source=agent`).
- **Access:** the agent CLI does this internally (below); REST direct: `POST /api/v1/agents/{id}/admin-ops/claim` with `Authorization: Bearer <agent-token>`, body `{"code":"XXXX-XXXX"}`.
- **Prerequisites:** the agent's token + id. For a dry sandbox agent these are in its data dir (`token`, `agent-id`).
- **Steps:**
  ```bash
  # Prepare an op as admin, capture CODE; then claim it as the agent.
  # (TOKEN/AID are the agent's own credentials.)
  curl -s -X POST -H "Authorization: Bearer $AGENT_TOKEN" -H "Content-Type: application/json" \
    -d "{\"code\":\"$CODE\"}" \
    http://localhost:8080/api/v1/agents/$AID/admin-ops/claim | python3 -m json.tool
  # Claim the SAME code again → expect 404.
  curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "Authorization: Bearer $AGENT_TOKEN" \
    -H "Content-Type: application/json" -d "{\"code\":\"$CODE\"}" \
    http://localhost:8080/api/v1/agents/$AID/admin-ops/claim
  ```
- **Pass:** first claim → 200 with `op_type=set_proxy_mode` and the payload echoed; second claim → `404`. Audit shows `admin_op.claim` under `source=agent`.
- **Coverage:** D (the atomicity + single-use are pure orchestrator/DB).
- **Pitfalls:** the code match is case/whitespace-insensitive (`HashConfirmationCode` upper-cases + trims, `confirmation_code.go:50-53`), so a copy-paste with stray spaces still works — but the *agent id in the URL* must be the claiming agent's own id or you get 403, not 404. Regression-guard: the single-use property lives entirely in the SQL guard; if a refactor moves the status check out of the UPDATE, a race could double-apply.

### Ack (report outcome)
- **Must:** `POST /agents/{id}/admin-ops/{opId}/ack {ok,result}` records the free-form `result` on the op and audits `admin_op.ack` with `ok=<bool> result=<text>` (`source=agent`). Scoped to the calling agent (403 otherwise); op must belong to the agent (404 otherwise). (`admin_ops.go:196-227`; `db.AckAdminOp` writes only the `result` column — `db/admin_ops.go:214-229`.)
- **Access:** the CLI acks automatically (`apply.go:230-233`); REST direct: `POST /api/v1/agents/{id}/admin-ops/{opId}/ack` body `{"ok":true,"result":"applied; permissions OK"}` with the agent token.
- **Steps:**
  ```bash
  curl -s -X POST -H "Authorization: Bearer $AGENT_TOKEN" -H "Content-Type: application/json" \
    -d '{"ok":true,"result":"applied; permissions OK"}' \
    http://localhost:8080/api/v1/agents/$AID/admin-ops/$OPID/ack
  ```
- **Pass:** 200 `{"status":"ok"}`; the op's `result` is set (visible via `GET .../admin-ops/{opId}` is not exposed publicly, but the audit log shows the `admin_op.ack` entry). Note: ack does **not** change `status` — `applied_at`/`status` were already set by claim; ack only fills `result`.
- **Coverage:** D.
- **Pitfalls:** `ok` is recorded only in the audit details string, not as a column — the op's status stays `applied` regardless of `ok` true/false. The dashboard "applied" signal is the op leaving the pending list (claim did that), not the ack.

### Agent CLI `nurproxy-agent apply <CODE>`
- **Must:** one command runs the whole host-side flow: resolve identity (flags > `runtime.json` > `agent.yaml`), **claim** the code, **persist** the payload to `agent.yaml`, **hot-apply** via the local agent API, **print** any remediation, and **ack** (`apply.go:69-237`). It normalizes the code (upper-case + trim, `apply.go:96, 110-112`). A 404 claim is a clean non-fatal user error: "no matching pending change — wrong, expired, or already-used code" with exit 1 (`apply.go:99-101`). If the local agent isn't reachable, it still persists and acks "will apply on next start" (`apply.go:205-211`).
- **Access:** CLI: `nurproxy-agent apply <CODE> [--data-dir DIR] [--orchestrator URL] [--api-port N]` (`apply.go:69-95`). The local hot-apply hits `http://127.0.0.1:<apiPort>/admin/reconfigure` (default port 8780, `apply.go:142, 309`).
- **Prerequisites:** run on the agent host (or a sandbox agent's data dir): the dir must contain `token` and `agent-id`, and orchestrator URL must be resolvable. For a dry sandbox, point `--data-dir` at the agent's per-FQDN temp data dir and `--api-port` at its API port.
- **Steps (dry):**
  ```bash
  # Prepare an op (admin), capture CODE, then on the agent host:
  ./nurproxy-agent apply "$CODE" --data-dir "$AGENT_DATA_DIR"
  ```
- **Pass:** prints `saved to <dataDir>/agent.yaml`, then the reconfigure message; exit 0. The op leaves the pending list (claimed) and the audit log shows `claim` then `ack`. With a dry agent the local reconfigure succeeds in-memory.
- **Coverage:** D (the claim/persist/ack and the in-memory dry reconfigure). The on-disk-serving effect is R.
- **Pitfalls:** Go's flag parser stops at the first non-flag token, so the CLI explicitly pulls a leading positional `<CODE>` before parsing flags and recovers it from `fs.Arg(0)` if it came after (`apply.go:78-91`) — both `apply CODE --orchestrator X` and `apply --orchestrator X CODE` work, but mixing is fragile, prefer `apply CODE --flags`. The persisted `agent.yaml` only overwrites `proxy_*` keys; orchestrator/fqdn/ports are preserved (`persist.go:55-110`), and missing identity is backfilled from `runtime.json` so the file stays self-sufficient.

### Confirmation code shape & hashing
- **Must:** codes are Crockford base32 with **I, L, O, U removed** (alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`), rendered as **two dash-separated groups of four**, e.g. `K7QF-2M9X`, from crypto-secure randomness (`confirmation_code.go:10-44`). Only the sha256 hex of the normalized (upper, trimmed) code is stored; matching re-hashes the presented plaintext (`confirmation_code.go:46-54`).
- **Access:** internal; observable via the `code` returned at prepare and via tolerant matching at claim.
- **Steps:** verify the unit behavior dry: `go test ./internal/orchestrator/db/ -run ConfirmationCode -v` (and `-run AdminOp` for the op lifecycle).
- **Pass:** code matches `^[0-9A-HJ-NP-TV-Z]{4}-[0-9A-HJ-NP-TV-Z]{4}$` (no I/L/O/U); a lower-cased or space-padded copy of the same code claims successfully.
- **Coverage:** D.
- **Pitfalls:** because ambiguous glyphs are excluded by design, a human-mistyped `0/O` or `1/I` simply won't match — re-read the code, don't assume a bug.

### `holder.Reconfigure` transitions (the live switch)
- **Must:** `Holder.Reconfigure` swaps the live backend under a write lock with **no process restart**, updating `mode` atomically, and is **fail-soft** — it never returns an error that could crash the agent (`holder.go:354-375`). Per transition:
  - **unknown mode** → `OK=false`, health error "unknown proxy mode …", no swap (`holder.go:367-374`).
  - **existing → existing / built-in → existing** (`reconfigureExisting`, `holder.go:382-456`): requires `Type` (else `OK=false`, "requires a proxy type (nginx | apache | caddy)"); builds the file backend, **runs the §12 permission probe before swapping**, **stops the bundled Caddy** if `StopCaddy` is wired (so the host proxy can own :80/:443; a stop error is logged, never fatal), then atomically sets `current` + `mode="existing"` and `SetCaddyRunning(false)`. Probe OK → `OK=true` "switched to existing <type> — config is writable and reloadable". Probe fails → **applied-with-warnings**: `OK=false` + health error + `Remediation` (exact grant commands), backend still swapped.
  - **existing → built-in / built-in → built-in** (`reconfigureBuiltIn`, `holder.go:538-562`): with a `CaddyFactory`, rebuilds the bundled backend and sets `mode="built-in"`, returns `OK=true` with the message that a **process restart may be needed** for the bundled Caddy subprocess to bind :80/:443 again. With **no factory wired**, `OK=false` "restart the agent in built-in mode …".
- **Access:**
  - Local agent API: `POST /admin/reconfigure` (Bearer agent token), body `{proxy_mode, proxy_type, proxy_config_dir, proxy_binary, proxy_reload_cmd, proxy_test_cmd, proxy_service, proxy_log_paths}` (`api.go:344-421`). Returns `{ok, message, remediation?}`. Returns `503 reconfigure not available on this agent` if no holder wired.
  - Driven end-to-end by `nurproxy-agent apply` (which POSTs to this endpoint, `apply.go:298-334`).
- **Prerequisites:** D-coverable: a running agent (dry) and its local API port + token. R-coverable: a real nginx/apache (existing) or real bundled Caddy (built-in) on the host.
- **Steps (dry, direct local API):**
  ```bash
  curl -s -X POST -H "Authorization: Bearer $AGENT_TOKEN" -H "Content-Type: application/json" \
    -d '{"proxy_mode":"existing","proxy_type":"nginx"}' \
    http://127.0.0.1:$AGENT_API_PORT/admin/reconfigure | python3 -m json.tool
  # Switch back:
  curl -s -X POST -H "Authorization: Bearer $AGENT_TOKEN" -H "Content-Type: application/json" \
    -d '{"proxy_mode":"built-in"}' \
    http://127.0.0.1:$AGENT_API_PORT/admin/reconfigure | python3 -m json.tool
  ```
- **Pass:** 200 with a coherent `{ok, message}`; existing without a type → `ok=false` "requires a proxy type"; unknown mode → `ok=false` "unknown proxy mode". The next heartbeat reports the new `proxy_mode`. On a real host with a writable+reloadable existing proxy: `ok=true` and traffic continues to serve through the host proxy.
- **Coverage:** D for the request/response, mode flip, validation, and fail-soft messaging; **R** for the actual on-disk config swap, port hand-off (:80/:443), and serving real traffic.
- **Pitfalls:**
  - The probe runs **before** the swap, but the swap happens **even when the probe fails** — "applied-with-warnings" means the backend is already live and you must apply the printed remediation; it is not a rollback (`holder.go:439-455`).
  - Switching back to built-in does **not** restart the Caddy subprocess from the Holder — if the subprocess was stopped, the rebuilt admin-API backend falls back to the in-memory mock and you must restart the agent process to actually bind :80/:443 (`holder.go:531-561`). Watch for this on a real host: `proxy_mode` reads `built-in` again but traffic doesn't flow until restart.
  - Existing mode needs the agent's cert store wired (`CertDir`/`CertKey` in `ReconfigureDeps`, `holder.go:298-302`); without it an existing-mode agent silently drops every central-TLS listener. Verify central TLS still serves after a real switch.
  - Caddy admin-API primitives become safe no-ops once the live backend is a file backend (`holder.go:162-237`) — route pushes to nginx/apache go through the file path, not the admin API. Don't treat a no-op `EnsureServer`/`AddRoute` after the switch as a failure.

### Audit trail
- **Must:** the prepare/cancel actions audit under the **caller's** channel. The prepare/list/cancel handlers are `requireAuth`, which derives `source` from the credential used: `ui` for a dashboard session cookie, `api` for the admin API key, and `agent` if an agent token is presented to these endpoints (`requireAuth` accepts all three — `middleware.go:25-65`; the audit source is read from context in `server.go:232-235`). There is **no `mcp` path here**: admin-ops are not exposed as MCP tools, so prepare/cancel can never carry `source=mcp`. The claim and ack actions, being `requireAgentAuth`, always audit under `source=agent`, actor `agent:<id>` (`middleware.go:85-87`). Actions: `admin_op.prepare`, `admin_op.cancel`, `admin_op.claim`, `admin_op.ack` (the prepare/cancel details are `op_type=<type>`; the ack detail is `ok=<bool> result=<text>`, `admin_ops.go:100,150,184,224`).
- **Access:** REST `GET /api/v1/audit-log?source=<ui|api|agent>`; dashboard Audit page with a source filter.
- **Steps:**
  ```bash
  curl -s -H "Authorization: Bearer $NP_API_KEY" \
    "http://localhost:8080/api/v1/audit-log?source=agent" | python3 -m json.tool | grep admin_op
  ```
- **Pass:** a full hot-switch leaves `admin_op.prepare` under the operator's source and `admin_op.claim` + `admin_op.ack` under `source=agent`; the ack detail string carries `ok=<bool> result=<text>`.
- **Coverage:** D.
- **Pitfalls:** the prepare's source is **not** always `ui` — if you drove prepare via the admin API key it'll be `api`. Filter accordingly. It is never `mcp` (admin-ops aren't an MCP tool). The code/hash never appears in any audit detail.

## Acceptance checklist

### Dry (every RC)
- [ ] Fresh agent reports `proxy_mode=built-in` via `GET /agents/{id}`.
- [ ] `POST .../admin-ops` with `set_proxy_mode` returns 201 with a `XXXX-XXXX` code, UUID `id`, and `expires_at` ~15 min out; audit `admin_op.prepare`.
- [ ] Unknown `op_type` → 400; the code is never returned twice.
- [ ] `GET .../admin-ops` lists pending ops with **no `code`/`code_hash`**; expired ops drop off.
- [ ] `DELETE .../admin-ops/{opId}` → 204; the code can no longer be claimed; audit `admin_op.cancel`.
- [ ] Claim a valid code → 200 with payload; **re-claim the same code → 404**; claim for another agent's id → 403.
- [ ] Ack → 200 `{"status":"ok"}`; audit `admin_op.ack` carries `ok=…`.
- [ ] `nurproxy-agent apply <CODE>` (dry): prints `saved to …/agent.yaml`, hot-applies in-memory, acks; exit 0. A bogus code → "no matching pending change" exit 1.
- [ ] `POST /admin/reconfigure` mode `existing` without `proxy_type` → `ok=false` "requires a proxy type"; unknown mode → `ok=false` "unknown proxy mode"; no holder → 503.
- [ ] After a dry switch, the next heartbeat flips `proxy_mode` to `existing`.
- [ ] `go test ./internal/orchestrator/db/ -run 'AdminOp|ConfirmationCode'` passes (lifecycle + atomicity + code shape/hash).

### Real run (before final)
- [ ] On a host with a real nginx/apache: built-in→existing switch returns `ok=true` (config writable + reloadable), the bundled Caddy is stopped, and the host proxy serves traffic on :80/:443 without an agent restart.
- [ ] With missing grants: switch returns `ok=false` + a copy-paste remediation; after applying it, the next heartbeat's `proxy_permissions` clears (no restart).
- [ ] Central-TLS domains still serve after the switch (cert store wired into the existing backend).
- [ ] existing→built-in: `proxy_mode` reads `built-in` again; confirm whether a process restart is required before the bundled Caddy actually binds :80/:443, and that traffic resumes after it.
- [ ] `agent.yaml` persists the new `proxy_*` keys; a real agent restart comes up in the persisted mode with all other config preserved.

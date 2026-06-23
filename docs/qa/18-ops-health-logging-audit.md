# Ops Signals: Health, Logging, Versioning & Audit Log

> **Scope:** the orchestrator's operational observability surface — the `/health` endpoint (with its real DB check and dry-run flags), structured logging, agent version-skew detection, and the audit log.
> **Code:** `internal/orchestrator/api/system.go` (health + audit-log handlers), `internal/orchestrator/db/db.go` (`Ping`), `internal/orchestrator/api/version_status.go` (skew classification), `internal/orchestrator/api/agents.go` (where skew is attached), `internal/orchestrator/db/audit.go` (audit storage/listing), `internal/shared/models/models.go` (`AuditSource` enum, `AuditLogEntry`), `internal/orchestrator/api/middleware.go` + `server.go` (source derivation), `internal/shared/logging/logging.go` (slog setup), `internal/orchestrator/reconciler/reconciler.go` (system vs dryrun source), `web/src/pages/Overview.tsx` (audit tail + source badges), `web/src/pages/Agents.tsx` (version badge).
> **Coverage legend:** D = coverable dry, R = needs a real run.

## Prerequisites
- Both binaries built: `make build-all` (produces `./nurproxy` and `./nurproxy-agent`).
- For most tests, a dry stack is enough: `make dev-sandbox` (orchestrator + 1 agent, seeded topology, dashboard up). It boots the orchestrator on `:8080` unless `PORT=` is set, and seeds a provider/zone/adopted agents/servers/central-TLS domains, so the audit log already has entries to inspect.
- `curl` and `jq` available for inspecting JSON responses.
- An **admin API key** for authenticated endpoints (`/audit-log` needs auth; `/health` does not). Generate one: `POST /api/v1/api-key` (returns the plaintext once) or read it from the sandbox launcher output. Pass it as `Authorization: Bearer <key>`.
- Know your orchestrator base URL; examples below assume `http://localhost:8080`.

## Features covered
- [ ] `GET /api/v1/health` — `status`, `version`, `checks.database`, `dry_run`, `dns_dry_run`, `acme_dry_run` fields; unauthenticated.
- [ ] Health real DB check via `db.Ping` (`SELECT 1`) with a 3s timeout, returning **503** + `status: "degraded"` when the DB is wedged (#65).
- [ ] Health dry-run flag wiring: `dry_run = dns_dry_run || acme_dry_run`; per-subsystem flags reflect `NP_DNS_DRY_RUN` / `NP_ACME_DRY_RUN` / `NP_DRY_RUN`.
- [ ] Structured logging: `NP_LOG_FORMAT=json` emits valid JSON lines on **stderr**; `text` default.
- [ ] `NP_LOG_LEVEL` filtering (debug | info | warn | error; default info).
- [ ] `component` attribute on every record ("orchestrator" / "agent").
- [ ] Legacy `log.Printf` bridged through the same slog handler (level + format apply).
- [ ] Agent version-skew classification: `current` | `outdated` | `ahead` | `unknown`.
- [ ] Version-skew surfaced in the dashboard (Agents page badge) and via API (`version_status` field).
- [ ] `GET /api/v1/audit-log` — pagination (`limit` default 50, max 1000; `offset`), `source` filter, `total`.
- [ ] Audit `source` enum: `ui | api | mcp | agent | system | dryrun`, derived from the request auth context.
- [ ] Source-correct tagging: reconciler/system actions are `system`; simulated DNS/ACME in dry-run are `dryrun`.
- [ ] Audit coverage of DNS/cert/route/security/CRUD actions.
- [ ] Dashboard Overview audit tail with per-entry source badges.

## Tests

### Health endpoint — fields, version, dry-run flags
- **Must:** `GET /api/v1/health` returns 200 with a JSON object: `status:"ok"`, `version:<orchestrator version string>`, `checks:{"database":"ok"}`, and the three booleans `dry_run`, `dns_dry_run`, `acme_dry_run`. It requires **no authentication** (registered as a plain `GET /api/v1/health`, not behind `requireAuth` — `server.go:133`).
- **Access:**
  - REST API: `GET /api/v1/health` (no auth header needed).
  - Dashboard: the Overview page consumes health indirectly; the dry-run banner (`web/src/components/DryRunBanner.tsx`) reflects the dry flags.
- **Prerequisites:** orchestrator running (dry sandbox is fine).
- **Steps:**
  ```bash
  curl -s http://localhost:8080/api/v1/health | jq
  ```
- **Pass:** HTTP 200; body has `status:"ok"`, `checks.database == "ok"`, a non-empty `version`, and all three dry flags present. Under a dry sandbox, `dry_run`, `dns_dry_run`, `acme_dry_run` are all `true`. Under a fully real orchestrator they are all `false`.
- **Coverage:** D.
- **Pitfalls:**
  - `version` is `"dev"` for an untagged local build (`cmd/nurproxy/main.go:33`); a released binary carries the tag. Don't fail the check on the exact string — assert it's non-empty and matches the binary you built.
  - The endpoint is intentionally unauthenticated so load balancers/monitors can hit it.

### Health dry-run flag wiring
- **Must:** `dry_run` equals `dns_dry_run || acme_dry_run` (`system.go:23`). `dns_dry_run` is true under `NP_DNS_DRY_RUN` or `NP_DRY_RUN`; `acme_dry_run` is true under `NP_ACME_DRY_RUN` or `NP_DRY_RUN`.
- **Access:** env vars / flags: `NP_DRY_RUN` (or `-dry-run`), `NP_DNS_DRY_RUN`, `NP_ACME_DRY_RUN`. Reported via `GET /api/v1/health`.
- **Prerequisites:** ability to start the orchestrator by hand.
- **Steps:** start three flavors on different ports and compare:
  ```bash
  NP_DNS_DRY_RUN=true ./nurproxy -port 18101 -data-dir /tmp/np-dns &  sleep 1
  NP_ACME_DRY_RUN=true ./nurproxy -port 18102 -data-dir /tmp/np-acme & sleep 1
  curl -s localhost:18101/api/v1/health | jq '{dry_run,dns_dry_run,acme_dry_run}'
  curl -s localhost:18102/api/v1/health | jq '{dry_run,dns_dry_run,acme_dry_run}'
  ```
- **Pass:** DNS-only instance → `dns_dry_run:true, acme_dry_run:false, dry_run:true`. ACME-only → `dns_dry_run:false, acme_dry_run:true, dry_run:true`. (`NP_DRY_RUN=true` would set all three true.)
- **Coverage:** D.
- **Pitfalls:** use separate `-data-dir` and `-port` per instance to avoid DB-lock and port clashes.

### Health real DB check → 503 when wedged (#65)
- **Must:** `/health` runs a real query (`SELECT 1`, `db.go:71-74`) under a 3s timeout (`system.go:16`). If `db.Ping` errors, the handler sets `status:"degraded"`, `checks.database:"error: <msg>"`, and returns **HTTP 503** (`system.go:27-31`) so a monitor sees a wedged orchestrator instead of a hollow "ok".
- **Access:** REST API: `GET /api/v1/health`.
- **Prerequisites:** the failure path is unit-tested; reproducing it live is hard because the running process holds the DB handle open.
- **Steps (verify the unit test that guards this):**
  ```bash
  go test ./internal/orchestrator/api/ -run Health -v
  ```
- **Pass:** the health unit test(s) pass, asserting 503 + `status:"degraded"` + a `checks.database` value starting with `error:` when the DB ping fails, and 200 + `"ok"` otherwise.
- **Coverage:** D (via unit test). Live 503 is impractical — see pitfalls.
- **Pitfalls:**
  - **Hard to reproduce live:** the orchestrator keeps the SQLite handle open, so you cannot "pull the DB out" from under a running process to force a 503. Trust the unit test for the failure path; the live test only confirms the happy path (200).
  - The 3s timeout means a slow/locked DB surfaces as a 503 rather than hanging the monitor.

### Structured logging — JSON format and stderr
- **Must:** with `NP_LOG_FORMAT=json`, log output is one valid JSON object per line on **stderr** (`logging.go:34-37`). Default (unset / any non-`json` value) is the text handler.
- **Access:** env vars: `NP_LOG_FORMAT` (text | json, default text). Applies to both `nurproxy` and `nurproxy-agent` (both call `logging.Setup`).
- **Prerequisites:** ability to start a binary and capture stderr.
- **Steps:**
  ```bash
  NP_LOG_FORMAT=json NP_DRY_RUN=true ./nurproxy -port 18103 -data-dir /tmp/np-json 2>/tmp/np-json.log &
  sleep 2
  # every non-empty line must be valid JSON:
  while IFS= read -r line; do [ -z "$line" ] && continue; echo "$line" | jq -e . >/dev/null || echo "NOT JSON: $line"; done < /tmp/np-json.log
  head -3 /tmp/np-json.log | jq .
  ```
- **Pass:** no "NOT JSON" lines; each record is a JSON object with `time`, `level`, `msg`, and a `component` attribute. Logs land on stderr (the `2>` redirect captured them; stdout did not).
- **Coverage:** D.
- **Pitfalls:** logs go to **stderr**, not stdout — redirect `2>` (a `>` redirect will miss them and the file looks empty).

### Structured logging — level filtering & component attribute
- **Must:** `NP_LOG_LEVEL` filters records: `debug | info | warn | error`, defaulting to `info` for empty/unrecognized values (`logging.go:54-65`). Every record carries a stable `component` attribute set by `Setup(component)` — `"orchestrator"` for `nurproxy`, `"agent"` for `nurproxy-agent`.
- **Access:** env var `NP_LOG_LEVEL`. `component` is set in code, not configurable.
- **Steps:**
  ```bash
  # error level: info/debug lines suppressed
  NP_LOG_LEVEL=error NP_LOG_FORMAT=json NP_DRY_RUN=true ./nurproxy -port 18104 -data-dir /tmp/np-lvl 2>/tmp/np-lvl.log & sleep 2
  jq -r .level /tmp/np-lvl.log | sort | uniq -c     # expect only WARN/ERROR
  jq -r .component /tmp/np-lvl.log | sort | uniq -c # expect "orchestrator"
  ```
- **Pass:** at `error` level no `INFO`/`DEBUG` records appear; every record has `component:"orchestrator"`. Start an agent dry and confirm its records carry `component:"agent"`.
- **Coverage:** D.
- **Pitfalls:** an unrecognized `NP_LOG_LEVEL` silently falls back to `info` (not an error) — a typo'd level won't crash, it just won't filter as you expect.

### Legacy log.Printf bridged through slog
- **Must:** `Setup` calls `slog.SetDefault`, which also bridges the standard library `log` package through the slog handler (`logging.go:45-48`). Existing `log.Printf` call sites therefore gain the configured level/format — e.g. the startup line `log.Printf("NurProxy %s listening on :%d", …)` (`cmd/nurproxy/main.go:214`) appears as a structured JSON record.
- **Access:** implicit; driven by the same `NP_LOG_FORMAT` / `NP_LOG_LEVEL` env vars.
- **Steps:** reuse `/tmp/np-json.log` from the JSON test:
  ```bash
  grep -i listening /tmp/np-json.log | jq .   # the log.Printf startup line, as JSON
  ```
- **Pass:** the "listening on" message (originally a `log.Printf`) appears as a JSON object with `level:"INFO"` and `component:"orchestrator"`, not as a raw unstructured line.
- **Coverage:** D.
- **Pitfalls:** the bridge logs `log.Printf` output at `LevelInfo`, so `NP_LOG_LEVEL=warn`+ will suppress those legacy lines too — expected behaviour, not a lost message.

### Agent version-skew classification
- **Must:** the orchestrator compares each agent's reported version against its own (`s.version`) and classifies (`version_status.go`):
  - equal strings → `current`;
  - both parse as `vX.Y.Z` semver and agent < orchestrator → `outdated`; agent > orchestrator → `ahead`; equal triple → `current`;
  - either side empty, or either side not a clean three-part numeric semver (e.g. `"dev"`, a git hash) → `unknown`.
  - Pre-release/build metadata (`-rc.1`, `+build`) is **stripped** before comparison — only the release triple is ranked (`version_status.go:53-58`).
- **Access:**
  - REST API: `GET /api/v1/agents` (list) and `GET /api/v1/agents/{id}` (detail) include `version_status` (`agents.go:40`, `agents.go:293`).
  - Dashboard: Agents page shows an `outdated`/`ahead` badge in the agent detail panel (`Agents.tsx:298-307`).
- **Prerequisites:** at least one adopted agent (dry sandbox seeds these). To exercise non-`current` verdicts you need an agent whose version differs from the orchestrator.
- **Steps:**
  ```bash
  curl -s -H "Authorization: Bearer $KEY" localhost:8080/api/v1/agents | jq '.[] | {fqdn, version, version_status}'
  ```
  To force `outdated`/`ahead` dry, start an agent with a pinned older/newer semver against a tagged orchestrator, or rely on the pure-function unit tests:
  ```bash
  go test ./internal/orchestrator/api/ -run Version -v
  ```
- **Pass:** an agent on the same version as the orchestrator reports `current`; an older semver agent reports `outdated`; a newer one `ahead`; a `"dev"`/hash build (or when the orchestrator itself is `"dev"`) reports `unknown`.
- **Coverage:** D.
- **Pitfalls:**
  - In a local untagged build the orchestrator version is `"dev"`, so **every** agent shows `unknown` — that is correct, not a bug. To see real verdicts, run a tagged orchestrator (or use the unit tests which feed explicit versions).
  - `version_status` is computed on read, not stored — it always reflects the *current* orchestrator version.

### Audit log — pagination, source filter, total
- **Must:** `GET /api/v1/audit-log` returns `{entries, total, limit, offset, source}` (`system.go:60-66`). `limit` defaults to **50** and is clamped to **1..1000** (out-of-range or non-numeric values are ignored, keeping the default — `system.go:41-45`). `offset` defaults to 0 and must be ≥0. Entries are newest-first (`audit.go:53`). `total` reflects the active `source` filter (`audit.go:43-58`). Requires authentication (behind `requireAuth`, `server.go:222`).
- **Access:**
  - REST API: `GET /api/v1/audit-log?limit=&offset=&source=` (auth required).
  - Dashboard: Overview page fetches the tail (`getAuditLog({ limit: '15' })`, `Overview.tsx:33`).
- **Prerequisites:** auth key; some audit entries (the dry sandbox seeds many during convergence).
- **Steps:**
  ```bash
  KEY=<admin api key>
  curl -s -H "Authorization: Bearer $KEY" localhost:8080/api/v1/audit-log | jq '{total, limit, offset, n: (.entries|length)}'
  # pagination
  curl -s -H "Authorization: Bearer $KEY" "localhost:8080/api/v1/audit-log?limit=5&offset=5" | jq '{limit, offset, n:(.entries|length)}'
  # clamp test — limit above max is ignored, falls back to 50
  curl -s -H "Authorization: Bearer $KEY" "localhost:8080/api/v1/audit-log?limit=99999" | jq '.limit'
  # without a key → 401
  curl -s -o /dev/null -w '%{http_code}\n' localhost:8080/api/v1/audit-log
  ```
- **Pass:** default `limit` is 50; `entries` is newest-first; `?limit=5&offset=5` returns up to 5 entries from offset 5; `?limit=99999` reports `limit:50` (clamped/ignored); unauthenticated request returns **401**.
- **Coverage:** D.
- **Pitfalls:**
  - The clamp is *silent*: an over-max or zero/negative `limit` doesn't error, it just stays at 50. Don't read that as "no entries".
  - `entries` may be JSON `null` rather than `[]` when empty (the slice is appended only when rows exist) — handle both (the dashboard does: `log.entries ?? []`).

### Audit source enum & derivation
- **Must:** every entry has a `source` from the enum `ui | api | mcp | agent | system | dryrun` (`models.go:399-406`). The source is derived from the request's auth path by the middleware: session cookie → `ui`, admin API key Bearer → `api`, agent token → `agent` (`middleware.go:31/42/55/87`). MCP tool calls record `mcp` (`mcp/server.go:472`). The `audit` helper pulls source from context; `auditAs` sets it explicitly for handlers that run without the auth middleware (`server.go:230-244`).
- **Access:** REST `GET /api/v1/audit-log?source=<value>`; dashboard source badges.
- **Prerequisites:** auth key; ideally actions performed through more than one channel.
- **Steps:**
  ```bash
  # filter by source
  for s in ui api mcp agent system dryrun; do
    echo -n "$s: "; curl -s -H "Authorization: Bearer $KEY" "localhost:8080/api/v1/audit-log?source=$s" | jq '.total'
  done
  # generate an api-sourced entry and confirm it lands as source=api
  curl -s -X POST -H "Authorization: Bearer $KEY" localhost:8080/api/v1/api-key >/dev/null  # NOTE: rotates the key
  ```
- **Pass:** the `source` filter returns only matching entries and a matching `total`. An action driven via the admin API key shows `source:"api"`; a dashboard-session action shows `ui`. The set of observed sources is a subset of the six enum values.
- **Coverage:** D.
- **Pitfalls:**
  - `AuditSource` is a `type AuditSource = string` **alias**, so the API accepts any `source=` string — an unknown value just returns zero rows, it is not rejected. Spelling matters (`dryrun`, not `dry-run` or `dry_run`).
  - Regenerating the admin API key (`POST /api/v1/api-key`) **rotates** it — your `$KEY` becomes invalid afterward. Capture the new key from the response if you run that step.

### System vs dryrun source tagging
- **Must:** orchestrator-internal actions (reconciler, TLS renewal) are tagged `system` in normal operation, but when DNS/ACME calls are **simulated** in dry-run they are tagged `dryrun` so a simulated CNAME/A/TXT/cert change can never be mistaken for a real one (`reconciler.go:1250-1263`, `cmd/nurproxy/main.go:256-264`). Real system events stay `system`.
- **Access:** REST `GET /api/v1/audit-log?source=dryrun` vs `?source=system`.
- **Prerequisites:** a dry sandbox (to produce `dryrun` events) — `make dev-sandbox`.
- **Steps:**
  ```bash
  curl -s -H "Authorization: Bearer $KEY" "localhost:8080/api/v1/audit-log?source=dryrun" | jq '.entries[0:5] | .[] | {entity_type, action, source, details}'
  ```
- **Pass:** under a dry sandbox, DNS-record and cert-issuance/renewal events appear with `source:"dryrun"`; the same events on a real orchestrator would be `source:"system"`. No simulated event leaks out as `system`.
- **Coverage:** D for `dryrun`; the `system` counterpart needs a real DNS/ACME run (R) to observe live.
- **Pitfalls:** this is a regression-guard for #93 — if a dry run starts emitting `system` for DNS/cert events, that's a real bug, not noise.

### Audit coverage of DNS/cert/route/security/CRUD actions
- **Must:** every meaningful change is audited — DNS record create/delete, cert issuance/renewal, route/config-artifact drift/adopt, security actions (API key generate/revoke — `system.go:96/106`), and entity CRUD. The dry sandbox convergence (provider → zone → adopt → server → domain → DNS-01 → cert → push → render → records → active) leaves a trail of these.
- **Access:** REST `GET /api/v1/audit-log`; dashboard Overview tail.
- **Prerequisites:** a converged dry sandbox.
- **Steps:**
  ```bash
  curl -s -H "Authorization: Bearer $KEY" "localhost:8080/api/v1/audit-log?limit=1000" \
    | jq -r '.entries[] | "\(.source)\t\(.entity_type)\t\(.action)"' | sort | uniq -c
  ```
- **Pass:** the histogram includes DNS actions (e.g. `dns_created`/`dns_deleted`), cert/renewal actions, agent register/adopt/drift actions, and any CRUD you performed. Tearing down a server and observing its DNS-cleanup entries confirms the security/cleanup path is audited.
- **Coverage:** D.
- **Pitfalls:** known DNS-cleanup edge case — deleting a server cascade-deletes domains and may orphan managed DNS records/certs (server-delete DNS leak). When auditing a delete, confirm `dns_deleted` entries actually appear for managed records; their absence is the regression to watch.

### Dashboard audit tail & source badges
- **Must:** the Overview page renders the latest audit entries with a per-entry colored `SourceBadge` (`Overview.tsx:157-199`). Known styled sources: `ui`, `api`, `mcp`, `agent`, `system`; any other value (including `dryrun`) falls back to a neutral chip (`Overview.tsx:184-193`).
- **Access:** Dashboard → Overview page (audit tail section, fetched with `limit=15`).
- **Prerequisites:** dashboard up (`make dev-sandbox` serves it) and logged in.
- **Steps:** open the dashboard Overview, scroll to the recent-activity/audit section.
- **Pass:** recent entries display newest-first with a source badge; the badge text matches the entry's `source`.
- **Coverage:** D.
- **Pitfalls:** `dryrun` has **no dedicated badge style** in `SOURCE_STYLES` — it renders with the neutral fallback chip, still labeled "dryrun". That's expected; don't treat the muted color as a missing source.

## Acceptance checklist

**Dry (every RC):**
- [ ] `GET /api/v1/health` → 200, has `status:"ok"`, `checks.database:"ok"`, non-empty `version`, and all three dry flags.
- [ ] Dry flags wire correctly: `NP_DNS_DRY_RUN` / `NP_ACME_DRY_RUN` / `NP_DRY_RUN` reflected in `dns_dry_run`/`acme_dry_run`/`dry_run`.
- [ ] Health 503 / `degraded` failure path covered by `go test ./internal/orchestrator/api/ -run Health`.
- [ ] `NP_LOG_FORMAT=json` → every stderr line is valid JSON with `component` attribute.
- [ ] `NP_LOG_LEVEL` filters (e.g. `error` suppresses INFO/DEBUG); default is info.
- [ ] Legacy `log.Printf` startup line appears as a structured JSON record.
- [ ] `agents` API returns `version_status` ∈ {current, outdated, ahead, unknown}; version-skew unit tests pass.
- [ ] `/api/v1/audit-log` default `limit=50`, clamps to ≤1000, paginates with `offset`, requires auth (401 without).
- [ ] `source` filter works; observed sources ⊆ {ui, api, mcp, agent, system, dryrun}.
- [ ] Under dry sandbox, simulated DNS/cert events are tagged `source=dryrun` (never `system`) — #93 guard.
- [ ] Audit trail covers DNS/cert/route/security/CRUD; managed-record deletes emit `dns_deleted` (server-delete DNS-leak guard).
- [ ] Dashboard Overview shows the audit tail with source badges.

**Real run (before final):**
- [ ] On a real orchestrator, `/health` reports all dry flags `false`.
- [ ] Real system DNS/cert events appear with `source:"system"` (not `dryrun`).
- [ ] Against a tagged orchestrator with a real agent, `version_status` shows a real verdict (not `unknown`); an intentionally older agent shows `outdated` and is badged in the dashboard.
- [ ] (Best-effort) confirm clock alignment before grepping logs — see gotcha below.

## Cross-cutting gotchas
- **Clock skew in logs (UTC vs local):** the orchestrator (apps-vm) logs **UTC (`…Z`)**; an agent may log **local time (e.g. `+02:00`)**. Audit-log `created_at` is always stored UTC (`audit.go:13/19`, `time.Now().UTC()` + RFC3339). When correlating an audit timestamp against an agent's own logs or grepping `journalctl --since`, convert first — otherwise you'll search the wrong window and conclude "nothing happened".
- **Tailscale ACL port for the API:** reaching `/health` or `/audit-log` over Tailscale needs `:8080` allowed in the ACL (the default grants only 22/80/443). Symptom of a blocked port: `curl … :8080` → `HTTP 000`. Same-`/24` LAN bypasses the ACL.
- **`/health` is unauthenticated; `/audit-log` is not.** Don't add an auth header to a health probe expecting it to matter, and don't forget the Bearer key on audit calls (you'll get 401).

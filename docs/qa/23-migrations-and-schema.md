# Database Migrations & Schema Integrity
> **Scope:** the SQLite schema and migration safety — every migration applies cleanly on a fresh and a populated DB without data loss, foreign-key ON DELETE behaviour is what the code says, and sensitive columns/settings are never returned by the API.
> **Code:** `internal/orchestrator/db/migrations.go` (the full ordered migration list + the `migrate()` runner), `internal/orchestrator/db/db.go` (`Open` pragmas, `SnapshotTo`), `internal/orchestrator/db/agents.go` (`agentColumns`), `internal/orchestrator/db/certificates.go`, `internal/orchestrator/db/admin_ops.go`, `internal/orchestrator/api/system.go` (settings redaction), `internal/shared/models/models.go` (`json:"-"` on sensitive fields).
> **Coverage legend:** D = coverable dry, R = needs a real run.

## Prerequisites
- Both binaries built: `make build-all` (produces `./nurproxy`, `./nurproxy-agent`).
- `sqlite3` CLI in PATH for inspecting the on-disk DB (`sqlite3 --version`).
- The whole subsystem is coverable **dry** — no real zone, ACME, root, or `:80/:443` needed. Use a dry orchestrator on a throwaway data dir:
  ```bash
  NP_DRY_RUN=true ./nurproxy -port 18081 -data-dir /tmp/np-schema
  ```
  The DB lives at `/tmp/np-schema/nurproxy.db` (data-dir + `nurproxy.db`).
- `make dev-sandbox` (seeds providers/zones/agents/servers/domains) is the fastest way to get a **populated** DB for the upgrade and FK tests. Its launcher is `scripts/dev-sandbox.sh`.

## Features covered
- [ ] Migration enumeration — all **18** migrations present, in order, with the right content (built from `migrations.go`, not from any summary).
- [ ] `migrate()` runner semantics: 1-indexed `schema_version` table, transactional per-migration, applies only `current..len(migrations)`.
- [ ] Fresh-DB migrate-clean (dry boot creates the DB from zero).
- [ ] In-place upgrade: migrations run on a populated DB without data loss.
- [ ] Append-only discipline: never edit a shipped migration; only append.
- [ ] `PRAGMA foreign_keys(1)` is on for every pooled connection (so FK ON DELETE actually fires).
- [ ] FK ON DELETE behaviour matrix: CASCADE vs SET NULL vs (implicit) RESTRICT — including the **known server/agent/zone-delete DNS/cert leak** guarded only at the application layer (409), not by the FK.
- [ ] Sensitive columns/settings never returned by the API: `token_hash`, `key_pem_enc`, `code_hash`, `admin_password_hash`, `session_secret`, `admin_api_key`.

## Tests

### Migration enumeration (count + content)
**Must:** `migrations` in `internal/orchestrator/db/migrations.go` is an ordered slice of **18** entries (index 0 → schema version 1, … index 17 → schema version 18). Verified content, from code:

| Ver | What it does (verbatim from `migrations.go`) |
|----:|----|
| 1 | Initial schema: creates `providers`, `agents`, `servers`, `domains`, `notifiers`, `audit_log`, `settings`; seeds settings `mcp_enabled='false'`, `reconciler_interval='60'`. |
| 2 | Rebuilds `agents` so `provider_id` allows NULL (pre-adoption agents have no provider): create `agents_new`, copy, drop, rename. |
| 3 | Splits zones out of providers + agent↔zone many-to-many: creates `zones`, `agent_zones`; migrates provider zone data into `zones` (reusing provider.id as zone.id); rebuilds `domains` to use `zone_id` instead of `provider_id` (`UNIQUE(subdomain, zone_id)`); rebuilds `agents` without `provider_id`; rebuilds `providers` without `zone_id`/`zone_name`. |
| 4 | Adds `agents.caddy_running` (default 1), `agents.last_error`, `agents.dns_error`; seeds setting `agent_offline_timeout='90'`. |
| 5 | Adds `audit_log.source` (default `''`). |
| 6 | Phase-0 proxy detection columns on `agents`: `detected_proxy_kind`, `detected_proxy_version`, `detected_binary_path`, `detected_config_dir`, `detected_log_paths`, `detected_port_conflicts`, `detected_installed` (default 0), `detected_at` (nullable). |
| 7 | Adds `agents.detected_capabilities` (nullable JSON). |
| 8 | Central managed-config store: creates `config_artifacts` (+ indexes `idx_config_artifacts_agent`, `idx_config_artifacts_domain`) and `config_artifact_versions` (+ index `idx_config_artifact_versions_artifact`). |
| 9 | Adds `agents.auto_reconcile_config` (default 0). |
| 10 | Central TLS cert store: creates `certificates` (`UNIQUE(host)`) + index `idx_certificates_expires`. |
| 11 | Agent admin-op channel: creates `agent_admin_ops` + index `idx_agent_admin_ops_agent_status`. |
| 12 | Adds `agents.proxy_mode` (default `'built-in'`). |
| 13 | Adds `agents.proxy_permissions` (nullable JSON). |
| 14 | Adds `config_artifacts.drift_content` (default `''`). |
| 15 | Adds `agents.detected_upstreams` (default `''`). |
| 16 | Adds `agents.detected_networks` (default `''`). |
| 17 | Adds `domains.dns_managed` (default 0). |
| 18 | IPv6: adds `agents.public_ip6` and `agents.dns_record_id6` (both default `''`). |

> Note: the in-code comments label the last entries "Migration 11"…"Migration 18" while 1–10 use zero-padded "001"…"010"; the **index position** is what matters, not the comment text.

**Access:** source only (`migrations.go`); runtime check via boot logs and `sqlite3`.
**Prerequisites:** none beyond file-level.
**Steps:**
```bash
# Count entries (count the migration comment markers; expect 18)
grep -cE '^[[:space:]]*// Migration' internal/orchestrator/db/migrations.go

# Boot a fresh dry orchestrator, then read the recorded schema version
rm -rf /tmp/np-schema && NP_DRY_RUN=true ./nurproxy -port 18081 -data-dir /tmp/np-schema &
sleep 3
sqlite3 /tmp/np-schema/nurproxy.db "SELECT MAX(version) FROM schema_version;"   # expect 18
sqlite3 /tmp/np-schema/nurproxy.db ".tables"
```
**Pass:** grep prints `18`; `MAX(version)` is `18`; `.tables` lists `providers agents servers domains notifiers audit_log settings zones agent_zones config_artifacts config_artifact_versions certificates agent_admin_ops schema_version`.
**Coverage:** D.
**Pitfalls:** the comment numbering is inconsistent (001-padded then 11-18 unpadded) — do not let it make you miscount; trust the slice length / `MAX(version)`. If a new migration was appended after this doc, the expected number is `len(migrations)`; update both this table and the expected `18` together.

### `migrate()` runner semantics
**Must:** `migrate()` (`migrations.go:453`) creates a `schema_version` table, reads `COALESCE(MAX(version),0)` as `current`, then for `i := current; i < len(migrations)` runs `migrations[i]` **inside its own transaction**, records `version = i+1`, and commits. A failing migration `Rollback()`s and aborts the boot (`Open` returns the wrapped error, see `db.go:55`). It is 1-indexed and append-only by construction: lowering `current` is never done, and already-applied indices are skipped.
**Access:** source + boot behaviour.
**Prerequisites:** none.
**Steps:**
```bash
# Already-migrated DB: a second boot applies nothing new
NP_DRY_RUN=true ./nurproxy -port 18082 -data-dir /tmp/np-schema 2>&1 | grep -iE "migrat" || echo "no migration log on already-current DB (expected)"
sqlite3 /tmp/np-schema/nurproxy.db "SELECT version FROM schema_version ORDER BY version;"
```
**Pass:** `schema_version` has exactly one row per applied migration `1..18`, monotonically increasing, no gaps, no duplicates; re-boot does not add rows.
**Coverage:** D.
**Pitfalls:** each migration runs in **one** `tx.Exec` of the whole multi-statement string — a syntax error anywhere rolls the whole migration back. SQLite `ALTER TABLE ADD COLUMN` cannot be split mid-migration; keep each migration self-contained.

### Fresh-DB migrate-clean
**Must:** booting against a non-existent DB path creates the file and applies all migrations from 0 to 18 with no error.
**Access:** `NP_DRY_RUN=true ./nurproxy -data-dir <empty dir>`.
**Prerequisites:** the data dir must not contain a stale `nurproxy.db`.
**Steps:**
```bash
rm -rf /tmp/np-fresh
NP_DRY_RUN=true ./nurproxy -port 18083 -data-dir /tmp/np-fresh &
sleep 3
curl -s localhost:18083/api/v1/health        # database:ok
sqlite3 /tmp/np-fresh/nurproxy.db "SELECT MAX(version) FROM schema_version;"   # 18
```
**Pass:** `/api/v1/health` reports `database` healthy and `MAX(version)=18`; orchestrator stays up.
**Coverage:** D.
**Pitfalls:** `/api/v1/health` returns **503** when the DB is wedged (`db.go:71` `Ping` runs a real `SELECT 1`, not a pool check) — a 503 here means migration/open failed, read the boot log.

### In-place upgrade (populated DB, no data loss)
**Must:** an existing DB at an older schema version is upgraded by running only the outstanding migrations; all rows survive and remain valid (this is the real cross-link to RELEASE-QA §2.11 in-place upgrade).
**Access:** stop old binary → swap → start new binary on the same data dir.
**Prerequisites:** a populated DB. Easiest: `make dev-sandbox` to seed, then point a new binary at that data dir; or hand-seed via the API.
**Steps:**
```bash
# 1. Populate: bring up the seeded sandbox, note its data dir from the launcher output.
make dev-sandbox            # leaves a seeded dry stack up (KEEP defaults to keep)
# 2. Snapshot the populated DB and capture row counts BEFORE upgrade.
DB=<sandbox-data-dir>/nurproxy.db
for t in providers zones agents servers domains certificates config_artifacts audit_log; do
  echo -n "$t="; sqlite3 "$DB" "SELECT COUNT(*) FROM $t;"
done
# 3. Stop, swap in the new binary, restart on the SAME data dir, then re-count.
```
**Pass:** every table's row count is unchanged after the new binary boots; `MAX(version)` is the new `len(migrations)`; `/api/v1/health` is `database:ok`; reconciler loads the seeded domains/agents.
**Coverage:** D (dry DB). For a real-DB upgrade with live traffic continuity, see RELEASE-QA §2.11 (R).
**Pitfalls:** migrations 2 and 3 do **table rebuilds** (`CREATE _new`, `INSERT … SELECT`, `DROP`, `RENAME`) — the column lists in their `INSERT … SELECT` must match exactly or data is dropped silently. When verifying an upgrade that crosses those versions, count rows in `agents`, `domains`, `providers` specifically. Always back up the data dir before upgrading a real DB (`nurproxy backup`, RELEASE-QA §2.9).

### Append-only migration discipline
**Must:** a shipped migration is **never edited** — only new entries are appended. Editing migration `i` would not re-run on any DB that already recorded version `i+1` (the runner skips `i < current`), so the change silently never lands on upgraded installs while applying on fresh ones — schema divergence.
**Access:** code review / git.
**Prerequisites:** none.
**Steps:**
```bash
# Guard: confirm no shipped migration string was modified in this release.
git log --oneline -p -- internal/orchestrator/db/migrations.go | grep -nE '^\-.*ALTER TABLE|^\-.*CREATE TABLE' | head
```
**Pass:** the diff for `migrations.go` in the release range only **adds** trailing slice entries; no removed/changed lines inside existing migration strings (additions to the slice are fine; the `// Migration NN` markers and `}` close move down, which is expected).
**Coverage:** D.
**Pitfalls:** the only legitimate "edit" of an old migration is whitespace inside the closing slice region; any change to SQL inside an existing entry is a release blocker.

### `PRAGMA foreign_keys` is on for every connection
**Must:** FK enforcement is on, so the ON DELETE clauses below actually fire. `Open` puts `foreign_keys(1)` (plus `busy_timeout(5000)`, `journal_mode(WAL)`) **in the DSN** so every pooled connection inherits it, and caps the pool at one connection (`db.go:28,41`). A per-connection `Exec("PRAGMA foreign_keys=ON")` would only configure one pool connection — the DSN form is deliberate.
**Access:** `sqlite3` against a running/idle DB.
**Prerequisites:** a DB file from any boot above.
**Steps:**
```bash
sqlite3 /tmp/np-schema/nurproxy.db "PRAGMA foreign_keys;"   # note: this is the CLI's own session
grep -n "foreign_keys(1)" internal/orchestrator/db/db.go
```
**Pass:** the DSN in `db.go` contains `_pragma=foreign_keys(1)`; pool is `SetMaxOpenConns(1)`.
**Coverage:** D.
**Pitfalls:** the `sqlite3` CLI does **not** inherit the app's DSN pragmas — `PRAGMA foreign_keys` in a bare CLI session reports the CLI default (off), which is **not** what the app uses. Verify the app's behaviour by source (`db.go:28`), not by the CLI session value.

### FK ON DELETE behaviour matrix (incl. the known DNS/cert leak)
**Must:** the actual ON DELETE clauses in the CREATE TABLE statements, from `migrations.go`:

| Child table.column | References | ON DELETE | Source |
|---|---|---|---|
| `servers.agent_id` | `agents(id)` | **CASCADE** | mig 1, `migrations.go:42` |
| `domains.server_id` | `servers(id)` | **CASCADE** | mig 1 + 3, `migrations.go:53,162` |
| `domains.provider_id` (v1) / `domains.zone_id` (v3+) | `providers(id)` / `zones(id)` | *(none → implicit RESTRICT/NO ACTION)* | `migrations.go:52,161` |
| `domains.zone_id` | `zones(id)` | *(none → implicit RESTRICT)* | `migrations.go:161` |
| `zones.provider_id` | `providers(id)` | *(none → implicit RESTRICT)* | `migrations.go:131` |
| `agent_zones.agent_id` | `agents(id)` | **CASCADE** | mig 3, `migrations.go:139` |
| `agent_zones.zone_id` | `zones(id)` | **CASCADE** | mig 3, `migrations.go:140` |
| `agents.provider_id` (v1/v2 only; removed in v3) | `providers(id)` | *(none)* | `migrations.go:28,108` |
| `config_artifacts.agent_id` | `agents(id)` | **CASCADE** | mig 8, `migrations.go:296` |
| `config_artifacts.domain_id` (nullable) | `domains(id)` | **SET NULL** | mig 8, `migrations.go:301` |
| `config_artifact_versions.artifact_id` | `config_artifacts(id)` | **CASCADE** | mig 8, `migrations.go:318` |

`certificates` and `agent_admin_ops` declare **no** FK constraints (`agent_admin_ops.agent_id` is a plain `TEXT NOT NULL`, no `REFERENCES` — `migrations.go:374`); they are not cascade-cleaned by the DB.

**KNOWN ISSUE (regression-guard, cross-link to teardown spec / RELEASE-QA §2.4):** deleting a **server / agent / zone** that still has domains is refused **only by an application-layer 409 guard**, not by the FK. The chain `agents → servers → domains` is `ON DELETE CASCADE`, so a **direct DB delete** (`DELETE FROM agents …` via `sqlite3`) cascades through servers into domains and **orphans those domains' managed DNS records and certs** — they were never torn down via the reconciler, so the records/certs leak. The certs live in `certificates` (no FK) and the managed-DNS-record IDs live on the now-deleted `domains` rows. The `RESTRICT` follow-up (make the FK itself block the delete) is still open.

**Access:** `sqlite3` to demonstrate the raw cascade; the REST API (`DELETE /api/v1/servers/{id}` etc.) for the 409 guard.
**Prerequisites:** a DB with an agent → server → domain chain (use the sandbox seed, or create via API).
**Steps:**
```bash
# 1. The application guard (correct behaviour): delete a server while a domain exists.
curl -s -X DELETE localhost:18081/api/v1/servers/<server-id> -H "X-API-Key: $KEY" -w " http=%{http_code}\n"
#    -> 409 with body listing the blocking domains.

# 2. The raw-cascade leak (DO NOT do this on prod). On a throwaway dry DB:
sqlite3 "$DB" "PRAGMA foreign_keys=ON; SELECT COUNT(*) FROM domains;"   # before
sqlite3 "$DB" "PRAGMA foreign_keys=ON; DELETE FROM agents WHERE id='<agent-id>';"
sqlite3 "$DB" "SELECT COUNT(*) FROM domains;"                          # after: dropped via CASCADE
sqlite3 "$DB" "SELECT COUNT(*) FROM certificates;"                     # cert rows: NOT removed (orphaned/leak)
```
**Pass:** API path returns **409** and the domain/server/agent/zone is **not** deleted while children exist. The raw-`sqlite3` path demonstrates the cascade and the orphaned `certificates` rows — confirming the leak is FK-level, the guard is app-level.
**Coverage:** D.
**Pitfalls:**
- Domain delete is **soft** (`status=deleting`); the 409 guard counts `deleting` rows too, so a parent delete right after a domain delete correctly 409s until the reconciler finishes (RELEASE-QA §2.4).
- Do not "fix" a perceived leak by hand-deleting rows in prod — that **is** the leak path. Always delete via the API so the reconciler tears down DNS + cert first.
- `agent_admin_ops` has no FK, so deleting an agent leaves stale admin-op rows; they expire by status, not by cascade.

### Sensitive columns / settings never returned by the API
**Must:** these never appear in any API response body:
- `agents.token_hash` — model field `TokenHash` is `json:"-"` (`models.go:233`).
- `certificates.key_pem_enc` — model field `KeyPEM` is `json:"-"` (`models.go:566`); `cert_pem` (public) **is** returned (`json:"cert_pem"`, `models.go:563`).
- `agent_admin_ops.code_hash` — model field `CodeHash` is `json:"-"` (`models.go:612`); the plaintext code is shown **once** at mint time only.
- settings `admin_password_hash`, `admin_api_key`, `session_secret` — filtered out of `GET /api/v1/settings` (`system.go:121`) and blocked from `PUT /api/v1/settings/{key}` (403, `system.go:143-153`).

**Access:** REST API (`GET /api/v1/agents`, `GET /api/v1/certificates`, `GET /api/v1/settings`, `GET /api/v1/agents/{id}/admin-ops` where applicable); Dashboard renders the same JSON.
**Prerequisites:** a dry orchestrator with an admin password set and an API key minted; at least one agent + central-TLS domain so a cert and token_hash exist (the sandbox seed covers this).
**Steps:**
```bash
KEY=<admin api key>
# token_hash must be absent
curl -s localhost:18081/api/v1/agents -H "X-API-Key: $KEY" | grep -c token_hash      # expect 0
# key_pem_enc absent, cert_pem present
curl -s localhost:18081/api/v1/certificates -H "X-API-Key: $KEY" | grep -c key_pem    # expect 0
curl -s localhost:18081/api/v1/certificates -H "X-API-Key: $KEY" | grep -c cert_pem   # >=1 if a cert exists
# settings redaction
curl -s localhost:18081/api/v1/settings -H "X-API-Key: $KEY" | grep -cE "admin_password_hash|admin_api_key|session_secret"   # expect 0
# settings write is blocked
curl -s -X PUT localhost:18081/api/v1/settings/admin_password_hash -H "X-API-Key: $KEY" -d '{"value":"x"}' -w " http=%{http_code}\n"   # 403
```
**Pass:** `token_hash`, `key_pem_enc`/`key_pem`, `code_hash`, and the three sensitive settings keys are absent from response bodies; `cert_pem` is present; `PUT` of a sensitive setting returns **403**.
**Coverage:** D.
**Pitfalls:** the secrets exist in the DB (`sqlite3` can read `token_hash`, `key_pem_enc`, the settings rows) — that is correct (hashes / AES-256-GCM ciphertext at rest). The guarantee is only about the **API surface**. `key_pem_enc` is the base64 AES-256-GCM ciphertext (decryptable only with the data dir's `encryption.key`); never log or export it. When grepping API output, grep for `token_hash`/`key_pem` substrings, not the Go field names (`TokenHash`/`KeyPEM`) — the JSON tags differ from the field names.

## Acceptance checklist

**Dry (every RC):**
- [ ] `len(migrations) == 18` (`grep -cE '^[[:space:]]*// Migration'`) and a fresh dry boot records `MAX(version)=18`.
- [ ] Fresh-DB migrate-clean: empty data dir boots to `database:ok`, all expected tables present.
- [ ] In-place upgrade on a seeded sandbox DB: row counts for `providers/zones/agents/servers/domains/certificates/config_artifacts/audit_log` unchanged; version bumped.
- [ ] Append-only: `migrations.go` diff in the release range adds only trailing slice entries; no edits inside shipped migrations.
- [ ] `db.go` DSN still contains `_pragma=foreign_keys(1)` and `SetMaxOpenConns(1)`.
- [ ] FK matrix matches the table above (re-read the CREATE TABLE clauses if any migration touched a table).
- [ ] 409 parent-delete guard blocks server/agent/zone delete while domains exist (RELEASE-QA §2.4).
- [ ] Known leak still acknowledged: raw `DELETE FROM agents` cascades into domains and orphans `certificates` (regression-guard until the RESTRICT follow-up lands).
- [ ] API hides `token_hash`, `key_pem_enc`, `code_hash`, `admin_password_hash`, `admin_api_key`, `session_secret`; `cert_pem` still returned; sensitive-setting `PUT` → 403.

**Real run (before final):**
- [ ] In-place upgrade on the **real** prod DB (apps-vm): `nurproxy backup` first, swap binary, migrations clean, agents reconnect, no traffic drop (RELEASE-QA §2.11).

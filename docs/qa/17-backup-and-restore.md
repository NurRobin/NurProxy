# Backup & Restore

> **Scope:** the `nurproxy backup` / `nurproxy restore` data-dir snapshot round-trip — what the archive captures, the restore safety guards (no-clobber, path-traversal rejection), and verifying a restored dir boots and decrypts cleanly in dry mode.
> **Code:** `cmd/nurproxy/backup.go` (backup + restore commands), `internal/orchestrator/db/db.go` `SnapshotTo` (consistent DB snapshot via `VACUUM INTO`), `cmd/nurproxy/main.go` (subcommand dispatch at `main.go:53-57` + data-dir resolution + key load), `internal/orchestrator/api/system.go` `handleHealth`, `internal/orchestrator/api/auth.go` `handleAuthStatus`, `internal/orchestrator/db/providers.go` `GetProvider` (provider-config decrypt).
> **Coverage legend:** D = coverable dry, R = needs a real run.

## Prerequisites
- `nurproxy` binary built: `make build` (orchestrator binary; backup/restore are subcommands of it — there is no separate tool). Run all `nurproxy` commands from a dir containing the binary or use an absolute path.
- A data dir to back up. Two options:
  - **Dry data dir** (D, every RC): `make dev-sandbox` (seeds a provider/zone/agents/servers/domains and writes `nurproxy.db` + `encryption.key` under the sandbox data dir), or boot a dry orchestrator by hand: `NP_DRY_RUN=true NP_DATA_DIR=/tmp/np-src ./nurproxy` then create entities via the API/CLI. A dry boot generates `encryption.key`; it does **not** generate `acme-account.key` unless ACME issuance ran, so a dry backup may legitimately omit that key (see Pitfalls).
  - **Real data dir** (R, before final): a live orchestrator's data dir (e.g. on apps-vm, default `./data` or `$NP_DATA_DIR`) containing `nurproxy.db`, `encryption.key`, and `acme-account.key`.
- `tar`, `gzip`, `sha256sum` available for inspecting/verifying archives.
- Know the data-dir resolution order (`cmd/nurproxy/backup.go:30-38`): `--data-dir` flag → `$NP_DATA_DIR` → `./data`. Same order for backup and restore.

## Features covered
- [ ] `nurproxy backup` writes a flat gzipped tar (`.tar.gz`) of `nurproxy.db` + `encryption.key` + `acme-account.key`.
- [ ] Default output name `nurproxy-backup-YYYYMMDD-HHMMSS.tar.gz` (UTC); `-o` overrides.
- [ ] `--data-dir` flag / `$NP_DATA_DIR` / `./data` resolution.
- [ ] DB captured as a consistent snapshot via `VACUUM INTO` (safe while orchestrator is live; no `-wal`/`-shm` sidecars in the archive).
- [ ] Missing-key warning (key file absent → warns to stderr, omits from archive, backup still succeeds).
- [ ] Backup fails cleanly when there is no DB at the data dir.
- [ ] Archive + restored files written `0600`.
- [ ] `nurproxy restore` refuses to overwrite an existing DB without `--force`.
- [ ] `nurproxy restore` with `--force` overwrites.
- [ ] Restore rejects path-traversal / unexpected entries (only the three known flat filenames are extracted).
- [ ] Restore fails when the archive contains no recognizable NurProxy files.
- [ ] Restore reports the file count and a "start the orchestrator" hint.
- [ ] Round-trip verify: restored key checksums match originals; dry boot on the restored dir → `/health database:ok`, `auth/status setup_required:false`, reconciler loads entities and decrypts the provider config (proves `encryption.key` round-tripped).

## Tests

### Backup: file set, naming, and `-o`
- **Must:** `nurproxy backup` writes a gzipped tar containing exactly the present subset of `nurproxy.db`, `encryption.key`, `acme-account.key` as flat top-level entries (`cmd/nurproxy/backup.go:22-26,93-108`). With no `-o`, the file is named `nurproxy-backup-<UTC timestamp>.tar.gz` using layout `20060102-150405` (`backup.go:53-55`). On success it prints `Backup written to <path>` (`backup.go:60`).
- **Access:** CLI only. `nurproxy backup [--data-dir DIR] [-o OUTFILE]` (`backup.go:45-49`). No dashboard, API, or MCP surface.
- **Prerequisites:** a data dir with `nurproxy.db` present (dry or real).
- **Steps:**
  ```bash
  # Dry source dir
  NP_DATA_DIR=/tmp/np-src ./nurproxy backup -o /tmp/np.tar.gz
  tar -tzf /tmp/np.tar.gz                 # list entries
  # Default-name form (run in a scratch dir):
  ( cd /tmp && NP_DATA_DIR=/tmp/np-src /path/to/nurproxy backup ) && ls /tmp/nurproxy-backup-*.tar.gz
  ```
- **Pass:** archive lists `nurproxy.db` and `encryption.key` (and `acme-account.key` if it existed) as flat names with no leading dirs and no `-wal`/`-shm` files. Default-name file matches `nurproxy-backup-YYYYMMDD-HHMMSS.tar.gz` with the timestamp in UTC.
- **Coverage:** D (dry source dir). Backup of a live **real** DB is R.
- **Pitfalls:** the timestamp is **UTC** (`time.Now().UTC()`), not local — don't flag a "wrong" clock. The output file is opened `O_TRUNC` (`backup.go:84`) so an existing `-o` target is silently overwritten.

### Backup: consistent DB snapshot while live
- **Must:** the DB is not copied byte-for-byte; it is written via SQLite `VACUUM INTO` to a temp file, then archived (`backup.go:74-95`, `db.go:76-93` — the `VACUUM INTO ?` call is at `db.go:89`). This produces a fully checkpointed single file safe to take from a separate process against a live WAL DB, with no `-wal`/`-shm` sidecars (per `db.go:76-81`). `VACUUM INTO` refuses to overwrite, hence the fresh temp path.
- **Access:** CLI: `nurproxy backup` (no special flag).
- **Prerequisites:** for the live test (R), a running orchestrator writing to the same DB.
- **Steps (R):**
  ```bash
  # On the host with the live orchestrator (real DB):
  ./nurproxy backup --data-dir /path/to/live/data -o /tmp/live.tar.gz
  tar -tzf /tmp/live.tar.gz                # no nurproxy.db-wal / -shm entries
  ```
- **Pass:** backup succeeds while the service is running; archive contains a single `nurproxy.db` and no WAL/SHM sidecars.
- **Coverage:** R (live DB) — the snapshot mechanism itself is exercised by every dry backup too (D).
- **Pitfalls (from RELEASE-QA §2.9):** a live-DB backup with WAL active is fine for the test; for a **guaranteed**-consistent operational snapshot, stop the service first. The temp snapshot dir is created under the OS temp dir and removed afterward (`backup.go:74-78`) — ensure `$TMPDIR` has room for a DB-sized copy.

### Backup: missing-key warning and no-DB error
- **Must:** if a key file (`encryption.key` or `acme-account.key`) is absent, backup prints `backup: warning: <name> not found, omitting from archive` to **stderr**, skips it, and still succeeds (`backup.go:99-104`). If there is no `nurproxy.db` at the data dir, backup fails with `no database at <path> (is the data dir correct?)` (`backup.go:67-69`).
- **Access:** CLI: `nurproxy backup`.
- **Prerequisites:** a data dir missing one or both keys (a dry boot that never issued ACME typically has no `acme-account.key`); and a separate empty/wrong dir for the no-DB case.
- **Steps:**
  ```bash
  NP_DATA_DIR=/tmp/np-src ./nurproxy backup -o /tmp/np.tar.gz   # observe stderr warning if a key is absent
  ./nurproxy backup --data-dir /tmp/does-not-exist -o /tmp/x.tar.gz  # expect failure, no archive
  ```
- **Pass:** missing-key case → warning on stderr, exit success, archive omits that key. No-DB case → non-zero exit, error message naming the missing DB path, no archive written.
- **Coverage:** D.
- **Pitfalls — UNVERIFIED:** RELEASE-QA §2.9 and the task brief mention a **"plaintext-key warning" / "plaintext-key risk"**. The current `backup.go` emits **only** the "not found, omitting" warning — there is **no** plaintext/at-risk warning in the code (grep for `plaintext`/`unencrypted` in `cmd/nurproxy/` returns nothing). Treat the plaintext-key warning as **not implemented / UNVERIFIED** and do not assert it. The real risk it alludes to is genuine: `encryption.key` is the cleartext master key that decrypts every provider token and TLS private key in the DB, so the archive (mode `0600`) must be handled as a secret.

### Restore: no-clobber guard and `--force`
- **Must:** `nurproxy restore <archive>` refuses to extract if the target data dir already contains `nurproxy.db`, failing with `<dir> already has a nurproxy.db — refusing to overwrite (pass --force to replace it)` (`backup.go:147-149`). `--force` overrides the guard (`backup.go:126,134`). On success it prints `Restored <n> file(s) into <dir>` and `Start the orchestrator against this data dir to bring it back up.` (`backup.go:138-139`).
- **Access:** CLI only. `nurproxy restore [--data-dir DIR] [--force] ARCHIVE` (`backup.go:123-127`). Exactly one archive argument is required; otherwise it errors `exactly one archive argument is required` (`backup.go:129-131`).
- **Prerequisites:** a valid backup archive (from the backup test) and an empty target dir.
- **Steps:**
  ```bash
  mkdir -p /tmp/np-dst
  ./nurproxy restore --data-dir /tmp/np-dst /tmp/np.tar.gz     # first time: succeeds
  ./nurproxy restore --data-dir /tmp/np-dst /tmp/np.tar.gz     # second time: refuses (DB exists)
  ./nurproxy restore --data-dir /tmp/np-dst --force /tmp/np.tar.gz   # overwrites
  ./nurproxy restore --data-dir /tmp/np-dst                    # no archive arg: errors
  ```
- **Pass:** first restore prints the file count + start hint; second restore exits non-zero with the no-clobber message and leaves the dir unchanged; `--force` restore succeeds; missing-arg invocation errors.
- **Coverage:** D.
- **Pitfalls:** the no-clobber check keys on `nurproxy.db` existence only — a dir with stray keys but no DB will restore without `--force`. Restore writes files `0600` (`backup.go:223-224`) and `mkdir`s the data dir `0700` (`backup.go:163`).

### Restore: path-traversal / unexpected-entry rejection
- **Must:** restore only honors the three known flat filenames (`nurproxy.db`, `encryption.key`, `acme-account.key`); any entry that is not a regular file, or whose name differs from its base name (i.e. contains a path / `../` / is absolute), or is not in the allowlist is skipped with `restore: skipping unexpected entry "<name>"` on stderr (`backup.go:167,178-184`). If nothing recognizable was extracted, restore fails with `archive contained no recognizable NurProxy files` (`backup.go:191-193`).
- **Access:** CLI: `nurproxy restore`.
- **Prerequisites:** a hand-crafted malicious/junk archive.
- **Steps:**
  ```bash
  # Build an archive with a traversal entry and a junk file
  mkdir -p /tmp/evil && echo pwned > /tmp/evil/payload
  tar -czf /tmp/evil.tar.gz --transform 's,.*,../../etc/whatever,' -C /tmp/evil payload
  ./nurproxy restore --data-dir /tmp/np-dst2 /tmp/evil.tar.gz   # expect: skip messages + "no recognizable files" failure
  ls -la /tmp/np-dst2   # nothing written outside the data dir; no traversal file created
  ```
- **Pass:** the traversal/junk entries are skipped (stderr messages), nothing is written outside the data dir, and (since no allowed file was present) restore exits non-zero with `archive contained no recognizable NurProxy files`.
- **Coverage:** D.
- **Pitfalls:** the guard is `filepath.Base(hdr.Name)` + `name != hdr.Name` + allowlist (`backup.go:180-181`). A correctly-named-but-foreign archive (e.g. someone else's `nurproxy.db`) is NOT rejected by this check — that's a legitimate cross-restore; the safety is purely against escaping the data dir and stray files.

### Round-trip verify: checksums + dry boot + decrypt
- **Must:** restored `encryption.key` / `acme-account.key` byte-match the originals, and a fresh orchestrator booted on the restored dir comes up healthy with all entities present and decryptable. This is the load-bearing acceptance test for the whole feature.
- **Access:** CLI (`backup`/`restore`) + the orchestrator's `/api/v1/health` and `/api/v1/auth/status` endpoints for assertions.
- **Prerequisites:** a source dir with entities (a `make dev-sandbox` data dir, or a dry orchestrator you populated with a provider + agent + server + domain).
- **Steps (D):**
  ```bash
  # 1. Back up the source dir
  NP_DATA_DIR=/tmp/np-src ./nurproxy backup -o /tmp/np.tar.gz
  # 2. Restore into a fresh temp dir
  rm -rf /tmp/np-restored && ./nurproxy restore --data-dir /tmp/np-restored /tmp/np.tar.gz
  # 3. Key checksums must match the originals
  sha256sum /tmp/np-src/encryption.key /tmp/np-restored/encryption.key
  # (and acme-account.key if present in both)
  # 4. Boot a DRY orchestrator on the restored dir, on a spare port
  NP_DRY_RUN=true NP_DATA_DIR=/tmp/np-restored NP_PORT=8099 ./nurproxy &
  sleep 2
  # 5. Health: database ok
  curl -s localhost:8099/api/v1/health
  # 6. Auth: setup not required (admin hash survived)
  curl -s localhost:8099/api/v1/auth/status
  # 7. Entities present + provider decrypts (log in or reuse a session cookie for these authed routes):
  #    GET /api/v1/providers, /api/v1/agents, /api/v1/domains
  # 8. Tear down
  kill %1
  ```
- **Pass:**
  - Step 3: identical SHA-256 for each key present in both dirs.
  - Step 5: HTTP 200, body `"status":"ok"` with `"checks":{"database":"ok"}` and `"dry_run":true` (`system.go:19-33`).
  - Step 6: `"setup_required":false` (an admin password was configured in the source DB; `auth.go:33-36`).
  - Step 7: providers/agents/domains lists return the source entities; the orchestrator log shows reconciler cycles running without decryption errors — confirming `encryption.key` round-tripped. Provider configs (tokens) are AES-256-GCM encrypted at rest and decrypted in `db.GetProvider` (`db/providers.go:60`, `crypto.DecryptString`), which the reconciler calls each cycle (`reconciler.go:659`); cert private keys are decrypted the same way in `db/certificates.go:163`. A wrong/missing `encryption.key` surfaces either as `GET /api/v1/providers` returning a decrypt error or as reconciler decrypt-failure log lines.
- **Coverage:** D (the dry boot is the whole point — it exercises decryption with zero external deps). Backing up the **real** DB is R, but verifying the restore is always done **dry**.
- **Pitfalls (HARD WARNING, from RELEASE-QA §2.9 + §summary):**
  - **NEVER** boot the restored **real** data with a **non-dry** orchestrator on the same tailnet. Two live orchestrators sharing the same Cloudflare zone + the same adopted agents will fight over DNS records and agent control — you get record flapping and split-brain pushes. Always restore-verify with `NP_DRY_RUN=true` and on a spare port (`NP_PORT`).
  - When the DB ping fails the health body reports `"status":"degraded"` and HTTP **503** (not `"down"`/`"ok"`; `system.go:27-31`) — assert `database:ok`, don't assume a `down` string.
  - If the source was a fresh dry boot that never set an admin password, step 6 will return `"setup_required":true` — that's correct for that source, not a restore failure. Use a populated source for the meaningful assertion.
  - A backup that omitted `acme-account.key` (warned at backup time) restores fine but the orchestrator will mint a **new** ACME account on next real issuance — fine for dry verify, relevant for real disaster recovery.

## Acceptance checklist

### Dry (every RC)
- [ ] `nurproxy backup -o f.tar.gz` produces a flat tar with `nurproxy.db` + `encryption.key` (+ `acme-account.key` if present), no WAL/SHM sidecars.
- [ ] Default-name backup matches `nurproxy-backup-YYYYMMDD-HHMMSS.tar.gz` (UTC).
- [ ] Missing-key → stderr warning, archive still written; missing-DB → clean failure, no archive.
- [ ] `nurproxy restore` into an empty dir succeeds and prints file count + start hint.
- [ ] Restore into a dir that already has `nurproxy.db` is refused without `--force`; `--force` overwrites.
- [ ] Path-traversal / junk archive → entries skipped, nothing escapes the data dir, `no recognizable NurProxy files` failure.
- [ ] Round-trip: restored key checksums match originals.
- [ ] Dry boot on restored dir → `/health` 200 `database:ok` `dry_run:true`; `/auth/status` `setup_required:false`; providers/agents/domains present; reconciler runs with no decrypt errors.

### Real run (before final)
- [ ] `nurproxy backup` against the **live** real DB while the orchestrator is running succeeds and yields a checkpointed single-file `nurproxy.db` (no sidecars).
- [ ] Restore-verify of that real archive performed **dry only** (never a second live orchestrator on the tailnet).

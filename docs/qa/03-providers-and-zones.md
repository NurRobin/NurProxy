# DNS Providers & Zones

> **Scope:** configuring DNS providers (Cloudflare) and zones — the provider interface, config validation, encryption at rest, zone CRUD, and the delete guards.
> **Code:** `internal/provider/provider.go`, `internal/provider/cloudflare/cloudflare.go`, `internal/provider/dryrun/dryrun.go`, `internal/orchestrator/api/providers.go`, `internal/orchestrator/api/zones.go`, `internal/orchestrator/db/providers.go`, `internal/orchestrator/db/zones.go`, `internal/orchestrator/db/db.go`, `internal/orchestrator/db/migrations.go`, `cmd/nurproxy/cli_commands.go`.
> **Coverage legend:** D = coverable dry, R = needs a real run.

## Prerequisites
- Both binaries built: `make build-all` (produces `./nurproxy` and `./nurproxy-agent`).
- For dry tests: the sandbox stack up, or a dry orchestrator by hand. Fastest path:
  `make dev-sandbox` (orchestrator + 1 agent, seeded provider/zone/agents). See
  `CLAUDE.md` "Dry-run / Sandbox". The seed already creates a Cloudflare-type
  provider (dummy token) and a zone, so you can verify list/test/delete immediately.
- An admin API key / session. The CLI reads it the same way every other command
  does (`parseClient` → `registerClientFlags`, `cmd/nurproxy/cli.go:64-67`): the
  shared flags are `-url` (base URL, env `NP_API_URL`, default
  `http://localhost:8080`), `-key` (admin API key, env `NP_API_KEY`) and
  `-password` (env `NP_API_PASSWORD`, login-based). So configure `nurproxy` with
  e.g. `-url http://localhost:8080 -key np_ak_…` (or the matching env vars). The
  `-key` value rides the wire as `Authorization: Bearer <key>` (`cli.go:21`); the
  `curl` examples below use that header directly. All `/api/v1/...` routes are
  behind `requireAuth` (`internal/orchestrator/api/server.go:146-158`).
- For **real** Cloudflare tests only: a real CF API token with `Zone:Read` (validation
  lists zones) and `DNS:Edit` (record CRUD), plus a real zone. Never needed for dry.

## Features covered
- [ ] Provider interface contract: `Info`, `ConfigSchema`, `ValidateConfig`, `ListZones`, `CreateRecord`, `UpdateRecord`, `DeleteRecord`, `GetRecord`, `ListRecords` (`provider.go`).
- [ ] Provider registry: `Register` / `Get` / `List`; unknown type rejected.
- [ ] `ProviderInfo.SupportsTXT()` (gates DNS-01 vs HTTP-01 fallback).
- [ ] Cloudflare config schema: `api_token` required, `zone_id` optional.
- [ ] Cloudflare `ValidateConfig` (validates by listing zones; works for user- and account-owned tokens).
- [ ] Cloudflare `ListZones` pagination.
- [ ] Cloudflare record CRUD + `zone_id` requirement on record ops.
- [ ] Cloudflare `Proxied` flag pass-through.
- [ ] Cloudflare `ErrRecordNotFound` mapping (API code 81044 → idempotent delete).
- [ ] dryrun decorator: in-memory store, synthetic zone/IDs, per-zone bucketing, `Reset()`, record-shape validation, forgiving delete.
- [ ] dryrun wrapping via `NP_DNS_DRY_RUN` / `NP_DRY_RUN` (provider setup needs no live creds).
- [ ] Provider config encryption at rest (AES-256-GCM via `encryption.key`).
- [ ] Provider config stripped from API responses (list / get).
- [ ] `GET/POST/PUT/DELETE /providers`, `POST /providers/test`, `GET /providers/{id}/zones`.
- [ ] `GET/POST /zones`, `POST /zones/batch`, `DELETE /zones/{id}` + delete guard.
- [ ] Provider-delete guard (provider still referenced by zones).
- [ ] CLI: `nurproxy provider add/list/delete/zones`, `nurproxy zone add/list/delete`.
- [ ] `Provider.is_default` flag surfaced in list output; `DB.SetDefaultProvider` exists but is **not** wired to any REST endpoint or CLI subcommand (no `provider default`/`PUT .../default` route) — see pitfall.

## Tests

### Provider registry & interface metadata (`Info`, `ConfigSchema`, `List`, `Get`, `SupportsTXT`)
- **Must:** every registered provider exposes static metadata without any network
  call. Cloudflare's `Info()` returns `id=cloudflare`, `name=Cloudflare`,
  `RecordTypes=[A, AAAA, CNAME, TXT]` (`cloudflare.go:78-86`). `SupportsTXT()` is
  true iff `TXT` is in `RecordTypes` (`provider.go:46-53`) — Cloudflare supports it,
  so DNS-01 is allowed rather than the HTTP-01 fallback. `provider.Get("cloudflare")`
  resolves; an unknown type errors (`providers.go:79-82`).
- **Access:**
  - REST: provider type list is surfaced through provider-aware endpoints; the
    Dashboard SetupWizard / Settings render the available types and the
    `ConfigSchema` fields (`api_token`, `zone_id`).
  - Code: `provider.Register` (called from `cloudflare.init()`, `cloudflare.go:74-76`),
    `provider.Get`, `provider.List`.
- **Prerequisites:** none.
- **Steps (dry):**
  ```bash
  go test ./internal/provider/... -run . -count=1
  ```
- **Pass:** tests pass; Cloudflare `Info().RecordTypes` includes `TXT` and
  `SupportsTXT()` is true. An unknown provider type at `POST /providers` returns
  `400 unknown provider type: <type>`.
- **Coverage:** D.
- **Pitfalls:** providers self-register in `init()`; a provider only exists if its
  package is imported into the binary. If a new provider doesn't appear, it isn't
  imported.

### Cloudflare `ValidateConfig` (token validation)
- **Must:** validation parses the config, requires a non-empty `api_token`
  (`cloudflare.go:321-329`), then proves the token by issuing `GET /zones?per_page=1`
  (`cloudflare.go:111-117`). This works for both user- and account-scoped tokens and
  proves `Zone:Read`. A missing token fails locally with
  `cloudflare: api_token is required` before any HTTP call.
- **Access:**
  - REST: `POST /api/v1/providers/test` `{ "type":"cloudflare", "config":{...} }`
    (`providers.go:184-230`) — returns `{ "valid":bool, "message":..., "zones":[...] }`.
    Validation also runs implicitly inside `POST /providers` and `PUT /providers/{id}`
    (`providers.go:85`, `153`).
  - Dashboard: Settings → add provider, and the SetupWizard "test token" step.
  - CLI: there is no standalone `test` subcommand; `nurproxy provider add` validates
    server-side as part of creation.
- **Prerequisites:** real token only for the real path.
- **Steps (dry):**
  ```bash
  # Dry orchestrator accepts any syntactically valid JSON config and returns the
  # synthetic zone (dryrun decorator ValidateConfig/ListZones).
  curl -s -X POST localhost:8080/api/v1/providers/test \
    -H 'Authorization: Bearer <token>' \
    -d '{"type":"cloudflare","config":{"api_token":"dummy"}}'
  ```
- **Steps (real):**
  ```bash
  curl -s -X POST https://<orch>/api/v1/providers/test \
    -H 'Authorization: Bearer <token>' \
    -d '{"type":"cloudflare","config":{"api_token":"<REAL_CF_TOKEN>"}}'
  ```
- **Pass:** dry → `{"valid":true,"message":"Token is valid","zones":[{"id":"dryrun-zone","name":"dryrun.invalid"}]}`.
  Real valid token → `valid:true` plus your actual zones. Garbage token →
  `valid:false` with the parse/validation error. A valid token whose subsequent
  `ListZones` call errors returns `valid:true` with
  `"Token is valid, but failed to list zones: ..."` and **no** `zones` field
  (`providers.go:216-222`); a valid token that simply owns no zones returns
  `valid:true` with `zones:[]`. (Note `/providers/test` does **not** require a
  non-empty `config` — unlike `POST /providers`, which rejects an empty config
  with `400 config is required` (`providers.go:73-76`); an empty config to
  `/providers/test` in dry mode validates as `valid:true`.)
- **Coverage:** D (token-valid path against mock) / R (real token + real zones).
- **Pitfalls:**
  - `/providers/test` returns **HTTP 200 even when the token is invalid** — the
    verdict is in the `valid` field, not the status code (`providers.go:207-213`).
    Don't assert on HTTP status; assert on `valid`.
  - In dry mode the decorator accepts *any* valid JSON without contacting Cloudflare
    (`dryrun.go:99-107`), so a dummy token "passes". That is intended — do not read it
    as the real token being valid.

### Cloudflare `ListZones` (pagination)
- **Must:** lists all zones across pages — `per_page=50`, loops until
  `page >= ResultInfo.TotalPages` (and also stops when `TotalPages == 0`, so an empty
  account terminates) (`cloudflare.go:120-160`, break at `:153`). Returns
  `provider.Zone{ID,Name}`.
- **Access:** REST `GET /api/v1/providers/{id}/zones` returns **stored** zones for the
  provider from the DB (`providers.go:232-246`, `db ListZonesByProvider`); the *live*
  provider zone list comes back from `POST /providers/test` (the `zones` field).
- **Prerequisites:** none for dry; a real CF token (multi-page account ideal) for the
  real path.
- **Steps (dry):** see the `/providers/test` step above — dry `ListZones` returns the
  single synthetic zone `dryrun.invalid` (`dryrun.go:109-113`).
- **Steps (real):** run `/providers/test` with a real token; confirm every zone the
  token can see is present (covers multi-page accounts).
- **Pass:** all expected zones returned, no duplicates, pagination terminates.
- **Coverage:** D (single synthetic zone) / R (real multi-page).
- **Pitfalls:** `GET /providers/{id}/zones` ≠ live CF zones — it lists what you
  persisted via `POST /zones`. To see live zones, use `/providers/test`.

### Cloudflare record CRUD + `zone_id` requirement + `Proxied`
- **Must:** `CreateRecord`/`GetRecord`/`UpdateRecord`/`DeleteRecord`/`ListRecords`
  all require `zone_id` in the config and error clearly if absent
  (`cloudflare.go:167-169,201-203,235-237,278-280,307-309`). `CreateRecord` returns
  the new CF record ID. `ListRecords` filters server-side by `name` and (optional)
  `type` and carries each record's CF ID for adopt/update (`cloudflare.go:226-271`).
  The `Proxied` bool is passed through verbatim on create/update (`cloudflare.go:171-176,282-288`).
- **Access:** not a user endpoint — exercised by the reconciler / TLS issuer. Test via
  the unit tests and (real) via the full domain lifecycle.
- **Steps (dry):**
  ```bash
  go test ./internal/provider/cloudflare/... -count=1
  ```
- **Steps (real):** drive a full central-TLS domain through `make`-built binaries
  against a real zone and watch the orchestrator create the CNAME/A + TXT challenge
  and clean up. (Covered in the TLS / domains QA files; record CRUD is the substrate.)
- **Pass:** unit tests pass; record ops without `zone_id` return the explicit
  "zone_id is required" error rather than calling the API.
- **Coverage:** D (unit, mocked HTTP via `baseURL`/`client` override) / R (live zone).
- **Pitfalls:** `zone_id` is **optional in the schema** (`ConfigSchema` only requires
  `api_token`, `cloudflare.go:101`) but **mandatory for any record operation** *against
  the real Cloudflare provider*. A provider created without `zone_id` validates and
  lists zones fine, then fails the first record op with `zone_id is required`. The
  zone's `external_id` is the CF zone id the reconciler merges into config; verify it's
  set when creating zones for record-managing flows. **Caveat:** the dry-run decorator
  does **not** enforce `zone_id` (`DeleteRecord`/`ListRecords` ignore config beyond the
  zone-bucket hash) — so the sandbox seed creates its zone with **no `external_id`**
  (`scripts/dev-sandbox.sh:93`) yet still drives a full DNS-01 lifecycle. The missing
  `zone_id` only bites on a real CF provider, so test that path with `-run MissingZoneID`
  / a real zone, not in dry.

### Cloudflare `ErrRecordNotFound` mapping (code 81044)
- **Must:** Cloudflare API error code `81044` ("Record does not exist") is mapped to
  the sentinel `provider.ErrRecordNotFound`, and **only** that code
  (`cloudflare.go:394-420`, `provider.go:9-15`). This lets idempotent teardown treat a
  delete of an already-gone record as success without masking auth/transient errors —
  every other code stays a plain error.
- **Access:** internal; covered by unit tests (mocked CF HTTP via `baseURL`/`client`).
- **Prerequisites:** none.
- **Steps (dry):**
  ```bash
  go test ./internal/provider/cloudflare/... -run NotFound -count=1
  go test ./internal/provider/cloudflare/... -count=1   # full file if -run misses
  ```
- **Pass:** an `81044` response yields an error for which
  `errors.Is(err, provider.ErrRecordNotFound)` is true; any other code does **not**.
- **Coverage:** D.
- **Pitfalls:** regression guard — if someone widens the mapping to "any 404" or "any
  error", a real auth failure during cleanup would be silently swallowed as
  already-deleted. Keep the single-code check.

### dryrun decorator (in-memory store, synthetic IDs, per-zone bucket, `Reset`, validation)
- **Must:** `dryrun.Wrap(p, logger)` returns a decorator that performs no network call
  but keeps the inner provider's `Info`/`ConfigSchema` (so `SupportsTXT()` still
  reflects the real provider) (`dryrun.go:79-95`). Mutations land in a process-global
  store keyed by a synthetic monotonic ID `dryrun-N` (`dryrun.go:69-73,119`).
  `ListZones` returns one synthetic zone `{dryrun-zone, dryrun.invalid}`
  (`dryrun.go:109-113`). Records are bucketed per zone via a SHA-256 of the config
  bytes, so `ListRecords` never returns a same-named record from another zone
  (`dryrun.go:29-67,205-228`). Write ops require type+name+content and TTL≥0
  (`dryrun.go:233-247`). Delete of an unknown record is a no-op (forgiving, matches
  real providers) (`dryrun.go:173-191`). `Reset()` clears the store for tests
  (`dryrun.go:50-56`).
- **Access:** code only; engaged automatically when the orchestrator runs in DNS dry
  mode (`s.dnsProvider` wraps via `dryrun.Wrap`, `providers.go:19-24`).
- **Steps (dry):**
  ```bash
  go test ./internal/provider/dryrun/... -count=1
  ```
- **Pass:** tests pass; create→get→list→update→delete cycle is consistent within a
  zone bucket; cross-zone lookups isolated; deleting an absent record returns nil.
- **Coverage:** D.
- **Pitfalls:**
  - The store is **process-global on purpose** — a record created in one reconcile
    cycle must be visible to the next and to the renewer. In tests that assert on
    counts, call `dryrun.Reset()` between cases or you'll see leftovers.
  - Names are canonicalized by stripping one trailing dot (`dryrun.go:249-254`), so a
    lookup for `x.example.com` matches a record stored as `x.example.com.` (lego
    presents the trailing dot). Don't expect dot-exact matching.

### dryrun wiring via `NP_DNS_DRY_RUN` / `NP_DRY_RUN`
- **Must:** when the orchestrator is in DNS sandbox mode (`s.dnsDryRun`), every
  resolved provider is wrapped by `dryrun.Wrap` before validate/list-zones
  (`providers.go:19-24,84,152,205`). So provider setup (create + test) works end to
  end against the mock with a dummy token — no live credentials.
- **Access:** env/flags on the orchestrator: `NP_DRY_RUN=true` (or `-dry-run`) mocks
  DNS + ACME; `NP_DNS_DRY_RUN=true` mocks DNS only. See `CLAUDE.md`.
- **Steps (dry):**
  ```bash
  make dev-sandbox        # orchestrator already in dry mode; provider seeded
  # or by hand:
  NP_DNS_DRY_RUN=true ./nurproxy
  curl -s localhost:8080/api/v1/health | grep -o '"dns_dry_run":[a-z]*'
  ```
- **Pass:** `/api/v1/health` reports `dns_dry_run:true` (and/or `dry_run`/`acme_dry_run`);
  `POST /providers` with a dummy Cloudflare token succeeds; the dashboard shows the
  "Dry-run mode" banner.
- **Coverage:** D.
- **Pitfalls:** `NP_DNS_DRY_RUN` + **real ACME** always fails DNS-01 (mock DNS never
  publishes the challenge TXT) — for cert flows use full `NP_DRY_RUN` or
  `NP_ACME_DRY_RUN` (carried over from RELEASE-QA §2.3). Not relevant to provider/zone
  CRUD itself, but bites if you chain into TLS testing.

### Provider config encryption at rest + stripped from responses
- **Must:** provider configs are encrypted with AES-256-GCM using the orchestrator's
  `encryption.key` before being stored, and decrypted on read
  (`db/providers.go:15,60,92,105`; key documented `db/db.go:18-21`). API responses
  **never** include the config: list builds a config-less DTO (`providers.go:37-54`)
  and get explicitly blanks it (`p.Config = ""`, `providers.go:118-120`).
- **Access:** REST `GET /providers`, `GET /providers/{id}`; the on-disk SQLite `config`
  column; the `encryption.key` file (backed up by `nurproxy backup`).
- **Prerequisites:** a created provider with a non-trivial token in its config.
- **Steps (dry):**
  ```bash
  curl -s localhost:8080/api/v1/providers -H 'Authorization: Bearer <token>'
  curl -s localhost:8080/api/v1/providers/<id> -H 'Authorization: Bearer <token>'
  # Inspect the raw column (path = orchestrator data dir):
  sqlite3 <datadir>/nurproxy.db 'select substr(config,1,40) from providers limit 1;'
  ```
- **Pass:** neither JSON response contains `api_token` or any config field. The
  list endpoint returns a hand-built DTO with exactly `id,type,name,is_default,created_at`
  (`providers.go:37-54`); `GET /providers/{id}` returns the full `models.Provider`
  with `Config` blanked **and** the field is `json:"-"` (`models.go:56`), so there is
  **no `config` key at all** in the JSON — `id,type,name,is_default,created_at` only.
  The raw DB `config` column is ciphertext (not readable JSON).
- **Coverage:** D.
- **Pitfalls:**
  - The `Config` field is `json:"-"` *and* defensively blanked — both. If you ever see
    a token in a response, that's a leak regression; fail the RC.
  - **`is_default` is read-only over the API.** The list DTO exposes `is_default`
    (`models.go:57`) and `DB.SetDefaultProvider` exists (`db/providers.go:148-172`),
    but no handler or CLI subcommand calls it — there is no `PUT /providers/{id}/default`
    route (`server.go:146-152`) and no `provider default` CLI verb. So `is_default`
    is always `false` for API-created providers unless a seed/migration set it. Don't
    write a test that flips it via the API; there is no path. (Flag a new RC as a
    feature-add if one appears.)
  - Losing/rotating `encryption.key` makes every stored provider config undecryptable —
    backups must include it (RELEASE-QA §backup: `nurproxy backup` snapshots db +
    `encryption.key` + `acme-account.key`; always restore-verify in dry).

### Zone CRUD — `GET/POST /zones`, `POST /zones/batch`, `DELETE /zones/{id}`
- **Must:** `POST /zones` requires `provider_id` and `name`, and validates the
  provider exists (`zones.go:25-65`). `POST /zones/batch` takes `provider_id` + a
  `zones[]` of `{external_id,name}`, validates the provider once, inserts each, audits
  each (`zones.go:67-114`). `GET /zones` lists all zones ordered by `created_at`
  (`zones.go:11-22`). Each create/delete emits an audit event.
- **Access:**
  - REST: `GET /api/v1/zones`; `POST /api/v1/zones` `{provider_id,name,external_id?}`;
    `POST /api/v1/zones/batch` `{provider_id, zones:[{external_id,name}]}`;
    `DELETE /api/v1/zones/{id}`.
  - Dashboard: Settings (zone management) and the SetupWizard (zone selection after
    token validation — uses the `zones` returned by `/providers/test`, often batch-added).
  - CLI: `nurproxy zone list`; `nurproxy zone add --provider <id> --name <name>
    [--external-id <cf-zone-id>]`; `nurproxy zone delete <id>`
    (`cli_commands.go:104-145`).
- **Prerequisites:** an existing provider id (from `nurproxy provider list`).
- **Steps (dry):**
  ```bash
  PID=$(curl -s localhost:8080/api/v1/providers -H 'Authorization: Bearer <token>' | jq -r '.[0].id')
  # single
  nurproxy zone add --provider "$PID" --name example.com --external-id cf-zone-123
  nurproxy zone list
  # batch
  curl -s -X POST localhost:8080/api/v1/zones/batch -H 'Authorization: Bearer <token>' \
    -d "{\"provider_id\":\"$PID\",\"zones\":[{\"name\":\"a.com\",\"external_id\":\"z1\"},{\"name\":\"b.com\",\"external_id\":\"z2\"}]}"
  ```
- **Pass:** single create returns `201 {id,name}`; batch returns `201 [{id,name},...]`;
  both appear in `nurproxy zone list`. A create with a bogus `provider_id` returns
  `400 provider not found`. Missing `provider_id`/`name` → `400`.
- **Coverage:** D.
- **Pitfalls:**
  - `external_id` is the **provider-side zone ID** (CF zone id). It's optional at the
    API layer but **required for record management** (the reconciler merges it into the
    Cloudflare config as `zone_id`; without it, record ops fail — see the CF record
    test). Always set `--external-id` for zones you intend to manage DNS in.
  - `domains` uniqueness is `UNIQUE(subdomain, zone_id)` (`migrations.go:175`) — the
    same subdomain can exist once per zone, not globally.

### Zone-delete guard (zone still has domains)
- **Must:** a zone that still has domains **cannot be deleted**. There is no
  application-level 409 in the handler; the guard is the foreign key:
  `domains.zone_id REFERENCES zones(id)` with **no `ON DELETE CASCADE`**
  (`migrations.go:161`), and SQLite foreign keys are enabled on every connection
  (`_pragma=foreign_keys(1)`, `db/db.go:28`). The `DELETE` therefore fails with a FK
  constraint error, `DeleteZone` returns it, and the handler maps it to a response.
- **Access:** REST `DELETE /api/v1/zones/{id}` (`zones.go:117-128`); CLI
  `nurproxy zone delete <id>` (`cli_commands.go:136-142`).
- **Prerequisites:** a zone with at least one domain attached.
- **Steps (dry):**
  ```bash
  # with a domain on the zone:
  curl -s -o /dev/null -w '%{http_code}\n' -X DELETE \
    localhost:8080/api/v1/zones/<zone-with-domains> -H 'Authorization: Bearer <token>'
  # then delete the domain(s), wait a reconcile cycle, retry:
  curl -s -X DELETE localhost:8080/api/v1/zones/<empty-zone> -H 'Authorization: Bearer <token>'
  ```
- **Pass:** delete of a zone with domains is **refused** (non-2xx); delete of an empty
  zone returns `200 {"message":"zone deleted"}`.
- **Coverage:** D.
- **Pitfalls:**
  - **Known wart — UNVERIFIED status code.** The handler maps *any* `DeleteZone` error
    to `404 "zone not found"` (`zones.go:120-122`), so a refused-because-has-domains
    delete currently surfaces as a misleading **404**, not a 409 like the
    server/agent guard (RELEASE-QA §2.4). Verify it is *refused*; do not assert it's a
    409. If an RC starts returning 200 here (i.e. the zone gets deleted with domains
    still pointing at it), that is a regression — the FK or the pragma is off.
  - Domain delete is **soft** (`status=deleting`) and the reconciler finishes the
    teardown a cycle later (RELEASE-QA §2.4). A zone delete **right after** a domain
    delete still has the (deleting) domain row referencing it, so it stays refused
    until the reconciler removes the row. Wait a cycle before retrying.

### Provider-delete guard (provider still referenced by zones)
- **Must:** deleting a provider that still owns zones is refused by the same FK
  mechanism — `zones.provider_id REFERENCES providers(id)` with no cascade
  (`migrations.go:131`). A provider with no zones deletes cleanly. The handler maps any
  error to `404 "provider not found"` (`providers.go:171-182`).
- **Access:** REST `DELETE /api/v1/providers/{id}` (`providers.go:171`); CLI
  `nurproxy provider delete <id>` (`cli_commands.go:81-88`).
- **Prerequisites:** a provider with ≥1 zone, and a separate provider with 0 zones.
- **Steps (dry):**
  ```bash
  # provider that still has zones — refused:
  curl -s -o /dev/null -w '%{http_code}\n' -X DELETE \
    localhost:8080/api/v1/providers/<provider-with-zones> -H 'Authorization: Bearer <token>'
  # delete its zones first, then the provider — succeeds:
  nurproxy provider delete <empty-provider>
  ```
- **Pass:** provider with zones → refused (non-2xx); provider with no zones →
  `200 {"message":"provider deleted"}`. The seeded sandbox provider has a zone, so it
  is a ready-made "refused" case.
- **Coverage:** D.
- **Pitfalls:** same misleading **404** caveat as zone-delete — confirm *refused*, not
  the exact code. Tear zones down before the provider.

### CLI surface — `nurproxy provider` and `nurproxy zone`
- **Must:** the CLI mirrors the REST API.
  - `nurproxy provider list` → `GET /providers` (`cli_commands.go:46-48`).
  - `nurproxy provider add --type <t> --name <n> [--config <json> | --config-file <path|->]`
    → `POST /providers`; `--type` and `--name` are required; config is read from
    `--config` or `--config-file` (`-` = stdin) (`cli_commands.go:61-79`).
  - `nurproxy provider delete <id>` → `DELETE /providers/{id}` (`cli_commands.go:81-88`).
  - `nurproxy provider zones <id>` → `GET /providers/{id}/zones` (stored zones)
    (`cli_commands.go:90-97`).
  - `nurproxy zone list` → `GET /zones`; `zone add --provider <id> --name <n>
    [--external-id <id>]` → `POST /zones` (`--provider` and `--name` required);
    `zone delete <id>` → `DELETE /zones/{id}` (`cli_commands.go:104-145`).
- **Access:** CLI only (these subcommands).
- **Steps (dry):**
  ```bash
  nurproxy provider list
  printf '{"api_token":"dummy"}' | nurproxy provider add --type cloudflare --name cf-dry --config-file -
  nurproxy provider zones <id-from-list>
  nurproxy zone add --provider <id> --name dry.example --external-id z1
  nurproxy zone list
  nurproxy zone delete <zone-id>
  ```
- **Pass:** each command round-trips against the API; `provider add` prints
  `provider created: <id>`; required-flag omissions fatal out with the documented
  message (`--type and --name are required` / `--provider and --name are required`).
- **Coverage:** D.
- **Pitfalls:**
  - `provider add` validates the config **server-side** at create time — in a live
    orchestrator a bad token fails the create; in dry it always passes (mock validate).
  - There is no CLI `provider test`; validation only happens via add/update or the
    REST `/providers/test`.
  - **No CLI update verb for either resource.** `PUT /api/v1/providers/{id}`
    (rename / rotate config, re-validated, `providers.go:124-168`) exists over REST
    and the Dashboard "edit provider" form, but there is **no `nurproxy provider
    update`** subcommand (`cmdProvider` only handles list/add/delete/zones,
    `cli_commands.go:42-102`). Zones have no update endpoint at all — only
    add/list/delete. To change a zone, delete and re-add it.

## Acceptance checklist

### Dry (every RC)
- [ ] `go test ./internal/provider/...` passes (interface, cloudflare, dryrun).
- [ ] `provider.Get("cloudflare")` resolves; unknown type → `400` at `POST /providers`.
- [ ] Cloudflare `Info().RecordTypes` includes `TXT`; `SupportsTXT()` true.
- [ ] `POST /providers/test` with dummy token (dry) → `200 {valid:true, zones:[dryrun.invalid]}`.
- [ ] `/api/v1/health` reports `dns_dry_run`/`dry_run` true under sandbox; dashboard banner shown.
- [ ] `GET /providers` and `GET /providers/{id}` contain **no** `api_token`/config.
- [ ] Raw `providers.config` DB column is ciphertext, not JSON.
- [ ] `POST /zones`, `POST /zones/batch`, `GET /zones` work; bad `provider_id` → `400 provider not found`.
- [ ] `nurproxy provider list/add/delete/zones` and `nurproxy zone list/add/delete` round-trip.
- [ ] Zone delete with domains is **refused**; empty zone delete → `200`.
- [ ] Provider delete with zones is **refused**; provider with no zones → `200`.
- [ ] `ErrRecordNotFound` test: code `81044` → `errors.Is(..., provider.ErrRecordNotFound)`; other codes do not.
- [ ] dryrun cross-zone isolation + forgiving delete + `Reset()` verified by unit tests.

### Real run (before final)
- [ ] `POST /providers/test` with a **real** CF token → `valid:true` and the account's actual zones (covers `ListZones` pagination).
- [ ] Provider created with real token + `external_id` zone id drives record CRUD through a full domain lifecycle (CNAME/A + TXT challenge create/cleanup) without leaks.
- [ ] Backup includes `encryption.key`; restore-verify in dry decrypts the provider and reaches it (RELEASE-QA backup section).

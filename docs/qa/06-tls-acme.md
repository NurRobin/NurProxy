# TLS — Central DNS-01 Issuance, Renewal, Self-ACME & Failure Modes
> **Scope:** the full certificate lifecycle — per-domain TLS policy resolution, central DNS-01 issuance via lego, the on-demand + periodic renewal loop, typed ACME errors (rate limit), wildcard issuance, the persisted ACME account key, and the dry-run failure-injection paths.
> **Code:** `internal/orchestrator/tls/{issuer,solver,errors,account,lego,dryrun,store,manager}.go`, `internal/orchestrator/reconciler/renewal.go`, `internal/shared/caddygen/generate.go` (`TLSPolicyForDomain`), `internal/shared/proxymodel/route.go` (`TLSPolicy`), `internal/shared/models/models.go` (`SSLMode`), `cmd/nurproxy/main.go` (`startRenewer`, `settingsACMEClient`).
> **Coverage legend:** D = coverable dry, R = needs a real run.

## Prerequisites
- Both binaries built: `make build-all` (produces `./nurproxy` and `./nurproxy-agent`).
- For dry tests: the sandbox stack via `make dev-sandbox` (seeds a provider, zone, adopted agent, server, and one **central-TLS domain** per agent and waits for convergence). The launcher is `scripts/dev-sandbox.sh`; defaults `PORT=8099`, base URL `http://localhost:8099`, and it exports `API_KEY` (an `np_ak_…` token).
- For per-`failMode` tests you boot the orchestrator by hand with `NP_ACME_DRY_RUN=true NP_DRY_RUN_FAIL=…` (the seeded `make dev-sandbox` always uses `NP_DRY_RUN=true` with no fail mode — see `scripts/dev-sandbox.sh:79`).
- For real issuance (R): a real Cloudflare zone with a valid token, a configured DNS provider, an ACME contact email set in Settings, public reachability is NOT required for DNS-01 (no `:80`/`:443` inbound needed for issuance), and `openssl` in PATH for leaf verification. Prefer the Let's Encrypt **staging** directory (`acme_directory`) to avoid burning production quota.
- API auth: every `curl` below uses `-H "Authorization: Bearer $API_KEY"`. The sandbox exports `API_KEY` for you.

## Features covered
- [ ] TLS policy enums: the **stored** `SSLMode` enum (`auto`/`manual`/`off`) vs. the **route** `TLSPolicy` enum (`central`/`self-acme`/`off`), and how `TLSPolicyForDomain` maps a domain to one of the three.
- [ ] `central` policy — orchestrator issues via DNS-01 and ships the bundle to the agent.
- [ ] `self-acme` policy — agent (Caddy) obtains its own cert; orchestrator issues nothing.
- [ ] `off` policy — no TLS listener.
- [ ] Central DNS-01 issuance via lego: solver `Present`/`CleanUp` of `_acme-challenge.<host>` TXT (TTL 120), idempotent adopt of a leftover identical TXT, `ErrNoTXTSupport` fallback when the provider lacks TXT support.
- [ ] On-demand first issuance (`EnsureCertForHost`) triggered on domain create.
- [ ] Periodic renewal scan: `DefaultRenewWindow` (30d), `DefaultRenewInterval` (12h), first-issuance backstop.
- [ ] Retry policy: `issueMaxAttempts` (4), `issueBaseBackoff` (2s), `issueMaxBackoff` (30s) with exponential backoff; **no retry** on rate-limit and `ErrACMENotConfigured`.
- [ ] Typed `RateLimitError` (Detail, UnblockURL, RetryAfter) and `classifyACMEError`.
- [ ] Wildcard issuance + the shared-private-key warning (`WildcardSharedKeyWarning`).
- [ ] ACME account key: P-256, persisted at `<data-dir>/acme-account.key` (0600), reused across restarts.
- [ ] `ErrACMENotConfigured` — issuance skipped quietly until `acme_email` is set; no restart needed.
- [ ] Settings wiring: `acme_email`, `acme_directory` read lazily at issuance time.
- [ ] Dry failure injection: `NP_DRY_RUN_FAIL=ratelimit|challenge|propagation`; self-signed dry cert (90d validity).
- [ ] `NP_DNS_DRY_RUN` + real ACME always fails DNS-01 (regression-guard pitfall).
- [ ] Audit: renewal/issuance events tagged `source=dryrun` in sandbox vs. `system` for real.

## Tests

### 1. TLS policy enums & `TLSPolicyForDomain` resolution
- **Must:** Two distinct enums exist and must not be confused.
  - **`SSLMode`** (stored on the domain, `internal/shared/models/models.go:42-48`): the only valid values are `auto`, `manual`, `off`. Default applied by the API on create is `auto` (`internal/orchestrator/api/domains.go:91-94`).
  - **`TLSPolicy`** (the route-level provisioning policy, `internal/shared/proxymodel/route.go:33-45`): values are `central`, `self-acme`, `off`. Stored per-domain in `ProxyConfig.TLSPolicy` (`models.go:356-363`); empty defaults to central.
  - Resolution (`caddygen.TLSPolicyForDomain` → `tlsPolicyFromDomain`, `generate.go:72-97`): an explicit `ProxyConfig.TLSPolicy` of `self-acme`/`off`/`central` wins. If empty, the result is `off` **only when `SSLMode == off`**, otherwise `central`. An unrecognized `TLSPolicy` string falls back to `central`.
  - **Wizard/label vs. stored-enum mismatch to document:** the dashboard and the sandbox seed speak in *policy* words, not `SSLMode` words. `scripts/dev-sandbox.sh:122-123` POSTs `"ssl_mode":"central"` — but `central` is **not** a member of the `SSLMode` enum. It is stored verbatim as the `ssl_mode` value, and because it is not `off` (and `ProxyConfig.TLSPolicy` is empty) `TLSPolicyForDomain` still resolves it to `central`. Net effect is correct, but the stored `ssl_mode` is an out-of-enum string. Do not treat `ssl_mode=central` as canonical; the canonical central selector is empty/unset policy + non-`off` SSLMode.
- **Access:**
  - REST: `POST /api/v1/domains` body `{"subdomain","zone_id","server_id","port","ssl_mode","proxy_config":{"tls_policy":"central|self-acme|off"}}` (`domains.go:42-51,107-109`). `ssl_mode` accepts `auto|manual|off` per the enum; `tls_policy` lives under `proxy_config`.
  - CLI: `nurproxy domain add --subdomain … --zone … --server … --port … [--ssl-mode <auto|manual|off>] [--websocket] [--force-https] [--proxy-config-file <path>]` (`cmd/nurproxy/cli_commands.go:366-398`). There is **no** dedicated `--tls-policy` flag — but `--proxy-config-file` takes a full `ProxyConfig` JSON file (which may include `"tls_policy"`), so policy *can* be set from the CLI that way as well as via the API/dashboard `proxy_config.tls_policy`.
  - Dashboard: Domains page; `proxy_config.tls_policy` documented in `web/src/lib/types.ts:212-214`, `ssl_mode` typed `'auto' | 'manual' | 'off'` (`types.ts:196`).
- **Prerequisites:** sandbox up (`make dev-sandbox`).
- **Steps:**
  ```bash
  # Inspect the seeded central-TLS domain's stored ssl_mode + resolved behaviour
  curl -fsS -H "Authorization: Bearer $API_KEY" http://localhost:8099/api/v1/domains | python3 -m json.tool
  # Create a self-acme domain (set policy under proxy_config)
  curl -fsS -X POST -H "Authorization: Bearer $API_KEY" -H 'Content-Type: application/json' \
    -d '{"subdomain":"self1","zone_id":"<ZONE_ID>","server_id":"<SERVER_ID>","port":8080,"proxy_config":{"tls_policy":"self-acme"}}' \
    http://localhost:8099/api/v1/domains
  # Equivalent via the CLI (policy goes in the proxy-config file, not a flag)
  echo '{"tls_policy":"self-acme"}' > /tmp/pc.json
  ./nurproxy domain add --subdomain self2 --zone <ZONE_ID> --server <SERVER_ID> --port 8080 \
    --proxy-config-file /tmp/pc.json
  ```
- **Pass:** the seeded domain reports `ssl_mode:"central"` yet still issues a cert (central path). The `self-acme` domain creates successfully and triggers **no** central issuance (see test 5).
- **Coverage:** D.
- **Pitfalls:** `ssl_mode` and `tls_policy` are independent fields living at different JSON levels (`ssl_mode` top-level, `tls_policy` nested under `proxy_config`). A `tls_policy:"off"` disables TLS even if `ssl_mode` is `auto`. Only `ssl_mode:"off"` (with empty policy) maps to `TLSPolicyOff`.

### 2. Central DNS-01 issuance via lego (solver TXT, TTL 120)
- **Must:** issuance creates a `_acme-challenge.<host>` TXT record with `Type:"TXT"`, `Name` = challenge FQDN (trailing dot trimmed), `Content` = challenge value, **`TTL: 120`** (`solver.go:39-46`), drives the ACME order, then **cleans up** exactly the record it created (`CleanUp`, `solver.go:83-96`). The CleanUp is keyed on `fqdn\x00value` (`challengeKey`) so it deletes precisely what `Present` added.
- **Access:** implicit — there is no direct issuance endpoint. Issuance is driven by `Issuer.Issue` (`issuer.go:110`), reached via domain create (on-demand) or the renewal scan.
- **Prerequisites:** a central-TLS domain whose zone has a TXT-capable provider.
- **Steps (dry):** `make dev-sandbox`, then watch the orchestrator log:
  ```bash
  # the sandbox writes orch.log under WORKDIR (default ./.dev-sandbox; override
  # with WORKDIR=… make dev-sandbox) — see scripts/dev-sandbox.sh:22,31,79
  grep -E 'DNS-01|presented DNS-01 challenge|issuing certificate via DNS-01' ./.dev-sandbox/orch.log
  ```
- **Pass:** log shows `issuing certificate via DNS-01` with `provider`, `host`, `names` (`issuer.go:142-146`) and `presented DNS-01 challenge` debug lines (`solver.go:75-79`); in full dry-run the TXT lands in the in-memory DNS store and the domain converges to `active`.
- **Coverage:** D (solve sequence + TXT shape). R (real TXT propagation + real CA validation).
- **Pitfalls:** debug-level solver lines (`presented DNS-01 challenge`) only appear at debug log level.

### 3. Idempotent challenge present (adopt a leftover TXT)
- **Must:** if `CreateRecord` fails because an **identical** `_acme-challenge` TXT already exists (a prior attempt died before `CleanUp` — e.g. Cloudflare error 81058), `Present` lists records at that name and adopts the existing record with the same `Content` instead of failing (`solver.go:47-65`, `findExistingChallenge` `solver.go:118-129`). It logs `adopted pre-existing DNS-01 challenge record`. If no identical record is found (or the provider cannot list), the original create error is surfaced unchanged.
- **Access:** implicit (issuance path).
- **Prerequisites:** hard to reproduce dry without a stuck record; covered by `solver_test.go`.
- **Steps:** unit-level — `go test ./internal/orchestrator/tls/ -run Solver`. For real, induce by killing the orchestrator mid-issuance (between Present and CleanUp), leaving the TXT, then re-trigger issuance for the same host.
- **Pass:** second attempt logs the adopt line and proceeds; it does not wedge.
- **Coverage:** D (unit). R (induced).
- **Pitfalls:** adoption only fires on an **exact** content match; a stale TXT with a different value is not adopted and the create error stands.

### 4. `ErrNoTXTSupport` fallback
- **Must:** if the resolved DNS provider does not support TXT records (`provider.Info().SupportsTXT()` false), `Issue` returns `ErrNoTXTSupport` **without contacting the CA** (`issuer.go:115-122`), logging that the caller must fall back to HTTP-01/self-acme. The error text is in `errors.go:15`.
- **Access:** implicit (issuance path); depends on the provider's `Info`.
- **Prerequisites:** a provider whose `Info().SupportsTXT()` is false.
- **Steps:** unit — `go test ./internal/orchestrator/tls/ -run Issue` (covered by `issuer_test.go`).
- **Pass:** `errors.Is(err, ErrNoTXTSupport)` true; no ACME order attempted.
- **Coverage:** D.
- **Pitfalls:** Cloudflare (the shipped provider) supports TXT, so you cannot hit this with the default sandbox provider — it is a unit-level guard.

### 5. On-demand first issuance on domain create (`EnsureCertForHost`)
- **Must:** creating a **central** domain triggers background first-issuance so HTTPS comes up in ~a minute instead of waiting for the next scan (`api/domains.go:116-149` `triggerCertIssuance` → `Renewer.EnsureCertForHost` `manager.go:225-248`). It is a **no-op** for `self-acme`/`off` domains (`domains.go:133-134`), when no issuer is wired (`domains.go:130`), when the zone can't be resolved (`domains.go:136-138`), or when a cert already exists (`renewal.go:123-139`). The background attempt has a 5-minute timeout (`domains.go:142-143`).
- **Access:** REST `POST /api/v1/domains` only; CLI `nurproxy domain add …`; Dashboard create-domain form. **Note:** the fast path fires on **create** alone. `PUT /api/v1/domains/{id}` / `nurproxy domain update` do **not** call `triggerCertIssuance` (`domains.go:168-259` has no issuance trigger), so flipping a domain to `central` (or to a TXT-capable zone) via update waits for the next periodic scan's first-issuance backstop instead of issuing in ~a minute.
- **Prerequisites:** sandbox up.
- **Steps:**
  ```bash
  curl -fsS -X POST -H "Authorization: Bearer $API_KEY" -H 'Content-Type: application/json' \
    -d '{"subdomain":"app2","zone_id":"<ZONE_ID>","server_id":"<SERVER_ID>","port":8080,"ssl_mode":"central"}' \
    http://localhost:8099/api/v1/domains
  # poll until active
  curl -fsS -H "Authorization: Bearer $API_KEY" http://localhost:8099/api/v1/domains | python3 -m json.tool
  ```
- **Pass:** orchestrator log shows `tls: issuing certificate on demand` (`manager.go:236`); domain reaches `status:active` (dry) without waiting 12h. A `self-acme` domain logs nothing about issuance.
- **Coverage:** D.
- **Pitfalls:** issuance runs in a goroutine and DNS-01 is slow even in dry-run; poll, don't assume instant. If `acme_email` is unset on a real run, this path logs `on-demand issuance skipped — ACME contact email not configured` and is a no-op (not a failure) (`manager.go:240-243`). Changing `ssl_mode`/`tls_policy` later via `PUT /api/v1/domains/{id}` does **not** re-trigger this fast path — only the 12h scan picks it up.

### 6. Periodic renewal scan + window/interval constants
- **Must:** the renewer runs one scan immediately on start, then every `DefaultRenewInterval` = **12h** (`manager.go:24`, `Start` `manager.go:158-174`). Each scan re-issues certs whose `NotAfter` is within `DefaultRenewWindow` = **30 days** (`manager.go:19`; the DB query `CertificatesDueForRenewal` `db/certificates.go:100-103`). The same scan also does **first issuance** for central domains that have no cert yet (`renewal.go:41-116`). A renewed cert preserves the exact `Names` set and `IsWildcard` flag (no scope drift) (`manager.go:300-336`, `sansFromNames` `manager.go:341-357`). One host's failure is logged + audited (`renew_failed`) but does not abort the rest (`manager.go:194-216`). After save it re-pushes to the serving agent via `Reloader.RepushCertForHost`; a push failure is **non-fatal** (audited `renew_repush_deferred`) (`manager.go:324-335`).
- **Access:** internal timer; no endpoint. Started by `startRenewer` (`cmd/nurproxy/main.go:235-270`), which logs `central renewal + first-issuance loop started (window 720h0m0s)`.
- **Prerequisites:** sandbox up.
- **Steps (dry, logic only):**
  ```bash
  # WORKDIR defaults to ./.dev-sandbox (scripts/dev-sandbox.sh:22,31)
  grep -E 'renewal \+ first-issuance loop started|renewing certificates within window' ./.dev-sandbox/orch.log
  ```
  Window/interval are verified by `manager_test.go` (`make test`). True in-window renewal requires a soak or LE-staging.
- **Pass:** the start line shows window `720h0m0s` (30d); first-issuance covers the seeded domain on the immediate scan.
- **Coverage:** D (constants, scan logic, first-issuance backstop). R (actual renewal of a cert nearing expiry — needs LE-staging or a soak).
- **Pitfalls:** the 30-day window is wide on purpose (margin for orchestrator downtime, rate limits, offline agents — `manager.go:14-18`); do not expect a freshly issued 90-day cert to renew during a short test. Renewal-in-window is **logic-tested only** dry (RELEASE-QA §2.3 pitfall).

### 7. Retry policy & no-retry classification
- **Must:** transient issuance errors retry up to `issueMaxAttempts` = **4** with exponential backoff `issueBaseBackoff` = **2s** doubling, capped at `issueMaxBackoff` = **30s** (`manager.go:35-39`, `issueWithRetry` `manager.go:256-298`). It does **NOT** retry: a `*RateLimitError` (returned immediately), `ErrACMENotConfigured` (returned immediately), or once `ctx` is done (`manager.go:266-275`). These constants are `var` so tests shrink the backoff; production never mutates them (`manager.go:34`).
- **Access:** internal; exercised via the dry fail modes (test 11).
- **Prerequisites:** boot orchestrator with `NP_ACME_DRY_RUN=true NP_DRY_RUN_FAIL=challenge`.
- **Steps:**
  ```bash
  make build-all
  NP_ACME_DRY_RUN=true NP_DRY_RUN_FAIL=challenge ./nurproxy -port 8099 -data-dir /tmp/np-tls 2>&1 | \
    grep -E 'issuance attempt failed, retrying'
  ```
  Drive issuance by creating a central domain (after seeding a provider/zone/server, or use the sandbox seed against this instance).
- **Pass:** for `challenge`/`propagation` you see up to 3 `issuance attempt failed, retrying` warnings (attempts 1–3, the 4th breaks out) with growing `backoff` (`manager.go:284-290`). For `ratelimit` you see **zero** retry lines (returned immediately).
- **Coverage:** D.
- **Pitfalls:** with the production backoff the retries take ~2+4+8 ≈ 14s; do not kill the process early. Rate-limit and not-configured are the only fast-fail classes — everything else, including the dry `challenge`/`propagation` failures, retries.

### 8. Typed `RateLimitError` & classification
- **Must:** a CA 429 / rate-limited problem is wrapped into `*RateLimitError` carrying `Detail`, `UnblockURL` (from `ProblemDetails.Instance`), and `RetryAfter` (parsed from the detail string `retry after YYYY-MM-DD HH:MM:SS UTC`) (`errors.go:24-52,57-72`). `classifyACMEError` recognizes lego's `*acme.ProblemDetails` (HTTP 429 or `acme.RateLimitedErr`) **and** a lightweight `IsRateLimited()/UnblockLink()/RateLimitDetail()` interface so fakes reproduce the path (`errors.go:83-118`). Callers detect it with `errors.As(err, &rl)` (`asRateLimit` `issuer.go:172-185`) and log the `unblock_url` (`issuer.go:152-157`). The renewer/retry never retries it.
- **Access:** surfaced in logs and audit (`renew_failed`/`issue_failed` details carry the error text). The dashboard renders the unblock link from the typed error (per code comments).
- **Prerequisites:** `NP_ACME_DRY_RUN=true NP_DRY_RUN_FAIL=ratelimit`.
- **Steps:**
  ```bash
  NP_ACME_DRY_RUN=true NP_DRY_RUN_FAIL=ratelimit ./nurproxy -port 8099 -data-dir /tmp/np-tls 2>&1 | \
    grep -E 'ACME rate limited|rate limit'
  ```
  Then create a central domain to trigger issuance.
- **Pass:** the dry client returns the `RateLimitError` at order creation (`dryrun.go:75-79`); log shows the rate-limit message; no retry attempts; the `Error()` string includes `tls: ACME rate limited: …` (`errors.go:43-52`). Unit coverage in `errors_test.go`.
- **Coverage:** D.
- **Pitfalls:** the dry rate-limit `Detail` has no parseable timestamp, so `RetryAfter` is nil for the dry path — that is expected; the real LE detail string is what populates `RetryAfter`.

### 9. Wildcard issuance & shared-key warning
- **Must:** a wildcard request (`IssueRequest.Wildcard`) produces a primary name `*.<host>` (`issuer.go:43-52`) and logs the `WildcardSharedKeyWarning` on **every** issuance (`issuer.go:127-132`), because the same private key lands on every agent serving any host under the wildcard. The renewer preserves the wildcard flag across renewal (no silent widening) (`manager.go:309-312`, `sansFromNames`). The full warning text is the const at `issuer.go:28`.
- **Access:** `IssueRequest.Wildcard` is set internally. The cert model carries `IsWildcard` (`models.go:561`); the route model has `TLSConfig.Wildcard` (`route.go:102-105`) and the dashboard type `TLS.Wildcard` (`web/src/lib/types.ts:314`). Note: the domain-create REST body has **no** wildcard field — wildcard issuance is exercised at the issuer/renewer layer and via the cert store's `is_wildcard`.
- **Prerequisites:** unit-level for the warning; a real wildcard run needs a zone-apex DNS-01.
- **Steps:** `go test ./internal/orchestrator/tls/ -run Wildcard` (issuer_test.go asserts the warning path).
- **Pass:** wildcard issuance logs `issuing wildcard certificate (opt-in)` with the warning; renewed wildcard keeps `is_wildcard=true`.
- **Coverage:** D (warning + flag preservation). R (real wildcard cert).
- **Pitfalls:** wildcard is **opt-in** and the default is per-host (`issuer.go:124-126`); do not assume the sandbox issues wildcards (it issues per-host central certs).

### 10. ACME account key — P-256, persisted, reused across restarts
- **Must:** `LoadOrGenerateAccountKey` loads the key from `<data-dir>/acme-account.key`, or generates a new **P-256 (`elliptic.P256()`)** key, marshals it PKCS#8, and writes it **0600** if absent (`account.go:20-50`, called at `cmd/nurproxy/main.go:236`). The same key must be reused across restarts so renewals stay under one registered ACME account (lego registers idempotently). A corrupt/non-PEM file is a hard error (`account.go:23-25`).
- **Access:** filesystem only — `<data-dir>/acme-account.key`. No endpoint.
- **Prerequisites:** any orchestrator run with a persistent `-data-dir`.
- **Steps:**
  ```bash
  ./nurproxy -port 8099 -data-dir /tmp/np-tls &  sleep 1; kill %1
  ls -l /tmp/np-tls/acme-account.key            # mode -rw------- (0600)
  openssl pkey -in /tmp/np-tls/acme-account.key -text -noout | grep -E 'Private-Key|ASN1 OID|NIST'
  # second boot must reuse, not regenerate:
  cksum /tmp/np-tls/acme-account.key
  ./nurproxy -port 8099 -data-dir /tmp/np-tls & sleep 1; kill %1
  cksum /tmp/np-tls/acme-account.key            # identical checksum
  ```
- **Pass:** file mode `0600`; `openssl` reports a P-256 / `prime256v1` (NIST P-256) key; checksum unchanged after a second boot.
- **Coverage:** D.
- **Pitfalls:** `make dev-sandbox` uses a throwaway temp `-data-dir`, so the key regenerates each run there — use a fixed `-data-dir` to test reuse. Note `LegoConfig.AccountKey` is separately generated if nil (`lego.go:59-65`), but production always passes the persisted key via `settingsACMEClient`.

### 11. Dry failure injection & self-signed dry cert
- **Must:** `NP_DRY_RUN_FAIL` selects one of `""` (none), `ratelimit`, `challenge`, `propagation` (`dryrun.go:23-32`):
  - `ratelimit` → returns a `*RateLimitError` at order creation, **before** any challenge (`dryrun.go:75-79`) — exercises the no-retry path.
  - `challenge` → presents+cleans up the TXT, then fails with a simulated DNS-01 challenge error (`dryrun.go:101-103`).
  - `propagation` → same, but a simulated propagation timeout (`dryrun.go:104-105`).
  - none → mints an **ECDSA P-256 self-signed** cert covering the names, validity **90 days** (`dryRunCertValidity` `dryrun.go:36`, `selfSignedCert` `dryrun.go:138-174`) so the renewer's window math matches production. The dry client still drives `Present`/`CleanUp` so the DNS path is exercised (`dryrun.go:82-99`).
- **Access:** env vars on the orchestrator: `NP_DRY_RUN`/`-dry-run` (both DNS+ACME), `NP_ACME_DRY_RUN` (mock ACME only), `NP_DNS_DRY_RUN` (mock DNS only), `NP_DRY_RUN_FAIL=<mode>`. The fail mode flows into `NewDryRunACMEClient` (`cmd/nurproxy/main.go:249`). The `/api/v1/health` payload exposes `dry_run`/`dns_dry_run`/`acme_dry_run` (`api/system.go:23-25`).
- **Prerequisites:** built binary; a seeded provider/zone/server/central-domain on the dry instance (run `scripts/dev-sandbox.sh` logic or seed by hand against your `NP_ACME_DRY_RUN` instance).
- **Steps:**
  ```bash
  for m in "" ratelimit challenge propagation; do
    NP_ACME_DRY_RUN=true NP_DRY_RUN_FAIL=$m ./nurproxy -port 8099 -data-dir /tmp/np-$m 2>&1 | head -40 &
    # … seed + create central domain, observe outcome, then kill …
  done
  curl -fsS -H "Authorization: Bearer $API_KEY" http://localhost:8099/api/v1/health | python3 -m json.tool
  ```
- **Pass:** health reports `acme_dry_run:true`. With no fail mode the domain reaches `active` on a self-signed 90-day cert (`dryrun ACME: issued self-signed certificate` log, `dryrun.go:112-113`). Each fail mode produces its tagged error and the matching retry/no-retry behaviour from tests 7–8.
- **Coverage:** D.
- **Pitfalls:** an **unknown** `NP_DRY_RUN_FAIL` value behaves as none (success) (`dryrun.go:50-52`) — typos silently "pass". The dry cert is self-signed (no real chain) and DNS records are in-memory (not resolvable) — this proves logic, not serving.

### 12. `NP_DNS_DRY_RUN` + real ACME always fails DNS-01 (regression guard)
- **Must:** running mock DNS with a **real** ACME CA (`NP_DNS_DRY_RUN=true`, no `NP_ACME_DRY_RUN`) **always fails** DNS-01: the mock DNS provider writes the challenge TXT only to its in-memory store, which the real CA cannot resolve, so validation never succeeds.
- **Access:** env: `NP_DNS_DRY_RUN=true` with a real `acme_email`/`acme_directory`.
- **Prerequisites:** N/A — this is a "don't do this" guard.
- **Steps:** do not use this combination for issuance testing. Use full `NP_DRY_RUN` or `NP_ACME_DRY_RUN` instead.
- **Pass:** understood as a known limitation; do not file a bug when this combination fails issuance.
- **Coverage:** D (documented guard).
- **Pitfalls:** this is the RELEASE-QA §2.3 hard-won pitfall — a real CA cannot see the mock TXT.

### 13. `ErrACMENotConfigured` & lazy settings (`acme_email`, `acme_directory`)
- **Must:** with no `acme_email` set, the real `settingsACMEClient` returns `ErrACMENotConfigured` (`cmd/nurproxy/main.go:287-290`). The renewer treats it as a **quiet skip** — no per-host retry, no `renew_failed` audit spam — and the scan stops quietly (`manager.go:201-204,240-243,266-268`). Setting `acme_email` post-boot enables issuance with **no restart** (settings are read lazily on each issuance, `main.go:272-301`). `acme_directory` (empty → LE production `lego.LEDirectoryProduction`, `lego.go:56-58`) selects the CA; use LE staging for testing.
- **Access:**
  - REST: `PUT /api/v1/settings/{key}` body `{"value":"…"}` for keys `acme_email` and `acme_directory` (`api/system.go:134-175`); `GET /api/v1/settings` lists them (sensitive keys filtered, `system.go:110-132`).
  - Dashboard: Settings/Config; Domains page warns when central domains exist but `acme_email` is unset (`web/src/pages/Domains.tsx:75,277-284`).
  - No dedicated CLI subcommand for settings (set via REST).
- **Prerequisites:** real ACME instance (not dry — dry never requires an email).
- **Steps:**
  ```bash
  # before: issuance is skipped quietly (real-ACME instance, no email)
  grep -E 'ACME contact email not configured' <orch.log>
  # set the email + staging directory, no restart
  curl -fsS -X PUT -H "Authorization: Bearer $API_KEY" -H 'Content-Type: application/json' \
    -d '{"value":"you@example.com"}' http://localhost:8099/api/v1/settings/acme_email
  curl -fsS -X PUT -H "Authorization: Bearer $API_KEY" -H 'Content-Type: application/json' \
    -d '{"value":"https://acme-staging-v02.api.letsencrypt.org/directory"}' \
    http://localhost:8099/api/v1/settings/acme_directory
  ```
- **Pass:** before setting the email, the log shows the quiet-skip line and no `renew_failed` audit; after setting it, the next scan (or a new central domain) issues without a restart.
- **Coverage:** D (skip-quietly logic; settings read lazily). R (real issuance after configuring).
- **Pitfalls:** dry-run never needs an email (the dry client skips the check); test this only on a real-ACME instance. `GET /api/v1/settings` never returns `admin_password_hash`/`admin_api_key`/session secret (`system.go:121`), but `acme_email`/`acme_directory` ARE listed.

### 14. Audit source tagging (dryrun vs system)
- **Must:** renewal/issuance audit events use `source=dryrun` in ACME-sandbox mode and `source=system` for real issuance (`cmd/nurproxy/main.go:256-265,303-328`; constants `AuditSourceDryRun`/`AuditSourceSystem` `models.go:404-405`). Actions: `renewed`, `renew_failed`, `issue_failed`, `renew_repush_deferred` (`manager.go:212,244,322,332`). Actor is `renewer`.
- **Access:** audit log via the audit/event API or dashboard; `source` field distinguishes simulated from real.
- **Prerequisites:** sandbox up (dryrun) or real instance (system).
- **Steps:** drive an issuance/renewal, then inspect the audit log for the cert entity.
- **Pass:** dry events carry `source:"dryrun"`; real events carry `source:"system"`; simulated calls are never mistaken for real ones.
- **Coverage:** D (dryrun tagging). R (system tagging).
- **Pitfalls:** a `nil` audit sink disables auditing (used only in narrow tests) (`manager.go:99-104`); production always wires `dbAuditSink`.

### 15. Real DNS-01 issuance & served-leaf verification
- **Must:** a real central-TLS domain gets a genuine Let's Encrypt cert via DNS-01 and the agent serves it; the served leaf is an LE cert whose SAN matches the host.
- **Access:** REST/CLI/dashboard domain create against a real zone with `acme_email` set.
- **Prerequisites:** real orchestrator + real agent (built-in Caddy), a real Cloudflare zone + token, `acme_email` set (staging recommended first).
- **Steps (real):**
  1. Create a central-TLS domain.
  2. Watch the orchestrator log for the DNS-01 solve and a successful obtain.
  3. Verify the served leaf:
     ```bash
     openssl s_client -connect <agent-ip>:443 -servername <host> </dev/null 2>/dev/null | \
       openssl x509 -noout -issuer -subject -ext subjectAltName
     curl --resolve <host>:443:<agent-ip> https://<host>/   # sslverify on, real chain
     curl -k --resolve <host>:443:<agent-ip> https://<host>/ # sslverify=0 sanity
     ```
- **Pass:** issuer is Let's Encrypt (or staging), the SAN list contains `<host>`, and `curl` returns the backend body. `sslverify=0` (`-k`) also succeeds.
- **Coverage:** R.
- **Pitfalls:** LE **production** rate limits — test with staging (`acme_directory` = staging URL) first; staging certs won't validate without `-k`. Issuance does not require inbound `:80`/`:443` (DNS-01), but **serving** does. See RELEASE-QA §2.5b (built-in Caddy central-TLS serving is HIGH RISK / the default mode) and the known route-apply caveat (issue #106).

## Acceptance checklist

### Dry (every RC)
- [ ] `SSLMode` enum is exactly `auto|manual|off`; `TLSPolicy` enum is exactly `central|self-acme|off`; `TLSPolicyForDomain` maps empty→central (off only when `ssl_mode=off`), and out-of-enum `ssl_mode=central` still resolves to central.
- [ ] Central domain issuance drives `_acme-challenge` TXT with `TTL:120`, then cleans up exactly what it created.
- [ ] On-create first issuance fires for central, no-ops for self-acme/off.
- [ ] Renewer start logs window `720h0m0s` (30d); interval is 12h; first-issuance backstop covers a cert-less central domain.
- [ ] Retry: ≤3 retry warnings with growing backoff (2s→4s→8s) for `challenge`/`propagation`; **zero** retries for `ratelimit` and not-configured.
- [ ] `RateLimitError` surfaced + classified; no retry; unblock URL logged.
- [ ] Wildcard issuance logs the shared-key warning and preserves `is_wildcard` on renewal.
- [ ] `acme-account.key` is P-256, mode 0600, and reused (identical checksum) across restarts on a fixed `-data-dir`.
- [ ] `NP_DRY_RUN_FAIL` modes behave: none → 90-day self-signed; `ratelimit`/`challenge`/`propagation` produce their tagged errors; unknown value passes.
- [ ] `/api/v1/health` reports `acme_dry_run`/`dns_dry_run`/`dry_run`.
- [ ] No-email instance skips issuance quietly (no `renew_failed` spam); setting `acme_email` enables issuance without restart.
- [ ] Audit events for renewal carry `source=dryrun` in sandbox.

### Real run (before final)
- [ ] Real central domain → DNS-01 solve → real LE cert obtained, served on `:443`, SAN matches host (`openssl s_client`), `curl -k` succeeds.
- [ ] Audit events for real issuance carry `source=system`.
- [ ] `acme_directory` switches the CA (staging vs production) without a restart.
- [ ] (Soak / LE-staging) renewal of a cert inside the 30-day window re-issues, saves, and re-pushes to the serving agent.
- [ ] (If applicable) wildcard cert issued against a real zone apex; shared-key warning surfaced.
- [ ] Do NOT use `NP_DNS_DRY_RUN` + real ACME — it always fails DNS-01 (mock DNS never publishes the TXT).

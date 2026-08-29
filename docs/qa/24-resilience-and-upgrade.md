# Resilience, In-Place Upgrade & Multi-Agent

> **Scope:** operational continuity — what the reconciler does each cycle, instant route push on change, central cert-renewal companion, in-place orchestrator upgrade with no traffic interruption, agent reconnect after an orchestrator restart, and multi-agent topologies.
> **Code:** `internal/orchestrator/reconciler/reconciler.go`, `internal/orchestrator/reconciler/renewal.go`, `internal/orchestrator/tls/manager.go`, `internal/orchestrator/db/migrations.go` (settings defaults), `cmd/nurproxy/main.go` (wiring), `internal/orchestrator/api/system.go` (`/health`), `internal/agent/stream/stream.go` (reconnect), `scripts/dev-sandbox.sh`, `scripts/durox-agent-swap.sh`.
> **Coverage legend:** D = coverable dry, R = needs a real run.

## Prerequisites
- Both binaries built: `make build-all` (produces `./nurproxy` and `./nurproxy-agent`).
- For dry tests: the sandbox stack, `make dev-sandbox` (orchestrator + 1 agent, seeded). For multi-agent, `make dev-sandbox AGENTS=3` — multiple agents on one box use distinct API ports and `app${n}` subdomains so they don't collide (`scripts/dev-sandbox.sh:97-121`).
- `curl` and `jq` available; know the orchestrator base URL (sandbox default `http://localhost:8099`, `PORT` overrides it).
- For the real in-place upgrade test (R): a real deployed orchestrator (systemd unit) on a real DB, and at least one real adopted agent serving live traffic (e.g. the `durox` nginx edge). `scripts/durox-agent-swap.sh` is the agent-side swap runbook.
- An authenticated session or admin API key for the REST/CLI calls (see §02 / §21). The sandbox seeds an unauthenticated-local instance per its launcher.

## Features covered
- [ ] Reconciler cycle order: agents → deletions → per-agent routes → DNS (domain CNAMEs) → agent DNS (A/AAAA, DDNS).
- [ ] `reconciler_interval` setting (default 60s, min floor 5s, re-read live each cycle).
- [ ] `agent_offline_timeout` setting (default 90s, floor 15s) → online/offline derived from heartbeat freshness, not inbound probes.
- [ ] Instant push on domain change via `PushAgentRoutes` over the agent's live stream (no wait for the next tick).
- [ ] Preflight ordering: certs ride the push ahead of intents; `Keep` retains drifted/under-review artifacts so prune doesn't orphan them.
- [ ] Stream-first vs inbound-fallback route delivery (the `:8780/routes` deadline pitfall).
- [ ] Prompt re-push after a domain delete shrinks the agent's desired set.
- [ ] Central cert-renewal companion: renew window (30d default) + first-issuance for central-TLS domains, scan interval (12h default), post-renew re-push to the serving agent.
- [ ] In-place orchestrator upgrade: stop → back up data dir → swap binary → start; migrations run clean; no traffic interruption.
- [ ] Agent reconnect after orchestrator restart: re-register, heartbeat, stream re-establish, re-sync of routes/certs.
- [ ] Multi-agent: 2+ agents, overlapping/assigned zones, domains on different agents, per-agent artifacts and admin-ops.
- [ ] `/health` reports `version`, `dry_run`/`dns_dry_run`/`acme_dry_run`, and the real DB check.

## Tests

### Reconciler cycle (what runs each tick, in what order)
- **Must:** one cycle runs phases in this fixed order (`reconciler.go:305-343`): `reconcileAgents` (online/offline) → `reconcileDeletions` (tear down `deleting` domains first so they aren't re-created) → per-adopted-agent `reconcileRoutes` → `reconcileDNS` (domain CNAMEs) → `reconcileAgentDNS` (agent A/AAAA + DDNS). A failure in any phase is logged and the remaining phases still run (`reconciler.go:308-339`). The loop runs once immediately on start, then on the timer (`reconciler.go:267-271`).
- **Access:**
  - Env/flag: started automatically by the orchestrator (`cmd/nurproxy/main.go:123-126`); no separate flag to enable it.
  - Observe: orchestrator log lines `reconciler: starting cycle` / `reconciler: cycle complete` and per-phase audit entries; the dashboard Audit Log; REST `GET /api/v1/audit-log`.
- **Prerequisites:** sandbox stack up (seeds provider/zone/agent/server/domain).
- **Steps:**
  ```bash
  make dev-sandbox                 # leaves stack running; note the orchestrator log path it prints
  # In the orchestrator log you will see "reconciler: starting cycle" ... "reconciler: cycle complete".
  curl -s http://localhost:8099/api/v1/audit-log | jq '.entries[] | {actor,action,source}' | head -40
  ```
- **Pass:** the log shows a complete cycle on boot and again after the interval; audit entries with `actor=reconciler` appear for the seeded domain (e.g. `route_pushed`/`dns_created`).
- **Coverage:** D.
- **Pitfalls:** the reconcile cycle is also the convergence engine for everything else — if a domain is stuck `pending`, check the log for the per-phase failure line before blaming the feature under test.

### `reconciler_interval` (default, min, live re-read)
- **Must:** the loop re-reads `reconciler_interval` (seconds) before each sleep, so a change takes effect without restarting the orchestrator (`reconciler.go:294-301`). Default seed value `60` (`migrations.go:97`). Values `< 5` are rejected and the constructed fallback interval is used (`reconciler.go:296-300`; same floor enforced at construction in `main.go:355-368`).
- **Access:**
  - Dashboard: Settings page → `reconciler_interval` field.
  - REST: `PUT /api/v1/settings/reconciler_interval` body `{"value":"15"}`.
  - CLI: no dedicated subcommand; use the settings REST endpoint.
- **Prerequisites:** stack up.
- **Steps:**
  ```bash
  curl -s -X PUT http://localhost:8099/api/v1/settings/reconciler_interval \
    -H 'Content-Type: application/json' -d '{"value":"10"}'
  # watch the orchestrator log: cycles should now begin ~10s apart, no restart.
  ```
- **Pass:** cycle log lines space out to the new interval within one cycle; setting `"3"` (below min) leaves the effective interval at the fallback (cycles do not speed up to 3s).
- **Coverage:** D.
- **Pitfalls:** the change applies on the NEXT timer reset, not instantly mid-sleep — wait up to one old interval. `reconciler_interval` (route/DNS reconcile cadence) is distinct from the cert renewal scan interval (12h, separate loop) — don't conflate them.

### `agent_offline_timeout` (heartbeat-derived online/offline)
- **Must:** an agent is offline iff `now - last_seen > timeout` — derived purely from heartbeat freshness, never from an inbound reachability probe (agents live behind NAT and dial home) (`reconciler.go:349-394`). Default seed `90` seconds (`migrations.go:241`); values below the 15s floor clamp to 15s (`reconciler.go:399-412`). Flipping to offline audits `status_change` ("marked offline: no heartbeat …"); a fresh heartbeat on an `offline` row flips it back to `adopted` and audits "agent came back online".
- **Access:**
  - Dashboard: Settings → `agent_offline_timeout`; agent status shown on the Agents page.
  - REST: `PUT /api/v1/settings/agent_offline_timeout`; `GET /api/v1/agents` (status field).
  - CLI: `nurproxy agent list`, `nurproxy agent status <id>`.
- **Prerequisites:** stack up with one agent adopted.
- **Steps:**
  ```bash
  curl -s http://localhost:8099/api/v1/agents | jq '.[] | {fqdn,status,last_seen}'
  # Kill the dry agent process (find it in the sandbox WORKDIR / ps), wait > timeout, re-list:
  curl -s -X PUT http://localhost:8099/api/v1/settings/agent_offline_timeout \
    -H 'Content-Type: application/json' -d '{"value":"15"}'
  ```
- **Pass:** after the timeout elapses with no heartbeat, status becomes `offline` and an audit `status_change` appears; restarting the agent flips it back to `adopted`.
- **Coverage:** D.
- **Pitfalls:** with the 15s floor, allow ~15-20s before asserting offline. Only `adopted`/`offline` agents are evaluated (`reconciler.go:366`) — a `pending`/`rejected` agent is not flipped.

### Instant push on domain change (`PushAgentRoutes`)
- **Must:** when a domain changes, API handlers call `PushAgentRoutes(agentID)` so a connected agent applies config immediately without waiting for the next reconcile tick (`reconciler.go:96-121`). It is a no-op if the agent isn't currently connected (`reconciler.go:101-103`) — the periodic cycle then catches up. The pushed set is computed by the same `buildDesiredRoutes` the periodic path uses, so push and reconcile always agree (`reconciler.go:418-422`).
- **Access:**
  - Dashboard: Domains page → add/edit a domain (triggers the push).
  - REST: `POST /api/v1/agents/{id}/servers/{sid}/domains` (or the domain create/update endpoints).
  - CLI: `nurproxy domain add …` (see §20).
- **Prerequisites:** stack up, agent connected.
- **Steps:**
  ```bash
  # Add a domain on the seeded agent's server and watch it converge fast (well under one interval):
  curl -s http://localhost:8099/api/v1/audit-log | jq '.entries[] | select(.actor=="reconciler") | {action,details}' | head
  ```
- **Pass:** the new/changed domain's route is applied and the domain reaches `active` faster than `reconciler_interval` (the push, not the tick, drove it).
- **Coverage:** D.
- **Pitfalls:** if the agent is offline at the moment of change, nothing is pushed — verify it converges on the next reconcile tick instead. Don't expect a push to reach a NAT'd agent over the inbound client; it rides the agent-initiated stream only.

### Preflight ordering & `Keep` (certs before intents, retain under-review artifacts)
- **Must:** the push delivers an `IntentSet{Intents, Certs, Keep}` (`reconciler.go:119`): the agent installs the cert bundles first, then applies the referencing config, so a generated config never validates against a missing cert file (`reconciler.go:113-119`). A host with no stored cert is skipped (built-in Caddy self-ACME fallback), never failing the push (`gatherCerts`, `reconciler.go:170-199`). `Keep` carries drifted/under-review artifact paths so the agent's prune retains them and never mistakes them for a deleted domain's orphan (invariant #3, `reconciler.go:434`, `476-484`, `542-549`).
- **Access:** internal (no direct user trigger) — exercised by any domain change or reconcile on an agent that has central-TLS domains.
- **Prerequisites:** sandbox (self-signed certs are issued for central-TLS domains).
- **Steps:**
  ```bash
  curl -s 'http://localhost:8099/api/v1/audit-log?source=dryrun' | jq '.entries[] | {action,details}' | head
  # Drift case: create on-disk drift (see §14), confirm the artifact is NOT bulldozed by reconcile.
  ```
- **Pass:** central-TLS domains go `active` (cert installed before apply, no validation error in agent log); a drifted artifact whose agent has `AutoReconcileConfig=false` is skipped with a `skipping push … (artifact … drifted, awaiting review)` log line and is NOT pruned.
- **Coverage:** D (drift retention and cert preflight both exercise dry; the cert is self-signed).
- **Pitfalls:** the per-agent `AutoReconcileConfig` policy overrides drift-skip and re-applies generated content over the drift (`reconciler.go:476`) — confirm which mode the agent is in before asserting.

### Stream-first vs inbound-fallback delivery (the `:8780/routes` deadline)
- **Must:** if the agent holds an open stream, `reconcileRoutes` publishes the desired set down it and returns (`reconciler.go:545-551`). Only when there is no stream does it fall back to the inbound client (`GetRoutes`/`PushRoute` to the agent's advertised `APIURL`, default agent API port 8780) (`reconciler.go:553-557`).
- **Access:** internal; observed via logs.
- **Prerequisites:** a real orchestrator + agent where the orchestrator cannot reach the agent inbound at its advertised address (the common NAT case).
- **Steps:** restart the orchestrator and watch its log around the agent's reconnect.
- **Pass:** routes converge via the stream; any `…:8780/routes … context deadline exceeded` line is one-time per reconnect and cosmetic (routes were delivered by push). Sites stay up.
- **Coverage:** R (the inbound timeout only manifests against a real NAT'd agent; the stream-push path itself is D).
- **Pitfalls (folds in §2.11):** the **one-time** `:8780/routes context deadline exceeded` per agent reconnect is expected and harmless when the orchestrator can't reach the agent at its advertised address — do not treat it as a failure. It should appear at most once per reconnect, not repeatedly.

### Prompt re-push after domain delete
- **Must:** `reconcileDeletions` tears down `deleting` domains (delete only NurProxy-managed DNS records, remove the central artifact, delete the row), collects each affected agent, then re-pushes that agent's now-smaller desired set so it prunes the orphaned vhost promptly rather than waiting for the next full tick (`reconciler.go:1061-1153`). Adopted (operator-owned) DNS records are left in place (`reconciler.go:1113-1116`).
- **Access:**
  - Dashboard: Domains → delete.
  - REST: `DELETE /api/v1/.../domains/{id}`.
  - CLI: `nurproxy domain delete <id>`.
- **Prerequisites:** stack up with a domain `active` on an agent.
- **Steps:** delete the domain, then inspect the audit log.
- **Pass:** audit shows `dns_deleted`/`dns_delete_skipped` (managed) or `dns_left_adopted` (adopted), `config_artifact remove`, and `domain deleted`; the vhost is pruned promptly.
- **Coverage:** D.
- **Pitfalls:** an adopted record (`DNSManaged=false`) is intentionally NOT deleted — verify your test domain's record was actually NurProxy-created if you expect deletion. A DNS delete failure (other than not-found) keeps the domain in `deleting` to retry; not-found counts as success so teardown never wedges (`reconciler.go:1094-1105`).

### Central cert-renewal companion (window, first-issuance, post-renew push)
- **Must:** a separate Renewer loop scans for work and acts on it (`tls/manager.go`). `DueForRenewal` returns (1) existing certs within the renew window of expiry, plus (2) central-TLS domains with no cert yet (first issuance) (`renewal.go:48-116`). Defaults: renew window `30 * 24h` = 30 days (`manager.go:14-19`), scan interval `12h` (`manager.go:21-24`). After re-issue, `SaveRenewed` upserts the host-keyed cert with the new expiry (`renewal.go:173-193`), and the post-renewal hook `RepushCertForHost` re-pushes the fresh cert + config to the serving agent (`reconciler.go:123-142`). An offline agent re-syncs the fresh cert on reconnect (best-effort by contract).
- **Access:**
  - Env/flag: started automatically (`main.go:135`, `235-267`). Dry: `NP_ACME_DRY_RUN=true` (or `-dry-run`) makes the DNS-01 + issuance synthetic; `NP_DRY_RUN_FAIL=ratelimit|challenge|propagation` injects failures.
  - Observe: orchestrator log `tls: renewing certificates within window`; audit log; `GET /api/v1/certificates` (expiry).
- **Prerequisites:** sandbox (self-signed certs) for D; for the real renew-within-window path, an LE-staging soak (R — see Known gaps §4 of RELEASE-QA).
- **Steps:**
  ```bash
  make dev-sandbox    # seeds central-TLS domains; the renewer first-issues them
  curl -s http://localhost:8099/api/v1/certificates | jq '.[] | {host,expires_at}'
  ```
- **Pass:** central-TLS domains get a (self-signed, in dry) cert via first-issuance; renewal window math behaves as in prod (the dry issuer dates certs so the window logic is exercised, `tls/dryrun.go`). A host whose zone/provider can't be resolved is logged and skipped, never aborting the scan (`renewal.go:67-70`).
- **Coverage:** D for first-issuance + window logic + push; R for an actual renewal of a real LE cert inside the 30-day window.
- **Pitfalls:** the 12h scan means a real renewal won't be observed by waiting — force it with a short-dated staging cert or trigger the on-create fast path (`TargetForHost`). Rate-limit failures are intentionally NOT retried within the backoff window (`manager.go:30-33`) — re-running won't burn quota but also won't recover until the limit clears.

### In-place orchestrator upgrade (no traffic interruption)
- **Must:** stop the orchestrator → back up the data dir → swap the binary → run `nurproxy permissions --data-dir <dir>` → start. Package upgrades resolve `NP_DATA_DIR` from `/etc/nurproxy/nurproxy.env` (default `/var/lib/nurproxy`), run that migration before start/restart, and propagate permission, daemon-reload, enable/start, and restart failures. DB migrations run cleanly on the real DB on boot (`migrations.go`). The agent keeps serving traffic the entire time (the proxy — Caddy/nginx/Apache — runs independently of the orchestrator), so there is **no traffic interruption**; the agent simply reconnects to the restarted orchestrator. `/health` reports the new `version` once back up.
- **Access:**
  - Ops: `systemctl stop nurproxy && cp -a <data-dir> <data-dir>.bak-$TS && install -m755 ./nurproxy /usr/bin/nurproxy && systemctl start nurproxy`.
  - Observe: `curl -s http://<orch>/api/v1/health | jq '{status,version}'`; `nurproxy version`; agent reconnect in both logs.
- **Prerequisites:** a real deployed orchestrator on a real DB; at least one real agent serving a live site (R).
- **Steps:**
  ```bash
  # On the orchestrator host (as the service user / root as appropriate):
  curl -s http://localhost:8080/api/v1/health | jq '{status,version}'   # record OLD version
  systemctl stop nurproxy
  cp -a /var/lib/nurproxy /var/lib/nurproxy.bak-$(date +%Y%m%d-%H%M%S)
  install -m755 ./nurproxy /usr/bin/nurproxy
  /usr/bin/nurproxy permissions --data-dir /var/lib/nurproxy
  systemctl start nurproxy
  # Throughout, keep curling a live proxied site to confirm zero downtime:
  while true; do curl -s -o /dev/null -w "%{http_code}\n" https://<live-site>/; sleep 1; done
  curl -s http://localhost:8080/api/v1/health | jq '{status,version}'   # NEW version, status ok
  ```
- **Pass:** the permission command exits zero, the data directory is `0700`, managed files are `0600`, `systemctl show nurproxy -p UMask` reports `UMask=0077`, `/health` returns `status:"ok"` with the bumped `version`; migrations log clean (no errors); the live-site curl loop never drops a request; the agent reconnects.
- **Coverage:** R (the live-traffic / real-DB migration aspect needs a real run; migration correctness itself is also covered by `make test`).
- **Pitfalls (folds in §2.11):** expect the **one-time** `:8780/routes context deadline exceeded` per agent reconnect — cosmetic. Always back up the data dir BEFORE the swap (the agent-swap script does this with timestamped `.bak-$TS` copies, `scripts/durox-agent-swap.sh:14-19`). A failed permission migration is a hard upgrade stop: inspect the named path and file type; do not bypass it with recursive `chmod` or symlink-following tools. Mode narrowing has no automatic rollback (see `17-backup-and-restore.md`). The agent binary swap is the symmetric procedure: `scripts/durox-agent-swap.sh` stops the agent, verifies `nginx -t` before and after, swaps, restarts, and prints rollback hints — run it as root on the edge host with the new binary staged at `/tmp/nurproxy-agent.new`.

### Agent reconnect after orchestrator restart
- **Must:** when the orchestrator restarts, the agent re-establishes its outbound stream and resumes heartbeating; the stream client reconnects on error (`internal/agent/stream/stream.go:215`, `TestStreamReconnectsOnError`). On reconnect the orchestrator re-pushes the agent's desired set (intents + certs), so the agent re-adopts its artifacts; the agent ACKs applied artifacts back. A fresh heartbeat flips an `offline` row back to `adopted` (`reconciler.go:385-390`).
- **Access:** automatic; observe via `GET /api/v1/agents` (status, last_seen), audit log, and agent/orchestrator logs.
- **Prerequisites:** stack up (D) or real deployment (R).
- **Steps:**
  ```bash
  # Dry: restart the sandbox orchestrator process (re-run the launcher's orchestrator step),
  # or in a real deploy: systemctl restart nurproxy. Then:
  curl -s http://localhost:8099/api/v1/agents | jq '.[] | {fqdn,status,last_seen}'
  ```
- **Pass:** agent returns to `adopted`, `last_seen` advances, routes/certs re-sync, audit shows the reconnect (and "agent came back online" if it had gone offline). No traffic drop (the proxy never stopped).
- **Coverage:** D for the reconnect + re-sync mechanics; R for confirming no live-traffic drop.
- **Pitfalls:** allow a few seconds for the stream to re-dial and the next reconcile tick to re-push. The one-time `:8780/routes` deadline line may appear here too.

### Multi-agent topology
- **Must:** the orchestrator drives N agents independently — per-agent desired route sets (`buildDesiredRoutes` is keyed by agent, `reconciler.go:422`), per-agent artifacts/backends (`backendForAgent`, `reconciler.go:222-228`), per-agent DNS A/AAAA anchored to each agent's FQDN (`reconcileAgentDNS`, `reconciler.go:865-932`). Domains attach to a specific agent's server, so domains on different agents are isolated; zones can be assigned to multiple agents (overlapping zones) and each agent's anchor FQDN is matched to the longest-suffix assigned zone (`matchZoneForFQDN`, `reconciler.go:1041-1052`).
- **Access:**
  - CLI: `nurproxy agent list`, `nurproxy agent adopt <id>`, `nurproxy agent update <id>`.
  - REST: `GET /api/v1/agents`, `PUT /api/v1/agents/{id}/adopt` (body `{"name":…,"zone_ids":[…]}`), `POST /api/v1/agents/{id}/servers`.
  - Dashboard: Agents page (per-agent view, servers, domains).
- **Prerequisites:** none beyond the multi-agent sandbox.
- **Steps:**
  ```bash
  make dev-sandbox AGENTS=3
  curl -s http://localhost:8099/api/v1/agents | jq '.[] | {fqdn,status}'
  # Each agent gets its own server + app${n}.<zone> domain; confirm 3 active agents:
  curl -s http://localhost:8099/api/v1/audit-log | jq '.entries[] | select(.entity_type=="agent") | {entity_id,action}' | head
  ```
- **Pass:** all N agents register, adopt, and reach `adopted`; each agent serves only its own domain(s); each agent's anchor A/AAAA record is created/adopted independently; no port collisions on the single box (agents use distinct API ports, `scripts/dev-sandbox.sh:97-103`).
- **Coverage:** D (full multi-agent control-plane on one box).
- **Pitfalls:** in the sandbox, agents share one host but distinct API ports and `app${n}` subdomains — don't reuse the same FQDN/subdomain across agents or routes collide. An agent whose anchor FQDN falls outside all its assigned zones gets a `dns_error` ("FQDN … not inside any assigned DNS zone") and its A/AAAA is skipped (`reconciler.go:886-894`) — assign the matching zone or set the anchor within a zone.

### `/health` self-report (version + dry-run flags + DB check)
- **Must:** `GET /api/v1/health` returns `status`, `version`, `checks.database`, and `dry_run`/`dns_dry_run`/`acme_dry_run` (`api/system.go:15-34`). It performs a real DB `Ping` with a 3s timeout and returns **503** with `status:"degraded"` when the DB is unreachable (so a monitor detects a wedged instance) (`api/system.go:27-31`).
- **Access:** REST `GET /api/v1/health` (unauthenticated liveness endpoint); dashboard shows a persistent "Dry-run mode" banner when dry.
- **Prerequisites:** stack up.
- **Steps:**
  ```bash
  curl -s http://localhost:8099/api/v1/health | jq
  ```
- **Pass:** dry sandbox reports `dry_run:true`, `dns_dry_run:true`, `acme_dry_run:true`, `status:"ok"`, `checks.database:"ok"`, and a `version`. After an upgrade the `version` reflects the new build. (503 behaviour is unit-tested in `api/health_test.go`.)
- **Coverage:** D.
- **Pitfalls:** `dry_run` is `true` if *either* DNS or ACME dry-run is on — check the specific `dns_dry_run`/`acme_dry_run` flags to know which subsystem is simulated.

## Acceptance checklist

**Dry (every RC):**
- [ ] `make dev-sandbox` boots; orchestrator log shows a full `reconciler: starting cycle … cycle complete` on boot and again on interval.
- [ ] `reconciler_interval` change via `PUT /api/v1/settings/reconciler_interval` takes effect live; sub-5 value rejected.
- [ ] Agent flips `offline` after `agent_offline_timeout` of no heartbeat and back to `adopted` on restart; floor 15s respected.
- [ ] Domain add converges faster than one interval (instant push); domain delete prunes promptly and leaves adopted DNS records in place.
- [ ] Central-TLS domains get a cert via first-issuance; renewal window/interval defaults confirmed (30d / 12h).
- [ ] `make dev-sandbox AGENTS=3` brings up 3 isolated agents, each serving its own domain, each with its own anchor record.
- [ ] `/health` reports `version` + correct `dry_run`/`dns_dry_run`/`acme_dry_run`.
- [ ] `make test` + `make test-sandbox` green (covers reconciler unit tests, migrations, stream reconnect).

**Real run (before final):**
- [ ] In-place orchestrator upgrade on a real DB: migrations clean, `/health` shows bumped `version` + `status:"ok"`, agent reconnects, the live-site curl loop drops **zero** requests.
- [ ] Agent binary swap via `scripts/durox-agent-swap.sh`: `nginx -t` passes before and after, agent active, site unaffected.
- [ ] The `:8780/routes context deadline exceeded` line appears at most **once** per agent reconnect (cosmetic) — not repeatedly.
- [ ] Real renewal of an LE(-staging) cert inside the 30-day window re-pushes to the serving agent (or noted as deferred per §4 Known gaps).

# DNS Record Lifecycle, Ownership, DDNS & IPv6

> **Scope:** managed DNS behaviour — domain CNAMEs (`sub → agentFQDN`), agent A/AAAA
> anchor records, record ownership (created vs adopted), the static/ddns DNS modes,
> public IPv4/IPv6 detection, and IPv6/AAAA verification caveats.
> **Code:** `internal/orchestrator/reconciler/reconciler.go` (CNAME + agent A/AAAA +
> deletions), `internal/agent/ddns/ddns.go` (heartbeat + public IP detection),
> `internal/agent/adoption/adoption.go` (register-time IP detection),
> `internal/provider/dryrun/dryrun.go` (in-memory DNS sandbox),
> `internal/provider/provider.go` + `internal/provider/cloudflare/cloudflare.go`,
> `internal/shared/models/models.go` (`DNSMode`, `Agent`, `Domain`),
> `internal/orchestrator/api/agents.go` (adopt/update/heartbeat),
> `cmd/nurproxy/cli_commands.go` (`agent adopt/update`),
> `cmd/nurproxy-agent/main.go` (heartbeat interval).
> **Coverage legend:** D = coverable dry, R = needs a real run.

## Prerequisites

What must already be true before any test in this file:

- Both binaries built: `make build-all` (produces `./nurproxy` and `./nurproxy-agent`).
- For the **dry** path, the fastest setup is the full stack:
  ```bash
  make dev-sandbox AGENTS=2     # orchestrator + 2 dry agents, seeded provider/zone/domains
  ```
  The launcher (`scripts/dev-sandbox.sh`) seeds a Cloudflare provider with a dummy
  token, a zone (default `dryrun.invalid` — see `ZONE` in the script), adopts each
  agent onto the zone, creates one central-TLS domain per agent
  (`app<n>.<zone>` → server `10.0.0.5:8080`), and waits for convergence. All DNS
  calls go through `internal/provider/dryrun` (in-memory, no Cloudflare). On startup
  it prints `BASE` (the API base URL, default `http://localhost:8080`; override with
  `PORT=…`), the admin API key (`np_ak_…`), and the `WORKDIR` (default
  `./.dev-sandbox`, holding `orch.log` / `agent*.log`). The curl steps below assume
  you have exported those:
  ```bash
  export BASE=http://localhost:8080
  export API_KEY=...        # the np_ak_… key the launcher printed
  ```
- For **real** verification you need: a real Cloudflare provider + a real zone, a real
  agent whose anchor FQDN lives inside that zone, and `dig` installed. Tests querying
  the authoritative nameserver also need the zone's NS hostnames (Cloudflare dashboard
  → DNS → "Cloudflare nameservers").
- Audit log read access: `GET /api/v1/audit-log?limit=N` (requires an admin session/API
  key; route registered at `internal/orchestrator/api/server.go:222`,
  handler `internal/orchestrator/api/system.go:36`). Supports `?limit=`, `?offset=`,
  and `?source=` filters.

> **Dry caveat that shapes every dry test below:** the dry agent does **not** mock its
> own public-IP detection. `adoption.go:121` / `ddns.go:170,179` still call the real
> ipify/ifconfig/icanhazip (and IPv6 equivalents) over the network. On a box **with**
> internet the agent reports a real public IPv4 (and a real IPv6 if the box is
> dual-stack), and the reconciler then creates **in-memory** A/AAAA records for the
> anchor. On a fully **offline** box `public_ip` stays `""` and `reconcileAgentDNS`
> skips the agent entirely (`reconciler.go:876-878`) — so **no A record audit event
> appears**. This is expected, not a bug.

## Features covered

- [ ] Domain CNAME `sub → agentFQDN` created **a reconcile cycle after** the domain
      goes active (the timing artifact).
- [ ] Record ownership: `dns_managed=true` (NurProxy-created, deleted on teardown) vs
      `dns_managed=false` (adopted identical pre-existing, left on teardown).
- [ ] Never overwrite a **conflicting** record (different content at the same name) —
      explicit `dns_conflict`, domain goes `error`.
- [ ] CNAME content drift correction (`dns_updated`).
- [ ] Domain-CNAME audit events: `dns_created` / `dns_adopted` / `dns_conflict` /
      `dns_updated` / `dns_deleted` / `dns_delete_skipped` / `dns_left_adopted`.
- [ ] Agent anchor **A** record (`dns_record_id`) and **AAAA** record
      (`dns_record_id6`) — separate provider record IDs per family.
- [ ] Agent-record audit events: `a_record_created/adopted`, `aaaa_record_created/adopted`,
      `a_record_conflict` / `aaaa_record_conflict` (CNAME-at-name), `ddns_updated`.
- [ ] FQDN-outside-zone error (`dns_error` / `dns_error_cleared`).
- [ ] DNS modes per agent: `DNSMode` enum (`static` | `ddns`) + `ddns_interval`
      (settable; see pitfall on what actually drives the cadence).
- [ ] Public IPv4 detection sources (ipify / ifconfig.me / icanhazip) and IPv6-only
      detection sources (api6.ipify / v6.ident.me / ipv6.icanhazip).
- [ ] Orchestrator updates the address record on IP change (DDNS) vs leaves it
      untouched (static).
- [ ] IPv6 / AAAA verification caveats (hairpin self-test flakiness, authoritative-NS
      vs public resolver, wildcard `*.zone` masking).
- [ ] Real verification with `dig` against the authoritative NS.

## Tests

### CNAME timing — created a reconcile cycle AFTER the domain goes active

- **Must:** creating a domain does **not** create the CNAME synchronously. The DNS
  phase (`reconcileDNS`, `reconciler.go:638`) runs on the periodic cycle; when it
  finds a domain with no `DNSRecordID` it calls `ensureDomainCNAME`
  (`reconciler.go:741`) which looks the name up, then adopts/creates. So the CNAME
  `sub → agent.FQDN` appears on the **next reconcile cycle after** the domain became
  active, not at create time.
- **Access:**
  - REST: `POST /api/v1/domains` body `{"subdomain":"app1","zone_id":"…","server_id":"…","port":8080,"ssl_mode":"auto"}`
    (`ssl_mode` enum is `auto` | `manual` | `off`, defaulting to `auto`; `models.go:46-48`,
    applied at `domains.go:91-93`. There is **no** `central` value — central/managed TLS
    is what `auto` yields on a zone that has a DNS provider).
  - CLI: `nurproxy domain add -subdomain app1 -zone <zoneid> -server <serverid> -port 8080 -ssl-mode auto`
    (flags at `cmd/nurproxy/cli_commands.go:370-378`; note CLI uses `-zone`/`-server`
    while the REST body uses `zone_id`/`server_id`).
  - Dashboard: Domains page → Add Domain.
  - MCP: the orchestrator MCP server exposes `create_domain` / `update_domain` /
    `delete_domain` (`internal/orchestrator/mcp/server.go:212-224`), so the same
    create/teardown lifecycle is drivable from an MCP client. (`create_domain`'s
    `ssl_mode` enum there is also `auto`|`manual`|`off`.)
  - Observe: `GET /api/v1/audit-log` (look for `dns_created`/`dns_adopted` on
    `entity_type=domain`).
- **Prerequisites:** stack up via `make dev-sandbox` (already seeds domains), or create
  one by hand against a dry orchestrator.
- **Steps (D):**
  ```bash
  make dev-sandbox KEEP=1 AGENTS=1
  # The launcher prints BASE (default http://localhost:8080), the API key, and the
  # WORKDIR (default ./.dev-sandbox). Export them, then watch the DNS phase + audit:
  export BASE=http://localhost:8080
  export API_KEY=...                       # the np_ak_… key the launcher printed
  # Reconcile cycles are visible in the orchestrator log:
  grep -nE 'reconciler: (starting cycle|cycle complete)' ./.dev-sandbox/orch.log | tail
  # The DNS ownership events live in the audit log (not the orch.log), source=dryrun:
  curl -fsS -H "Authorization: Bearer $API_KEY" "$BASE/api/v1/audit-log?limit=20" \
    | python3 -c 'import sys,json;[print(e["action"],e["source"],e["details"]) for e in json.load(sys.stdin)["entries"] if e["entity_type"]=="domain"]'
  ```
- **Pass:** a `dns_created` (or `dns_adopted`) audit entry for the domain appears
  **after** the domain first reached `active`, on a later cycle — not in the same
  instant as the create. In dry the entry's `source` is `dryrun` (`reconciler.go:1254`).
- **Coverage:** D.
- **Pitfalls:**
  - **Timing artifact (from RELEASE-QA §2.2):** reading `dns_managed` immediately after
    create shows the zero value because the record does not exist yet. That is **not**
    the final state. Confirm via the audit log, not an instant read. On a real run the
    gap is roughly one reconcile interval (~30–50 s).
  - The reconcile interval is configurable (`reconciler_interval` setting, floor 5 s,
    `reconciler.go:294-301`); the default is whatever the orchestrator was constructed
    with. Don't assume exactly 30 s.

### Record ownership — managed (created) vs adopted (pre-existing identical)

- **Must:**
  - When **no** record exists at the name, the reconciler **creates** it and stores
    `dns_managed=true` (`reconciler.go:790`, audit `dns_created`).
  - When a record at the name **already matches** what NurProxy would set (same type
    CNAME + same content, case/trailing-dot tolerant — `matchingRecord` +
    `sameRecordContent`, `reconciler.go:816,838`), it is **adopted**: stored with
    `dns_managed=false` (`reconciler.go:756`, audit `dns_adopted`).
  - On teardown, only `dns_managed=true` records are deleted (`reconciler.go:1090`,
    audit `dns_deleted` / `dns_delete_skipped`); a `dns_managed=false` record is left
    in place (`reconciler.go:1113`, audit `dns_left_adopted`).
- **Access:** implicit via domain create/delete; observe via `dns_managed` on
  `GET /api/v1/domains` and via the audit log.
- **Prerequisites:** dry stack (the adopt branch needs a pre-existing in-memory record;
  see Steps).
- **Steps (D, create + delete = managed):**
  ```bash
  # With the sandbox up, delete a seeded domain and watch teardown:
  DOM=$(curl -fsS -H "Authorization: Bearer $API_KEY" "$BASE/api/v1/domains" \
        | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])')
  curl -fsS -X DELETE -H "Authorization: Bearer $API_KEY" "$BASE/api/v1/domains/$DOM"
  # next reconcile cycle: audit shows dns_deleted (managed) for that domain
  curl -fsS -H "Authorization: Bearer $API_KEY" "$BASE/api/v1/audit-log?limit=30" \
    | python3 -c 'import sys,json;[print(e["action"],e["details"]) for e in json.load(sys.stdin)["entries"] if e["entity_type"]=="domain"]'
  ```
  Adopt branch (D): the dry store is process-global, so a record "pre-created" in one
  cycle is visible to the next. The cleanest dry proof of the adopt path is the unit
  test `internal/orchestrator/reconciler/reconciler_test.go` (grep `dns_adopted` /
  `Adopt`). For an end-to-end real proof, see the R variant below.
- **Steps (R, true adopt + leave-on-teardown):**
  ```bash
  # 1. At the real provider, hand-create the EXACT record NurProxy would: CNAME sub -> agent.FQDN
  # 2. Create the domain in NurProxy. After a cycle: audit dns_adopted, domain dns_managed=false.
  # 3. dig +short sub.<zone> @<authoritative-NS>  -> resolves to agent.FQDN
  # 4. Delete the domain. After a cycle: audit dns_left_adopted; the record is STILL present:
  dig +short sub.<zone> @<authoritative-NS>      # still returns agent.FQDN
  ```
- **Pass:** create-then-delete of a NurProxy-created record → `dns_created` then
  `dns_deleted`, record gone. Adopt-then-delete of an operator record → `dns_adopted`
  then `dns_left_adopted`, record **retained**.
- **Coverage:** D (managed create/delete, and adopt logic via the dry store / unit
  test) / R (true operator-owned-record adopt + leave-on-teardown end to end).
- **Pitfalls:**
  - Teardown DNS deletion runs in the **reconciler** (`reconcileDeletions`), not in the
    `DELETE` handler — the delete is **soft** (`status=deleting`) and the real removal
    happens a cycle later (RELEASE-QA §2.4).
  - Deletion is **idempotent**: a record already gone at the provider
    (`provider.ErrRecordNotFound`) is logged as `dns_delete_skipped` and teardown
    proceeds; any **other** delete error keeps the domain in `deleting` to retry next
    cycle (`reconciler.go:1097-1104`).
  - On successful (or already-absent) delete the stored record id + managed flag are
    cleared immediately (`reconciler.go:1108`) so a later-step failure in the same cycle
    doesn't re-delete a dead id.

### Never overwrite a conflicting record

- **Must:** when a record exists at the name but is **not** the one NurProxy would set
  (different content / not a matching CNAME), the reconciler refuses to touch it: it
  sets the domain to `error` with an actionable message and audits `dns_conflict`
  (`reconciler.go:767-776`). It **never** overwrites a record it did not create.
- **Access:** implicit; observe domain `status=error` + `error` message on
  `GET /api/v1/domains`, and audit `dns_conflict`.
- **Prerequisites:** a pre-existing non-matching record at the target name.
- **Steps (R):** hand-create a CNAME `sub.<zone> → somewhere-else.example.` (different
  target) at the provider, then create the domain in NurProxy. After a cycle, inspect
  the domain status.
- **Pass:** domain `status=error`; message names the current record vs the desired
  target and says NurProxy won't overwrite a record it didn't create; audit
  `dns_conflict`. The foreign record is unchanged at the provider.
- **Coverage:** D (logic via dry store / unit test) / R (against a real provider record).
- **Pitfalls:** the conflict message includes the existing record(s) (`describeRecords`,
  `reconciler.go:849`). A matching CNAME is **adopted**, not flagged — only a genuine
  mismatch conflicts.

### CNAME content drift correction

- **Must:** if the stored `DNSRecordID` resolves but its content no longer equals
  `agent.FQDN`, the reconciler updates it back (`reconciler.go:711-727`, audit
  `dns_updated`). If the stored id no longer resolves, it re-resolves by name
  (`reconciler.go:700-707`) rather than blind-creating.
- **Access:** implicit; observe via audit `dns_updated` / `dns_update_failed`.
- **Prerequisites:** a managed CNAME already in place (a domain that converged to
  `active` with `dns_managed=true`), plus out-of-band write access to the provider to
  forge the drift.
- **Steps (R):** with a managed CNAME in place, hand-edit it at the provider to point
  elsewhere; wait a cycle.
- **Pass:** the CNAME is restored to `agent.FQDN`; audit `dns_updated` records the
  old → new content.
- **Coverage:** D (logic) / R (real provider write). DNS-drift correction needs write
  access to the provider outside NurProxy, so it is hard to fully self-test (RELEASE-QA
  §2.7).
- **Pitfalls:** if the stored `DNSRecordID` no longer resolves at all (record deleted
  out of band), the reconciler does **not** blind-create — it re-resolves by name via
  `ensureDomainCNAME` (`reconciler.go:700-707`), so it re-adopts a matching live record
  or flags a conflict rather than risking a duplicate.

### Agent anchor A and AAAA records — separate IDs per family

- **Must:** for every adopted (or offline-but-known) agent with a non-empty
  `PublicIP`, the reconciler ensures an **A** record for the anchor `agent.FQDN`
  (`reconcileAgentDNS`, `reconciler.go:865`; `ensureAgentAddressRecord`,
  `reconciler.go:940`), tracked by `dns_record_id`. When the agent also reports a
  routable `PublicIP6`, it additionally ensures an **AAAA** record tracked by a
  **separate** `dns_record_id6` (`reconciler.go:921-928`), so the two families update
  independently. A and AAAA legitimately coexist at the same name; the only hard
  conflict is a **CNAME** already sitting there (`reconciler.go:966-972`, audit
  `a_record_conflict` / `aaaa_record_conflict`).
- **Access:**
  - Implicit via agent register + adopt.
  - Observe: `GET /api/v1/agents` → `public_ip`, `public_ip6`, `dns_record_id`,
    `dns_record_id6` (model `internal/shared/models/models.go:234-245`). Audit actions:
    `a_record_created` / `a_record_adopted`, `aaaa_record_created` / `aaaa_record_adopted`.
- **Prerequisites:** for AAAA, the agent box must have working **outbound IPv6** (the
  IPv6 detection services resolve over AAAA only — `ddns.go:271-275` — so a request
  succeeds exactly when the host has routable IPv6, which is the precondition for
  publishing an AAAA at all).
- **Steps (D, A record — needs an online box):**
  ```bash
  # With dev-sandbox up on an internet-connected host:
  curl -fsS -H "Authorization: Bearer $API_KEY" "$BASE/api/v1/agents" \
    | python3 -c 'import sys,json;[print(a["fqdn"],a.get("public_ip"),a.get("public_ip6"),a.get("dns_record_id"),a.get("dns_record_id6")) for a in json.load(sys.stdin)]'
  curl -fsS -H "Authorization: Bearer $API_KEY" "$BASE/api/v1/audit-log?limit=40" \
    | python3 -c 'import sys,json;[print(e["action"],e["details"]) for e in json.load(sys.stdin)["entries"] if e["entity_type"]=="agent"]'
  ```
- **Steps (R, AAAA):** on a dual-stack real agent, confirm `public_ip6` is non-empty
  on `GET /api/v1/agents`, then verify the AAAA at the provider / via dig (next test).
- **Pass:** A-capable host → `dns_record_id` set, audit `a_record_created` (or
  `_adopted`). Dual-stack host → `dns_record_id6` set (distinct from `dns_record_id`),
  audit `aaaa_record_created`. IPv4-only host → `public_ip6` empty, **no** AAAA record,
  no AAAA audit event.
- **Coverage:** D (A record on an online box; logic) / R (AAAA on a real dual-stack host).
- **Pitfalls:**
  - On an **offline** box `public_ip` is empty and `reconcileAgentDNS` skips the agent
    (`reconciler.go:876-878`) — you will see no A record. Expected (see file-level dry
    caveat).
  - A blank `public_ip6` on a beat leaves the orchestrator's stored value and any AAAA
    untouched (`ddns.go:178-182`, `reconciler.go:921`); IPv6 is strictly best-effort and
    must never affect the IPv4 path.
  - The agent's `FQDN` must be **inside** an assigned zone or the A/AAAA can't be made;
    see the next test.

### FQDN outside any assigned zone

- **Must:** if the agent's anchor FQDN is not inside any of its assigned zones
  (`matchZoneForFQDN`, `reconciler.go:1041` — longest-suffix match), the reconciler
  cannot create its A/AAAA and every domain CNAME pointing at it dangles. It surfaces a
  clear `dns_error` on the agent (`setAgentDNSError`, `reconciler.go:1014`, audit
  `dns_error`) and clears it (`dns_error_cleared`) once the FQDN lands inside a zone.
- **Access:** observe `dns_error` on `GET /api/v1/agents`; the MCP `get_agent_status`
  tool also surfaces it (`mcp/server.go:292`). Audit `dns_error` / `dns_error_cleared`.
  Fix by reassigning the zone or changing the anchor FQDN via `PUT /api/v1/agents/{id}` /
  `nurproxy agent update -fqdn … -zones …`. (Agent adopt/update is **not** exposed over
  MCP — the MCP agent tools are read-only; use REST/CLI/Dashboard to change the FQDN/zones.)
- **Prerequisites:** dry stack; an agent with a non-empty `public_ip` (otherwise
  `reconcileAgentDNS` skips it before the zone check, `reconciler.go:876-878`) whose
  anchor FQDN is **not** a suffix-member of any assigned zone.
- **Steps (D):** adopt an agent whose FQDN is **not** a suffix-member of the assigned
  zone (e.g. zone `dryrun.invalid` but FQDN `edge1.other.test`), then read the agent.
- **Pass:** `dns_error` set with the hint to set the anchor within a zone; flipping the
  FQDN/zone clears it with `dns_error_cleared`.
- **Coverage:** D.
- **Pitfalls:** `dns_error` is kept **separate** from `last_error`
  (`models.go:268-272`) so an agent-reported proxy error and an orchestrator-side DNS
  error never overwrite each other. `setAgentDNSError` only writes/audits on a **change**
  (`reconciler.go:1015`) — no audit spam in steady state.

### DNS modes — static vs ddns

- **Must:** `DNSMode` is an enum with exactly two values: `static` and `ddns`
  (`models.go:38-39`; verified by `models_test.go:141`). Default is `static`
  (DB default, `migrations.go:29`). In **static** mode the agent's address record is
  created once and never auto-updated on IP change
  (`ensureAgentAddressRecord`, `reconciler.go:985-988`: `if a.DNSMode != DNSModeDDNS
  { return }`). In **ddns** mode the record is updated whenever the detected IP changes
  (`reconciler.go:990-1007`, audit `ddns_updated`); if the IP is unchanged it skips the
  API call (`reconciler.go:999-1001`).
- **Access:**
  - REST adopt: `PUT /api/v1/agents/{id}/adopt` body
    `{"name":"…","zone_ids":["…"],"dns_mode":"ddns","ddns_interval":300}`
    (`api/agents.go:139-163`).
  - REST update: `PUT /api/v1/agents/{id}` body `{"dns_mode":"ddns","ddns_interval":60}`
    (`api/agents.go:218-244`).
  - CLI: `nurproxy agent adopt <id> -dns-mode ddns -ddns-interval 300 -zones <zoneid>`
    and `nurproxy agent update <id> -dns-mode static` (`cli_commands.go:180-228`).
  - Dashboard: agent adopt/edit dialog (DNS mode + DDNS interval fields, `web/src/pages/Agents.tsx`).
  - MCP: **not** available — the MCP server exposes no agent adopt/update tool, so DNS
    mode/DDNS interval can only be set via REST / CLI / Dashboard.
- **Prerequisites:** dry stack; an online box for the A record to exist at all.
- **Steps (D):**
  ```bash
  AG=$(curl -fsS -H "Authorization: Bearer $API_KEY" "$BASE/api/v1/agents" \
       | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])')
  curl -fsS -X PUT -H "Authorization: Bearer $API_KEY" -H 'Content-Type: application/json' \
    -d '{"dns_mode":"ddns","ddns_interval":60}' "$BASE/api/v1/agents/$AG"
  curl -fsS -H "Authorization: Bearer $API_KEY" "$BASE/api/v1/agents" \
    | python3 -c 'import sys,json;a=json.load(sys.stdin)[0];print(a["dns_mode"],a["ddns_interval"])'
  ```
- **Pass:** `dns_mode` reads back `ddns` (or `static`); `ddns_interval` reads back the
  set integer. In `ddns` mode, a changed reported IP yields a `ddns_updated` audit entry
  on the next cycle; in `static` mode no auto-update occurs.
- **Coverage:** D (mode set/readback + static-vs-ddns branch logic) / R (an actual IP
  change driving a `ddns_updated` against a real provider).
- **Pitfalls:**
  - **`ddns_interval` does NOT drive the DDNS cadence** in the current code. It is a
    stored field (DB default `300`, `migrations.go:30`) settable via adopt/update/CLI,
    but **no code path uses it as a timer** (grep confirms its only non-DB/API/model
    consumers are the CLI bodies). The actual update cadence is the product of the
    **agent heartbeat interval — a hardcoded `30 * time.Second`** constant
    (`cmd/nurproxy-agent/main.go:36-39`, `heartbeatInterval`) — and the
    **reconciler interval** (`reconciler_interval` setting). Treat `ddns_interval` as
    metadata, not a live knob, unless/until that wiring lands. **UNVERIFIED** whether any
    future build consumes it.
  - DDNS update only fires when the IP **actually changed** (`reconciler.go:999`); to
    exercise it you must make the agent report a different IP (hard to force on a real
    box without changing its egress).
  - In `ddns` mode, if `GetRecord` on the stored id fails transiently the reconciler
    **skips** the cycle rather than recreating (avoids duplicate records on a transient
    error, `reconciler.go:991-998`).

### Public IP detection sources (IPv4 and IPv6)

- **Must:** IPv4 detection tries, in order, `https://api.ipify.org`,
  `https://ifconfig.me/ip`, `https://icanhazip.com` (`ddns.go:261-265`), returning the
  first response that parses as a valid **IPv4** (`isValidIPForFamily` → `addr.Is4()`,
  `ddns.go:347`). IPv6 detection tries `https://api6.ipify.org`, `https://v6.ident.me`,
  `https://ipv6.icanhazip.com` (`ddns.go:271-275`), accepting only a real IPv6
  (`addr.Is6() && !addr.Is4In6()`, `ddns.go:344-345`) — never a v4-mapped address.
  The v4 services are v4-only hostnames and the v6 services v6-only, so a dual-stack
  host reports each family correctly instead of "whichever the resolver picked".
- **Access:** internal to the agent; also exposed via the agent's own
  **auth-gated** `GET /ip` endpoint (`internal/agent/api/api.go:167`, registered at
  `api.go:95` behind `authMiddleware`), which returns `{"ip":"…"}` — **IPv4 only**, via
  its own minimal 3-source detector (`detectIP`, `api.go:449`). Detection feeding the DNS
  records runs at register (`adoption.go:121` IPv4 via `detectPublicIPSimple`,
  `adoption.go:124` IPv6 via `ddns.DetectPublicIP6`) and on every heartbeat
  (`ddns.go:170` IPv4, `ddns.go:179` IPv6).
- **Prerequisites:** real outbound network from the agent box (these endpoints are
  **not** mocked, even in dry); for the IPv6 half, working outbound IPv6.
- **Steps (D, verify the sources are reachable / parse):** on the agent box,
  ```bash
  for u in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com; do echo "$u -> $(curl -fsS --max-time 5 $u)"; done
  for u in https://api6.ipify.org https://v6.ident.me https://ipv6.icanhazip.com; do echo "$u -> $(curl -fsS --max-time 5 $u || echo '(no v6)')"; done
  ```
  Then confirm the reported values land on the agent record: `GET /api/v1/agents` →
  `public_ip` / `public_ip6`.
- **Pass:** `public_ip` is a valid IPv4; on a dual-stack host `public_ip6` is a valid
  global IPv6 (not v4-mapped). On an IPv4-only host the v6 services fail and
  `public_ip6` is empty — by design.
- **Coverage:** D (reachability + parse) but **requires real outbound network** (these
  are not mocked even in dry).
- **Pitfalls:** each detection client has a short timeout (5 s, `ddns.go:302`); a failed
  IP lookup must **not** skip the heartbeat — the agent sends a blank IP and the
  orchestrator keeps the last known value (`ddns.go:167-174`). Family validation guards
  against a service returning an error page or the wrong family being published verbatim
  as a record (`isValidIPForFamily`, `ddns.go:338-349`; gate at `ddns.go:296-300`/`331`).
  Note the asymmetry: the **heartbeat** path (`DetectPublicIP`/`DetectPublicIP6`) and the
  v6 register path validate the family, but the **register-time IPv4** call
  (`detectPublicIPSimple`, `adoption.go:265-292`) returns the first non-empty response
  **without** family validation — it is a deliberately minimal first-contact probe, and
  the very next heartbeat re-reports a validated value.

### IPv6 / AAAA verification caveats and real `dig` verification

- **Must:** a published AAAA for the anchor FQDN is resolvable from an external,
  v6-capable vantage point. (Built-in Caddy binds all interfaces by default, so it
  answers on v6 once an AAAA exists; this spec does **not** assert the listener binding
  itself — that is the backend/serving spec's job. Serving real v6 traffic is out of
  scope for the dry stack — see the "Not covered" note in CLAUDE.md.)
- **Access:** verify via `dig` against the **authoritative** nameserver, not a local
  resolver.
- **Prerequisites (R):** a real dual-stack agent, a real zone, the zone's authoritative
  NS hostnames, and ideally a **second** v6-capable host to test inbound reachability.
- **Steps (R):**
  ```bash
  # Authoritative answer (bypasses caches and CNAME-flattening surprises):
  dig +short CNAME app1.<zone> @<authoritative-NS>     # domain CNAME -> agent.FQDN
  dig +short A    <agent.FQDN> @<authoritative-NS>     # anchor A
  dig +short AAAA <agent.FQDN> @<authoritative-NS>     # anchor AAAA (dual-stack only)
  # Prove external v6 from a DIFFERENT v6-capable host, pinned to the real AAAA:
  curl -6 --resolve <host>:443:<the-AAAA> https://<host>/ -w "http=%{http_code}\n"
  ```
- **Pass:** authoritative NS returns the expected CNAME/A/AAAA; an external v6 client
  reaches `:443`.
- **Coverage:** R (resolvable records + real v6 reachability cannot be proven dry).
- **Pitfalls (hard-won, RELEASE-QA §2.2 / §6 + the v0.3.0 RC soak):**
  - **IPv6 self-tests are flaky from inside.** A host curling its **own** public v6
    (hairpin) often fails, and `systemd-resolved` can hand back a v4-mapped address for
    an AAAA query. Prove external v6 from a **different** host with `--resolve` to the
    real AAAA; trust the authoritative DNS, not the local resolver.
  - **Wildcard `*.zone` masks reality.** A wildcard makes any subdomain resolve even
    without a dedicated record — don't conclude "created" from a public-resolver `dig`
    alone. Query the **authoritative NS** and compare proxied (orange-cloud) vs grey
    answers.
  - **Cloudflare proxying (orange cloud)** rewrites answers: a proxied record returns
    Cloudflare anycast IPs, not your origin. For ownership/content checks, query the
    authoritative NS and/or check the record at the provider, not a proxied public dig.
  - **Real-world side effect to expect:** publishing the anchor AAAA makes every
    subdomain CNAMEd to it dual-stack-advertised. In the homelab soak, enabling #61
    published a real `durox.nurrobin.de` AAAA and all subdomains became dual-stack;
    inbound v6 through the router/firewall remained the one thing unverifiable from
    inside the network. Verify inbound v6 externally.
  - **Clock skew in logs:** the orchestrator logs **UTC (`…Z`)**, agents may log local
    (`+02:00`). Convert before grepping log windows or you'll get empty results.

## Acceptance checklist

**Dry (every RC):**
- [ ] `make test` + `make test-sandbox` green (covers the DNS state machine end to end).
- [ ] `make dev-sandbox` converges; audit log shows `dns_created`/`dns_adopted` for
      seeded domains **after** they go active (timing artifact understood), `source=dryrun`.
- [ ] Domain delete → `dns_deleted` for a managed record; record/artifact gone.
- [ ] `DNSMode` set/readback works for both `static` and `ddns`; `ddns_interval` stored
      and returned (noting it does **not** drive the cadence today).
- [ ] On an online box: agent `dns_record_id` set with `a_record_created`/`_adopted`;
      `dns_record_id6` set + `aaaa_record_created` iff the box is dual-stack.
- [ ] FQDN-outside-zone surfaces `dns_error`; fixing it emits `dns_error_cleared`.

**Real run (before final, on a throwaway domain/agent):**
- [ ] CNAME `sub → agent.FQDN` resolves via the **authoritative NS** a cycle after the
      domain goes active.
- [ ] True adopt: an operator-created identical CNAME → `dns_adopted` (`dns_managed=false`);
      on domain delete it is **retained** (`dns_left_adopted`).
- [ ] Conflict: a non-matching record at the name → domain `error` + `dns_conflict`,
      foreign record untouched.
- [ ] Managed record: created (`dns_created`) and removed on teardown (`dns_deleted`),
      idempotently (`dns_delete_skipped` if already gone).
- [ ] Dual-stack agent: anchor A **and** AAAA present (distinct record ids); external v6
      reachability proven from a **second** v6 host with `--resolve` to the real AAAA.
- [ ] DDNS: an actual IP change drives `ddns_updated`; static leaves the record untouched.

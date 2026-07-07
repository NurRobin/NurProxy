# Servers & Domains (CRUD + every create/edit field)

> **Scope:** the Server and Domain objects and all their create/edit fields,
> validation, status machine, config preview/override, and server-move handling.
> Proxy directives themselves (headers, rate-limit, upstream scheme, etc.) get
> their own matrix file — here we cover the object lifecycle, not directive output.
> **Code:** `internal/orchestrator/api/servers.go`,
> `internal/orchestrator/api/domains.go`,
> `internal/orchestrator/db/servers.go`,
> `internal/orchestrator/db/migrations.go`,
> `internal/shared/models/models.go` (`Server`, `Domain`, `SSLMode`, `DomainStatus`),
> `internal/shared/dnsname/` (`ValidateSubdomain`),
> `cmd/nurproxy/cli_commands.go` (`cmdServer`, `cmdDomain`),
> `internal/orchestrator/mcp/server.go` (`list_servers`/`list_domains`/`create_domain`/`update_domain`/`delete_domain`),
> `web/src/pages/Servers.tsx`, `web/src/pages/Domains.tsx`.
> **Coverage legend:** D = coverable dry, R = needs a real run.

## Prerequisites

- Both binaries built: `make build-all` (produces `./nurproxy` and `./nurproxy-agent`).
- A running control plane. Fastest dry path: `make dev-sandbox` (orchestrator on
  `:8080`, one adopted agent, a seeded provider/zone/server). Everything in this
  file except the items marked **R** is coverable on the dry stack.
- An admin API key for REST/CLI. The dashboard uses a browser session; the CLI and
  curl examples below assume:
  ```bash
  export NP_API="http://localhost:8080"
  export NP_KEY="<admin api key>"     # the CLI also reads its own config; see `nurproxy --help`
  AUTH=(-H "Authorization: Bearer $NP_KEY")
  ```
- At least one **adopted** agent with at least one **server** row (the sandbox
  seeds these). Get IDs:
  ```bash
  curl -s "${AUTH[@]}" "$NP_API/api/v1/agents" | python3 -m json.tool
  AGENT=$(curl -s "${AUTH[@]}" "$NP_API/api/v1/agents" | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])')
  curl -s "${AUTH[@]}" "$NP_API/api/v1/agents/$AGENT/servers" | python3 -m json.tool
  ZONE=$(curl -s "${AUTH[@]}" "$NP_API/api/v1/zones" | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])')
  ```

## Features covered

- [ ] Server list — `GET /agents/{id}/servers` (agent-scoped; 404 if agent missing)
- [ ] Server create — `POST /agents/{id}/servers`; fields `name`, `address`, `notes`; name+address required
- [ ] Server update — `PUT /servers/{id}` (partial / pointer fields)
- [ ] Server delete — `DELETE /servers/{id}` + the **cascade behaviour** vs. the documented "refuse with 409" guard (regression-guard / known bug)
- [ ] Add-Server dialog: detected-subnet prefill + nginx-inferred upstream suggestions
- [ ] Domain list — `GET /domains` + `agent_id` / `server_id` / `status` filters
- [ ] Domain create — `POST /domains`; fields `subdomain`, `zone_id`, `server_id`, `port`, `websocket`, `force_https`, `ssl_mode`, `proxy_config`
- [ ] Subdomain DNS-label validation (`ValidateSubdomain`, wildcard, length, charset)
- [ ] Port range validation (1–65535)
- [ ] `ssl_mode` enum: `auto` / `manual` / `off` (default `auto`)
- [ ] Subdomain uniqueness within a zone (409)
- [ ] Domain get — `GET /domains/{id}`
- [ ] Domain update — `PUT /domains/{id}` (partial; re-queues to `pending`)
- [ ] Domain delete — `DELETE /domains/{id}` (soft → `deleting`, immediate route push)
- [ ] Domain status machine: `pending` / `active` / `error` / `deleting` (+ `degraded`)
- [ ] On-create side effects: immediate route push + on-demand central-TLS issuance
- [ ] Config preview — `GET /domains/{id}/config` (backend caddy | nginx | apache)
- [ ] Manual config override — `PUT /domains/{id}/config`
- [ ] Config reset — `POST /domains/{id}/config/reset`
- [ ] Server-move handling: artifact cleanup on old agent + re-push to new agent
- [ ] `force_https` + `websocket` behaviour and capability gating (greyed-out when backend lacks it)
- [ ] CLI surface: `nurproxy server *`, `nurproxy domain *`
- [ ] MCP surface: `list_servers`, `list_domains`, `create_domain`, `update_domain`, `delete_domain`

## Tests

### Server list — `GET /agents/{id}/servers`

- **Must:** lists exactly the servers owned by that agent; returns `[]` (not
  `null`) when none; `404 agent not found` when the agent ID is unknown.
  (`servers.go:12-30`).
- **Access:**
  - REST: `GET /api/v1/agents/{id}/servers`.
  - CLI: `nurproxy server list <agent-id>` (`cli_commands.go:261-276`; table
    `ID NAME ADDRESS NOTES`, or `--json`).
  - MCP: `list_servers` `{"agent_id":"<id>"}` (agent_id optional → all servers).
  - Dashboard: **Servers** page, grouped per agent.
- **Steps:**
  ```bash
  curl -s "${AUTH[@]}" "$NP_API/api/v1/agents/$AGENT/servers"
  curl -s -o /dev/null -w '%{http_code}\n' "${AUTH[@]}" "$NP_API/api/v1/agents/nope/servers"   # 404
  ./nurproxy server list "$AGENT" --json
  ```
- **Pass:** real servers listed; bad agent → 404; empty agent → `[]`.
- **Coverage:** D.
- **Pitfalls:** the list is agent-scoped — there is no global `GET /servers`. To
  enumerate all servers you must iterate agents (MCP `list_servers` with no
  `agent_id` does this for you).

### Server create — `POST /agents/{id}/servers`

- **Must:** creates a server bound to the agent. Required: `name`, `address`
  (both non-empty → else `400 name and address are required`). `notes` optional.
  `address` is the backend `host:port` **from the agent's point of view** (it is
  stored as a free string; no host:port parse/validation server-side —
  `servers.go:42-73`). New ID is a UUID. Audited as `server / create`.
- **Access:**
  - REST: `POST /api/v1/agents/{id}/servers` body `{"name","address","notes"}`.
  - CLI: `nurproxy server add <agent-id> --name --address [--notes]`
    (`cli_commands.go:278-295`; `--name`/`--address` required client-side).
  - Dashboard: **Servers** → **Add server** (per-agent), fields Name / Address /
    Notes. Note: there is **no** MCP `create_server` tool — MCP can only list
    servers (`server.go:200-204`).
- **Steps:**
  ```bash
  SRV=$(curl -s "${AUTH[@]}" -X POST "$NP_API/api/v1/agents/$AGENT/servers" \
    -d '{"name":"app","address":"127.0.0.1:8081","notes":"qa"}' \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
  echo "$SRV"
  curl -s -o /dev/null -w '%{http_code}\n' "${AUTH[@]}" -X POST \
    "$NP_API/api/v1/agents/$AGENT/servers" -d '{"name":"x"}'    # 400 (no address)
  ```
- **Pass:** 201 with a UUID `id`; missing name/address → 400; unknown agent → 404.
- **Coverage:** D.
- **Pitfalls:** `address` is not validated for shape — a typo (`localhost8081`)
  is accepted and only surfaces as a broken upstream at apply time. The audit
  entry records the server **name**, not the address.

### Server update — `PUT /servers/{id}`

- **Must:** partial update via pointer fields — only `name`/`address`/`notes`
  present in the body change; absent fields are left as-is (`servers.go:85-103`).
  Unknown ID → `404 server not found`. Audited as `server / update`.
- **Access:**
  - REST: `PUT /api/v1/servers/{id}` body any subset of `{"name","address","notes"}`.
  - CLI: `nurproxy server update <id> [--name] [--address] [--notes]`
    (`cli_commands.go:297-313`). **CLI caveat:** the CLI sends a field only if the
    flag string is non-empty (`putStr`), so the CLI cannot clear `notes` to ""
    (REST can, by sending `"notes":""`).
  - Dashboard: **Servers** → edit a server row.
- **Steps:**
  ```bash
  curl -s "${AUTH[@]}" -X PUT "$NP_API/api/v1/servers/$SRV" -d '{"notes":"updated"}'
  curl -s "${AUTH[@]}" "$NP_API/api/v1/agents/$AGENT/servers" | python3 -m json.tool   # name/address unchanged
  ```
- **Pass:** only the supplied fields change; others retained; unknown ID → 404.
- **Coverage:** D.
- **Pitfalls:** updating `address` does **not** itself re-push the agent here (no
  `triggerAgentPush` in `handleUpdateServer`) — the change is picked up by the
  reconciler / next push, not synchronously. Domains bound to this server only
  re-render on their own next reconcile cycle.

### Server delete — `DELETE /servers/{id}` (cascade vs. documented 409 guard)

- **Must (documented intent):** RELEASE-QA.md §2.4 states deleting a server that
  still has domains is **refused with 409** and the body lists the domains.
- **Must (actual code, 2026-06-08):** `handleDeleteServer` is a plain delete with
  **no reference guard** (`servers.go:116-127`), and `DB.DeleteServer` is a bare
  `DELETE FROM servers` (`db/servers.go:97-108`). The live `domains.server_id` FK
  is `REFERENCES servers(id) ON DELETE CASCADE` (`migrations.go:162`, the
  migration-003 `domains_new` table; the original at `:53` was the same) and
  `foreign_keys` is ON via the DSN pragma (`db/db.go:28`). So deleting a server
  **succeeds (200)**
  and **cascade-deletes its domain rows** — which orphans those domains' managed
  DNS records and certs (the deleted rows never transition through `deleting`, so
  the reconciler never tears them down). This is the known **server-delete DNS
  leak** bug. **Treat the §2.4 "409 guard" as UNVERIFIED / not implemented for
  servers** and file/track against the teardown doc (cross-link: see the
  teardown / cascade-guards QA file).
- **Access:**
  - REST: `DELETE /api/v1/servers/{id}`.
  - CLI: `nurproxy server delete <id>` (`cli_commands.go:315-322`).
  - Dashboard: **Servers** → delete a server. No MCP delete-server tool.
- **Steps (regression-guard — assert the real behaviour and the leak):**
  ```bash
  # create a server + a domain on it, then delete the server
  S2=$(curl -s "${AUTH[@]}" -X POST "$NP_API/api/v1/agents/$AGENT/servers" \
    -d '{"name":"victim","address":"127.0.0.1:9000"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
  curl -s "${AUTH[@]}" -X POST "$NP_API/api/v1/domains" \
    -d "{\"subdomain\":\"leak\",\"zone_id\":\"$ZONE\",\"server_id\":\"$S2\",\"port\":80}" >/dev/null
  curl -s -o /dev/null -w 'delete-server: %{http_code}\n' "${AUTH[@]}" -X DELETE "$NP_API/api/v1/servers/$S2"
  curl -s "${AUTH[@]}" "$NP_API/api/v1/domains?server_id=$S2"    # the domain row is GONE (cascade), not 'deleting'
  ```
- **Pass (current code):** delete returns **200**, the domain row vanishes from
  `GET /domains`, and no `deleting`/`dns_deleted` audit ever fires for it (the
  leak). **Pass (after the bug is fixed):** delete should instead return **409**
  with a body listing the referencing domains, and the domain row should remain.
  Record which behaviour you observed in the release notes.
- **Coverage:** D (the cascade and the missing guard are fully observable dry; the
  *leaked DNS record* is only "real" against a live zone — R).
- **Pitfalls:** because the cascade bypasses the soft-delete path, a "delete
  server then recreate the domain" flow can leave a stale provider record behind
  on a real zone. Until fixed, delete domains **first** (which goes through the
  `deleting` reconciler cleanup), then delete the server.

### Add-Server dialog: subnet prefill + nginx-inferred upstream suggestions

- **Must:** the dashboard Add-Server UX offers two conveniences:
  1. **Detected-subnet prefill** — the agent's discovered subnet prefills the
     address field's network prefix so the operator types only the host part;
     always editable (`Servers.tsx:16`, `:227-228`, `prefillFromNetwork`).
  2. **nginx-inferred upstream suggestions** — for an existing-mode agent that
     reported `proxy_detection.discovered_upstreams`, the page renders one-click
     "Suggested" server cards (collapsed by address, vhost names merged, dropping
     any address that already exists as a server) (`Servers.tsx:76-83`, `:180-200`).
     Clicking a suggestion prefills name/address/notes from the discovered upstream.
- **Access:** Dashboard **Servers** page only (no REST/CLI/MCP equivalent — these
  are pure UI affordances over `agent.proxy_detection`).
- **Prerequisites:** for suggestions, an **existing-mode** agent that has run
  nginx discovery and reported `discovered_upstreams` (R — needs a real nginx
  with upstreams, or a seeded agent row carrying that field).
- **Steps:**
  - Dry: open Servers, click **Add server**, confirm the address field is
    prefilled with the agent's subnet prefix and remains editable.
  - Suggestions: with an agent reporting upstreams, confirm "Suggested" cards
    appear, that an address already added as a server is **not** suggested, and
    that **Add** prefills the form.
- **Pass:** prefill matches the detected subnet; suggestion cards match
  `discovered_upstreams` deduped by address; clicking pre-populates the dialog.
- **Coverage:** subnet prefill D (if the agent reports a subnet); upstream
  suggestions R (need real nginx discovery output).
- **Pitfalls:** suggestions only show for agents whose `proxy_detection` reports
  upstreams — a built-in-Caddy agent shows none. The dedupe is by **address**, so
  two vhosts pointing at the same upstream collapse into one suggestion with both
  vhost names merged into the note.

### Domain list + filters — `GET /domains`

- **Must:** lists all domains; supports `agent_id`, `server_id`, `status` query
  filters (combined as AND in `db.DomainFilter`); returns `[]` not `null` when
  empty (`domains.go:22-37`).
- **Access:**
  - REST: `GET /api/v1/domains?agent_id=&server_id=&status=`.
  - CLI: `nurproxy domain list [--agent] [--server] [--status]`
    (`cli_commands.go:334-364`; table `ID SUBDOMAIN SERVER PORT STATUS`).
  - MCP: `list_domains` `{"agent_id","status"}` (no `server_id` in the MCP schema —
    `server.go:206-209`).
  - Dashboard: **Domains** page (status + agent filters in the toolbar).
- **Steps:**
  ```bash
  curl -s "${AUTH[@]}" "$NP_API/api/v1/domains?status=pending"
  curl -s "${AUTH[@]}" "$NP_API/api/v1/domains?server_id=$SRV"
  ./nurproxy domain list --status active --json
  ```
- **Pass:** filters narrow the set correctly; combining `agent_id`+`status` ANDs
  them; empty result is `[]`.
- **Coverage:** D.
- **Pitfalls:** MCP `list_domains` cannot filter by `server_id`; use REST/CLI for
  that. The dashboard's agent filter resolves agent→server→domain client-side.

### Domain create — `POST /domains` (all fields + validation)

- **Must:** creates a `pending` domain (`domains.go:41-121`). Required:
  `subdomain`, `zone_id`, `server_id` (any empty → 400). Then, in order:
  1. `dnsname.ValidateSubdomain(subdomain)` (see next test) → 400 on failure.
  2. `port` must be `1..65535` (`port <= 0 || port > 65535` → `400 port must be
     between 1 and 65535`). Note: `port` has no default — omitting it sends 0 → 400.
  3. zone must exist → else `400 zone not found`.
  4. server must exist → else `400 server not found`.
  5. subdomain must be unique **within the zone** → else `409 subdomain already
     exists for this zone` (`domains.go:83-89`).
  6. `ssl_mode` empty → defaults to `auto` (`SSLModeAuto`, `domains.go:91-94`).
  - Optional fields: `websocket` (bool), `force_https` (bool), `proxy_config`
    (object, copied verbatim if present). Status set to `pending`. Audited
    `domain / create`. Then `triggerAgentPush` + `triggerCertIssuance` fire.
- **Access:**
  - REST: `POST /api/v1/domains` body
    `{"subdomain","zone_id","server_id","port","websocket","force_https","ssl_mode","proxy_config"}`.
  - CLI: `nurproxy domain add --subdomain --zone --server --port [--websocket]
    [--force-https] [--ssl-mode] [--proxy-config-file]`
    (`cli_commands.go:366-395`; client requires subdomain/zone/server/port).
  - MCP: `create_domain` (required `subdomain,zone_id,server_id,port`;
    `ssl_mode` enum `auto|manual|off`; no `proxy_config` in MCP schema —
    `server.go:212-215`).
  - Dashboard: **Domains** → **Add domain**. Create dialog exposes only
    subdomain / zone / server / port / websocket / force_https; it does **not**
    expose `ssl_mode` or `proxy_config`, so a dashboard-created domain always
    defaults to `ssl_mode = auto` and an empty proxy_config (`Domains.tsx:412-420`).
    UI defaults `force_https = true`, `websocket = false` (`Domains.tsx:50-51`);
    the port `<input>` is client-clamped `min=1 max=65535` (`Domains.tsx:416`).
- **Steps:**
  ```bash
  DOM=$(curl -s "${AUTH[@]}" -X POST "$NP_API/api/v1/domains" \
    -d "{\"subdomain\":\"app\",\"zone_id\":\"$ZONE\",\"server_id\":\"$SRV\",\"port\":8080,\"force_https\":true}" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
  echo "$DOM"
  # validation
  curl -s "${AUTH[@]}" -X POST "$NP_API/api/v1/domains" -d "{\"subdomain\":\"app\",\"zone_id\":\"$ZONE\",\"server_id\":\"$SRV\",\"port\":70000}"  # 400 port
  curl -s "${AUTH[@]}" -X POST "$NP_API/api/v1/domains" -d "{\"subdomain\":\"app\",\"zone_id\":\"$ZONE\",\"server_id\":\"$SRV\",\"port\":80}"     # 409 dup
  ```
- **Pass:** 201 with numeric `id`, `status:"pending"`, `ssl_mode:"auto"` when
  omitted; each validation rule returns its exact 400/409 above.
- **Coverage:** D.
- **Pitfalls:**
  - **`port` is mandatory in practice** — there is no default at the API; 0 → 400.
    (The SQL column defaults to 80, but the handler rejects 0 before insert.)
  - On the **live** schema (migration 003) the DB UNIQUE constraint is
    `(subdomain, zone_id)` (`migrations.go:175`) — the same key the API enforces
    in-handler by listing existing domains and comparing `(subdomain, zone_id)`
    (`domains.go:83-89`). The 409 you get from `POST /domains` is the
    application-level check (it fires before insert), so the DB constraint is a
    backstop, not the path you normally hit. (The original migration-001 table
    keyed on `(subdomain, provider_id)` at `migrations.go:66`, but that table was
    replaced by `domains_new` in migration 003.)
  - The MCP and CLI surfaces can't set `proxy_config` directly except the CLI's
    `--proxy-config-file` (a ProxyConfig JSON file, `cli_commands.go:388-390`).

### Subdomain DNS-label validation (`ValidateSubdomain`)

- **Must:** `dnsname.ValidateSubdomain` enforces (file `internal/shared/dnsname/`):
  empty → `subdomain is required`; total length > 253 → too long; each
  dot-separated label: non-empty (no leading/trailing/doubled dots), ≤ 63 chars,
  must not start/end with `-`, charset `[A-Za-z0-9-]` only; a **leading `*` label
  is allowed** (wildcard, only at index 0).
- **Access:** runs on `subdomain` in both create and update (`domains.go:61`,
  `:197`); reachable via REST/CLI/MCP/Dashboard create+edit.
- **Steps:**
  ```bash
  for s in "" "bad_underscore" "-lead" "a..b" "$(python3 -c 'print("x"*64)')" "*" "*.team"; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" -X POST "$NP_API/api/v1/domains" \
      -d "{\"subdomain\":\"$s\",\"zone_id\":\"$ZONE\",\"server_id\":\"$SRV\",\"port\":80}")
    echo "$code  <- $s"
  done
  ```
- **Pass:** `*` and `*.team` → not rejected by validation (they pass label rules;
  may still 409/200 depending on uniqueness); underscore, leading hyphen, doubled
  dots, 64-char label, and empty → 400 with the matching message.
- **Coverage:** D.
- **Pitfalls:** the wildcard exception is **only** for a leading `*` label
  (`*.foo` ok, `foo.*` is not). Underscores are rejected even though some DNS
  records use them — by design for proxied subdomains.

### `ssl_mode` enum

- **Must:** `SSLMode` values are exactly `auto`, `manual`, `off`
  (`models.go:46-48`; verified by `models_test.go:127-136`). Empty on create →
  `auto`. The API does **not** reject an unknown string at this layer — it is
  stored as-given (only the MCP schema constrains the enum, `server.go:214`).
- **Access:** create/update body `ssl_mode`; CLI `--ssl-mode`; MCP enum-validated.
- **Steps:**
  ```bash
  curl -s "${AUTH[@]}" "$NP_API/api/v1/domains/$DOM" | python3 -c 'import sys,json;print(json.load(sys.stdin)["ssl_mode"])'  # auto
  curl -s "${AUTH[@]}" -X PUT "$NP_API/api/v1/domains/$DOM" -d '{"ssl_mode":"off"}' >/dev/null
  ```
- **Pass:** created domain reports `auto`; PUT to `off`/`manual` round-trips.
- **Coverage:** D.
- **Pitfalls:** REST/CLI accept arbitrary `ssl_mode` strings (no server-side enum
  guard); only MCP enforces `auto|manual|off`. Don't confuse `ssl_mode` (cert
  management mode) with the renderer-internal `TLSPolicy` (`central|self-acme|off`,
  enum in `proxymodel/route.go:33-45`, described on the `ProxyConfig.TLSPolicy`
  field at `models.go:356-363`) used by `caddygen.TLSPolicyForDomain`.

### Domain get — `GET /domains/{id}`

- **Must:** returns the full domain; non-numeric ID → `400 invalid domain ID`;
  unknown numeric → `404 domain not found` (`domains.go:151-165`).
- **Access:** REST only directly; CLI/Dashboard read via list. MCP has no get-one.
- **Steps:**
  ```bash
  curl -s "${AUTH[@]}" "$NP_API/api/v1/domains/$DOM" | python3 -m json.tool
  curl -s -o /dev/null -w '%{http_code}\n' "${AUTH[@]}" "$NP_API/api/v1/domains/abc"   # 400
  ```
- **Pass:** correct object; `abc` → 400; large unused id → 404.
- **Coverage:** D.
- **Pitfalls:** the domain ID is the numeric autoincrement `id` (not a UUID like
  servers/agents) — a non-numeric path segment 400s before any DB lookup. There is
  no MCP/CLI get-one; both read the object out of their list calls instead.

### Domain update — `PUT /domains/{id}`

- **Must:** partial update via pointer fields `subdomain`, `zone_id`, `server_id`,
  `port`, `websocket`, `force_https`, `ssl_mode`, `proxy_config`
  (`domains.go:168-259`). `subdomain` re-validated; `zone_id`/`server_id`
  re-checked to exist (400 if not). **Always** sets `status = pending` so the
  reconciler re-applies. Audited `domain / update`. Fires `triggerAgentPush` for
  the (possibly new) server; if `server_id` changed and crosses agents, also runs
  `handleArtifactServerMove` (see server-move test).
- **Access:**
  - REST: `PUT /api/v1/domains/{id}` any subset.
  - CLI: `nurproxy domain update <id> [--subdomain --zone --server --port
    --websocket --force-https --ssl-mode]` (`cli_commands.go:397-433`). **Bool
    caveat:** the CLI only sends `websocket`/`force_https` when the flag was
    **explicitly set** (`fs.Visit`), so it never silently flips them off; `--port`
    only sent when `> 0`.
  - MCP: `update_domain` (`id` required; `server_id,port,websocket,force_https,
    ssl_mode` optional; no `subdomain`/`zone_id`/`proxy_config` —
    `server.go:218-221`).
  - Dashboard: **Domains** → edit (General / Headers / Advanced tabs).
- **Steps:**
  ```bash
  curl -s "${AUTH[@]}" -X PUT "$NP_API/api/v1/domains/$DOM" -d '{"port":9090,"websocket":true}'
  curl -s "${AUTH[@]}" "$NP_API/api/v1/domains/$DOM" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["port"],d["websocket"],d["status"])'  # 9090 True pending
  ```
- **Pass:** only supplied fields change; `status` flips to `pending`; bad
  zone/server → 400.
- **Coverage:** D.
- **Pitfalls:** every update resets status to `pending` even for a no-op body —
  expect a reconcile cycle and a re-push after any PUT. Setting `proxy_config` here
  **replaces** the whole object (it does not deep-merge).

### Domain delete — `DELETE /domains/{id}` (soft delete)

- **Must:** soft delete — sets `status = deleting` via `UpdateDomainStatus`
  (`domains.go:308-333`), audits `domain / delete`, and immediately
  `triggerAgentPush` on the owning server so a connected agent drops the route at
  once. The actual DNS-record + row cleanup happens **a reconcile cycle later**.
  Non-numeric ID → 400; unknown numeric → 404 (from `UpdateDomainStatus`).
- **Access:** REST `DELETE /api/v1/domains/{id}`; CLI `nurproxy domain delete <id>`
  (prints "domain marked for deletion"); MCP `delete_domain {"id":N}`; Dashboard
  delete action.
- **Steps:**
  ```bash
  curl -s "${AUTH[@]}" -X DELETE "$NP_API/api/v1/domains/$DOM"
  curl -s "${AUTH[@]}" "$NP_API/api/v1/domains/$DOM" | python3 -c 'import sys,json;print(json.load(sys.stdin)["status"])'  # deleting (then 404 after reconcile)
  ```
- **Pass:** 200 `{"message":"domain marked for deletion"}`; status becomes
  `deleting`, then the row disappears after the reconciler runs.
- **Coverage:** D (state transition + push); the real DNS-record removal is R.
- **Pitfalls:** delete is **async** — the row lingers as `deleting` briefly. The
  documented teardown guard (server/agent/zone delete refused while domains exist)
  counts `deleting` rows too; see the teardown QA file.

### Domain status machine

- **Must:** `DomainStatus` values are exactly `pending`, `active`, `error`,
  `deleting` (`models.go:22-25`; verified `models_test.go:54-57`), plus a fifth
  `degraded` (`models.go:26-31`): "the route is applied and serving, but not as the
  operator intended — a central-TLS domain is being served over plaintext HTTP
  because no certificate has been issued yet (TLS + force_https were dropped)".
  Transitions: create/update → `pending`; reconciler/apply-ACK →
  `active` (or `error` with `error_msg`, or `degraded`); delete → `deleting`.
- **Access:** observe via `GET /domains/{id}` `status`/`error_msg`, the CLI
  `STATUS` column, the Dashboard status badge + `?status=` filter.
- **Steps:** create a domain (dry) and watch it converge:
  ```bash
  for i in $(seq 10); do curl -s "${AUTH[@]}" "$NP_API/api/v1/domains/$DOM" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["status"])'; sleep 1; done
  ```
- **Pass:** in the dry sandbox a created domain converges `pending → active`
  within a few reconcile cycles (DNS + cert simulated). An injected failure path
  surfaces `error` with `error_msg`.
- **Coverage:** D (`pending`→`active`); `error`/`degraded` partially D (inject via
  `NP_DRY_RUN_FAIL=…` for ACME, or a real backend mismatch for `degraded`, R).
- **Pitfalls:** the `?status=` filter matches the raw string — use `degraded` and
  `deleting` exactly. `degraded` is easy to miss; it means the route is up but
  served over plaintext HTTP (TLS + force_https were dropped) because no central
  cert has been issued yet — not a hard failure.

### On-create side effects — push + on-demand TLS

- **Must:** after a successful create, the orchestrator (`domains.go:117-148`):
  1. `triggerAgentPush(dom.ServerID)` — pushes the new intent so HTTPS/route comes
     up promptly.
  2. `triggerCertIssuance(dom)` — **only** if an issuer is wired **and**
     `caddygen.TLSPolicyForDomain(dom) == central`; runs DNS-01 first-issuance in
     a background goroutine with a **5-minute** timeout; best-effort (failure logs
     "renewal scan will retry"). Self-acme / off / no-issuer → skipped.
- **Access:** automatic on `POST /domains`; no separate trigger.
- **Steps (dry):** create a central-TLS domain on the sandbox and tail the
  orchestrator log — you should see the simulated DNS-01 + self-signed issuance
  tagged `source=dryrun`.
- **Pass:** route push happens immediately; a central-policy domain triggers an
  async issuance attempt; a `self-acme`/`off` domain triggers none.
- **Coverage:** D (issuance simulated to a self-signed cert dry); real LE chain R.
- **Pitfalls:** issuance is **async + best-effort** — a freshly created domain may
  read `pending` for a moment before the cert lands; the periodic renewal scan is
  the backstop. No issuer wired (headless/test) → silently skipped.

### Config preview — `GET /domains/{id}/config`

- **Must:** returns the config the **serving agent's backend** would render, not
  always Caddy (`domains.go:336-446`). Response `{"manual":bool,"backend":...,
  "config":...}`. `backend` is the agent's detected host proxy in existing mode
  (`nginx`/`apache`) else `caddy` (`backendForDomain`). For Caddy, `config` is a
  JSON **route object**; for nginx/apache it is the native config **text (string)**.
  If a manual override is stored, returns `{"manual":true,...}` echoing the stored
  backend + content.
- **Access:** REST `GET /api/v1/domains/{id}/config`; Dashboard **Domains → edit →
  Advanced** tab (`Domains.tsx:186-199`). No CLI/MCP.
- **Steps:**
  ```bash
  curl -s "${AUTH[@]}" "$NP_API/api/v1/domains/$DOM/config" | python3 -m json.tool
  ```
- **Pass:** `backend` matches the agent's real backend; `config` is JSON for
  caddy, a text string for nginx/apache; `manual:false` for auto-generated.
- **Coverage:** D (rendering uses the real `caddygen`/`nginxgen`/`apachegen`).
- **Pitfalls:** the preview's cert/key paths are the **conventional**
  `/var/lib/nurproxy/certs/<host>.crt|.key` (`previewCertDir`,
  `domains.go:451-458`) — not necessarily the agent's real dir; the note in the
  code says operators adjust if they use a custom cert dir. Wildcard hosts map the
  leading `*.` to `_wildcard.` in the filename (`sanitizeHostForPreview`).

### Manual config override — `PUT /domains/{id}/config`

- **Must:** stores a manual override tagged with the serving agent's backend
  (`domains.go:498-558`). Body is `{"config": <raw>}`. For nginx/apache the
  `config` must be the native config **as a JSON string** (else `400 config for
  <backend> must be the native config as a JSON string`); for caddy it must be
  **valid JSON** (else `400 invalid JSON config`). Sets `ManualConfig = true`,
  stores `ProxyConfig.RawConfig{Backend,Content}`, flips status to `pending`,
  audits `update_config`, pushes the agent.
- **Access:** REST `PUT /api/v1/domains/{id}/config`; Dashboard **Advanced** tab
  Save (`Domains.tsx:203-225`). No CLI/MCP.
- **Steps (caddy backend):**
  ```bash
  curl -s "${AUTH[@]}" -X PUT "$NP_API/api/v1/domains/$DOM/config" \
    -d '{"config":{"handle":[{"handler":"static_response","body":"hi"}]}}'
  curl -s "${AUTH[@]}" "$NP_API/api/v1/domains/$DOM/config" | python3 -c 'import sys,json;print(json.load(sys.stdin)["manual"])'  # True
  ```
- **Pass:** override stored; `GET .../config` returns `manual:true` with your
  content; status `pending`; malformed input returns the exact 400.
- **Coverage:** D.
- **Pitfalls:** the expected `config` **shape depends on the serving agent's
  backend** — a caddy agent wants a JSON object, an nginx/apache agent wants a
  JSON-string blob of native config. Sending the wrong shape 400s. A manual
  override **bypasses** all the structured fields (websocket/force_https/headers) —
  the renderer uses your verbatim content.

### Config reset — `POST /domains/{id}/config/reset`

- **Must:** clears the manual override — `ManualConfig=false`,
  `RawConfig` zeroed, status → `pending`, audits `reset_config`, pushes the agent
  (`domains.go:561-587`).
- **Access:** REST `POST /api/v1/domains/{id}/config/reset`; Dashboard **Advanced**
  tab Reset (`Domains.tsx:236-240`). No CLI/MCP.
- **Steps:**
  ```bash
  curl -s "${AUTH[@]}" -X POST "$NP_API/api/v1/domains/$DOM/config/reset"
  curl -s "${AUTH[@]}" "$NP_API/api/v1/domains/$DOM/config" | python3 -c 'import sys,json;print(json.load(sys.stdin)["manual"])'  # False
  ```
- **Pass:** `manual:false`; subsequent `GET .../config` shows the auto-generated
  backend config again; status `pending`.
- **Coverage:** D.
- **Pitfalls:** reset zeroes the whole `ProxyConfig.RawConfig` (`{Backend,Content}`),
  not just the content — there is no partial reset. Reset on a domain that never
  had a manual override is a harmless no-op that still flips status to `pending`
  and re-pushes the agent. No CLI/MCP surface — REST or the dashboard Advanced tab
  only.

### Server-move handling (artifact cleanup + re-push)

- **Must:** when `PUT /domains/{id}` changes `server_id` to a server on a
  **different agent** (`domains.go:210-254`, `handleArtifactServerMove`
  `:268-286`): the stale config artifact `dom-<id>` (keyed to the old agent) is
  **deleted** (audited `config_artifact / remove`, "domain moved to another
  agent"), the **old** agent is pushed (its shrunk intent set no longer lists the
  domain → it drops the route, no ghost vhost), and the **new** agent renders +
  round-trips a fresh artifact on its apply-ACK. A move **within the same agent**
  is a no-op for cleanup (artifact stays valid; agent just re-applies).
- **Access:** `PUT /domains/{id}` with a new `server_id`; CLI `domain update <id>
  --server <new>`; MCP `update_domain {"id":N,"server_id":"…"}`; Dashboard edit.
- **Prerequisites:** **two adopted agents**, each with at least one server
  (`make dev-sandbox AGENTS=2`, then add a server on the second agent).
- **Steps (dry, 2 agents):**
  ```bash
  # S_OTHER = a server on a different agent than $DOM's current server
  curl -s "${AUTH[@]}" -X PUT "$NP_API/api/v1/domains/$DOM" -d "{\"server_id\":\"$S_OTHER\"}"
  # confirm the stale artifact was removed and old agent re-pushed:
  curl -s "${AUTH[@]}" "$NP_API/api/v1/audit?entity_type=config_artifact" | python3 -m json.tool
  ```
- **Pass:** an audit `config_artifact / remove` for `dom-<id>` appears; the old
  agent's pushed intent no longer includes the domain; the new agent reports a
  fresh artifact; the domain ends `active` on the new agent.
- **Coverage:** D (artifact rows + pushes + ACK all run dry); real ghost-vhost
  removal on disk is R (needs real nginx/Caddy).
- **Pitfalls:** the artifact ID is `dom-<id>` (`artifactIDForDomainID`,
  `domains.go:303-305`) — it must round-trip with the agents-stream
  `domainIDFromArtifactID`. A same-agent move does **not** delete the artifact;
  only cross-agent moves do. If `oldServerID` is unresolvable, cleanup is skipped.

### `force_https` + `websocket` + capability gating

- **Must:** `force_https` and `websocket` are plain domain booleans
  (`models.go:375-376`) consumed by the renderer (force_https → HTTP→HTTPS
  redirect; websocket → upgrade handling — directive output is covered in the
  proxy-matrix file). In the **dashboard edit dialog**, each checkbox/field is
  **disabled (greyed-out)** when the serving agent reported the matching
  capability as `false` in its `proxy_capabilities`, with a tooltip "not supported
  by <backend>" (`Domains.tsx:108-116`, `:456-457`, `:471-482`). Gated keys:
  `websocket`, `force_https`, `reverse_proxy` (max-body-size hint),
  `custom_headers` (header rows + a warning Callout). **With no reported matrix,
  everything stays enabled** (`supports = !caps || caps[key]`).
- **Access:** booleans via REST `force_https`/`websocket`, CLI
  `--force-https`/`--websocket`, MCP `force_https`/`websocket`, Dashboard
  General/Headers tabs. The **gating is dashboard-only** (the API does not reject
  an unsupported toggle — it stores it; the renderer/agent decides).
- **Prerequisites:** for gating, an agent whose `proxy_capabilities` reports a
  `false` for some key (e.g. an existing-mode backend lacking websocket).
- **Steps:**
  - API: `PUT` `force_https`/`websocket` and confirm they round-trip in
    `GET /domains/{id}`.
  - Dashboard: open edit for a domain on a capability-limited agent → confirm the
    relevant checkbox is greyed with the tooltip, and the header rows are disabled
    with the warning Callout.
- **Pass:** booleans persist via every surface; the dashboard greys out only the
  capabilities the agent reported `false`; an agent with no matrix shows all
  enabled.
- **Coverage:** booleans D; capability greying D **if** you can seed/observe an
  agent with a restrictive `proxy_capabilities` (otherwise R against a real
  limited backend).
- **Pitfalls:** the **create** dialog does **not** gate (gating is only in the
  edit dialog, which knows the resolved agent) — create defaults `force_https=true`
  and `websocket=false` regardless of backend. Because the API doesn't enforce
  capabilities, a script can set `websocket=true` on a backend that can't do it;
  the agent then ignores/degrades it. Don't rely on the API to block unsupported
  toggles — only the UI hints.

## Acceptance checklist

**Dry (every RC):**
- [ ] Server list agent-scoped; `[]` when empty; 404 for unknown agent.
- [ ] Server create requires name+address (400 otherwise); UUID id; audited.
- [ ] Server update is partial (pointer fields); 404 unknown.
- [ ] Server delete returns **200 and cascade-deletes domains** (known leak) —
      recorded; assert §2.4's documented 409 guard is **not** yet implemented for
      servers (or, once fixed, flips to 409 + domain list).
- [ ] Add-Server dialog prefills the detected subnet (UI).
- [ ] Domain list filters `agent_id`/`server_id`/`status` AND correctly; `[]` empty.
- [ ] Domain create: required fields, port 1–65535, zone/server existence,
      subdomain uniqueness 409, `ssl_mode` defaults to `auto`.
- [ ] Subdomain validation: empty / `_` / leading-`-` / `a..b` / 64-char label
      → 400; leading `*` allowed.
- [ ] `SSLMode` enum is exactly `auto|manual|off`; `DomainStatus` is
      `pending|active|error|deleting` (+ `degraded`).
- [ ] Domain get: 400 non-numeric, 404 unknown.
- [ ] Domain update is partial and resets status to `pending`.
- [ ] Domain delete is soft (`deleting`) + immediate route push.
- [ ] On create: immediate push + central-policy async issuance (skipped for
      self-acme/off/no-issuer).
- [ ] `GET /config` returns the serving backend's shape (caddy JSON vs nginx/apache text).
- [ ] `PUT /config` validates shape per backend; `manual:true`; status `pending`.
- [ ] `POST /config/reset` clears override; `manual:false`.
- [ ] Cross-agent server move: stale `dom-<id>` artifact removed (audit) + old
      agent re-pushed; same-agent move is a no-op.
- [ ] force_https/websocket persist via REST/CLI/MCP; dashboard edit greys
      capabilities the agent reports `false`.

**Real run (before final):**
- [ ] nginx-inferred upstream suggestions appear in Add-Server for an existing-mode
      nginx agent with discovered upstreams.
- [ ] A central-TLS domain create issues a real LE cert (DNS-01) within the
      5-minute on-create window; route serves on `:443`.
- [ ] A cross-agent server move removes the ghost vhost on disk on the old agent
      and serves correctly on the new one.
- [ ] Capability gating matches a real limited backend (e.g. websocket unsupported).
- [ ] Server-delete DNS leak: on a real zone, confirm whether deleting a server
      with domains orphans the provider DNS records (until the guard is fixed,
      delete domains first).

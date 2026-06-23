# MCP Server (AI-driven management)
> **Scope:** the optional Model Context Protocol endpoint that lets AI tools drive NurProxy (inspect agents/servers, manage domains) over a single JSON-RPC 2.0 HTTP endpoint — enablement, auth, rate limiting, protocol handshake, and every tool.
> **Code:** `internal/orchestrator/mcp/server.go`, `internal/orchestrator/mcp/jsonrpc.go`, mount in `cmd/nurproxy/main.go:157-161`, settings/api-key endpoints in `internal/orchestrator/api/system.go` + `internal/orchestrator/api/server.go:224-227`, audit source `internal/shared/models/models.go:402`.
> **Coverage legend:** D = coverable dry, R = needs a real run.

## Prerequisites
- Both binaries built: `make build-all` (orchestrator `./nurproxy`, agent `./nurproxy-agent`).
- A running orchestrator. The cheapest setup is the dry sandbox (`make dev-sandbox`),
  which on default port **8099** runs `auth setup` (password `sandbox123`) and creates
  an admin API key via `nurproxy apikey create`, printing the first 14 chars
  (`scripts/dev-sandbox.sh:84-88`). Capture the **full** key — you need it as the Bearer token.
- The MCP endpoint shares the orchestrator's HTTP listener at `/mcp` and `/mcp/`
  (`cmd/nurproxy/main.go:160-161`). It is **off by default**; the tests below enable it.
- An admin API key MUST exist (`admin_api_key` setting non-empty) — MCP is unusable
  without it (`server.go:56-60`).
- `curl` and `jq`. All steps are dry-coverable (no live DNS/ACME/Caddy needed).

Set up a working shell against the sandbox (adjust if you booted by hand):
```bash
BASE=http://localhost:8099
# Full API key — from `make dev-sandbox` output, or generate one:
KEY=$(./nurproxy apikey create --password sandbox123 | grep -oE 'np_ak_[a-f0-9]+' | head -1)
echo "$KEY"   # must start with np_ak_ (internal/shared/auth/token.go:15)
```
> When booting the orchestrator by hand instead of `make dev-sandbox`:
> `NP_DRY_RUN=true ./nurproxy -port 8099 -data-dir /tmp/np` then
> `./nurproxy auth setup --password sandbox123` and `./nurproxy apikey create --password sandbox123`.

## Features covered
- [ ] MCP off by default — disabled endpoint returns **404** (behaves as if it doesn't exist).
- [ ] Enable via `mcp_enabled=true` (`PUT /api/v1/settings/mcp_enabled`).
- [ ] Endpoint mounted at both `/mcp` and `/mcp/`; only `POST` allowed (405 otherwise).
- [ ] Auth: Bearer admin API key required; missing/wrong → **401** with `WWW-Authenticate: Bearer`.
- [ ] Rate limit: 10 failed auth attempts per IP / 15 min → **429** with `Retry-After`.
- [ ] Request body limit: 1 MiB (`io.LimitReader`).
- [ ] JSON-RPC 2.0 framing; error codes parseError/methodNotFound/invalidParams.
- [ ] Protocol method `initialize` → protocolVersion `2024-11-05`, serverInfo.
- [ ] `ping` → empty result.
- [ ] `tools/list` → exactly 7 tools, sorted, with inputSchema.
- [ ] `notifications/*` → 202 Accepted, no body.
- [ ] Tool `list_agents` (no token-hash leak).
- [ ] Tool `get_agent_status` (single agent by id).
- [ ] Tool `list_servers` (optional `agent_id` filter; aggregates across agents).
- [ ] Tool `list_domains` (optional `agent_id`/`status` filters).
- [ ] Tool `create_domain` (validation, duplicate guard, audit).
- [ ] Tool `update_domain` (partial update, re-queues, audit).
- [ ] Tool `delete_domain` (marks `deleting`, audit).
- [ ] Audit: every mutation logged `source=mcp`, `actor=mcp`.
- [ ] Tool-level errors returned as tool result `isError=true`, not JSON-RPC error.

## Tests

### MCP off by default → 404
**Must:** With `mcp_enabled` unset/not `"true"`, `/mcp` returns HTTP 404 regardless of method or auth, behaving as if the route does not exist (`server.go:49-52, 80-84`).
**Access:**
- Setting: `mcp_enabled` (string `"true"` to enable). Read via `GET /api/v1/settings`; written via `PUT /api/v1/settings/mcp_enabled`.
- Endpoint: `POST /mcp` (HTTP JSON-RPC).
**Prerequisites:** Fresh orchestrator where `mcp_enabled` has never been set to `"true"`.
**Steps:**
```bash
# Confirm not enabled (mcp_enabled absent or != true):
curl -s -H "Authorization: Bearer $KEY" "$BASE/api/v1/settings" | jq '.[] | select(.key=="mcp_enabled")'
# Hit the endpoint while disabled:
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$BASE/mcp" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```
**Pass:** Returns `404`. (Regression guard: `TestDisabledReturns404`, `server_test.go:91-98`.)
**Coverage:** D.
**Pitfalls:** The 404 fires before auth/rate-limit/method checks, so a valid key still 404s while disabled. `mcp_enabled` must be the exact string `"true"` — any other value keeps it off (`server.go:51`).

### Enable MCP via settings
**Must:** Setting `mcp_enabled` to `"true"` makes the endpoint live; it can be turned off again by setting any other value.
**Access:**
- REST: `PUT /api/v1/settings/mcp_enabled` body `{"value":"true"}` (requires admin auth — Bearer key or session). Route: `server.go:224` → `handleUpdateSetting` (`system.go:134-169`).
- Dashboard: there is **no dedicated MCP toggle** in Settings (`web/src/pages/Settings.tsx` exposes the admin API key but not `mcp_enabled`). UNVERIFIED whether any dashboard control writes `mcp_enabled`; enable it via the REST settings endpoint.
- CLI: no dedicated `nurproxy mcp` command exists; use the REST endpoint.
**Prerequisites:** Admin auth (Bearer key works).
**Steps:**
```bash
curl -s -X PUT "$BASE/api/v1/settings/mcp_enabled" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"value":"true"}' -w '\nHTTP %{http_code}\n'
# Verify it now appears as true:
curl -s -H "Authorization: Bearer $KEY" "$BASE/api/v1/settings" \
  | jq '.[] | select(.key=="mcp_enabled")'
```
**Pass:** PUT returns 200; `GET /settings` shows `mcp_enabled` with value `true`. (Regression guard: `api_test.go:909-927`.) After this, the 404 test above instead returns a JSON-RPC response.
**Coverage:** D.
**Pitfalls:** `PUT /settings/{key}` refuses `admin_password_hash`, `admin_api_key`, and the session-secret key (`system.go:143-154`) — but `mcp_enabled` is a normal setting and is allowed. The setting body field is `value` (not `mcp_enabled`).

### Endpoint mount + method handling
**Must:** Handler is reachable at both `/mcp` and `/mcp/` (`main.go:160-161`). When enabled, only `POST` is accepted; other methods return **405** with `Allow: POST` (`server.go:85-89`).
**Access:** `POST /mcp`, `POST /mcp/`.
**Prerequisites:** MCP enabled.
**Steps:**
```bash
# trailing-slash variant works:
curl -s -X POST "$BASE/mcp/" -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"ping"}' | jq .
# wrong method:
curl -s -X GET "$BASE/mcp" -H "Authorization: Bearer $KEY" \
  -D - -o /dev/null | grep -iE 'HTTP/|allow'
```
**Pass:** `POST /mcp/` returns a JSON-RPC result; `GET /mcp` returns `405` with header `Allow: POST`.
**Coverage:** D.
**Pitfalls:** The 404-when-disabled check runs before the method check, so a `GET` while disabled returns 404, not 405.

### Auth: Bearer admin API key
**Must:** Every request needs `Authorization: Bearer <admin_api_key>`. Missing prefix, wrong token, or no key configured → **401** with `WWW-Authenticate: Bearer`; comparison is constant-time (`server.go:54-68, 96-101`).
**Access:** HTTP header `Authorization: Bearer np_ak_…`.
**Prerequisites:** MCP enabled; admin API key set.
**Steps:**
```bash
# no token → 401
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$BASE/mcp" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
# wrong token → 401 + WWW-Authenticate
curl -s -D - -o /dev/null -X POST "$BASE/mcp" \
  -H 'Authorization: Bearer wrong-key' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | grep -iE 'HTTP/|www-authenticate'
# correct token → 200 JSON-RPC
curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq '.result.tools | length'
```
**Pass:** No/wrong token → `401` + `WWW-Authenticate: Bearer`; correct token → JSON-RPC 200. (Regression guard: `TestUnauthorized`, `server_test.go:100-110`.)
**Coverage:** D.
**Pitfalls:** Uses the **same** `admin_api_key` as the REST API — it is not a separate MCP key. If the key is revoked (`DELETE /api/v1/api-key`, which empties the setting, `system.go:101-107`), MCP returns 401 even while enabled. Token comparison is `subtle.ConstantTimeCompare`.

### Rate limit on failed auth
**Must:** Failed auth attempts are throttled per client IP: 10 fails per 15 min locks the IP out for 15 min, returning **429** with a `Retry-After` header (seconds). A successful auth resets the counter (`server.go:43-44, 90-102`). IP is keyed on `RemoteAddr`, not `X-Forwarded-For` (`server.go:72-77`).
**Access:** HTTP — triggered by repeated bad Bearer tokens.
**Prerequisites:** MCP enabled. Use a throwaway instance/IP — the lockout persists 15 min for that IP.
**Steps:**
```bash
# Fire 11 bad-auth requests; expect the 11th (or first after 10 fails) to 429.
for i in $(seq 1 11); do
  curl -s -o /dev/null -w "%{http_code} " -X POST "$BASE/mcp" \
    -H 'Authorization: Bearer wrong' -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"ping"}'
done; echo
# Inspect the Retry-After header on a locked response:
curl -s -D - -o /dev/null -X POST "$BASE/mcp" \
  -H 'Authorization: Bearer wrong' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"ping"}' | grep -iE 'HTTP/|retry-after'
```
**Pass:** After 10 failures the next requests return `429` with a `Retry-After` header whose value is a positive integer (seconds, `int(retryAfter.Seconds())+1`, `server.go:91-94`).
**Coverage:** D.
**Pitfalls:** The limiter checks **before** auth, so once locked even a correct key gets 429 until the window passes. The lockout is per source IP and lasts 15 min — run this last, or against a disposable instance, so it doesn't block your other MCP tests. A single successful auth resets that IP's counter (`server.go:102`).

### Request body size limit (1 MiB)
**Must:** The request body is read through `io.LimitReader(r.Body, 1<<20)` = 1 MiB (`server.go:104`). Bytes beyond 1 MiB are silently dropped, so an oversized payload is truncated and then fails JSON parsing → JSON-RPC parse error.
**Access:** HTTP request body.
**Prerequisites:** MCP enabled; valid key.
**Steps:**
```bash
# Build a >1MiB JSON body (huge string field) and send it:
python3 - <<'PY' > /tmp/big.json
import json
print(json.dumps({"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"A"*2_000_000}}))
PY
curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' --data-binary @/tmp/big.json | jq .
```
**Pass:** Response is a JSON-RPC error with `error.code = -32700` and message `"invalid JSON"` (the truncated body no longer parses; `server.go:104-114`, `jsonrpc.go:11`). A well-formed body under 1 MiB processes normally.
**Coverage:** D.
**Pitfalls:** The limit truncates rather than rejecting with 413, so the visible symptom is a parse error, not a size error.

### JSON-RPC protocol: initialize / ping / tools/list / notifications
**Must:**
- `initialize` → result with `protocolVersion="2024-11-05"`, `capabilities.tools={}`, `serverInfo={name:"nurproxy", version:<build version>}` (`server.go:28, 128-133`).
- `ping` → empty object result (`server.go:134-135`).
- `tools/list` → `{tools:[…]}` with exactly 7 entries, name-sorted, each carrying `name`, `description`, `inputSchema` (`server.go:136-137, 236-252`).
- `notifications/*` (e.g. `notifications/initialized`) → HTTP **202 Accepted**, no body (`server.go:122-125`).
- Unknown method → JSON-RPC error code `-32601` (methodNotFound) (`server.go:140-141`).
**Access:** `POST /mcp` JSON-RPC. Framing: `{"jsonrpc":"2.0","id":<n>,"method":<m>,"params":<…>}` (`jsonrpc.go:16-21`). Responses always HTTP 200 with `Content-Type: application/json` (`jsonrpc.go:43-46`); the JSON-RPC error lives in the body.
**Prerequisites:** MCP enabled; valid key.
**Steps:**
```bash
# initialize
curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  | jq '.result.protocolVersion, .result.serverInfo'
# ping
curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"ping"}' | jq '.result'
# tools/list — count + names
curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/list"}' \
  | jq '.result.tools | length, [.[].name]'
# notification → 202, no JSON-RPC body
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
# unknown method → -32601
curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":4,"method":"bogus"}' | jq '.error'
```
**Pass:**
- `initialize` → `"2024-11-05"` and serverInfo `{name:"nurproxy", version:…}`.
- `ping` → `{}`.
- `tools/list` → length `7`; names exactly `["create_domain","delete_domain","get_agent_status","list_agents","list_domains","list_servers","update_domain"]` (sorted).
- notification → HTTP `202`, empty body.
- unknown method → `{"code":-32601,"message":"unknown method: bogus"}`.
(Regression guards: `TestInitialize` `server_test.go:112-123`, `TestToolsList` `server_test.go:125-149`.)
**Coverage:** D.
**Pitfalls:** Even JSON-RPC errors return HTTP 200 — don't assert on HTTP status for protocol errors, inspect `.error`. The `version` in serverInfo is the orchestrator build version passed to `mcp.New(database, version)` (`main.go:159`); in the sandbox it may read `dev`/`unknown`.

### Tool: list_agents
**Must:** Returns all registered agents with status/health; never returns null (empty → `[]`) and must not leak the agent token hash (`server.go:258-267`, guard `server_test.go:264-266`).
**Access:** `tools/call` name `list_agents`, no arguments (schema `{}`, `additionalProperties:false`, `server.go:190`).
**Prerequisites:** MCP enabled; at least one adopted agent (the sandbox seeds agents).
**Steps:**
```bash
curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_agents","arguments":{}}}' \
  | jq -r '.result.content[0].text' | jq '. | length, .[0] | {id,name,fqdn,status}'
```
**Pass:** Tool result content[0].text is JSON array of agents; each has id/name/fqdn/status; no `token_hash` / TokenHash field present. `isError` is false.
**Coverage:** D.
**Pitfalls:** Tool output is wrapped as MCP content — the actual JSON is in `.result.content[0].text` (a string), so double-decode (`jsonrpc.go:51-60`).

### Tool: get_agent_status
**Must:** Returns a single agent's status/health by id. Required arg `agent_id`; missing or unknown agent → tool error (`isError=true`) (`server.go:269-295`). Returns exactly: id, name, fqdn, status, public_ip, version, caddy_running, last_error, dns_error, last_seen (`server.go:283-294`).
**Access:** `tools/call` name `get_agent_status`, args `{"agent_id":"<id>"}` (schema requires `agent_id`, `server.go:196`).
**Prerequisites:** MCP enabled; a known agent id (from `list_agents`).
**Steps:**
```bash
AID=$(curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_agents","arguments":{}}}' \
  | jq -r '.result.content[0].text' | jq -r '.[0].id')
curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"get_agent_status\",\"arguments\":{\"agent_id\":\"$AID\"}}}" \
  | jq '{isError:.result.isError, status:(.result.content[0].text|fromjson)}'
# unknown agent → isError
curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_agent_status","arguments":{"agent_id":"ghost"}}}' \
  | jq '.result.isError, .result.content[0].text'
```
**Pass:** Known id → `isError=false` and the 10 fields above. Unknown id → `isError=true` (guard `server_test.go:281-283`).
**Coverage:** D.
**Pitfalls:** Empty/missing `agent_id` returns a tool error `"agent_id is required"`, not a JSON-RPC error.

### Tool: list_servers
**Must:** Lists backend servers. Optional `agent_id` filters to one agent; without it, aggregates across all agents. Never null (`server.go:297-323, 477-485`).
**Access:** `tools/call` name `list_servers`, args `{}` or `{"agent_id":"<id>"}` (schema `server.go:202`).
**Prerequisites:** MCP enabled; at least one server (sandbox seeds servers).
**Steps:**
```bash
# all servers
curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_servers","arguments":{}}}' \
  | jq -r '.result.content[0].text' | jq 'length'
# filtered by agent
curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"list_servers\",\"arguments\":{\"agent_id\":\"$AID\"}}}" \
  | jq -r '.result.content[0].text' | jq 'length'
```
**Pass:** Both calls return a JSON array (filtered count ≤ aggregate count); `isError=false`. (Guard `server_test.go:274-278`.)
**Coverage:** D.
**Pitfalls:** With no args at all the tool still works (args optional, decoded only when present, `server.go:301-305`).

### Tool: list_domains
**Must:** Lists proxied domains. Optional `agent_id` and `status` filters (passed to `db.DomainFilter`). Never null (`server.go:325-343`).
**Access:** `tools/call` name `list_domains`, args `{}` / `{"agent_id":…}` / `{"status":…}` (schema `server.go:208`).
**Prerequisites:** MCP enabled; domains seeded (sandbox seeds central-TLS domains) or created via `create_domain` below.
**Steps:**
```bash
curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_domains","arguments":{}}}' \
  | jq -r '.result.content[0].text' | jq 'length, .[0] | {id,subdomain,zone_id,server_id,status}'
# filter by status
curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_domains","arguments":{"status":"pending"}}}' \
  | jq -r '.result.content[0].text' | jq 'length'
```
**Pass:** Returns a JSON array; status filter narrows results; `isError=false`. (Guard `server_test.go:227-231`.)
**Coverage:** D.
**Pitfalls:** `status` is a free-form string passed straight to the filter; an invalid status just yields zero matches, not an error.

### Tool: create_domain
**Must:** Creates a proxied domain. Required: `subdomain`, `zone_id`, `server_id`, `port` (schema `server.go:214`). Validation (`server.go:358-378`): subdomain via `dnsname.ValidateSubdomain`; port 1–65535; zone must exist; server must exist; duplicate (same subdomain+zone) rejected. Optional `websocket`, `force_https`, `ssl_mode` (enum `auto`/`manual`/`off`); empty `ssl_mode` defaults to `auto` (`models.SSLModeAuto`, `server.go:379-382`). New domain is created with status `pending` and audited as MCP (`server.go:391-397`).
**Access:** `tools/call` name `create_domain`, args object with the fields above.
**Prerequisites:** MCP enabled; a valid `zone_id` and `server_id`. Grab them from the REST API or from `list_servers`/the zones endpoint.
**Steps:**
```bash
ZID=$(curl -s -H "Authorization: Bearer $KEY" "$BASE/api/v1/zones" | jq -r '.[0].id')
SID=$(curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_servers","arguments":{}}}' \
  | jq -r '.result.content[0].text' | jq -r '.[0].id')
# create
curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"create_domain\",\"arguments\":{\"subdomain\":\"mcptest\",\"zone_id\":\"$ZID\",\"server_id\":\"$SID\",\"port\":8080}}}" \
  | jq '{isError:.result.isError, domain:(.result.content[0].text|fromjson)|{id,subdomain,status,ssl_mode}}'
# duplicate → isError
curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"create_domain\",\"arguments\":{\"subdomain\":\"mcptest\",\"zone_id\":\"$ZID\",\"server_id\":\"$SID\",\"port\":8080}}}" \
  | jq '.result.isError, .result.content[0].text'
# bad port → isError
curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"create_domain\",\"arguments\":{\"subdomain\":\"badport\",\"zone_id\":\"$ZID\",\"server_id\":\"$SID\",\"port\":0}}}" \
  | jq '.result.isError'
# verify MCP-sourced audit entry:
curl -s -H "Authorization: Bearer $KEY" "$BASE/api/v1/audit?source=mcp" \
  | jq '.entries[] | select(.entity_type=="domain" and .action=="create") | {actor,source,action,entity_id}' | head
```
**Pass:** First create → `isError=false`, domain has an id, `status:"pending"`, `ssl_mode:"auto"` (default). Duplicate → `isError=true` (`"subdomain already exists for this zone"`). Port 0 → `isError=true`. Audit query shows an entry `action=create entity_type=domain source=mcp actor=mcp`. (Guards `server_test.go:184-224`, `194-210`.)
**Coverage:** D.
**Pitfalls:** A domain reaches `active` only after the reconciler/DNS/TLS state machine runs — in dry mode this converges with simulated DNS/cert; don't expect `active` immediately. `ssl_mode` enum is `auto|manual|off` here (`server.go:214`) — note the sandbox CLI/REST seed uses `central`; the MCP schema does NOT list `central`, so passing `central` is outside the declared enum (clients may reject; the server itself stores the raw string). The convenience var `$AID`/`$ZID`/`$SID` must be set in the same shell.

### Tool: update_domain
**Must:** Updates an existing domain by `id` (required, `server.go:220`). All other fields are pointers — only provided fields change: `server_id` (must exist), `port` (1–65535), `websocket`, `force_https`, `ssl_mode`. The update always resets status to `pending` to re-queue reconciliation, and is audited as MCP (`server.go:400-445`).
**Access:** `tools/call` name `update_domain`, args `{"id":<n>, …}`.
**Prerequisites:** MCP enabled; a domain id (from `create_domain`/`list_domains`).
**Steps:**
```bash
DID=$(curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_domains","arguments":{}}}' \
  | jq -r '.result.content[0].text' | jq -r '.[]|select(.subdomain=="mcptest").id')
curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"update_domain\",\"arguments\":{\"id\":$DID,\"port\":9090}}}" \
  | jq '{isError:.result.isError, domain:(.result.content[0].text|fromjson)|{id,port,status}}'
```
**Pass:** `isError=false`; returned domain has `port:9090` and `status:"pending"`. Audit (`?source=mcp`) shows `action=update entity_type=domain source=mcp actor=mcp`. (Guard `server_test.go:233-238`.)
**Coverage:** D.
**Pitfalls:** Missing/zero `id` → tool error `"id is required"`. Unknown id → `"domain not found"`. `server_id` pointing at a non-existent server → `"server not found"` (no partial update applied — validation happens before `UpdateDomain`).

### Tool: delete_domain
**Must:** Marks a domain for teardown: sets status to `deleting` (does not hard-delete) and audits as MCP. Required `id` (`server.go:448-463`). Returns `{"id":<n>,"status":"deleting"}`.
**Access:** `tools/call` name `delete_domain`, args `{"id":<n>}`.
**Prerequisites:** MCP enabled; a domain id.
**Steps:**
```bash
curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"delete_domain\",\"arguments\":{\"id\":$DID}}}" \
  | jq '{isError:.result.isError, result:(.result.content[0].text|fromjson)}'
# confirm via REST that status moved to deleting:
curl -s -H "Authorization: Bearer $KEY" "$BASE/api/v1/domains" | jq ".[]|select(.id==$DID)|{id,status}"
```
**Pass:** `isError=false`, result `{"id":…,"status":"deleting"}`; the domain's status is `deleting`. Audit (`?source=mcp`) shows `action=delete entity_type=domain source=mcp`. (Guard `server_test.go:241-251`.)
**Coverage:** D.
**Pitfalls:** Unknown id → tool error `"domain not found"` (because `UpdateDomainStatus` fails). Teardown of the DNS record/route then happens via the reconciler — in dry mode the simulated delete completes; on a real run, **watch for the known server-delete DNS-leak class of bug** (see `docs/RELEASE-QA.md` and MEMORY: deleting cascades can orphan managed DNS/certs — verify the managed record/cert is actually removed, not just the domain row).

### Audit attribution (source=mcp, actor=mcp)
**Must:** Every MCP mutation (create/update/delete_domain) writes an audit entry with `Actor="mcp"` and `Source=models.AuditSourceMCP` (`"mcp"`) (`server.go:466-475`, `models.go:402`). Read tools do not audit.
**Access:** REST `GET /api/v1/audit?source=mcp` (`server.go` audit route → `system.go:60-66`). Dashboard audit log filters by source channel `mcp` (`web/src/lib/types.ts:223`); the Overview maps the `mcp` source to a badge color (`web/src/pages/Overview.tsx:187`).
**Prerequisites:** Performed at least one MCP mutation above.
**Steps:**
```bash
curl -s -H "Authorization: Bearer $KEY" "$BASE/api/v1/audit?source=mcp" \
  | jq '.entries[] | {actor,source,action,entity_type,entity_id}'
```
**Pass:** All listed entries have `source:"mcp"` and `actor:"mcp"`, covering the create/update/delete you ran. (Guard `server_test.go:194-210`.)
**Coverage:** D.
**Pitfalls:** Read tools (`list_*`, `get_agent_status`) intentionally produce no audit entries — don't expect them.

### Tool-error vs JSON-RPC-error semantics
**Must:** A **tool-level** failure (bad args, validation, not-found) is returned as a *successful* JSON-RPC result whose payload has `isError=true` and the message in `content[0].text` (`server.go:163-170`, `jsonrpc.go:62-68`). A **protocol** error (unknown method, unknown tool name, malformed params/JSON) is a JSON-RPC `error` object with a numeric code (`server.go:140-141, 152-159`; codes in `jsonrpc.go:9-14`).
**Access:** `tools/call` with a bad tool name vs a real tool with bad args.
**Prerequisites:** MCP enabled.
**Steps:**
```bash
# unknown tool → JSON-RPC error -32602 (invalidParams)
curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope","arguments":{}}}' | jq '.error'
# known tool, bad args → tool result isError=true (no .error)
curl -s -X POST "$BASE/mcp" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_agent_status","arguments":{}}}' \
  | jq '{error:.error, isError:.result.isError, text:.result.content[0].text}'
```
**Pass:** Unknown tool → `{"code":-32602,"message":"unknown tool: nope"}` and no `result`. Known tool with empty args → no `.error`, `result.isError=true`, text `"agent_id is required"`. (Guard `TestUnknownTool` `server_test.go:151-158`.)
**Coverage:** D.
**Pitfalls:** Clients must inspect both `.error` (protocol) and `.result.isError` (tool) — a tool failure is HTTP 200 with no `.error`.

## Acceptance checklist

### Dry (every RC)
- [ ] Disabled MCP → `POST /mcp` returns 404 even with a valid key.
- [ ] `PUT /api/v1/settings/mcp_enabled` `{"value":"true"}` enables it (200; visible in `GET /settings`).
- [ ] `/mcp` and `/mcp/` both serve; non-POST → 405 + `Allow: POST`.
- [ ] No/wrong Bearer token → 401 + `WWW-Authenticate: Bearer`; correct key → 200.
- [ ] 10 failed auths from one IP → 429 with positive `Retry-After`; success resets.
- [ ] Oversized body (>1 MiB) → JSON-RPC parse error (`-32700`).
- [ ] `initialize` → protocolVersion `2024-11-05` + serverInfo `nurproxy`.
- [ ] `ping` → `{}`; `notifications/*` → 202 no body; unknown method → `-32601`.
- [ ] `tools/list` → exactly 7 sorted tools each with inputSchema.
- [ ] `list_agents` returns agents, no token-hash leak.
- [ ] `get_agent_status` returns the 10 status fields; unknown id → isError.
- [ ] `list_servers` (all + agent-filtered) returns arrays.
- [ ] `list_domains` (all + status filter) returns arrays.
- [ ] `create_domain` creates status=pending, defaults ssl_mode=auto; duplicate & bad-port → isError.
- [ ] `update_domain` applies partial change, re-queues to pending.
- [ ] `delete_domain` sets status=deleting and returns it.
- [ ] All three mutations appear in `GET /api/v1/audit?source=mcp` as actor=mcp.
- [ ] Tool-error (isError=true) vs JSON-RPC-error (code) semantics hold.

### Real run (before final)
- [ ] R: After `delete_domain` against a real zone, confirm the managed DNS record AND cert are actually torn down (regression guard for the server-delete DNS-leak class of bug), not just the domain row.
- [ ] R: With a real Cloudflare zone + ACME, a domain created via `create_domain` converges to `active` (DNS record resolvable, real cert chain).

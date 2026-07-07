# Interface: REST API (full endpoint reference & test surface)
> **Scope:** the complete REST surface of the orchestrator (`/api/v1/*`) plus the opt-in MCP endpoint (`/mcp`) as an authoritative reference, plus contract tests for auth enforcement, method-not-allowed, bad-body rejection, CORS, content-types and pagination.
> **Code:** `internal/orchestrator/api/server.go` (route registration), `internal/orchestrator/api/{middleware,helpers,auth}.go` (auth + CORS + JSON helpers), the per-area handler files (`providers.go`, `zones.go`, `agents.go`, `agents_stream.go`, `servers.go`, `domains.go`, `artifacts.go`, `artifacts_adopt.go`, `artifact_mask.go`, `admin_ops.go`, `logs.go`, `system.go`, `version_status.go`), `internal/orchestrator/mcp/server.go` (MCP), and `cmd/nurproxy/main.go` (mux wiring of `/api/` + `/mcp`).
> **Coverage legend:** D = coverable dry, R = needs a real run.

## Prerequisites
- Both binaries built (`make build-all`) or a dry stack up.
- A running orchestrator. For most of this file a **hand-booted dry instance** with a fresh data dir is best so you can fully control auth state and avoid prod risk:
  ```bash
  NP_DRY_RUN=true ./nurproxy -port 18080 -data-dir /tmp/np-api &
  export NP_API_URL=http://localhost:18080
  ```
  `make dev-sandbox` also works and **pre-seeds** an admin password + API key + a populated topology (provider/zone/agents/servers/domains) — handy when you want real objects to GET, but it is *not* a clean slate.
- `jq` and `curl` in PATH.
- An **admin API key** to exercise authenticated REST calls. Bootstrap it on a fresh dry instance:
  ```bash
  curl -s -X POST $NP_API_URL/api/v1/auth/setup -H 'Content-Type: application/json' \
    -d '{"password":"hunter2!"}' -c /tmp/np.cookies >/dev/null      # sets admin password + session cookie
  export NP_KEY=$(curl -s -X POST $NP_API_URL/api/v1/api-key -b /tmp/np.cookies | jq -r .api_key)
  echo "$NP_KEY"
  ```
  All REST examples below use `-H "Authorization: Bearer $NP_KEY"`. Dashboard access uses the session cookie (`-b /tmp/np.cookies`) instead; both satisfy `requireAuth`.

## Features covered
- [ ] Authoritative endpoint table — every route, method, path, auth class, purpose, body shape (enumerated from `server.go:131-228` + `main.go:155-161`).
- [ ] Three auth classes: `none` (public), `requireAuth` (session cookie OR admin API key OR agent token), `requireAgentAuth` (agent token only, scoped to self).
- [ ] Auth enforcement — 401 on missing/bad credentials; 403 on agent-scoped routes called for a different agent.
- [ ] Admin-vs-agent token separation (admin key works everywhere `requireAuth`; agent token works on `requireAuth` *and* its own `requireAgentAuth` routes).
- [ ] Method-not-allowed — 405 from Go 1.22 method-scoped routing (e.g. `GET /api/v1/agents/{id}`).
- [ ] 400 on malformed / empty / missing-required bodies.
- [ ] CORS — wildcard origin, no credentials, `OPTIONS` preflight → 204.
- [ ] Content-Type — JSON responses; error envelope shape `{"error": "..."}`.
- [ ] Pagination & filters — audit-log `limit`/`offset`/`source`; domains `agent_id`/`server_id`/`status`; artifacts `agent_id`/`domain_id`/`source`/`apply_state`/`drifted`.
- [ ] Health endpoint contract (`200`/`503`, dry-run flags).
- [ ] MCP endpoint (`/mcp`) — opt-in 404, POST-only 405, Bearer-key auth, JSON-RPC dispatch.

## Tests

### Authoritative endpoint table
- **Must:** the following is the complete route set registered in `registerRoutes` (`server.go:131-228`) plus the two root-mounted MCP handlers (`main.go:160-161`). Auth column: **none** = public, **auth** = `requireAuth` (session cookie OR admin API key OR a valid agent token — `middleware.go:25-65`), **agent** = `requireAgentAuth` (agent token only, and the agent-scoped handlers additionally verify the caller's `agent_id` matches the path `{id}`).

  **Health**
  | Method | Path | Auth | Purpose | Body |
  |---|---|---|---|---|
  | GET | `/api/v1/health` | none | liveness + DB ping; 503 if DB down | — |

  **Auth**
  | Method | Path | Auth | Purpose | Body |
  |---|---|---|---|---|
  | GET | `/api/v1/auth/status` | none | `{setup_required, authenticated}` | — |
  | POST | `/api/v1/auth/setup` | none | first-run admin password (409 if set) | `{"password":"..."}` |
  | POST | `/api/v1/auth/login` | none | password login → session cookie | `{"password":"..."}` |
  | POST | `/api/v1/auth/logout` | none | clears session cookie | — |
  | POST | `/api/v1/auth/change-password` | auth | rotate admin password | `{"current_password":"...","new_password":"..."}` |

  **Providers**
  | Method | Path | Auth | Purpose | Body |
  |---|---|---|---|---|
  | GET | `/api/v1/providers` | auth | list (config stripped) | — |
  | POST | `/api/v1/providers` | auth | create + validate config | `{"type":"...","name":"...","config":{...}}` |
  | POST | `/api/v1/providers/test` | auth | validate config + list zones | `{"type":"...","config":{...}}` |
  | GET | `/api/v1/providers/{id}` | auth | get one (config stripped) | — |
  | PUT | `/api/v1/providers/{id}` | auth | update name/config | `{"name"?:"...","config"?:{...}}` |
  | DELETE | `/api/v1/providers/{id}` | auth | delete | — |
  | GET | `/api/v1/providers/{id}/zones` | auth | zones stored for provider | — |

  **Zones**
  | Method | Path | Auth | Purpose | Body |
  |---|---|---|---|---|
  | GET | `/api/v1/zones` | auth | list all zones | — |
  | POST | `/api/v1/zones` | auth | create one zone | `{"provider_id":"...","external_id"?:"...","name":"..."}` |
  | POST | `/api/v1/zones/batch` | auth | create many | `{"provider_id":"...","zones":[{"external_id":"...","name":"..."}]}` |
  | DELETE | `/api/v1/zones/{id}` | auth | delete | — |

  **Agents** (lifecycle)
  | Method | Path | Auth | Purpose | Body |
  |---|---|---|---|---|
  | GET | `/api/v1/agents` | auth | list (+ zones, version_status) | — |
  | POST | `/api/v1/agents/register` | none | agent self-registers a token | `{"id","fqdn","token",...}` |
  | PUT | `/api/v1/agents/{id}` | auth | update name/fqdn/zones/dns_mode/ddns_interval | `{"name"?,"fqdn"?,"zone_ids"?,"dns_mode"?,"ddns_interval"?}` |
  | DELETE | `/api/v1/agents/{id}` | auth | delete | — |
  | PUT | `/api/v1/agents/{id}/adopt` | auth | adopt a pending agent | `{"name"?,"fqdn"?,"zone_ids"?,"dns_mode"?,"ddns_interval"?}` |
  | PUT | `/api/v1/agents/{id}/reject` | auth | reject (delete) a pending agent | — |
  | PUT | `/api/v1/agents/{id}/auto-reconcile` | auth | toggle auto-reconcile-config policy | `{"enabled":true}` |
  | GET | `/api/v1/agents/{id}/status` | auth | health/version/proxy detail | — |
  | POST | `/api/v1/agents/{id}/heartbeat` | agent | agent health self-report | health/detection/capabilities/checksums |
  | GET | `/api/v1/agents/{id}/stream` | agent | long-lived SSE push channel | — |
  | POST | `/api/v1/agents/{id}/routes/ack` | agent | apply-ACK + rendered artifacts | `ApplyAck` |
  | POST | `/api/v1/agents/{id}/artifacts/adopt` | agent | report read-off-disk configs (§17) | `AdoptedArtifactReport` |

  **Agent log-tail (§15)**
  | Method | Path | Auth | Purpose | Body |
  |---|---|---|---|---|
  | POST | `/api/v1/agents/{id}/logs/chunk` | agent | agent posts tailed lines up | `LogChunk` |
  | POST | `/api/v1/agents/{id}/logs/tail` | auth | dashboard starts a tail | `{"path":"...","lines"?:N}` |
  | GET | `/api/v1/agents/{id}/logs/tail/{session}` | auth | poll buffered lines (`?cursor=N`) | — |
  | DELETE | `/api/v1/agents/{id}/logs/tail/{session}` | auth | stop a tail | — |

  **Agent admin-ops (§19)**
  | Method | Path | Auth | Purpose | Body |
  |---|---|---|---|---|
  | POST | `/api/v1/agents/{id}/admin-ops` | auth | prepare op → one-time code | `{"op_type":"set_proxy_mode","payload":{...}}` |
  | GET | `/api/v1/agents/{id}/admin-ops` | auth | list pending ops (no code/hash) | — |
  | DELETE | `/api/v1/agents/{id}/admin-ops/{opId}` | auth | cancel a pending op (204) | — |
  | POST | `/api/v1/agents/{id}/admin-ops/claim` | agent | agent claims op by code | `{"code":"..."}` |
  | POST | `/api/v1/agents/{id}/admin-ops/{opId}/ack` | agent | agent reports op outcome | `{"ok":true,"result":"..."}` |

  **Servers**
  | Method | Path | Auth | Purpose | Body |
  |---|---|---|---|---|
  | GET | `/api/v1/agents/{id}/servers` | auth | list servers for an agent | — |
  | POST | `/api/v1/agents/{id}/servers` | auth | create a backend server | `{"name":"...","address":"...","notes"?:"..."}` |
  | PUT | `/api/v1/servers/{id}` | auth | update | `{"name"?,"address"?,"notes"?}` |
  | DELETE | `/api/v1/servers/{id}` | auth | delete | — |

  **Domains**
  | Method | Path | Auth | Purpose | Body |
  |---|---|---|---|---|
  | GET | `/api/v1/domains` | auth | list (`?agent_id=&server_id=&status=`) | — |
  | POST | `/api/v1/domains` | auth | create a proxied domain | `{"subdomain","zone_id","server_id","port",...}` |
  | GET | `/api/v1/domains/{id}` | auth | get one | — |
  | PUT | `/api/v1/domains/{id}` | auth | update (re-queues reconcile) | partial domain fields |
  | DELETE | `/api/v1/domains/{id}` | auth | mark for deletion | — |
  | GET | `/api/v1/domains/{id}/config` | auth | rendered/manual config preview | — |
  | PUT | `/api/v1/domains/{id}/config` | auth | set a manual config override | `{"config": <json|string>}` |
  | POST | `/api/v1/domains/{id}/config/reset` | auth | clear manual override | — |

  **Config artifacts + drift (§11/§6)**
  | Method | Path | Auth | Purpose | Body |
  |---|---|---|---|---|
  | GET | `/api/v1/artifacts` | auth | list (`?agent_id=&domain_id=&source=&apply_state=&drifted=`) | — |
  | POST | `/api/v1/artifacts/bulk` | auth | bulk accept/reject drift | `{"action":"accept"\|"reject","agent_id"?:"..."}` |
  | GET | `/api/v1/artifacts/{id}` | auth | get one | — |
  | GET | `/api/v1/artifacts/{id}/versions` | auth | version history | — |
  | POST | `/api/v1/artifacts/{id}/accept` | auth | accept on-disk content | `{"content"?:"..."}` |
  | POST | `/api/v1/artifacts/{id}/reject` | auth | revert drift to accepted | — |
  | POST | `/api/v1/artifacts/{id}/rollback` | auth | promote a prior version | `{"version":N}` |
  | GET | `/api/v1/artifacts/{id}/mask` | auth | structured-view parse (§6) | — |
  | PUT | `/api/v1/artifacts/{id}/content` | auth | raw-edit (generated→manual) | `{"content":"..."}` |
  | POST | `/api/v1/artifacts/{id}/reset-to-model` | auth | re-render from domain intent | — |

  **System / audit / settings / api-key**
  | Method | Path | Auth | Purpose | Body |
  |---|---|---|---|---|
  | GET | `/api/v1/audit-log` | auth | audit log (`?limit=&offset=&source=`) | — |
  | GET | `/api/v1/settings` | auth | list settings (sensitive masked) | — |
  | PUT | `/api/v1/settings/{key}` | auth | set a setting | `{"value":"..."}` |
  | GET | `/api/v1/api-key` | auth | exists? + masked preview | — |
  | POST | `/api/v1/api-key` | auth | (re)generate; plaintext shown once | — |
  | DELETE | `/api/v1/api-key` | auth | revoke | — |

  **MCP** (root-mounted, off by default)
  | Method | Path | Auth | Purpose | Body |
  |---|---|---|---|---|
  | POST | `/mcp` and `/mcp/` | admin API key (Bearer) | JSON-RPC 2.0 (`initialize`/`tools/list`/`tools/call`/`ping`) | JSON-RPC envelope |

- **Access:** this whole file IS the access surface — curl against a dry instance.
- **Prerequisites:** file-level only.
- **Steps:** verify the live route set matches this table (catches an accidentally added/removed/renamed route):
  ```bash
  grep -nE 'mux.HandleFunc\("' internal/orchestrator/api/server.go | \
    sed -E 's/.*HandleFunc\("([A-Z]+) ([^"]+)".*/\1 \2/'
  ```
- **Pass:** the printed `METHOD PATH` list equals the table above (40 `/api/v1` routes). `/mcp` + `/mcp/` come from `main.go`, not this list.
- **Coverage:** D.
- **Pitfalls:** routes are registered with Go 1.22 method-scoped patterns (`"GET /api/v1/..."`), so the method is part of the route key — a wrong verb is a 405, not a 404 (see method-not-allowed test). `register`, `heartbeat`, `stream`, `routes/ack`, `artifacts/adopt`, `logs/chunk`, `admin-ops/claim`, `admin-ops/{opId}/ack` are **agent-driven** — you normally never call them by hand with the admin key.

### Auth class: `none` (public endpoints)
- **Must:** `GET /api/v1/health`, `GET /api/v1/auth/status`, `POST /api/v1/auth/{setup,login,logout}`, and `POST /api/v1/agents/register` require **no** credentials (`server.go:133-143`). `register` still validates its body and 409s on a duplicate FQDN (`agents.go:68-77`).
- **Access:** REST only.
- **Steps:**
  ```bash
  curl -s -o /dev/null -w "%{http_code}\n" $NP_API_URL/api/v1/health           # 200 (or 503)
  curl -s $NP_API_URL/api/v1/auth/status | jq .                                # works with no auth
  ```
- **Pass:** all return without an `Authorization` header.
- **Coverage:** D.
- **Pitfalls:** none — these are intentionally open. `health` returns 503 (not 200) when the DB ping fails (`system.go:27-31`).

### Auth class: `requireAuth` — enforcement (401)
- **Must:** every `requireAuth` route returns **401** `{"error":"authentication required"}` when the request carries no valid session cookie, no matching admin API key, and no matching agent token (`middleware.go:63`). A valid **session cookie**, a matching **admin API key** (Bearer), OR a matching **agent token** (Bearer) all pass (`middleware.go:28-60`).
- **Access:** REST (Bearer) / Dashboard (cookie).
- **Steps:**
  ```bash
  # No credentials → 401
  curl -s -o /dev/null -w "%{http_code}\n" $NP_API_URL/api/v1/agents                          # 401
  # Bogus bearer → 401
  curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer nope" $NP_API_URL/api/v1/agents   # 401
  # Valid admin key → 200
  curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $NP_KEY" $NP_API_URL/api/v1/agents # 200
  # Valid session cookie → 200
  curl -s -o /dev/null -w "%{http_code}\n" -b /tmp/np.cookies $NP_API_URL/api/v1/agents               # 200
  ```
- **Pass:** 401 / 401 / 200 / 200 respectively; error body is `{"error":"authentication required"}`.
- **Coverage:** D.
- **Pitfalls:** the admin key is matched with a constant-time compare against the `admin_api_key` setting (`middleware.go:40`); a freshly **revoked** key fails immediately. RELEASE-QA: API keys used in a test are revocable — `DELETE /api/v1/api-key` afterward. **Global session revocation:** changing the admin password rotates nothing about the cookie, but the cookie key is per-install; verify with the auth-file tests.

### Auth class: admin-vs-agent token separation
- **Must:** the admin API key satisfies `requireAuth` everywhere. An **agent token** also satisfies `requireAuth` (it is the 3rd accepted credential, `middleware.go:48-59`) **but** the agent-scoped `requireAgentAuth` handlers additionally check the caller's `agent_id` equals the path `{id}`, returning **403** `agent can only … for itself` otherwise (e.g. `agents.go:367-371`, `agents_stream.go:31-34`, `admin_ops.go:159-163`).
- **Access:** REST.
- **Prerequisites:** a registered agent with a known plaintext token. On a dry stack you can register one by hand, or read a seeded agent ID from `GET /api/v1/agents`. The agent's **plaintext** token is only known to the agent process; for a hand test, register a fresh agent and keep the token you sent:
  ```bash
  AID=$(uuidgen); ATOK="agent-secret-token"
  curl -s -X POST $NP_API_URL/api/v1/agents/register -H 'Content-Type: application/json' \
    -d "{\"id\":\"$AID\",\"fqdn\":\"edge-test.example.com\",\"token\":\"$ATOK\"}" | jq .
  ```
- **Steps:**
  ```bash
  # Agent token on an admin route that is requireAuth → 200 (agent tokens authenticate)
  curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $ATOK" $NP_API_URL/api/v1/agents     # 200
  # Agent token on ANOTHER agent's heartbeat → 403 (scoped to self)
  curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "Authorization: Bearer $ATOK" \
    -H 'Content-Type: application/json' -d '{}' $NP_API_URL/api/v1/agents/some-other-id/heartbeat        # 403
  ```
- **Pass:** 200 then 403 (`{"error":"agent can only heartbeat for itself"}`).
- **Coverage:** D.
- **Pitfalls:** the token you pass to `register` is hashed before storage (`agents.go:80`); only the original plaintext authenticates afterward — there is no way to recover it from the DB. RELEASE-QA §2.6 note: "agent bearer on its own agent route → 200; on a wrong agent route → 403."

### Auth class: `requireAgentAuth` — enforcement
- **Must:** routes wrapped with `requireAgentAuth` (`heartbeat`, `stream`, `routes/ack`, `artifacts/adopt`, `logs/chunk`, `admin-ops/claim`, `admin-ops/{opId}/ack`) reject a request with no Bearer token (**401** `agent authentication required`) and a Bearer token that matches no agent (**401** `invalid agent token`) (`middleware.go:68-94`). An **admin API key** does **not** satisfy `requireAgentAuth` (it isn't an agent token) → also 401.
- **Access:** REST.
- **Steps:**
  ```bash
  # No token → 401
  curl -s -o /dev/null -w "%{http_code}\n" -X POST $NP_API_URL/api/v1/agents/$AID/heartbeat              # 401
  # Admin key on an agent-only route → 401 (not an agent token)
  curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "Authorization: Bearer $NP_KEY" \
    -H 'Content-Type: application/json' -d '{}' $NP_API_URL/api/v1/agents/$AID/heartbeat                 # 401
  # Correct agent token, correct id, valid body → 200
  curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "Authorization: Bearer $ATOK" \
    -H 'Content-Type: application/json' -d '{}' $NP_API_URL/api/v1/agents/$AID/heartbeat                 # 200
  ```
- **Pass:** 401 / 401 / 200.
- **Coverage:** D.
- **Pitfalls:** `heartbeat` with an unknown `{id}` that *does* belong to a real agent's token but a different path id is 403, not 401 — order matters (auth passes, scope check fails). The empty `{}` heartbeat body is valid (all fields optional, `agents.go:373-401`).

### Method-not-allowed (405)
- **Must:** because routes are method-scoped (`server.go`), hitting an existing path with the wrong verb returns **405** (Go's `ServeMux` emits 405 with an `Allow` header when a path matches another method). E.g. `GET /api/v1/agents/{id}` is **not** registered (only `PUT`/`DELETE`/`GET .../status` are), so `GET /api/v1/agents/<id>` is a 405. Same for `POST /api/v1/health` etc.
- **Access:** REST.
- **Steps:**
  ```bash
  # GET on an id that only has PUT/DELETE → 405 (regression-guard from RELEASE-QA §1.2)
  curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $NP_KEY" $NP_API_URL/api/v1/agents/$AID   # 405
  # Wrong verb on health → 405
  curl -s -o /dev/null -w "%{http_code}\n" -X POST $NP_API_URL/api/v1/health                                  # 405
  # Inspect the Allow header
  curl -sI -H "Authorization: Bearer $NP_KEY" $NP_API_URL/api/v1/agents/$AID | grep -i allow
  ```
- **Pass:** 405 with an `Allow:` header listing the registered methods for that path.
- **Coverage:** D.
- **Pitfalls:** 405 vs 404 confusion — a *typo'd* path (e.g. `/api/v1/agent/$AID`) is a 404; a *valid path, wrong verb* is a 405. RELEASE-QA §1.2 explicitly calls out `GET /agents/{id}` → 405 as a guard.

### 400 on bad / empty / missing-required bodies
- **Must:** every handler that reads a body calls `readJSON`, which returns `invalid JSON: ...` on a malformed/empty body → handlers map that to **400** (`helpers.go:19-29`). Handlers also 400 on missing required fields with their own message, e.g. adopt with no body, provider create with no `config`, zone create with no `provider_id`/`name`, server create with no `name`/`address`, domain create with bad/zero `port` (1–65535) or invalid subdomain.
- **Access:** REST.
- **Steps:**
  ```bash
  # Empty adopt body → 400 (readJSON: invalid JSON). Note: adopt requires the agent be 'pending'.
  curl -s -X PUT -H "Authorization: Bearer $NP_KEY" -H 'Content-Type: application/json' \
    --data '' $NP_API_URL/api/v1/agents/$AID/adopt | jq .                       # {"error":"invalid JSON: EOF"} (400)
  # Provider create missing config → 400
  curl -s -X POST -H "Authorization: Bearer $NP_KEY" -H 'Content-Type: application/json' \
    -d '{"type":"cloudflare","name":"cf"}' $NP_API_URL/api/v1/providers | jq .  # {"error":"config is required"}
  # Zone create missing name → 400
  curl -s -X POST -H "Authorization: Bearer $NP_KEY" -H 'Content-Type: application/json' \
    -d '{"provider_id":"x"}' $NP_API_URL/api/v1/zones | jq .                     # {"error":"provider_id and name are required"}
  # Domain create bad port → 400
  curl -s -X POST -H "Authorization: Bearer $NP_KEY" -H 'Content-Type: application/json' \
    -d '{"subdomain":"a","zone_id":"z","server_id":"s","port":0}' $NP_API_URL/api/v1/domains | jq .  # port message
  # Malformed JSON anywhere → 400
  curl -s -X POST -H "Authorization: Bearer $NP_KEY" -d '{not json' $NP_API_URL/api/v1/providers | jq .
  ```
- **Pass:** each returns HTTP 400 with a JSON `{"error": "..."}` matching the messages above.
- **Coverage:** D.
- **Pitfalls:** field-validation order matters — `adopt` first checks the agent exists (404) and is `pending` (400 `agent is not in pending state`) *before* it reads the body, so testing the empty-body 400 needs a genuinely pending agent (a freshly registered one). Domain create validates `subdomain` syntax (`dnsname.ValidateSubdomain`) and that the zone/server exist (those existence failures are **400**, not 404 — `domains.go:71-80`). Duplicate domain subdomain-in-zone is **409** (`domains.go:84-88`).

### CORS behaviour
- **Must:** `corsMiddleware` (`middleware.go:104-117`) sets on **every** response: `Access-Control-Allow-Origin: *`, `Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS`, `Access-Control-Allow-Headers: Content-Type, Authorization`. It deliberately does **not** set `Access-Control-Allow-Credentials` (a wildcard origin + credentials is rejected by browsers, and the dashboard is same-origin). An `OPTIONS` preflight short-circuits to **204 No Content** before reaching any handler.
- **Access:** REST (browser preflight).
- **Steps:**
  ```bash
  curl -si -X OPTIONS $NP_API_URL/api/v1/agents | head -20      # expect 204 + the three Access-Control-* headers
  curl -sI -H "Authorization: Bearer $NP_KEY" $NP_API_URL/api/v1/agents | grep -i access-control
  ```
- **Pass:** `OPTIONS` → `HTTP/.. 204`; `Access-Control-Allow-Origin: *` present; **no** `Access-Control-Allow-Credentials` header anywhere.
- **Coverage:** D.
- **Pitfalls:** the absence of `Allow-Credentials` is intentional (`middleware.go:97-103`) — do not "fix" it; a wildcard-origin + credentials combo is a regression the hardening pass removed. CORS applies to `/api/` only; `/mcp` is mounted separately and has no CORS middleware.

### Content-Type and error envelope
- **Must:** all `/api/v1` JSON responses set `Content-Type: application/json` (`helpers.go:12,33`). Success payloads are the resource/shape documented per handler; errors are uniformly `{"error":"<message>"}`. `204` responses (cancel admin-op) carry no body.
- **Access:** REST.
- **Steps:**
  ```bash
  curl -sI -H "Authorization: Bearer $NP_KEY" $NP_API_URL/api/v1/agents | grep -i content-type   # application/json
  curl -s $NP_API_URL/api/v1/agents | jq -r .error                                                # "authentication required"
  ```
- **Pass:** `Content-Type: application/json`; the unauthenticated call's body parses as `{"error":"authentication required"}`.
- **Coverage:** D.
- **Pitfalls:** the request side does **not** require a `Content-Type` header — `readJSON` decodes the body regardless. Sending JSON without `Content-Type: application/json` still works; the header is only enforced/relevant on responses. The SSE stream endpoint sets `text/event-stream`, not JSON (`agents_stream.go:45`).

### Pagination & filters
- **Must:**
  - **Audit log** (`system.go:37-67`): `?limit=` defaults to 50, clamped to `1..1000` (out-of-range/garbage falls back to default); `?offset=` defaults 0, must be `>= 0`; `?source=` optionally filters by `ui|api|mcp|agent|system`. Response: `{"entries":[...],"total":N,"limit":L,"offset":O,"source":S}`.
  - **Domains** (`domains.go:22-27`): `?agent_id=`, `?server_id=`, `?status=` filters (AND-combined).
  - **Artifacts** (`artifacts.go:23-38`): `?agent_id=`, `?domain_id=` (int), `?source=`, `?apply_state=`, `?drifted=` (`true`/`1`).
- **Access:** REST.
- **Steps:**
  ```bash
  curl -s -H "Authorization: Bearer $NP_KEY" "$NP_API_URL/api/v1/audit-log?limit=5&offset=0" | jq '{total,limit,offset,n:(.entries|length)}'
  curl -s -H "Authorization: Bearer $NP_KEY" "$NP_API_URL/api/v1/audit-log?limit=99999" | jq .limit   # clamps; >1000 keeps default 50
  curl -s -H "Authorization: Bearer $NP_KEY" "$NP_API_URL/api/v1/audit-log?source=dryrun" | jq '.entries[0].source'
  curl -s -H "Authorization: Bearer $NP_KEY" "$NP_API_URL/api/v1/domains?status=pending" | jq 'length'
  curl -s -H "Authorization: Bearer $NP_KEY" "$NP_API_URL/api/v1/artifacts?drifted=true" | jq 'length'
  ```
- **Pass:** `limit` reflects the clamped value (`limit=99999` → falls back to 50 since `>1000`); `total` is the unpaginated count; filters narrow the set. On a dry instance, simulated DNS/cert events are tagged `source=dryrun` (real events `system`).
- **Coverage:** D.
- **Pitfalls:** `limit=99999` does **not** become 1000 — values outside `1..1000` are *rejected* and the default (50) is used (`system.go:42-44`). Audit `source` accepts an empty string (returns all) and is echoed back in the response. `domain_id` must parse as an int or the filter is silently ignored (`artifacts.go:30-34`).

### Health endpoint contract
- **Must:** `GET /api/v1/health` returns `{"status":"ok","version":...,"checks":{"database":"ok"},"dry_run":B,"dns_dry_run":B,"acme_dry_run":B}` with **200** when the DB ping (3s timeout) succeeds, and **503** with `status:"degraded"` + `checks.database:"error: ..."` when it fails (`system.go:15-33`). `dry_run` is `dns_dry_run || acme_dry_run`.
- **Access:** REST (no auth). Used by load balancers / monitors.
- **Steps:**
  ```bash
  curl -s $NP_API_URL/api/v1/health | jq .
  curl -s -o /dev/null -w "%{http_code}\n" $NP_API_URL/api/v1/health
  ```
- **Pass:** 200 with `status:"ok"`. On a dry instance `dry_run`, `dns_dry_run`, `acme_dry_run` are all `true`.
- **Coverage:** D for the 200 path and the dry-run flags. The **503-on-DB-down** path is unit-tested (`health_test.go`); reproducing it live requires wedging the DB (R, rarely worth it for an RC).
- **Pitfalls:** RELEASE-QA §1.3 notes the 503 path is covered by a unit test — do not try to force it on prod. The dry-run flags are how the dashboard decides to show the "Dry-run mode" banner (#93).

### MCP endpoint (`/mcp`)
- **Must:** mounted at `/mcp` and `/mcp/` at the server root (`main.go:160-161`), **outside** the `/api/` mux. It is **off by default**: when the `mcp_enabled` setting is not `"true"`, every request returns **404** (`server.go:80-84`). When enabled: non-POST → **405** with `Allow: POST` (`server.go:85-89`); missing/wrong Bearer (compared against `admin_api_key`) → **401** with `WWW-Authenticate: Bearer` (`server.go:96-101`); 10 failed auths per IP in 15 min → **429** with `Retry-After` (`server.go:44,90-95`). Valid requests speak JSON-RPC 2.0: `initialize`, `ping`, `tools/list`, `tools/call` (`server.go:127-143`); 7 tools registered (`list_agents`, `get_agent_status`, `list_servers`, `list_domains`, `create_domain`, `update_domain`, `delete_domain` — `server.go:187-228`). Mutations are audited with `source=mcp`, `actor=mcp` (`server.go:466-472`). Request body capped at 1 MiB (`server.go:104`).
- **Access:** REST (JSON-RPC over POST). Enabled via `PUT /api/v1/settings/mcp_enabled` `{"value":"true"}`. Auth: the **admin API key** as a Bearer token (same key as REST).
- **Steps:**
  ```bash
  # Off by default → 404
  curl -s -o /dev/null -w "%{http_code}\n" -X POST $NP_API_URL/mcp                                   # 404
  # Enable it
  curl -s -X PUT -H "Authorization: Bearer $NP_KEY" -H 'Content-Type: application/json' \
    -d '{"value":"true"}' $NP_API_URL/api/v1/settings/mcp_enabled >/dev/null
  # Wrong method → 405
  curl -s -o /dev/null -w "%{http_code}\n" $NP_API_URL/mcp                                           # 405 (GET)
  # No auth → 401
  curl -s -o /dev/null -w "%{http_code}\n" -X POST $NP_API_URL/mcp                                   # 401
  # initialize → server info
  curl -s -X POST -H "Authorization: Bearer $NP_KEY" -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize"}' $NP_API_URL/mcp | jq .
  # tools/list → 7 tools
  curl -s -X POST -H "Authorization: Bearer $NP_KEY" -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' $NP_API_URL/mcp | jq '.result.tools | length'  # 7
  # Restore default afterward
  curl -s -X PUT -H "Authorization: Bearer $NP_KEY" -H 'Content-Type: application/json' \
    -d '{"value":"false"}' $NP_API_URL/api/v1/settings/mcp_enabled >/dev/null
  ```
- **Pass:** disabled → 404; enabled: GET → 405, no-auth POST → 401, `initialize` returns `protocolVersion:"2024-11-05"` + `serverInfo.name:"nurproxy"`, `tools/list` → 7 tools.
- **Coverage:** D.
- **Pitfalls:** MCP is unusable until an admin API key exists (`server.go:56-60`) — generating one is a prerequisite. A wrong tool name or bad arguments comes back as a tool **result with `isError:true`**, not a JSON-RPC error (`server.go:163-170`); only protocol-level problems (unknown method, bad params) are JSON-RPC errors. `notifications/*` get a bare 202 with no body (`server.go:122-125`). MCP has no CORS headers and is not under `/api/` — don't expect the REST middleware to apply.

## Acceptance checklist

**Dry (every RC):**
- [ ] Live route set equals the authoritative table (`grep` of `server.go` matches; 40 `/api/v1` routes).
- [ ] Public endpoints reachable with no auth (`health`, `auth/status`, `auth/*`, `agents/register`).
- [ ] `requireAuth`: no creds → 401; bogus bearer → 401; admin key → 200; session cookie → 200.
- [ ] Token separation: agent token authenticates `requireAuth`; agent token on a *different* agent's scoped route → 403; admin key on an agent-only route → 401.
- [ ] `requireAgentAuth`: no token → 401; unknown token → 401; correct token+id → 200.
- [ ] 405 on wrong verb (`GET /api/v1/agents/{id}`, `POST /api/v1/health`) with `Allow` header.
- [ ] 400 on empty/malformed body and on missing required fields (adopt empty body, provider no config, zone no name, domain bad port).
- [ ] CORS: `OPTIONS` → 204; `Access-Control-Allow-Origin: *`; **no** `Allow-Credentials`.
- [ ] Responses are `application/json`; error envelope is `{"error":...}`.
- [ ] Pagination/filters: audit `limit`/`offset`/`source` (clamp >1000 → default); domains `status`; artifacts `drifted`.
- [ ] `health` → 200 + `dry_run`/`dns_dry_run`/`acme_dry_run` flags on a dry instance.
- [ ] MCP: 404 when off; enable → GET 405, no-auth 401, `initialize` ok, `tools/list` = 7; restore `mcp_enabled=false`.
- [ ] API key generated for the test is revoked afterward (`DELETE /api/v1/api-key`).

**Real run (before final):**
- [ ] `health` → 503 when the DB is genuinely unreachable (normally left to the unit test; only if a real-DB-failure scenario is in scope).
- [ ] Tailscale ACL: the orchestrator API port (`:8080`, or your `-port`) is reachable from the intended clients — symptom of a blocked port is `HTTP 000` from curl (RELEASE-QA §misc).

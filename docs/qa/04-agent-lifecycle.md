# Agent Lifecycle (register → adopt → heartbeat → stream → ack)

> **Scope:** the agent control-plane protocol — how an agent bootstraps (register), is taken over (adopt/reject/update/delete), proves liveness (heartbeat + offline timeout), receives config (SSE stream), reports back (routes/ack, artifacts/adopt), and what it self-reports (proxy detection, capabilities, version skew); plus running many agents on one box.
> **Code:** `internal/agent/adoption/adoption.go`, `internal/agent/stream/stream.go`, `internal/agent/ddns/ddns.go`, `cmd/nurproxy-agent/main.go`, `internal/agent/config/config.go`, `internal/orchestrator/api/agents.go`, `internal/orchestrator/api/agents_stream.go`, `internal/orchestrator/api/artifacts.go`, `internal/orchestrator/api/artifacts_adopt.go`, `internal/orchestrator/api/version_status.go`, `internal/orchestrator/api/server.go`, `internal/orchestrator/reconciler/reconciler.go`.
> **Coverage legend:** D = coverable dry, R = needs a real run.

## Prerequisites
- Both binaries built: `make build-all` (produces `./nurproxy` and `./nurproxy-agent`).
- For the fast path, the dry stack up: `make dev-sandbox` (orchestrator + 1 dry agent, seeded zone + adopted agent). For multi-agent: `make dev-sandbox AGENTS=3`.
- To drive the REST API by hand you need a session/API auth context. The dev-sandbox launcher (`scripts/dev-sandbox.sh`) already authenticates; reuse its `api`/`BASE` pattern, or log into the dashboard. Agent-auth routes (`heartbeat`, `stream`, `routes/ack`, `artifacts/adopt`, `logs/chunk`) require the **agent's** bearer token, not the admin session.
- `jq` and `curl` for the manual API steps.
- Anything marked **R** additionally needs a real `caddy`/`nginx`/`apache` reachable and (for serving) `:80`/`:443`.

The agent token + agent ID are persisted in the agent's data dir (`token`, `agent-id` files, mode `0600`) — `internal/agent/adoption/adoption.go:222-261`. In dry-run with no explicit `-data-dir`, the dir relocates to a per-FQDN temp dir (`os.TempDir()/nurproxy-agent-dry-<sanitized-fqdn>`), so many dry agents coexist — `internal/agent/config/config.go:115-121,266-276`. (The `dev-sandbox` launcher instead passes an explicit `-data-dir` per agent, so it does not rely on this fallback.)

## Features covered
- [ ] **register** (no auth): full payload, required fields, duplicate-FQDN 409, re-register-of-adopted 409.
- [ ] **adopt** (`PUT …/adopt`): requires JSON body (empty → 400), only from `pending`, FQDN-override validation/conflict, zone assignment.
- [ ] **reject** (`PUT …/reject`): only from `pending`, deletes the agent row.
- [ ] **update** (`PUT …/{id}`): name/fqdn/zone_ids/dns_mode/ddns_interval, pointer-optional fields.
- [ ] **delete** (`DELETE …/{id}`).
- [ ] **status** (`GET …/{id}/status`): full self-report fields.
- [ ] **No `GET /agents/{id}`** → 405; list+filter is the only read-one path.
- [ ] **heartbeat** (`POST …/{id}/heartbeat`): every field, 30s interval, caller-ID guard, offline→online flip, audit transitions.
- [ ] **offline timeout** (`agent_offline_timeout`, default 90s, floor 15s).
- [ ] **SSE stream** (`GET …/{id}/stream`): dial-out, 20s keepalive, reconnect backoff (1s→×2→30s cap), 4 MiB line cap, initial route push, caller-ID guard.
- [ ] **routes/ack** (`POST …/{id}/routes/ack`): apply-ACK round-trip, per-host domain status convergence, ownership guard.
- [ ] **artifacts/adopt** (`POST …/{id}/artifacts/adopt`): existing-mode read-only config ingest.
- [ ] **proxy detection** (Phase-0, read-only) reported on register + every beat.
- [ ] **capabilities** matrix reported on register + every beat.
- [ ] **version-skew status** (`current`/`outdated`/`ahead`/`unknown`).
- [ ] **auto-reconcile** toggle (`PUT …/{id}/auto-reconcile`).
- [ ] **multi-agent** on one box (dry, per-FQDN temp data dir).
- [ ] Access surfaces: dashboard Agents page, CLI `nurproxy agent …`, REST, MCP `list_agents`/`get_agent_status`.

## Tests

### register (agent bootstrap, no auth)
- **Must:** an unadopted agent POSTs its identity + token and is created in `pending`. Re-registering an FQDN that already exists returns **409** and the agent keeps running via heartbeat. The token is stored **hashed** (`auth.HashToken`), never in plaintext.
- **Access:**
  - REST: `POST /api/v1/agents/register` — **no auth** (`internal/orchestrator/api/server.go:143`). Body (`internal/agent/adoption/adoption.go:36-52`, handler `internal/orchestrator/api/agents.go:52-62`):
    ```json
    {"id":"<uuid>","fqdn":"edge1.example.com","token":"<agent-token>",
     "api_url":"http://<ip>:8780","public_ip":"1.2.3.4","public_ip6":"",
     "version":"v0.3.0","proxy_detection":{...},"proxy_capabilities":{...}}
    ```
    Required: `id`, `fqdn`, `token` (else 400 — `agents.go:68-71`). `public_ip6`, `proxy_detection`, `proxy_capabilities` are `omitempty`.
  - Agent: happens automatically on `nurproxy-agent` startup via `mgr.Register(ctx)` (`cmd/nurproxy-agent/main.go:184-187`). A register failure is **non-fatal** — the agent logs it and proceeds to wait for adoption / retry.
- **Prerequisites:** orchestrator up.
- **Steps (dry):**
  ```bash
  make dev-sandbox            # starts + registers + adopts a dry agent for you
  # then inspect the registered agent:
  curl -s $BASE/api/v1/agents | jq '.[].fqdn,.[].status'
  ```
  Manual re-register-409 check (using the sandbox `api` helper or a session):
  ```bash
  # re-POST register with an FQDN that already exists → 409
  curl -s -o /dev/null -w "%{http_code}\n" -X POST $BASE/api/v1/agents/register \
    -H 'Content-Type: application/json' \
    -d '{"id":"dup-1","fqdn":"edge1.example.com","token":"x"}'
  ```
- **Pass:** fresh register → **201** `{"id":...,"status":"pending"}` (`agents.go:118-121`). Duplicate FQDN → **409** `agent with this FQDN already registered` (`agents.go:74-77`). Missing required field → **400**. Audit log shows a `register` event with `source=agent` (`agents.go:116`).
- **Coverage:** D.
- **Pitfalls:**
  - A restarted **already-adopted** agent re-registers and gets **409** — this is **expected, not an error**; it keeps serving via heartbeat (RELEASE-QA §2.1). The agent log line `Registration failed (orchestrator may be unavailable)` on a 409 is benign.
  - Duplicate detection is by **FQDN**, not ID: the `GetAgentByFQDN` check fires before the insert (`agents.go:74`). The DB `UNIQUE` constraint is a second 409 net (`agents.go:108-110`).
  - On register the orchestrator assumes `caddy_running=true` so a brand-new agent doesn't surface a spurious "Caddy down" until its first heartbeat (`agents.go:92-94`).
  - **UNVERIFIED:** RELEASE-QA §`Security battery` mentions a per-IP register rate limit (~10 → 429). The current code has **no** register limiter — `POST /api/v1/agents/register` is registered with **no** middleware (`server.go:143`); only a login limiter exists (`ratelimit.New(5, 15*time.Minute, 15*time.Minute)`, `server.go:92`). Treat a register 429 as a regression/feature-add to re-verify against code, not a guaranteed behaviour.

### adopt
- **Must:** an operator takes over a `pending` agent, optionally renaming it, overriding the anchor FQDN, assigning DNS zones, and setting DNS mode / DDNS interval. Status becomes `adopted`. Adopt **requires a JSON body**.
- **Access:**
  - Dashboard: Agents page → a pending agent's **Adopt** action (name, FQDN, zones, DNS mode, DDNS interval fields).
  - REST: `PUT /api/v1/agents/{id}/adopt` (admin auth). Body (`agents.go:139-145`): `{"name":"edge1","fqdn":"edge1.example.com","zone_ids":["<zoneID>"],"dns_mode":"static","ddns_interval":300}` — all optional, but the **body itself is required**.
  - CLI: `nurproxy agent adopt <id> [--name] [--fqdn] [--zones a,b] [--dns-mode] [--ddns-interval]` (`cmd/nurproxy/cli_commands.go:179-204`).
- **Prerequisites:** a `pending` agent exists; a zone ID if assigning zones.
- **Steps (dry):**
  ```bash
  ID=$(curl -s $BASE/api/v1/agents | jq -r '.[]|select(.status=="pending").id' | head -1)
  # empty body → 400 (regression guard):
  curl -s -o /dev/null -w "%{http_code}\n" -X PUT $BASE/api/v1/agents/$ID/adopt
  # valid adopt:
  ./nurproxy agent adopt $ID --name edge1 --zones $ZONE_ID --dns-mode static
  ```
- **Pass:** valid adopt → **200**, agent JSON with `"status":"adopted"`. Empty/no body → **400** (`readJSON` fails). Adopting a non-pending agent → **400** `agent is not in pending state` (`agents.go:134-137`). FQDN override that collides with another agent → **409** (`agents.go:324-326`); syntactically invalid FQDN → **400** (`agents.go:321-323`). Audit shows `adopt`.
- **Coverage:** D.
- **Pitfalls:**
  - **Adopt requires a JSON body — empty body → 400** (RELEASE-QA §2.1). The sandbox launcher always sends at least `{"name":...,"zone_ids":[...]}` (`scripts/dev-sandbox.sh:114`).
  - Overriding the FQDN clears the stored `DNSRecordID` and `DNSError` so the reconciler recreates the A record at the new anchor (`agents.go:316-330`). Expect a fresh `dns_created` afterward.
  - Adopt only flips `pending → adopted`. A heartbeat can flip `offline → adopted` but **never** `pending → adopted` (operator owns adoption — `agents.go:451-460`).

### reject
- **Must:** declining a `pending` agent deletes its row entirely (it can re-register later).
- **Access:** Dashboard Agents page **Reject**; REST `PUT /api/v1/agents/{id}/reject`; CLI `nurproxy agent reject <id>` (`cli_commands.go:233-240`).
- **Steps (dry):** `./nurproxy agent reject <pending-id>`
- **Pass:** **200** `{"message":"agent rejected"}`; the agent disappears from `GET /agents`. Rejecting a non-pending agent → **400** `agent is not in pending state` (`agents.go:193-196`). Audit shows `reject`.
- **Coverage:** D.
- **Pitfalls:** reject = delete (`s.db.DeleteAgent`, `agents.go:198`). A still-running rejected agent will re-register on its next attempt and reappear as `pending`.

### update
- **Must:** an adopted agent's name, anchor FQDN, zones, DNS mode and DDNS interval can be edited without re-adopting.
- **Access:** Dashboard Agents page **Edit**; REST `PUT /api/v1/agents/{id}` (note: **PUT on the bare ID**, distinct from `/adopt`); CLI `nurproxy agent update <id> [--name] [--fqdn] [--zones] [--dns-mode] [--ddns-interval]` (`cli_commands.go:206-231`).
- **Steps (dry):** `./nurproxy agent update <id> --name renamed-edge`
- **Pass:** **200** with updated agent JSON; the change is visible in `GET /agents`. Audit shows `update`.
- **Coverage:** D.
- **Pitfalls:** update fields are **pointers** (`*string`/`*[]string`/`*int`, `agents.go:218-224`) so an omitted field is untouched, but `zone_ids` present-as-`[]` **replaces** zones with empty. FQDN validation/conflict is identical to adopt.

### delete
- **Must:** removing an agent removes its row.
- **Access:** Dashboard Agents page **Delete**; REST `DELETE /api/v1/agents/{id}`; CLI `nurproxy agent delete <id>` (`cli_commands.go:242-249`).
- **Pass:** **200** `{"message":"agent deleted"}`; missing agent → **404** (`agents.go:264-275`).
- **Coverage:** D.
- **Pitfalls:** deleting an agent that still owns servers/domains can orphan their managed DNS records — see the known **server-delete DNS leak** (MEMORY: bug-server-delete-dns-leak); RELEASE-QA §2.4 notes deleting a server/agent/zone that still has domains is refused in newer code. Re-verify the refusal vs. cascade for the RC under test.

### status (single-agent self-report)
- **Must:** returns the agent's live status, last_seen, IPs, version + skew verdict, caddy_running, proxy mode, last_error, and the full proxy detection/capabilities/permissions blocks.
- **Access:** REST `GET /api/v1/agents/{id}/status` (admin auth); CLI `nurproxy agent status <id>` (`cli_commands.go:170-177`); MCP `get_agent_status` (`{"agent_id":"..."}`). The agent itself also polls this endpoint **every 5s** (with its bearer token) while waiting for adoption, returning as soon as `status != "pending"` (`adoption.go:170-220`, ticker `:172`).
- **Steps (dry):** `./nurproxy agent status <id>` or `curl -s $BASE/api/v1/agents/<id>/status | jq`
- **Pass:** **200** JSON with keys `id,status,last_seen,public_ip,version,version_status,caddy_running,proxy_mode,last_error,proxy_detection,proxy_detected_at,proxy_capabilities,proxy_permissions` (`agents.go:287-301`). Unknown id → **404**.
- **Coverage:** D.
- **Pitfalls:** `version_status` is computed live against the orchestrator's own version (see version-skew test). `proxy_permissions` is **nil in built-in mode** by design (only existing-mode agents self-test reload/write — `cmd/nurproxy-agent/main.go:428-438,489-491`).

### No `GET /agents/{id}` (405) — list + filter
- **Must:** there is **no read-one route** for `GET /api/v1/agents/{id}`; consumers list and filter.
- **Access:** REST `GET /api/v1/agents` (admin auth, `server.go:161`); CLI `nurproxy agent list` (`cli_commands.go:154-168`); MCP `list_agents` (`{}`).
- **Steps (dry):**
  ```bash
  curl -s -o /dev/null -w "%{http_code}\n" $BASE/api/v1/agents/<id>   # expect 405
  ./nurproxy agent list                                               # table: ID NAME FQDN STATUS VERSION PROXY
  ```
- **Pass:** `GET /api/v1/agents/{id}` → **405** (only `PUT`/`DELETE` are registered on `/{id}`, so Go's `ServeMux` returns Method Not Allowed). `GET /api/v1/agents` returns the array, each entry carrying its `zones` and computed `version_status` (`agents.go:27-46`).
- **Coverage:** D.
- **Pitfalls:** **There is no `GET /agents/{id}`** (RELEASE-QA §2.1) — reaching for it is the classic mistake; use the list (or `/status` for one agent). `list_agents` / `GET /agents` must **not** leak the token hash (regression-guarded in `internal/orchestrator/mcp/server_test.go:264-265`).

### heartbeat
- **Must:** the agent POSTs a full self-report every **30s**; the orchestrator refreshes `last_seen`/IPs/health, persists detection/capabilities/permissions, flips an `offline` agent back to `adopted`, audits real transitions, and reconciles artifact-checksum drift. An agent may only heartbeat **for itself**.
- **Access:**
  - REST: `POST /api/v1/agents/{id}/heartbeat` — **agent auth** (`server.go:168`). Body (`internal/agent/ddns/ddns.go:39-70`, handler `agents.go:373-401`):
    ```json
    {"agent_id":"...","public_ip":"1.2.3.4","public_ip6":"2001:db8::1",
     "version":"v0.3.0","caddy_running":true,"last_error":"",
     "proxy_mode":"built-in","proxy_detection":{...},"proxy_capabilities":{...},
     "proxy_permissions":{...},"artifact_checksums":[{"artifact_id":"dom-1","checksum":"...","content":"..."}]}
    ```
    `omitempty` on the wire: `public_ip6`, `proxy_mode`, `proxy_detection`, `proxy_capabilities`, `proxy_permissions`, `artifact_checksums`. `caddy_running` is a **pointer** on the orchestrator side so an older agent omitting it is not read as "down" (`agents.go:379,414-417`).
  - Agent: automatic — `ddns.New(... heartbeatInterval ...)` started in `cmd/nurproxy-agent/main.go:411-442`; `heartbeatInterval = 30 * time.Second` (`main.go:39`). First beat fires **immediately** then on the ticker (`ddns.go:136-150`).
- **Prerequisites:** an adopted, running agent (dry is fine).
- **Steps (dry):**
  ```bash
  make dev-sandbox
  # watch the orchestrator log for recurring "heartbeat 200" and the agent log for "Heartbeat sent (IP: ...)"
  tail -f /tmp/nurproxy-sandbox*/orch.log   # path printed by dev-sandbox; or the WORKDIR it reports
  # confirm fields land:
  curl -s $BASE/api/v1/agents/<id>/status | jq '{last_seen,version,caddy_running,proxy_mode,public_ip}'
  ```
- **Pass:** `last_seen` advances roughly every 30s; `public_ip`/`version`/`caddy_running`/`proxy_mode` reflect the agent. A heartbeat from agent A targeting agent B's ID → **403** `agent can only heartbeat for itself` (`agents.go:367-371`). Health-state changes are audited: `caddy_state` on a caddy up/down flip (`agents.go:463-465`), `proxy_mode` on a live mode switch (`agents.go:475-477`), `status_change` "came back online (heartbeat)" on an offline→adopted flip (`agents.go:454-460`).
- **Coverage:** D.
- **Pitfalls:**
  - The 30s interval is deliberately well under the **90s** offline timeout so one missed beat never flaps the agent (`main.go:36-39`).
  - A recurring agent **error** (e.g. existing-mode reload-permission denial re-probed each beat) is **not** audited — it is live telemetry surfaced via `last_error`/`proxy_permissions`, to avoid spamming the timeline (`agents.go:466-471`). Don't expect an `agent_error` audit line.
  - A blank `public_ip`/`public_ip6` in a beat means "keep the last known value", not "clear it" (`ddns.go:167-182`); a failed IP lookup must not skip the beat.
  - IPv6/AAAA caveat: IPv6 is best-effort; v6-less hosts simply omit `public_ip6` (MEMORY: v030-rc-prod-soak AAAA caveat).
  - `artifact_checksums` drives §11 drift detection; a divergence is audited as `config_artifact … drifted` / `drift_resolved` only on a genuine transition, not every beat (`agents.go:514-537`).

### offline timeout
- **Must:** an agent that misses heartbeats past `agent_offline_timeout` is marked offline by the reconciler; the next beat (or stream connect) brings it back.
- **Access:** setting `agent_offline_timeout` (seconds). Default seeded value **90** (`internal/orchestrator/db/migrations.go:241`); reconciler reads it, clamped to a **15s floor** (`internal/orchestrator/reconciler/reconciler.go:399-412`). Default in the absence of the setting is also 90s.
- **Steps (dry):**
  ```bash
  make dev-sandbox
  # kill one agent process (find its PID from the sandbox WORKDIR / printed PIDs) and wait > 90s
  curl -s $BASE/api/v1/agents | jq '.[]|{fqdn,status,last_seen}'   # expect status "offline"
  # restart that agent (or rely on a survivor) → next heartbeat flips it back to "adopted"
  ```
- **Pass:** a silent agent transitions to `offline` after >90s (or the configured value, floored at 15s); a resumed heartbeat/stream-connect flips it back to `adopted` with a `status_change` audit (`agents.go:454-460`, `agents_stream.go:104-118`).
- **Coverage:** D.
- **Pitfalls:** the **open stream's keepalive also refreshes `last_seen` every 20s** (`agents_stream.go:18-20,83-89`), so a connected-but-quiet agent never drifts offline even without POST beats. To force an offline you must stop the agent process (both beats and stream), not just pause traffic.

### SSE stream (dial-out push)
- **Must:** the agent dials **out** and holds open a Server-Sent-Events connection; the orchestrator pushes the desired intent set down it (so it works behind NAT). On connect the orchestrator immediately pushes current routes, refreshes `last_seen`, and brings an offline agent online. The agent reconnects with exponential backoff. Only the agent itself may open its stream.
- **Access:**
  - REST: `GET /api/v1/agents/{id}/stream` — **agent auth**, `Accept: text/event-stream` (`server.go:171`, handler `agents_stream.go:29-92`).
  - Agent: automatic — `stream.New(...).Run(ctx)` in a goroutine (`cmd/nurproxy-agent/main.go:388-445`).
  - Event types the agent handles: `routes` (intent set → render+apply+ack), `ping` (liveness no-op), `log_tail` / `log_tail_stop` (§15 on-demand tail); unknown events are ignored (`stream.go:262-289`).
- **Prerequisites:** adopted agent; orchestrator streaming enabled (the hub must be wired — else **503** `streaming not enabled`, `agents_stream.go:35-38`).
- **Steps (dry):**
  ```bash
  make dev-sandbox
  # agent log shows "Stream: connected to orchestrator" and "Stream: applied N/M intents"
  grep -E "Stream: (connected|applied)" <WORKDIR>/agent1.log
  ```
  Caller-ID guard:
  ```bash
  # open agent-2's stream with agent-1's token → 403 (see agents_stream_test.go:273-274)
  ```
- **Pass:** agent connects; the orchestrator log emits the initial route push; the agent applies intents and ACKs. Server emits SSE wire frames `event: <type>\ndata: <json>\n\n` (`agents_stream.go:95-101`) and a `: keepalive` comment every **20s** (`streamKeepalive = 20 * time.Second`, `agents_stream.go:20,83-89`). A stream opened for someone else's ID → **403** `agent can only stream for itself` (`agents_stream.go:31-34`).
- **Coverage:** D (push/render/ack convergence). Real serving is R.
- **Pitfalls:**
  - Reconnect backoff starts at **1s**, doubles, caps at **30s** (`maxBackoff = 30 * time.Second`, `stream.go:30-31,192-212`); a clean server-side close resets it to 1s.
  - A single SSE data line is capped at **4 MiB** (`maxLine = 4 << 20`, `stream.go:32-33,235-236`) — a route snapshot larger than 4 MiB would break the scan. Watch this if a single agent has an enormous route set.
  - A brief stream blip does **not** force the agent offline — disconnect handling deliberately leaves status to the POST heartbeat + staleness sweeper to avoid flapping (`agents_stream.go:72-76`).
  - RELEASE-QA §6 reconnect note: on orchestrator restart you may see a per-agent `context deadline exceeded` when it can't reach the agent at its advertised `api_url` — expected for NAT'd agents; the dial-out stream is what actually carries config.

### routes/ack (apply-ACK round-trip)
- **Must:** after applying a pushed intent set the agent POSTs an atomic ACK carrying each rendered artifact (content + checksum) and per-host errors; the orchestrator round-trips rendered content into the central versioned store and converges each domain's status. ACK is also a sign of life. An agent may only ACK for itself.
- **Access:** REST `POST /api/v1/agents/{id}/routes/ack` — **agent auth** (`server.go:172`, handler `agents_stream.go:130-194`). Body is `proxymodel.ApplyAck{Reports:[...]}` produced by the agent (`stream.go:663-684`). Driven automatically by the stream's `applyIntents` (`stream.go:395-592`).
- **Steps (dry):**
  ```bash
  make dev-sandbox            # seeds a central-TLS domain; the agent applies + acks it
  curl -s "$BASE/api/v1/domains" | jq '.[]|{fqdn,status}'   # expect "active" after convergence
  ```
- **Pass:** a successfully-applied host marks its domain `active`/applied (`agents_stream.go:186-190`); a per-host error sets the domain to `error` with the message (`agents_stream.go:180-185`). The store gains a `config_artifact` version (audited `apply`/`apply_failed`). Dropped backend options are audited `option_dropped` only on first-store/content-change (`agents_stream.go:229-231,289-294`). ACK for another agent's ID → **403** (`agents_stream.go:132-134`).
- **Coverage:** D (the dry agent renders real `caddygen` artifacts — identical to prod built-in Caddy).
- **Pitfalls:**
  - **Ownership guard:** an agent may only write its **own** artifacts; a cross-agent artifact-ID write is refused and logged (`agents_stream.go:216-219`) — a regression guard for multi-agent.
  - A semantic-equal re-ACK (re-serialized identical content) does **not** bump the version or audit (`agents_stream.go:275-279`) — don't expect noise on idempotent re-applies.
  - `apply_failed` flags the stored artifact but writes **no** new live version (the content never went live, `agents_stream.go:235-243`).

### artifacts/adopt (existing-mode read-only ingest)
- **Must:** an **existing-mode** agent reports the host config files it can READ off disk into the central store, independent of the apply path — so a limited-permission agent (can't reload) still surfaces its config under Config.
- **Access:** REST `POST /api/v1/agents/{id}/artifacts/adopt` — **agent auth** (`server.go:175`, handler `internal/orchestrator/api/artifacts_adopt.go:25-55`). Agent side: one-shot at startup in existing mode via `streamClient.ReportAdopted(...)` (`cmd/nurproxy-agent/main.go:399-407`).
- **Steps (R):** start an agent with `-proxy-mode existing -proxy-type nginx` against a host with readable nginx configs; check the agent log `Reported N existing config artifact(s) to the central store` and the dashboard Config view.
- **Pass:** **200** `{"received":N,"created":C,"updated":U}` (`artifacts_adopt.go:52-56`); the host's `nurproxy-*` (and adopted) configs appear under Config. A report for another agent's ID → **403** `agent can only report for itself` (`artifacts_adopt.go:27-30`). Operator-authored files store `Source: manual` (never auto-overwritten); generated files store `Source: generated`.
- **Coverage:** R (existing-mode requires a real nginx/apache; built-in Caddy reports config through the normal apply path instead). Note the dry agent runs built-in by default so this path is **not** exercised dry.
- **Pitfalls:** existing-mode is gated by `cfg.ProxyMode == existing` (`main.go:206,399`); built-in agents skip this entirely. RELEASE-QA §2.5a: the agent only manages the `nurproxy-` prefix — a hand-written non-prefixed vhost is read/adopted but never owned/pruned.

### proxy detection (Phase-0, read-only)
- **Must:** the agent runs a read-only probe of which proxy is installed (kind/version/config dir) and which process holds `:80`/`:443`, reporting it on **register** and **every heartbeat**. It mutates nothing.
- **Access:** carried in register (`proxy_detection`, `adoption.go:139,47`) and heartbeat (`proxy_detection`, `ddns.go:56,189-192`; refreshed via `hb.SetDetectionFn(... detectProxy ...)`, `main.go:414`). Stored on the agent row; surfaced in `GET …/status` as `proxy_detection` + `proxy_detected_at`.
- **Steps (dry):** `curl -s $BASE/api/v1/agents/<id>/status | jq '{proxy_detection,proxy_detected_at}'`
- **Pass:** `proxy_detection` is populated (installed/kind/version/config_dir/port_conflicts) and refreshes over beats; the orchestrator stores it via a **narrow update** that doesn't clobber the health self-report (`agents.go:424-431`). The agent log shows `Proxy detection: installed=… kind=… version=… config_dir=…` at startup (`main.go:147-154`).
- **Coverage:** D (detection runs in dry too; values reflect whatever is on the dev host).
- **Pitfalls:** a `nil` detection in a beat leaves the stored copy as-is — a transient probe failure must not erase a known-good value (`agents.go:427`, `main.go:474-481`). Detection is read-only and never touches the running Caddy path (§13.0).

### capabilities matrix
- **Must:** the agent reports its selected backend's capability matrix (e.g. `rate_limit`, `central_tls`, module-probed options) on register and every beat, so the orchestrator/dashboard know what the agent can honor.
- **Access:** register `proxy_capabilities` (`adoption.go:140,51`); heartbeat `proxy_capabilities` (`ddns.go:60,194-197`; `hb.SetCapabilitiesFn`, `main.go:418`). For built-in Caddy this probes the binary's module list (works before the Caddy subprocess starts — `main.go:160-166,528-536`). Surfaced in `GET …/status` as `proxy_capabilities`.
- **Steps (dry):** `curl -s $BASE/api/v1/agents/<id>/status | jq '.proxy_capabilities'`
- **Pass:** `proxy_capabilities` is populated and matches what `Render` emits; module changes (e.g. installing caddy-ratelimit later) propagate on a subsequent beat (`main.go:416-418`). Agent log: `Proxy capabilities: rate_limit=… central_tls=…` (`main.go:162-165`).
- **Coverage:** D.
- **Pitfalls:** a `nil` capabilities report in a beat leaves the stored matrix untouched, so a transient probe failure doesn't erase a known-good matrix (`agents.go:436-440`).

### version-skew status
- **Must:** each agent is classified against the orchestrator's own version as `current` / `outdated` / `ahead` / `unknown`.
- **Access:** computed on `GET /api/v1/agents` (each entry's `version_status`, `agents.go:40`) and `GET …/status` (`agents.go:293`). Logic in `internal/orchestrator/api/version_status.go:8-46`.
- **Steps (dry):** `curl -s $BASE/api/v1/agents | jq '.[]|{version,version_status}'`
- **Pass / exact rules** (`version_status.go`):
  - empty agent OR empty orchestrator version → `unknown` (`:27-29`).
  - exact string match → `current` (`:30-32`).
  - both parse as semver `vX.Y.Z`/`X.Y.Z` (pre-release/build suffix dropped, `:50-72`): `<` → `outdated`, `>` → `ahead`, `=` → `current` (`:38-45`).
  - either side not three numeric components (e.g. `dev`, a git hash) → `unknown` (`:35-37`).
- **Coverage:** D.
- **Pitfalls:** a `dev` build (the default `version = "dev"`, `cmd/nurproxy-agent/main.go:34`) yields **`unknown`**, not a misleading verdict (RELEASE-QA §5 version-skew). To see `outdated`/`ahead` you need two real semver builds.

### auto-reconcile config toggle
- **Must:** an opt-in per-agent policy controls whether drifted config is auto-reconciled (§11).
- **Access:** Dashboard Agents page **auto-reconcile** toggle; REST `PUT /api/v1/agents/{id}/auto-reconcile` body `{"enabled":true|false}` (admin auth, `server.go:166`, handler `internal/orchestrator/api/artifacts.go:243-262`). No dedicated CLI subcommand.
- **Steps (dry):**
  ```bash
  curl -s -X PUT $BASE/api/v1/agents/<id>/auto-reconcile -H 'Content-Type: application/json' -d '{"enabled":true}'
  ```
- **Pass:** **200** `{"enabled":true}`; audit `auto_reconcile_config enabled=true` (`artifacts.go:260`). Unknown agent → **404**; malformed body → **400**.
- **Coverage:** D.
- **Pitfalls:** this only sets the **policy**; the actual heal is heartbeat-checksum-driven (RELEASE-QA §3.7: drift healing is heartbeat-driven, ~30–60s, not instant).

### multi-agent on one box (dry)
- **Must:** several dry agents run simultaneously on one host without port or data-dir collisions, each registering/adopting/heartbeating independently.
- **Access:** `make dev-sandbox AGENTS=3` (CLAUDE.md), or by hand multiple `nurproxy-agent -dry-run -fqdn edgeN.example.com -api-port 878N` processes.
- **Steps (dry):**
  ```bash
  make dev-sandbox AGENTS=3
  curl -s $BASE/api/v1/agents | jq -r '.[]|"\(.fqdn) \(.status)"'   # 3 agents, all adopted
  ```
- **Pass:** all `AGENTS` agents reach `adopted`/active; the launcher prints `Domains active : N/N` (`scripts/dev-sandbox.sh:139`). Each agent gets a distinct API port (`apiport=$((8780 + n))`, `:99`), its own explicit data dir (`-data-dir "$WORKDIR/agent${n}"`, `:100,103`) and a unique subdomain (`edge${n}` / `app${n}`, `:98,118-119`).
- **Coverage:** D.
- **Pitfalls:** in the **launcher**, isolation comes from the explicit `-data-dir` per agent (`scripts/dev-sandbox.sh:100,103`) plus distinct `-api-port`. The **per-FQDN temp data dir** fallback (`os.TempDir()/nurproxy-agent-dry-<sanitized-fqdn>`, `internal/agent/config/config.go:115-121,266-276`) only kicks in when you run an agent dry **by hand with no `-data-dir`** — then the FQDN is folded into the temp dir name. Two such hand-run dry agents with the **same** FQDN and no explicit data dir would collide on `token`/`agent-id`; always vary `-fqdn`. API ports must also differ (`-api-port`) or the second agent's local API bind fails (non-fatal but reported via health).

## Acceptance checklist

**Dry (every RC):**
- [ ] Fresh `register` → 201 `pending`; missing id/fqdn/token → 400.
- [ ] Re-register of an existing FQDN → 409 (and a restarted adopted agent logging 409 is expected).
- [ ] `adopt` with empty body → 400; valid adopt → 200 `adopted`; non-pending adopt → 400.
- [ ] FQDN-override conflict → 409, invalid FQDN → 400.
- [ ] `reject` from pending → 200 + row gone; from non-pending → 400.
- [ ] `update` (name/zones/dns_mode/ddns) → 200; pointer-optional fields untouched when omitted.
- [ ] `delete` → 200; missing → 404.
- [ ] `GET /agents/{id}` → 405 (use list / `/status`).
- [ ] `status` returns all self-report fields; unknown id → 404.
- [ ] Heartbeats recur ~30s; `last_seen`/IP/version/proxy_mode update; cross-ID beat → 403.
- [ ] Offline timeout: stopped agent → `offline` after >90s; restart → back to `adopted` (status_change audit).
- [ ] Stream: connects (dial-out), 20s keepalive, initial route push, cross-ID stream → 403; backoff caps at 30s.
- [ ] routes/ack: domain converges to `active`; per-host error → `error`; cross-agent artifact write refused.
- [ ] Proxy detection + capabilities populated on status and refresh over beats.
- [ ] version_status: `dev` builds → `unknown`; exact match → `current`.
- [ ] auto-reconcile toggle → 200 + audit.
- [ ] Multi-agent: `make dev-sandbox AGENTS=3` → 3 agents adopted, distinct ports/data dirs.
- [ ] `list_agents` / `get_agent_status` MCP tools work and do not leak token hash.

**Real run (before final):**
- [ ] artifacts/adopt: an existing-mode (nginx/apache) agent reports readable host config into the central store (200 `received/created/updated`), even without reload permission.
- [ ] version_status: a genuinely older agent against a newer orchestrator shows `outdated` (and vice-versa `ahead`).
- [ ] Stream survives an orchestrator restart: agents reconnect, re-adopt artifacts, resume heartbeats/acks, no traffic interruption.
- [ ] Real serving on `:443` after a routes/ack convergence (built-in Caddy and/or existing nginx).

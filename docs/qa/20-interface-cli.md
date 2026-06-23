# Interface: Management CLI

> **Scope:** the `nurproxy` management CLI as a test surface — every management
> subcommand (provider / zone / agent / server / domain / apikey / auth), all
> their flags, the shared auth/output flags, and the `--json` output shape.
> **Code:** `cmd/nurproxy/cli_commands.go` (subcommands + flags), `cmd/nurproxy/cli.go`
> (client, auth resolution, `registerClientFlags`, table/JSON emit, error parsing),
> `cmd/nurproxy/main.go` (dispatch in `runCLI` at lines 30-50), `internal/shared/models/models.go`
> (enum values rendered in tables).
> **Coverage legend:** D = coverable dry, R = needs a real run.

The CLI is a thin REST client over the orchestrator's `/api/v1` surface
(`cmd/nurproxy/cli.go:16-26`). Everything here is fully coverable against a **dry
orchestrator** — no DNS, ACME, agent proxy, or root needed. The CLI itself makes
the same calls regardless of dry/real; only the orchestrator behind it differs.

## Prerequisites

- Binary built: `make build` (produces `./nurproxy`). `make build-all` also builds the agent.
- A **dry orchestrator** running on a throwaway data dir and port. Use a dedicated
  instance so brute-force/lockout side-effects and test entities never touch prod:
  ```bash
  NP_DRY_RUN=true ./nurproxy -port 18081 -data-dir /tmp/np-cli-qa
  ```
- For most subcommands you need credentials (admin API key or password). Bootstrap
  with `auth setup` + `apikey create` (see the `auth` and `apikey` tests below), or
  bring the whole seeded stack up with `make dev-sandbox` (its launcher
  `scripts/dev-sandbox.sh:84-88` runs `auth setup` then `apikey create` and exports
  `NP_API_URL` / `API_KEY` for you).
- Convenience for all examples below (point the CLI at the dry instance):
  ```bash
  export NP_API_URL=http://localhost:18081
  export NP_API_PASSWORD=sandbox123      # min 8 chars; used until a key exists
  ```

## Features covered

- [ ] Global auth/output flags: `-url`, `-key`, `-password`, `-json` and env fallbacks `NP_API_URL`, `NP_API_KEY`, `NP_API_PASSWORD`
- [ ] Auth resolution order (key → password→cookie) and the "no credentials" error
- [ ] `provider list`
- [ ] `provider add` (`--type`, `--name`, `--config`, `--config-file`)
- [ ] `provider delete <id>`
- [ ] `provider zones <id>`
- [ ] `zone list`
- [ ] `zone add` (`--provider`, `--name`, `--external-id`)
- [ ] `zone delete <id>`
- [ ] `agent list`
- [ ] `agent status <id>`
- [ ] `agent adopt <id>` (`--name`, `--fqdn`, `--zones`, `--dns-mode`, `--ddns-interval`)
- [ ] `agent update <id>` (same flags as adopt)
- [ ] `agent reject <id>`
- [ ] `agent delete <id>`
- [ ] `server list <agent-id>`
- [ ] `server add <agent-id>` (`--name`, `--address`, `--notes`)
- [ ] `server update <id>` (`--name`, `--address`, `--notes`)
- [ ] `server delete <id>`
- [ ] `domain list` (`--agent`, `--server`, `--status`)
- [ ] `domain add` (`--subdomain`, `--zone`, `--server`, `--port`, `--websocket`, `--force-https`, `--ssl-mode`, `--proxy-config-file`)
- [ ] `domain update <id>` (same flags; tri-state bool handling)
- [ ] `domain delete <id>`
- [ ] `apikey show`
- [ ] `apikey create`
- [ ] `apikey revoke`
- [ ] `auth setup`
- [ ] `auth status`
- [ ] `--json` output shape for every list/get command
- [ ] Usage/help text on unknown action; required-flag and missing-positional errors

## Tests

### Global flags & auth resolution

- **Must:** every subcommand accepts the four shared flags from
  `registerClientFlags` (`cmd/nurproxy/cli.go:64-70`): `-url` (default
  `NP_API_URL` else `http://localhost:8080`), `-key` (default `NP_API_KEY`),
  `-password` (default `NP_API_PASSWORD`), `-json` (default false). Auth resolves
  key-first: an API key sets `Authorization: Bearer <key>`; otherwise the password
  is exchanged once for a `nurproxy_session` cookie that is reused
  (`cli.go:85-118`, `122-160`). With neither, the command errors
  `no credentials: set NP_API_KEY (or --key), or NP_API_PASSWORD (or --password)`
  (`cli.go:90`).
- **Access:** this IS the access layer. Flags: `-url string`, `-key string`,
  `-password string`, `-json` (bool). Env vars: `NP_API_URL`, `NP_API_KEY`,
  `NP_API_PASSWORD`. Note Go's `flag` package accepts both single- and
  double-dash (`-json` and `--json` are equivalent).
- **Steps:**
  ```bash
  # No credentials at all → error
  env -u NP_API_KEY -u NP_API_PASSWORD ./nurproxy provider list -url http://localhost:18081
  # Password auth (no key yet)
  ./nurproxy provider list -url http://localhost:18081 -password sandbox123
  # Key auth (after apikey create below); flag overrides env
  ./nurproxy provider list -url http://localhost:18081 -key np_ak_xxxxx
  # Env-var auth
  NP_API_URL=http://localhost:18081 NP_API_KEY=np_ak_xxxxx ./nurproxy provider list
  ```
- **Pass:** the no-credentials run prints `error: no credentials: ...` to stderr
  and exits non-zero (`fatalf`, exit 1). Authed runs print a table (or JSON with
  `-json`). HTTP/API errors are surfaced as `error: <METHOD> <path>: <message>`
  where `<message>` is the API's `{"error":...}` text (`apiErrorBytes`, `cli.go:200-211`).
- **Coverage:** D
- **Pitfalls:** the `-url` value is right-trimmed of trailing `/` (`cli.go:74`).
  HTTP client timeout is 30s (`cli.go:78`) — a wedged orchestrator surfaces a Go
  net error, not an API error. Mixing `-key` and `-password`: the key wins (auth
  is short-circuited if `apiKey != ""`, `cli.go:86`).

### `provider list`

- **Must:** lists all configured DNS providers.
- **Access:** `nurproxy provider list` (no positional/flags beyond globals).
  REST: `GET /api/v1/providers`.
- **Steps:** `./nurproxy provider list` ; `./nurproxy provider list -json`
- **Pass:** table columns `ID  TYPE  NAME  DEFAULT` (`cli_commands.go:59`); DEFAULT
  is `yes`/`no` (`boolStr`). `-json` prints a 2-space-indented array of `models.Provider`.
- **Coverage:** D
- **Pitfalls:** empty list prints just the header row.

### `provider add`

- **Must:** creates a provider from a type, name, and a JSON config blob.
- **Access:** `nurproxy provider add --type <t> --name <n> (--config <json> | --config-file <path|->)`.
  REST: `POST /api/v1/providers` body `{"type","name","config":<raw JSON>}` (`cli_commands.go:73-75`).
- **Steps (dry — a dummy Cloudflare token validates in dry mode):**
  ```bash
  ./nurproxy provider add --type cloudflare --name cf-qa \
    --config '{"api_token":"dummy"}'
  # or from a file / stdin
  echo '{"api_token":"dummy"}' | ./nurproxy provider add --type cloudflare --name cf2 --config-file -
  ```
- **Pass:** prints `provider created: <id>` (the `id` field pulled via `gjson`,
  `cli_commands.go:79`). `-json` prints the raw create response. `--type` and
  `--name` are both required (`cli_commands.go:69` → `error: --type and --name are required`).
- **Coverage:** D
- **Pitfalls:** you must supply exactly one of `--config` / `--config-file`; with
  neither, `readConfigArg` fatals `provide --config or --config-file`
  (`cli_commands.go:634-643`). `--config-file -` reads stdin; `--config` inline
  wins if both are given (`cli_commands.go:634-639`). The config is passed through
  as raw JSON — malformed JSON is rejected by the API, not the CLI.

### `provider delete <id>`

- **Must:** deletes a provider by ID.
- **Access:** `nurproxy provider delete <id>`. REST: `DELETE /api/v1/providers/{id}`.
- **Steps:** `./nurproxy provider delete <provider-id>`
- **Pass:** prints `provider deleted: <id>`. Missing positional → `error: missing provider id`
  (`requireArg`, `cli_commands.go:32-37`).
- **Coverage:** D
- **Pitfalls:** deleting a provider that still backs zones may 409 from the API —
  surfaces as `error: DELETE /api/v1/providers/<id>: <message>`.

### `provider zones <id>`

- **Must:** lists the zones discoverable at the provider (live provider call; mocked in dry).
- **Access:** `nurproxy provider zones <id>`. REST: `GET /api/v1/providers/{id}/zones`.
- **Steps:** `./nurproxy provider zones <provider-id>` ; add `-json`
- **Pass:** table `ID  NAME  PROVIDER  EXTERNAL_ID` via `printZones`
  (`cli_commands.go:550-560`); EXTERNAL_ID empty renders as `-`. `-json` prints
  `[]models.Zone`.
- **Coverage:** D (provider list-zones is mocked in dry per CLAUDE.md).
- **Pitfalls:** positional ID required.

### `zone list`

- **Must:** lists all zones known to the orchestrator.
- **Access:** `nurproxy zone list`. REST: `GET /api/v1/zones`.
- **Steps:** `./nurproxy zone list` ; `-json`
- **Pass:** same `printZones` columns as above; `-json` → `[]models.Zone`.
- **Coverage:** D

### `zone add`

- **Must:** registers a zone under a provider.
- **Access:** `nurproxy zone add --provider <id> --name <fqdn> [--external-id <id>]`.
  REST: `POST /api/v1/zones` body `{"provider_id","name","external_id"}` (`cli_commands.go:127-129`).
- **Steps:** `./nurproxy zone add --provider <provider-id> --name example.com`
- **Pass:** `zone created: <id>`. `--provider` and `--name` required
  (`cli_commands.go:124` → `error: --provider and --name are required`).
- **Coverage:** D
- **Pitfalls:** `--external-id` is optional; an empty value is still sent as
  `"external_id":""` in the body (it is a plain `map[string]string`, not the
  `putStr` helper).

### `zone delete <id>`

- **Must:** removes a zone.
- **Access:** `nurproxy zone delete <id>`. REST: `DELETE /api/v1/zones/{id}`.
- **Steps:** `./nurproxy zone delete <zone-id>`
- **Pass:** `zone deleted: <id>`. Missing positional → `error: missing zone id`.
- **Coverage:** D
- **Pitfalls:** the parent-delete guard (RELEASE-QA §2.4) refuses a zone that still
  has domains with **409** — surfaces as an `error:` line listing the blocking domains.

### `agent list`

- **Must:** lists all agents (pending + adopted).
- **Access:** `nurproxy agent list`. REST: `GET /api/v1/agents`.
- **Steps:** `./nurproxy agent list` ; `-json`
- **Pass:** table `ID  NAME  FQDN  STATUS  VERSION  PROXY` (`cli_commands.go:168`).
  STATUS is `pending`/`adopted` (`models.go:12-13`); VERSION empty → `-`; PROXY is
  `yes`/`no` for `CaddyRunning`. `-json` → `[]models.Agent`.
- **Coverage:** D
- **Pitfalls:** there is **no `agent get` / `GET /agents/{id}`** in the API (it 405s,
  RELEASE-QA §2.1) — use `list` and filter, or `agent status`.

### `agent status <id>`

- **Must:** shows the live status detail for one agent.
- **Access:** `nurproxy agent status <id>`. REST: `GET /api/v1/agents/{id}/status`
  (`cli_commands.go:173`, server route `server.go:167`).
- **Steps:** `./nurproxy agent status <agent-id>`
- **Pass:** prints pretty-printed JSON of the status response (`prettyJSON`,
  `cli_commands.go:177`); `-json` prints the same raw body. Missing positional →
  `error: missing agent id`.
- **Coverage:** D
- **Pitfalls:** note this is the one "list-shaped" command that always emits JSON
  (there is no table form) — `-json` only strips the indentation/trailing whitespace.

### `agent adopt <id>`

- **Must:** adopts a pending agent, optionally setting name, anchor FQDN, attached
  zones, DNS mode, and DDNS interval.
- **Access:** `nurproxy agent adopt <id> [--name] [--fqdn] [--zones a,b] [--dns-mode] [--ddns-interval N]`.
  REST: `PUT /api/v1/agents/{id}/adopt` (`cli_commands.go:200`). Body is built only
  from set flags: `name`, `fqdn`, `dns_mode` via `putStr` (omitted when empty),
  `ddns_interval` only when `> 0`, `zone_ids` (CSV split) only when non-empty
  (`cli_commands.go:190-199`).
- **Prerequisites:** a pending agent. Bring one up dry on a separate data dir:
  ```bash
  NP_DRY_RUN=true ./nurproxy-agent -orchestrator http://localhost:18081 -fqdn edge1.example.com &
  ./nurproxy agent list   # grab the pending agent's ID
  ```
- **Steps:**
  ```bash
  ./nurproxy agent adopt <agent-id> --name edge1 --dns-mode static --zones <zone-id>
  ```
- **Pass:** prints `agent adopted: <id>`; `agent list` then shows STATUS `adopted`.
  `-json` prints the adopt response body.
- **Coverage:** D
- **Pitfalls:** valid `--dns-mode` values are **`static`** and **`ddns`**
  (`models.go:38-39`) — any other string is passed straight through to the API,
  which validates it. The CLI sends a JSON body here; the underlying API **requires
  a body** for adopt (empty → 400, RELEASE-QA §2.1), but the CLI always sends an
  object so even a bare `agent adopt <id>` is fine. `--ddns-interval 0` (or omitted)
  is **not** sent (`> 0` guard, `cli_commands.go:194`), so you cannot zero it via
  this flag.

### `agent update <id>`

- **Must:** edits an already-adopted agent's name/fqdn/zones/dns-mode/ddns-interval.
- **Access:** `nurproxy agent update <id>` with the same flags as `adopt`.
  REST: `PUT /api/v1/agents/{id}` (note: no `/adopt` suffix, `cli_commands.go:227`).
- **Steps:** `./nurproxy agent update <agent-id> --name edge1-renamed --dns-mode ddns --ddns-interval 60`
- **Pass:** `agent updated: <id>`; re-list shows the change.
- **Coverage:** D
- **Pitfalls:** same flag semantics as adopt (empty flags omitted, `ddns-interval`
  only if `>0`, zones only if non-empty). Differs from adopt only in the target path.

### `agent reject <id>`

- **Must:** rejects a pending agent.
- **Access:** `nurproxy agent reject <id>`. REST: `PUT /api/v1/agents/{id}/reject` (nil body, `cli_commands.go:236`).
- **Steps:** `./nurproxy agent reject <agent-id>`
- **Pass:** `agent rejected: <id>`.
- **Coverage:** D

### `agent delete <id>`

- **Must:** deletes an agent.
- **Access:** `nurproxy agent delete <id>`. REST: `DELETE /api/v1/agents/{id}`.
- **Steps:** `./nurproxy agent delete <agent-id>`
- **Pass:** `agent deleted: <id>`.
- **Coverage:** D
- **Pitfalls:** parent-delete guard (RELEASE-QA §2.4): an agent that still has
  servers/domains is refused with **409** listing the blockers — surfaces as an
  `error:` line.

### `server list <agent-id>`

- **Must:** lists the backend servers registered under one agent.
- **Access:** `nurproxy server list <agent-id>` (agent ID is a **positional**, not a flag).
  REST: `GET /api/v1/agents/{agentID}/servers`.
- **Steps:** `./nurproxy server list <agent-id>` ; `-json`
- **Pass:** table `ID  NAME  ADDRESS  NOTES` (`cli_commands.go:276`); empty NOTES → `-`.
  `-json` → `[]models.Server`. Missing positional → `error: missing agent id`.
- **Coverage:** D
- **Pitfalls:** easy to forget the positional and pass `--agent` (no such flag here;
  that's `domain list`). Without it you get `error: missing agent id`.

### `server add <agent-id>`

- **Must:** registers a backend address under an agent.
- **Access:** `nurproxy server add <agent-id> --name <n> --address <host:port> [--notes <s>]`.
  REST: `POST /api/v1/agents/{agentID}/servers` body `{"name","address","notes"}` (`cli_commands.go:289-291`).
- **Steps:** `./nurproxy server add <agent-id> --name app --address 127.0.0.1:18099 --notes "qa backend"`
- **Pass:** `server created: <id>`. `--name` and `--address` required
  (`cli_commands.go:286` → `error: --name and --address are required`).
- **Coverage:** D
- **Pitfalls:** `--address` is the backend from the **agent's** point of view
  (`cli_commands.go:282`). Positional agent ID must come — order with flags is
  flexible (Go `flag` permits interleaving until the first non-flag), but conventionally
  put the ID first.

### `server update <id>`

- **Must:** edits a server's name/address/notes (by server ID, not agent ID).
- **Access:** `nurproxy server update <id> [--name] [--address] [--notes]`.
  REST: `PUT /api/v1/servers/{id}` (`cli_commands.go:309`). Only set string flags
  are sent (`putStr`, `cli_commands.go:305-308`).
- **Steps:** `./nurproxy server update <server-id> --notes "updated"`
- **Pass:** `server updated: <id>`.
- **Coverage:** D
- **Pitfalls:** the positional here is the **server** ID (from `server list`),
  whereas `server list`/`add` take the **agent** ID. Don't cross them.

### `server delete <id>`

- **Must:** removes a server.
- **Access:** `nurproxy server delete <id>`. REST: `DELETE /api/v1/servers/{id}`.
- **Steps:** `./nurproxy server delete <server-id>`
- **Pass:** `server deleted: <id>`.
- **Coverage:** D
- **Pitfalls:** parent-delete guard — a server with domains is refused **409**
  (RELEASE-QA §2.4).

### `domain list`

- **Must:** lists domains, optionally filtered by agent, server, or status.
- **Access:** `nurproxy domain list [--agent <id>] [--server <id>] [--status <s>]`.
  REST: `GET /api/v1/domains` with query params `agent_id` / `server_id` / `status`
  (only non-empty ones added, `cli_commands.go:341-348`).
- **Steps:** `./nurproxy domain list` ; `./nurproxy domain list --status active` ; `-json`
- **Pass:** table `ID  SUBDOMAIN  SERVER  PORT  STATUS` (`cli_commands.go:364`); ID
  is the numeric domain ID; STATUS is `pending`/`active`/`deleting`-etc.
  (`models.go:22-23`). `-json` → `[]models.Domain`.
- **Coverage:** D
- **Pitfalls:** here it is `--agent`/`--server` (flags), unlike `server list` which
  uses a positional. `--status` is a free string passed to the query; an unknown
  status simply returns no rows.

### `domain add`

- **Must:** creates a proxied domain (subdomain under a zone → server:port),
  optionally with websocket, force-HTTPS, SSL mode, and an advanced ProxyConfig.
- **Access:** `nurproxy domain add --subdomain <s> --zone <id> --server <id> --port <n>
  [--websocket] [--force-https] [--ssl-mode <m>] [--proxy-config-file <path|->]`.
  REST: `POST /api/v1/domains` body `{"subdomain","zone_id","server_id","port",
  "websocket","force_https"[,"ssl_mode"][,"proxy_config":<raw JSON>]}` (`cli_commands.go:383-390`).
- **Prerequisites:** an existing zone ID and server ID (create via the commands above).
- **Steps:**
  ```bash
  ./nurproxy domain add --subdomain app --zone <zone-id> --server <server-id> --port 18099 \
    --websocket --force-https --ssl-mode auto
  # Advanced: structured proxy config from a file
  cat > /tmp/pc.json <<'JSON'
  {"max_body_size":"10m","custom_response_headers":{"X-QA":"1"}}
  JSON
  ./nurproxy domain add --subdomain api --zone <zone-id> --server <server-id> --port 18099 \
    --proxy-config-file /tmp/pc.json
  ```
- **Pass:** `domain created: <id>`. Required: `--subdomain`, `--zone`, `--server`,
  `--port` (non-zero) — else `error: --subdomain, --zone, --server and --port are required`
  (`cli_commands.go:380-382`).
- **Coverage:** D (creation/state-machine is dry-coverable; real serving is R, out of scope here).
- **Pitfalls:** `--ssl-mode` valid values are **`auto`**, **`manual`**, **`off`**
  (`models.go:46-48`); empty is omitted and the API defaults to `auto`
  (`domains.go:91-93`). `--proxy-config-file -` reads stdin; the file content is
  passed as **raw JSON** under `proxy_config` (`readFileArg`, `cli_commands.go:389`) —
  a bad file path fatals `error: reading <path>: ...`. `--port 0` counts as "not set"
  and fails the required-check.

### `domain update <id>`

- **Must:** edits a domain. Crucially, bool flags (`--websocket`, `--force-https`)
  are sent **only when explicitly passed**, so an update doesn't silently flip them
  off (tri-state via `fs.Visit`, `cli_commands.go:419-428`).
- **Access:** `nurproxy domain update <id> [--subdomain] [--zone] [--server] [--port]
  [--websocket] [--force-https] [--ssl-mode]`. REST: `PUT /api/v1/domains/{id}`
  (`cli_commands.go:429`). Note: **no `--proxy-config-file`** on update (only on add).
- **Steps:**
  ```bash
  # Toggle websocket ON without touching force_https
  ./nurproxy domain update <id> --websocket
  # Explicitly turn force_https OFF
  ./nurproxy domain update <id> --force-https=false
  # Change just the port
  ./nurproxy domain update <id> --port 9090
  ```
- **Pass:** `domain updated: <id>`. Verify via `domain list -json` that only the
  intended fields changed; a `domain update <id> --subdomain x` must leave
  `websocket`/`force_https` untouched.
- **Coverage:** D
- **Pitfalls:** **regression-guard the tri-state bools.** Because the API uses
  pointer fields for bools (`domains.go:188`+), omitting `--websocket` must leave it
  unchanged; only `fs.Visit` seeing the flag adds it to the body. `--port` only sent
  when `>0` (`cli_commands.go:416`), so you cannot set port 0. String flags use
  `putStr` (empty omitted). There is no way to clear a string field to empty via the CLI.

### `domain delete <id>`

- **Must:** marks a domain for deletion (soft delete; reconciler tears down DNS/route/cert).
- **Access:** `nurproxy domain delete <id>`. REST: `DELETE /api/v1/domains/{id}`.
- **Steps:** `./nurproxy domain delete <id>`
- **Pass:** prints `domain marked for deletion: <id>` (note the wording differs from
  other deletes — it's a soft delete, `cli_commands.go:442`).
- **Coverage:** D
- **Pitfalls:** delete is **soft** (`status=deleting`); the actual DNS/row cleanup
  happens a reconcile cycle later (RELEASE-QA §2.4). A parent-delete (server/agent/zone)
  immediately after correctly 409s until the reconciler finishes.

### `apikey show`

- **Must:** reports whether an admin API key exists, masked (never the plaintext).
- **Access:** `nurproxy apikey show`. REST: `GET /api/v1/api-key`.
- **Steps:** `./nurproxy apikey show`
- **Pass:** prints pretty JSON. When a key exists: `{"exists":true,"masked":"abcd…wxyz"}`;
  otherwise `{"exists":false}` (`system.go:69-82`). `-json` emits the same raw body.
- **Coverage:** D
- **Pitfalls:** "show" never reveals the key — only `create` does, once.

### `apikey create`

- **Must:** generates (or regenerates) the admin API key and returns it once.
- **Access:** `nurproxy apikey create`. REST: `POST /api/v1/api-key` (nil body).
- **Steps:** `./nurproxy apikey create --password sandbox123`
- **Pass:** prints `API key (shown once): <np_ak_...>` (HTTP 201, `system.go:84-97`;
  the `api_key` field pulled via `gjson`, `cli_commands.go:468`). `-json` prints
  `{"api_key":"np_ak_..."}`.
- **Coverage:** D
- **Pitfalls:** keys are prefixed `np_ak_` (matches the dev-sandbox grep
  `scripts/dev-sandbox.sh:85`). Calling `create` again **regenerates** and
  invalidates the old key. The plaintext is shown **only at creation** — capture it.
  Revoke test keys when done (`apikey revoke`), since they land in transcripts
  (RELEASE-QA §6).

### `apikey revoke`

- **Must:** revokes the admin API key.
- **Access:** `nurproxy apikey revoke`. REST: `DELETE /api/v1/api-key`.
- **Steps:** `./nurproxy apikey revoke --password sandbox123`
- **Pass:** prints `API key revoked`. A subsequent `apikey show` reports `{"exists":false}`.
- **Coverage:** D
- **Pitfalls:** revoking the key you authenticated with means later key-auth calls
  fail — fall back to `--password` / `NP_API_PASSWORD`.

### `auth setup`

- **Must:** bootstraps the admin password on a fresh install. Needs **no
  credentials** — it bypasses the normal auth flow via an unauthenticated POST
  (`postNoAuth`, `cli_commands.go:516-524`). The password comes from the shared
  `--password` / `NP_API_PASSWORD`.
- **Access:** `nurproxy auth setup --password <pw>` (or `NP_API_PASSWORD`).
  REST: `POST /api/v1/auth/setup` body `{"password":"<pw>"}` (unauthenticated).
- **Steps (on a fresh dry data dir):** `./nurproxy auth setup --password sandbox123`
- **Pass:** prints `admin password configured — now run: nurproxy apikey create --password <pw>`
  (`cli_commands.go:500`).
- **Coverage:** D
- **Pitfalls:** `--password` is **required** here even though it's a global flag —
  empty → `error: --password (or NP_API_PASSWORD) is required` (`cli_commands.go:493-495`).
  The **password must be ≥ 8 chars** (`auth.go:59-61`) or the API returns 400. Setup
  only works once: a second call on an already-configured install returns **409
  `admin password already configured`** (`auth.go:43-46`) — surfaces as an `error:` line.

### `auth status`

- **Must:** reports authentication state without needing credentials
  (unauthenticated GET, `postNoAuthGet`, `cli_commands.go:526-533`).
- **Access:** `nurproxy auth status`. REST: `GET /api/v1/auth/status`.
- **Steps:** `./nurproxy auth status`
- **Pass:** prints pretty JSON `{"setup_required":<bool>,"authenticated":<bool>}`
  (`auth.go:14-37`). On a fresh install `setup_required:true`; after `auth setup`,
  `false`. (Because the CLI sends no session cookie, `authenticated` is generally
  `false` here.) `-json` emits the same raw body.
- **Coverage:** D
- **Pitfalls:** this is the canonical post-restore smoke check (RELEASE-QA §2.9):
  `setup_required:false` proves the restored DB carries the admin hash.

### Usage / error surfaces (cross-cutting)

- **Must:** an unknown action prints group usage to stderr and exits 2; a missing
  required flag or positional exits 1 with `error: ...`.
- **Access:** any group with a bad/empty action, e.g. `nurproxy provider`,
  `nurproxy agent foo`.
- **Steps:**
  ```bash
  ./nurproxy provider            # usage with: list, add, delete <id>, zones <id>
  ./nurproxy agent bogus         # usage with: list, status <id>, adopt <id>, ...
  ./nurproxy zone delete         # error: missing zone id
  ./nurproxy zone add            # error: --provider and --name are required
  ```
- **Pass:** `usage: nurproxy <group> <action>` block on stderr, exit 2 (`usage`,
  `cli_commands.go:571-577`); required/positional failures print `error: ...`,
  exit 1 (`fatalf`).
- **Coverage:** D
- **Pitfalls:** `os.Args[1]` not matching any of provider/zone/agent/server/domain/
  apikey/auth (and not install/uninstall/version/backup/restore) falls through to
  **starting the orchestrator server** (`main.go:59-66`, `runCLI` returns false) —
  a typo'd group name can accidentally try to boot a server on `:8080`. Use a known
  group name.

## Acceptance checklist

**Dry (every RC):**
- [ ] `make build` produces `./nurproxy`; `nurproxy version` prints the build version.
- [ ] No-credentials call errors with `no credentials: ...`; key-auth and password-auth both work; `-key` overrides `-password`.
- [ ] Env fallbacks honored: `NP_API_URL`, `NP_API_KEY`, `NP_API_PASSWORD`.
- [ ] `auth setup` (≥8-char pw) → `apikey create` → key works; second `setup` → 409.
- [ ] `auth status` → `setup_required:false` after setup; `apikey show` masks the key; `apikey revoke` → `exists:false`.
- [ ] provider add (`--config` and `--config-file -`) / list / zones / delete round-trip.
- [ ] zone add / list / delete; zone-delete-with-domains → 409.
- [ ] agent list / status / adopt (`--dns-mode static|ddns`, `--zones`, `--ddns-interval`) / update / reject / delete.
- [ ] server list `<agent-id>` (positional) / add / update `<server-id>` / delete.
- [ ] domain add (incl. `--proxy-config-file`, `--ssl-mode auto|manual|off`) / list (`--agent/--server/--status`) / update (tri-state bool guard) / delete ("marked for deletion").
- [ ] `--json` returns valid, indented JSON for every list/get command; table form otherwise.
- [ ] Unknown action → usage on stderr, exit 2; missing required flag/positional → `error:`, exit 1.
- [ ] Test API keys revoked after the run.

# Proxy Directive Matrix (every ProxyConfig field × backend)

> **Scope:** for every field of `models.ProxyConfig`, document what it renders to in each backend (built-in Caddy, nginx, Apache) and how to verify both the rendered directive and the runtime behaviour.
> **Code:** `internal/shared/models/models.go` (`ProxyConfig`, `BasicAuthConfig`, `RawConfig`), `internal/shared/proxymodel/route.go` (`Route` intent + `Validate`), `internal/shared/caddygen/generate.go` (`ConfigFromDomain`, `GenerateRoute`, `tlsPolicyFromDomain`), `internal/shared/nginxgen/generate.go` (`Render`), `internal/shared/apachegen/generate.go` (`Render`), `internal/orchestrator/api/domains.go` (`handleGetDomainConfig` / `renderDomainPreview` / `handleUpdateDomainConfig`), `cmd/nurproxy/cli_commands.go` (`--proxy-config-file`).
> **Coverage legend:** D = coverable dry, R = needs a real run. For this matrix: **render = D** (the three renderers are pure functions, fully unit-tested, and the `GET …/config` preview runs in dry mode); **behaviour = R** (needs a real Caddy/nginx/Apache + the mini backend + `curl`).

---

## Prerequisites

Before any test here:

- Both binaries built: `make build-all` (produces `./nurproxy` and `./nurproxy-agent`).
- For **render checks (D)**: a dry orchestrator with at least one adopted agent + server + domain. Fastest: `make dev-sandbox` (orchestrator + 1 dry agent, seeded topology). The `GET /api/v1/domains/{id}/config` preview renders in the backend the serving agent runs (`renderDomainPreview` → `backendForDomain`); a dry built-in agent previews **Caddy** JSON. To preview **nginx**/**apache** output you need an agent in `existing` mode whose `ProxyDetection.Kind` is `nginx`/`apache` (`backendForDomain`, domains.go:437-446) — otherwise the preview defaults to caddy.
- For **behaviour checks (R)**: a real proxy binary in PATH on the agent host (`caddy`, or an `nginx`/`apache` the agent adopted), the **mini backend** fixture from `docs/RELEASE-QA.md §5` (echoes `NURPROXY-E2E-PROOF`, request headers, and `path=`, binds `0.0.0.0:18099`), and `curl`/`openssl`.
- bcrypt helper for `basic_auth`: `python3 -c 'import bcrypt;print(bcrypt.hashpw(b"pw",bcrypt.gensalt()).decode())'`.
- **Deterministic client IP** (for IP allow/block and rate-limit): drive the agent directly with `curl --resolve <host>:443:<agent-ip>` so the observed source IP is stable. The public hairpin/edge path mangles the source IP (RELEASE-QA §2.6 / §6).

The complete field set, enumerated from `models.ProxyConfig` (models.go:339-364):

| ProxyConfig field | type | JSON key |
|---|---|---|
| WebSocket | bool | `websocket` |
| ForceHTTPS | bool | `force_https` |
| MaxBodySize | string | `max_body_size` |
| CustomRequestHeaders | map[string]string | `custom_request_headers` |
| CustomResponseHeaders | map[string]string | `custom_response_headers` |
| PathStrip | string | `path_strip` |
| PathRewrite | string | `path_rewrite` |
| UpstreamScheme | string (`http`/`https`) | `upstream_scheme` |
| TimeoutRead | int (seconds) | `timeout_read` |
| TimeoutWrite | int (seconds) | `timeout_write` |
| TimeoutIdle | int (seconds) | `timeout_idle` |
| BasicAuth | *BasicAuthConfig (Username, Password=**bcrypt hash**) | `basic_auth` |
| IPAllowlist | []string (CIDR) | `ip_allowlist` |
| IPBlocklist | []string (CIDR) | `ip_blocklist` |
| RateLimit | float64 (req/s) | `rate_limit` |
| RawConfig | RawConfig (Backend, Content) | `raw_config` |
| TLSPolicy | string (`central`/`self-acme`/`off`) | `tls_policy` |

> Note: `websocket` and `force_https` also exist as top-level `Domain` fields. `ConfigFromDomain` ORs the two: `WebSocket: d.WebSocket || d.ProxyConfig.WebSocket`, `ForceHTTPS: d.ForceHTTPS || d.ProxyConfig.ForceHTTPS` (caddygen/generate.go:32-33). Either source enables it.

---

## Features covered

- [ ] `websocket` — connection-upgrade passthrough
- [ ] `force_https` — HTTP→HTTPS redirect
- [ ] `max_body_size` — request-body cap
- [ ] `custom_request_headers` — headers to upstream
- [ ] `custom_response_headers` — headers to client
- [ ] `path_strip` — strip leading prefix
- [ ] `path_rewrite` — rewrite request URI
- [ ] `upstream_scheme` — http/https to backend
- [ ] `timeout_read` / `timeout_write` / `timeout_idle`
- [ ] `basic_auth` — bcrypt-hash credentials
- [ ] `ip_allowlist` / `ip_blocklist` — CIDR access control (403)
- [ ] `rate_limit` — per-client req/s (nginx 503, **Apache drops it**)
- [ ] `raw_config` — per-backend escape hatch (verbatim) + `config/reset` to clear it
- [ ] `tls_policy` — central / self-acme / off
- [ ] Default forwarding headers (always added)
- [ ] Dropped-with-warning matrix (per backend)

---

## How to drive the matrix (shared steps)

**Render check (D)** — preview the generated config for a domain:

```bash
# pick the domain id from: nurproxy domain list   (or GET /api/v1/domains)
curl -s -H "Authorization: Bearer $NP_API_KEY" \
  http://localhost:8080/api/v1/domains/$DID/config | jq .
# -> {"manual":false,"backend":"caddy"|"nginx"|"apache","config": <object|string>}
```

`config` is a **JSON object** (Caddy route JSON) for built-in Caddy, or a **string** (native config text) for nginx/apache (`renderDomainPreview`, domains.go:407-432; nginx joins the http-context preamble via `joinNginx`, apache via `joinBlocks`).

**Set the ProxyConfig** — three equivalent access paths:

- **REST:** `POST /api/v1/domains` (create) or `PUT /api/v1/domains/{id}` (update) with a `proxy_config` object, e.g.
  ```bash
  curl -s -H "Authorization: Bearer $NP_API_KEY" -X PUT \
    http://localhost:8080/api/v1/domains/$DID \
    -d '{"proxy_config":{"websocket":true,"max_body_size":"10MB"}}'
  ```
- **CLI:** `nurproxy domain add --subdomain … --zone … --server … --port … --proxy-config-file ./pc.json` where `pc.json` is a raw `ProxyConfig` JSON document (cli_commands.go:378, 388-390). NOTE: `domain add` also has dedicated `--websocket` / `--force-https` flags; `domain update` exposes `--websocket`/`--force-https` but **no** `--proxy-config-file` (cli_commands.go:397-409), so structured-field edits go via REST/dashboard.
- **Dashboard:** the domain edit drawer — **Headers** tab (custom request/response headers) and **Advanced** tab (everything else: websocket, force-https, body size, path rules, upstream scheme, timeouts, basic auth, IP lists, rate limit, TLS policy, raw config).
- **MCP:** the orchestrator's MCP server (`internal/orchestrator/mcp/server.go`) exposes `create_domain` / `update_domain` / `delete_domain` / `list_domains`. **Limitation:** the `create_domain` (server.go:214) and `update_domain` (server.go:220) input schemas accept only `websocket`, `force_https`, `ssl_mode` (plus subdomain/zone/server/port/id) with `additionalProperties:false`, so **MCP cannot set any structured `ProxyConfig` field** (max_body_size, headers, path rules, basic_auth, IP lists, rate_limit, timeouts, upstream_scheme, tls_policy, raw_config) and offers **no config-preview tool** — those edits must go via REST/CLI/dashboard. MCP `websocket`/`force_https` write the top-level `Domain` fields (which `ConfigFromDomain` ORs into the route — see note above).

**Behaviour check (R)** — after the agent applies, hit it directly:

```bash
curl --resolve $HOST:443:$AGENT_IP https://$HOST/ -i -w "\nhttp=%{http_code}\n"
```

---

## Tests

### websocket

- **Must:** enables connection-upgrade passthrough to the upstream.
- **Access:** Dashboard Advanced tab (toggle) / `proxy_config.websocket:true` (also `domain.websocket`) / CLI `--websocket`.
- **Renders to:**
  - **Caddy:** `reverse_proxy` handler with `"flush_interval": -1` (caddygen/generate.go:243-245; test asserts `FlushInterval == -1`).
  - **nginx:** inside `location /`: `proxy_http_version 1.1;`, `proxy_set_header Upgrade $http_upgrade;`, `proxy_set_header Connection "upgrade";` (nginxgen/generate.go:242-246).
  - **Apache:** a mod_rewrite/mod_proxy_wstunnel rule **before** `ProxyPass`: `RewriteEngine On` + `RewriteCond %{HTTP:Upgrade} =websocket [NC]` + `RewriteRule ^/?(.*)$ ws[s]://addr:port/$1 [P,L]` (apachegen/generate.go:258-268). `wss` is used when upstream scheme is https (test: `wss://10.0.0.4:8080/$1 [P,L]`). Apache only emits the WS rule on the **default** path case (no path_strip/path_rewrite) — see Pitfalls.
- **Steps (render D):** set `{"websocket":true}`, `GET …/config`, grep for the directive above.
- **Steps (behaviour R):** point upstream at a WS echo server; open a WS connection through the proxy; confirm the upgrade completes.
- **Pass:** render contains the backend's WS directive; a live WS handshake succeeds end to end.
- **Coverage:** D (render) / R (behaviour).
- **Pitfalls:** Apache requires `mod_proxy_wstunnel` loaded. In Apache, websocket is **not** rendered when `path_strip` or `path_rewrite` is set: the WS rule only lives in the `default` arm of the path `switch` (apachegen/generate.go:256-268); the rewrite branch (243-248) and strip branch (249-255) do not emit it — a real gotcha if you combine path rules with websocket on Apache.

### force_https

- **Must:** plaintext HTTP requests are redirected to HTTPS.
- **Access:** Dashboard Advanced tab / `proxy_config.force_https:true` (also `domain.force_https`) / CLI `--force-https`.
- **Renders to:**
  - **Caddy:** a top-level `subroute` matching `{"protocol":"http"}`, `terminal:true`, returning a **302** `static_response` with `Location: https://{http.request.host}{http.request.uri}` (caddygen/generate.go:308-327). Matched on protocol `http` + terminal so an HTTPS request does NOT also match (would loop).
  - **nginx:** a dedicated `server { listen 80; … return 301 https://$host$request_uri; }` block (nginxgen/generate.go:138-149). **301**, not 302.
  - **Apache:** a dedicated `<VirtualHost *:80>` with `Redirect permanent / https://host/` (apachegen/generate.go:136-145). **301** (`permanent`).
- **Steps (render D):** set `{"force_https":true}` with TLS enabled; preview; confirm the redirect block.
- **Steps (behaviour R):** `curl --resolve $HOST:80:$AGENT_IP http://$HOST/ -i` → 301/302 with `Location: https://…`.
- **Pass:** plaintext request gets the redirect status + Location header.
- **Coverage:** D / R.
- **Pitfalls:** **nginx and Apache DROP force_https with a warning when TLS is not enabled** (`force_https: no TLS certificate available for this route; HTTP→HTTPS redirect dropped`) — nginxgen/generate.go:146-148, apachegen/generate.go:142-144. So `force_https` only renders if the route actually has a cert (central policy with cert/key present, or self-acme on Caddy). Caddy always emits the redirect regardless (no TLS guard in caddygen). Status code differs by backend (Caddy 302 vs nginx/apache 301) — assert the right one.

### max_body_size

- **Must:** caps the request body size; `"unlimited"` disables the cap.
- **Access:** Dashboard Advanced tab / `proxy_config.max_body_size:"10MB"`.
- **Renders to:**
  - **Caddy:** `request_body` handler with `max_size: "<value>"`; **omitted** when empty or `"unlimited"` (caddygen/generate.go:203-208). Value passed through verbatim.
  - **nginx:** `client_max_body_size <size>;` with the value normalized — trailing `b` stripped, lowercased, whitespace removed; `"unlimited"` → `0` (nginxgen `normalizeBodySize`, lines 170-172, 328-340). Test: `"10MB"` → `client_max_body_size 10m;`; `"unlimited"` → `client_max_body_size 0;`.
  - **Apache:** `LimitRequestBody <bytes>` — value parsed to a **byte count** (k/m/g are decimal 1000-based, optional trailing `b`); `"unlimited"` → `0`; an **unparseable** size is DROPPED with warning `max_body_size: could not parse size "…"; LimitRequestBody dropped` (apachegen `normalizeBodySize`/`parseSizeToBytes`, lines 163-165, 321-365).
- **Steps (render D):** set `{"max_body_size":"10MB"}`, preview each backend.
- **Steps (behaviour R):** `curl --resolve … -X POST --data-binary @bigfile https://$HOST/` with a body over the limit → **413** (Caddy/nginx) / Apache returns the configured error.
- **Pass:** over-limit body rejected; under-limit passes.
- **Coverage:** D / R.
- **Pitfalls:** units differ by backend — nginx wants `k/m/g` suffixes (so `10MB`→`10m`), Apache wants raw bytes. An Apache size it can't parse is silently dropped (warning only); check the ArtifactReport warnings.

### custom_request_headers

- **Must:** sets headers on the request before it reaches the upstream (in addition to default forwarding headers).
- **Access:** Dashboard **Headers** tab / `proxy_config.custom_request_headers:{"X-Foo":"bar"}`.
- **Renders to:**
  - **Caddy:** merged into `reverse_proxy` → `headers.request.set` alongside the defaults `X-Forwarded-Proto`/`X-Real-IP` (caddygen/generate.go:219-231).
  - **nginx:** `proxy_set_header <K> <V>;` inside `location /`, deterministic sorted order, value quoted if it contains space/tab/`;`/`"` (nginxgen/generate.go:248-251, `quoteHeaderValue`).
  - **Apache:** `RequestHeader set <K> <V>` inside the VirtualHost, sorted, quoted via `quoteValue` (apachegen/generate.go:213-218).
- **Steps (render D):** set a header; preview; confirm it appears.
- **Steps (behaviour R):** mini backend echoes request headers — `curl --resolve … https://$HOST/` and grep the echoed header in the body.
- **Pass:** upstream sees the header with the configured value.
- **Coverage:** D / R.
- **Pitfalls:** keys are emitted in sorted order (deterministic), so don't assert source-map ordering.

### custom_response_headers

- **Must:** sets headers on the response returned to the client.
- **Access:** Dashboard **Headers** tab / `proxy_config.custom_response_headers:{"X-Frame-Options":"DENY"}`.
- **Renders to:**
  - **Caddy:** `reverse_proxy` → `headers.response.set` (only emitted when non-empty) (caddygen/generate.go:234-240).
  - **nginx:** `add_header <K> <V> always;` at **server** scope (so it applies to proxied + error responses), sorted (nginxgen/generate.go:207-212). Test: `add_header X-Frame-Options DENY always;`.
  - **Apache:** `Header always set <K> <V>` at VirtualHost scope, sorted (apachegen/generate.go:204-209).
- **Steps (render D):** set a header; preview.
- **Steps (behaviour R):** `curl -I --resolve … https://$HOST/` → header present in the response.
- **Pass:** client response carries the header.
- **Coverage:** D / R.
- **Pitfalls:** nginx `add_header` only fires on a known set of status codes unless `always` is set — the renderer always uses `always`, so error responses carry it too. Don't expect it on responses nginx short-circuits before the headers phase.

### path_strip

- **Must:** removes a leading prefix from the request path before the upstream sees it (e.g. `/api` so `/api/users` → `/users`).
- **Access:** Dashboard Advanced tab / `proxy_config.path_strip:"/api"`.
- **Renders to:**
  - **Caddy:** a `rewrite` handler with `strip_path_prefix: "<prefix>"`, placed **before** `reverse_proxy` (caddygen/generate.go:156-161). Test asserts `"strip_path_prefix":"/api"` and that it precedes reverse_proxy.
  - **nginx:** `rewrite ^<escaped-prefix>/?(.*)$ /$1 break;` inside `location /`, regex-escaped prefix (nginxgen/generate.go:221-224).
  - **Apache:** takes the **strip branch** — `RewriteEngine On` + `RewriteRule ^<prefix>/?(.*)$ <upstream>/$1 [P]` + `ProxyPassReverse / <upstream>/` (apachegen/generate.go:249-255).
- **Steps (render D):** set `{"path_strip":"/api"}`, preview.
- **Steps (behaviour R):** mini backend echoes `path=` — `curl --resolve … https://$HOST/api/users` → body shows `path=/users`.
- **Pass:** upstream receives the path with the prefix removed.
- **Coverage:** D / R.
- **Pitfalls:** prefix is normalized to a single leading slash (`"/" + strings.Trim(...)`). On Apache, path_strip and websocket are mutually exclusive in the rendered output (strip branch doesn't emit WS — see websocket Pitfalls).

### path_rewrite

- **Must:** replaces the entire request URI with a fixed value.
- **Access:** Dashboard Advanced tab / `proxy_config.path_rewrite:"/newpath"`.
- **Renders to:**
  - **Caddy:** a `rewrite` handler with `uri: "<value>"`, before reverse_proxy (caddygen/generate.go:162-167). Both strip and rewrite can be present; strip is emitted first.
  - **nginx:** `rewrite ^.*$ <value> break;` inside `location /` (nginxgen/generate.go:225-227).
  - **Apache:** takes the **rewrite branch** (checked before strip): `RewriteRule ^.*$ <upstream><value> [P]` + `ProxyPassReverse` (apachegen/generate.go:242-248). If both path_rewrite and path_strip are set, Apache uses **rewrite** (the `switch` tests `Rewrite != ""` first).
- **Steps (render D):** set `{"path_rewrite":"/newpath"}`, preview.
- **Steps (behaviour R):** mini backend `path=` shows `/newpath` regardless of requested path.
- **Pass:** upstream always sees the rewritten URI.
- **Coverage:** D / R.
- **Pitfalls:** In Caddy both strip+rewrite render and run in order. In Apache they are exclusive (rewrite wins). Don't assume identical strip/rewrite semantics across backends.

### upstream_scheme

- **Must:** selects http or https when connecting to the backend; empty defaults to http.
- **Access:** Dashboard Advanced tab / `proxy_config.upstream_scheme:"https"`.
- **Renders to:**
  - **Caddy:** when `https`, the `reverse_proxy` gets a `transport` of protocol `http` with a `tls` block (`t.TLS = &TLS{}`) (caddygen/generate.go:249-253). A transport is also added when any timeout is set.
  - **nginx:** `proxy_pass https://addr:port;` (nginxgen/generate.go:229-233).
  - **Apache:** `ProxyPass / https://addr:port/` (apachegen/generate.go:234-238).
- **Steps (render D):** set `{"upstream_scheme":"https"}`, preview; confirm scheme on the proxy line / the caddy `tls` transport block.
- **Steps (behaviour R):** stand up an HTTPS upstream; confirm proxy reaches it over TLS.
- **Pass:** upstream is reached over the chosen scheme.
- **Coverage:** D / R.
- **Pitfalls:** `EffectiveScheme()` treats empty as http; only `http`/`https` are valid (`Validate` rejects others). Caddy's https-upstream does not disable backend cert verification in the renderer — a self-signed upstream may fail TLS (no `insecure_skip_verify` is emitted).

### timeout_read / timeout_write / timeout_idle

- **Must:** bound upstream interactions in **seconds**; `0` = backend default (unset, directive omitted).
- **Access:** Dashboard Advanced tab / `proxy_config.timeout_read|timeout_write|timeout_idle` (ints).
- **Renders to:**
  - **Caddy** (`http` transport added when any timeout > 0, or https upstream): `timeout_write` → `dial_timeout: "<n>s"`; `timeout_read` → `response_header_timeout: "<n>s"`; `timeout_idle` → `keep_alive.idle_timeout: "<n>s"` (caddygen/generate.go:250-266). Test: write 10 → `DialTimeout "10s"`, read 30 → `ResponseHeaderTimeout "30s"`.
  - **nginx:** `timeout_write` → **both** `proxy_connect_timeout <n>s;` and `proxy_send_timeout <n>s;`; `timeout_read` → `proxy_read_timeout <n>s;` (nginxgen/generate.go:255-261). **`timeout_idle` is NOT rendered by nginx** (no directive emitted — silently unused, no warning).
  - **Apache:** on the default `ProxyPass` worker line: `timeout_write` → `connectiontimeout=<n>`, `timeout_read` → `timeout=<n>` (apachegen/generate.go:272-277). **`timeout_idle` is NOT rendered.** Timeouts are also **not emitted on the strip/rewrite RewriteRule branches** — only on the plain default ProxyPass path.
- **Steps (render D):** set all three; preview each backend; confirm the mapping above.
- **Steps (behaviour R):** make the upstream stall longer than `timeout_read`; confirm the proxy returns a gateway timeout.
- **Pass:** rendered timeouts match the mapping; a stalled upstream trips the read timeout.
- **Coverage:** D / R.
- **Pitfalls:** `timeout_idle` only does anything on **Caddy** (keep-alive idle). On nginx/Apache it is dropped with no warning. On Apache, timeouts only apply when no path_strip/path_rewrite is set (they ride the default ProxyPass line). `timeout_write` maps to connect+send on nginx and connect on Apache — it is **not** a body-write timeout in the strict sense.

### basic_auth (password is a BCRYPT hash, not plaintext)

- **Must:** gates the route behind HTTP basic auth; the stored `Password` is a **bcrypt hash**, never plaintext (`BasicAuthConfig.Password // bcrypt hash`, models.go:316; `proxymodel.BasicAuth.PasswordHash`, route.go:76-78).
- **Access:** Dashboard Advanced tab (username + password fields — the server hashes/stores the bcrypt) / `proxy_config.basic_auth:{"username":"u","password":"<bcrypt-hash>"}`.
- **Renders to:**
  - **Caddy:** an `authentication` handler with `http_basic`, `hash.algorithm: "bcrypt"`, and an account whose `password` is the **base64 of the bcrypt hash string** (`base64.StdEncoding.EncodeToString([]byte(PasswordHash))`) — caddygen/generate.go:170-186. Caddy expects the hash base64-encoded. Only emitted when both username and hash are non-empty.
  - **nginx:** `auth_basic "Restricted: <host>";` + `auth_basic_user_file <htpasswd-path>;` — the agent writes the bcrypt entry to an htpasswd file, the renderer only references `Input.AuthFile` (nginxgen/generate.go:191-198). **Dropped with warning** `basic_auth: no htpasswd file path provided; basic auth dropped` if `AuthFile` is empty — which it is in the preview (`renderDomainPreview` passes no AuthFile), so the **preview shows the drop warning** while the real agent fills it.
  - **Apache:** a `<Location />` with `AuthType Basic` + `AuthName "Restricted: <host>"` + `AuthUserFile <htpasswd>` + `Require valid-user` (apachegen/generate.go:189-200). Same `AuthFile`-empty drop behaviour as nginx.
- **Steps (render D):** generate a hash (`python3 -c 'import bcrypt;print(bcrypt.hashpw(b"pw",bcrypt.gensalt()).decode())'`), set `basic_auth`, preview. For Caddy, confirm the base64-of-hash. For nginx/apache, note the preview drops it (no AuthFile) — verify the **real** agent's rendered artifact (ArtifactReport content) instead.
- **Steps (behaviour R):** `curl --resolve … https://$HOST/` → **401**; `curl -u u:pw …` → 200 (mini backend body).
- **Pass:** no creds → 401; correct creds → 200; wrong creds → 401.
- **Coverage:** D (Caddy render; nginx/apache render needs the agent's AuthFile) / R (behaviour).
- **Pitfalls:** **Never** send plaintext in `password` — it is stored and treated as a bcrypt hash. Caddy double-encodes (bcrypt then base64); don't be surprised the JSON value isn't the raw hash. For nginx/apache the **preview will warn-drop** basic auth because the orchestrator preview supplies no htpasswd path — that is expected, not a regression; the agent supplies the path at apply time.

### ip_allowlist / ip_blocklist

- **Must:** allowlist permits only the listed CIDRs (all others 403); blocklist denies the listed CIDRs (403). Blocklist is evaluated **before** the allowlist.
- **Access:** Dashboard Advanced tab / `proxy_config.ip_allowlist:["10.0.0.0/8"]`, `proxy_config.ip_blocklist:["203.0.113.0/24"]`.
- **Renders to:**
  - **Caddy:** terminal inner `subroute` routes returning `static_response` **403** "Forbidden": blocklist route matches `remote_ip.ranges` and is terminal; allowlist route matches `not remote_ip.ranges` and is terminal — both run **before** the proxy (caddygen/generate.go:99-106, 274-293).
  - **nginx:** top-to-bottom `deny <cidr>;` for each blocklist entry, then (if allowlist set) `allow <cidr>;` per entry + `deny all;` (nginxgen/generate.go:177-188). Test: `deny 203.0.113.0/24;` then `allow 10.0.0.0/8;` then `deny all;`.
  - **Apache:** a `<RequireAll>` block — `Require ip <allowlist…>` (or `Require all granted` if no allowlist) + `Require not ip <cidr>` per blocklist entry (apachegen/generate.go:171-183).
- **Steps (render D):** set both lists; preview; confirm the deny/allow ordering.
- **Steps (behaviour R):** `curl --resolve $HOST:443:$AGENT_IP https://$HOST/` from an IP outside the allowlist (or inside the blocklist) → **403**; from an allowed IP → 200.
- **Pass:** blocked/non-allowed client gets 403; allowed client gets through.
- **Coverage:** D / R.
- **Pitfalls (real bug we hit):** the observed client IP must be **deterministic** — drive the agent directly with `--resolve $HOST:443:<agent-ip>`. Going through the public edge / hairpin **mangles the source IP** (RELEASE-QA §2.6/§6) and your allowlist test will give the wrong verdict. Blocklist always wins over allowlist (it's evaluated first / is a terminal deny).

### rate_limit (nginx => 503 not 429; Apache DOES NOT support it)

- **Must:** caps per-client sustained throughput in requests/second (float64); `0` = disabled.
- **Access:** Dashboard Advanced tab / `proxy_config.rate_limit:5`.
- **Renders to:**
  - **Caddy:** a `rate_limit` handler (requires the `caddy-ratelimit` module) keyed on `{http.request.remote.host}`, `window: "1s"`, `max_events: int(rps)` (caddygen/generate.go:189-200). Test: rate 25 → `"max_events":25`. **Sub-1 rps truncates to 0** via `int()`.
  - **nginx:** an http-context `limit_req_zone $binary_remote_addr zone=nurproxy_<slug>:10m rate=<n>r/s;` **preamble** (lives in `Result.HTTPPreamble`, NOT the server block) + `limit_req zone=<zone> burst=<n> nodelay;` in the server block (nginxgen/generate.go:124-131, 201-203). Sub-1 rps is expressed as `r/m` (per minute) to avoid flooring to zero (`formatRate`). burst = `int(rps)` min 1. Test: rate 5 → preamble `rate=5r/s`, server `burst=5 nodelay`.
  - **Apache:** **DROPPED with warning** `rate_limit: Apache core has no per-client request rate limiting; option dropped` (apachegen/generate.go:126-128). Apache core has no per-client request-rate equivalent (mod_ratelimit only throttles bandwidth). No directive is emitted.
- **Steps (render D):** set `{"rate_limit":5}`; preview Caddy (max_events), nginx (preamble must carry the zone — confirm `GET …/config` for nginx includes the `limit_req_zone` line via `joinNginx`), Apache (expect the drop warning, no directive).
- **Steps (behaviour R):** hammer `curl --resolve $HOST:443:$AGENT_IP https://$HOST/` in a tight loop from one client IP. nginx: excess requests return **503** (not 429!). Caddy: excess return 429 (caddy-ratelimit default).
- **Pass:** sustained over-rate requests are throttled with the backend's status; Apache silently serves all (rate_limit dropped — confirm the warning is audited).
- **Coverage:** D / R.
- **Pitfalls (institutional knowledge, RELEASE-QA §2.6):** **nginx `limit_req` returns 503, not 429** — assert 503 for nginx. **Apache drops rate_limit entirely** — there is no per-client rate limiting; verify the warning shows in the agent's ArtifactReport / audit log rather than expecting throttling. The nginx zone lives in the **http preamble**, not the server block — a render check that only greps the server block will miss it; check the joined preview (`joinNginx`). Caddy needs the `caddy-ratelimit` module compiled in — the bundled binary may not have it.

### raw_config (escape hatch)

- **Must:** when set, the operator's raw native config is used **verbatim** instead of rendering from the structured fields; backend-tagged (`caddy`/`nginx`/`apache`).
- **Access:** Dashboard Advanced tab (raw config text area) / `proxy_config.raw_config:{"backend":"nginx","content":"server {…}"}` on the domain create/update body (`POST /api/v1/domains` or `PUT /api/v1/domains/{id}`, both accept a full `proxy_config`) / via the dedicated manual-config endpoint `PUT /api/v1/domains/{id}/config` with `{"config": …}`. Clear a manual override with `POST /api/v1/domains/{id}/config/reset` (`handleResetDomainConfig`, domains.go:560-587 — sets `ManualConfig=false`, clears `RawConfig`, re-pends the domain so it falls back to the auto-rendered config). All three are auth-gated (`server.go:204-206`).
- **Behaviour / rendering:**
  - The dedicated path body is `{"config": <json>}` (NOT `{"raw_config": …}`); `handleUpdateDomainConfig` sets `ManualConfig=true` and stores `RawConfig{Backend, Content}` tagged with the **serving agent's backend** (`backendForDomain`, domains.go:528). For caddy the body `config` is JSON (validated with `json.Valid`, else 400 `invalid JSON config`); for nginx/apache it must be the native config **as a JSON string** else 400 `config for <backend> must be the native config as a JSON string` (domains.go:530-543).
  - `GET …/config` returns `{"manual":true,"backend":…,"config":…}` for a manual domain — Caddy `config` is the parsed JSON object (falls back to the raw string if it doesn't parse), nginx/apache is the raw string (domains.go:352-371).
  - **Caddy renderer:** `GenerateRoute` returns the raw JSON verbatim if it is valid JSON; errors `invalid raw Caddy JSON` otherwise (caddygen/generate.go:128-138).
  - **nginx/apache renderers:** return `Result{Server/VHost: Raw.Content}` verbatim (nginxgen/generate.go:95-100, apachegen/generate.go:97-102).
  - **Backend mismatch is a hard error:** a payload tagged for a different backend → `raw config targets backend "X", not "Y"` (all three renderers refuse content not tagged for them). `ConfigFromDomain` defaults an empty backend tag to `caddy` (caddygen/generate.go:57-63).
- **Steps (render D):** `PUT …/config` with a backend-appropriate raw payload (`-d '{"config":"server {\n  listen 80;\n}"}'` for an nginx agent — note the JSON string; `-d '{"config":{...}}'` JSON object for a caddy agent); `GET …/config` → `manual:true` + your content echoed; then `curl -s -H "Authorization: Bearer $NP_API_KEY" -X POST http://localhost:8080/api/v1/domains/$DID/config/reset` and confirm `GET …/config` flips back to `manual:false` + the auto-rendered config.
- **Steps (behaviour R):** confirm the agent applies the verbatim config and the site serves as the raw config dictates.
- **Pass:** structured fields are ignored; the raw content is what's applied; backend mismatch errors out.
- **Coverage:** D / R.
- **Pitfalls:** the raw content must match the **serving agent's** backend — the API tags it with `backendForDomain`, so a Caddy-JSON blob on an nginx agent will be stored as nginx text and fail `nginx -t`. nginx/apache content must be sent as a **JSON string**, not a JSON object (400 otherwise). The orchestrator does NOT validate nginx/apache raw syntax — only the proxy does at apply time (`nginx -t` / `apachectl configtest`). A manual domain's preview returns the stored override, not a re-render.

### tls_policy

- **Must:** selects how the public-listener cert is provisioned: `central` (default — DNS-01 via orchestrator, agent runs on provided cert), `self-acme` (Caddy obtains its own cert; fallback), `off` (no TLS). Empty defaults to central unless `SSLMode==off`.
- **Access:** Dashboard Advanced tab / `proxy_config.tls_policy:"central"|"self-acme"|"off"`.
- **Resolution (`tlsPolicyFromDomain`, caddygen/generate.go:83-97):** explicit policy wins; empty → `off` if `domain.ssl_mode=="off"`, else `central`; an unrecognized value falls back to `central` (does not fail).
- **Renders to:**
  - **Caddy:** policy carried in the route's `TLS` config; central/self-acme handled by the agent's Caddy serving path (provided cert vs self-ACME); `off` = plaintext. (caddygen sets `TLS: {Policy: …}`; the listener/cert behaviour lives in the agent, not the route JSON renderer.)
  - **nginx:** `central` with cert+key on disk → `listen 443 ssl; http2 on; ssl_certificate…; ssl_certificate_key…`. `off` → plaintext `listen 80`. `self-acme` → **dropped to plaintext with warning** `tls: self-acme is not supported by the nginx backend; route served over plaintext HTTP` (nginx never does its own ACME). Central but **missing cert/key** → plaintext + warning `tls: no provided certificate available; route served over plaintext HTTP`. Wildcard cert adds a non-drop warning `tls_wildcard: wildcard certificate shares one private key across hosts (§7)`. (nginxgen `resolveTLS`, lines 276-298.)
  - **Apache:** identical policy logic — `central` → `:443 SSLEngine on` + cert/key; `off` → `:80`; `self-acme` → drop-to-plaintext warning; missing cert → drop-to-plaintext warning; wildcard → caveat warning (apachegen `resolveTLS`, lines 293-315).
- **Steps (render D):** preview with each policy. The preview supplies conventional cert paths (`/var/lib/nurproxy/certs/<host>.crt|.key`, domains.go:451-458) so a central route previews a real TLS listener. Set `{"tls_policy":"off"}` → expect plaintext `listen 80` / `:80`. Set `self-acme` on an nginx/apache preview → expect the self-acme-not-supported warning (visible via the agent's ArtifactReport in a real run).
- **Steps (behaviour R):** central → `curl --resolve $HOST:443:$AGENT_IP https://$HOST/` terminates TLS with the LE cert; off → only `:80` serves.
- **Pass:** the listener/cert behaviour matches the selected policy; unsupported combinations drop-to-plaintext with the documented warning rather than failing.
- **Coverage:** D (render + policy resolution unit-tested) / R (real TLS termination, self-acme serving — self-acme serving is a **known gap**, RELEASE-QA §4, needs a public host with open :80/:443).
- **Pitfalls:** `self-acme` is **Caddy-only** — nginx and Apache silently drop it to plaintext (warning). Empty policy + `ssl_mode=off` → off; otherwise empty → central (don't assume empty means "no TLS"). Built-in Caddy on central runs with `automatic_https` disabled on provided certs — see `docs/qa` Caddy serving notes / RELEASE-QA §2.5b regression-guards (`routes≥1` AND `tls_connection_policies≥1` AND `sslverify=0`).

### Default forwarding headers (always added)

- **Must:** every structured route adds standard forwarding headers regardless of `custom_request_headers`.
- **Renders to:**
  - **Caddy:** `X-Forwarded-Proto: {http.request.scheme}`, `X-Real-IP: {http.request.remote.host}` (caddygen/generate.go:219-222).
  - **nginx:** `proxy_set_header Host $host;`, `X-Real-IP $remote_addr;`, `X-Forwarded-For $proxy_add_x_forwarded_for;`, `X-Forwarded-Proto $scheme;` (nginxgen/generate.go:236-239).
  - **Apache:** `RequestHeader set X-Forwarded-Proto <http|https>` + `ProxyPreserveHost On` (mod_proxy_http auto-adds X-Forwarded-For/Host/Server) (apachegen/generate.go:223-232).
- **Steps:** preview any route; confirm the forwarding headers present. Behaviour: mini backend echoes them.
- **Pass:** forwarding headers reach the upstream.
- **Coverage:** D / R.
- **Pitfalls:** Apache's `X-Forwarded-Proto` is a static literal computed from `tlsEnabled` (not the live request scheme), so behind another TLS-terminator it can be wrong; Caddy/nginx use the live scheme variable.

### Dropped-with-warning matrix (invariant #4)

- **Must:** an option a backend can't express is **dropped, not fatal**, and surfaced as a `Warning` (`Option: Reason`) the agent logs + the orchestrator audits (proxymodel `Warnings` on `ArtifactReport`, wire.go:102-107). Caddy's `GenerateRoute` returns no warnings (it errors only on bad raw JSON / missing host/upstream/port).
- **Drop matrix (confirmed in code):**

  | Option | nginx | apache | caddy |
  |---|---|---|---|
  | `rate_limit` | rendered (`limit_req`, 503) | **DROPPED** "Apache core has no per-client request rate limiting" | rendered (needs caddy-ratelimit) |
  | `force_https` w/o TLS | DROPPED (warn) | DROPPED (warn) | rendered always |
  | `tls_policy: self-acme` | DROPPED to plaintext (warn) | DROPPED to plaintext (warn) | supported (Caddy self-ACME) |
  | central TLS, no cert/key | DROPPED to plaintext (warn) | DROPPED to plaintext (warn) | n/a (orchestrator-provided) |
  | `tls` wildcard | caveat warning (not a drop) | caveat warning (not a drop) | n/a here |
  | `basic_auth` w/o htpasswd path | DROPPED (warn) | DROPPED (warn) | rendered (inline) |
  | `max_body_size` unparseable | normalized (best-effort) | DROPPED (warn) | passed verbatim |
  | `timeout_idle` | not rendered (no warn) | not rendered (no warn) | rendered (keep-alive) |

- **Steps:** in a real run, set e.g. `rate_limit` on an Apache-backed domain; inspect the agent's `ArtifactReport.Warnings` and the **central audit log** — each dropped option appears as `<option>: <reason>` with `source` attributing the apply.
- **Pass:** unsupported options are dropped (apply still succeeds) and every drop is audited; nothing is silently honored where unsupported.
- **Coverage:** D (warnings are produced by the pure renderers — assertable in unit tests / dry apply) / R (audit-log surfacing end to end).
- **Pitfalls:** "not rendered" (e.g. `timeout_idle` on nginx/apache) produces **no** warning — it just doesn't appear; don't expect an audit entry for those. Wildcard produces a **caveat** warning even though TLS is rendered (it's not a drop). The orchestrator preview (`renderDomainPreview`) supplies no `AuthFile`, so basic_auth always warn-drops in the **preview** for nginx/apache even though the real agent renders it.

---

## Acceptance checklist

**Dry (every RC) — render + warning coverage:**
- [ ] `make test` green (the three `generate_test.go` suites assert every directive above).
- [ ] `GET /api/v1/domains/{id}/config` previews the serving backend (caddy JSON object; nginx/apache string) for a seeded sandbox domain.
- [ ] Each field set via `proxy_config` shows the expected directive in the preview: websocket, force_https, max_body_size, custom req/resp headers, path_strip, path_rewrite, upstream_scheme, timeouts, basic_auth (Caddy base64-of-bcrypt), ip allow/block ordering, rate_limit (Caddy max_events + nginx zone in preamble), tls_policy (off→:80, central→:443).
- [ ] `raw_config` round-trips verbatim via `PUT/GET …/config`; backend-mismatch errors; nginx/apache content rejected unless a JSON string; `POST …/config/reset` flips the domain back to `manual:false` (auto-rendered).
- [ ] Drop matrix: Apache rate_limit dropped; nginx/apache self-acme dropped-to-plaintext; force_https-without-TLS dropped — warnings present.

**Real run (before final, throwaway domain/agent):**
- [ ] custom_request_headers / custom_response_headers visible at the upstream / in `curl -I`.
- [ ] path_strip / path_rewrite: mini backend `path=` reflects the transform.
- [ ] websocket handshake completes through the proxy.
- [ ] max_body_size: over-limit body → 413 (Caddy/nginx).
- [ ] timeouts: stalled upstream trips `timeout_read`.
- [ ] basic_auth: no creds → 401, correct bcrypt creds → 200 (creds stored as **bcrypt hash**).
- [ ] ip_allowlist/ip_blocklist via `--resolve $HOST:443:<agent-ip>` (deterministic IP): blocked/non-allowed → 403.
- [ ] rate_limit: nginx over-rate → **503** (not 429); Caddy over-rate → 429; **Apache serves all** (rate_limit dropped + audited).
- [ ] tls_policy central → real TLS termination; off → plaintext-only. (self-acme serving is a known gap, §4.)
- [ ] Every dropped option appears in the central audit log via the agent's ArtifactReport warnings.

# Domains

A domain in NurProxy is a **subdomain that proxies to one of your servers**.
Creating one does two things: it adds a DNS record in the right zone, and it
configures the agent's proxy (Caddy) to forward traffic to your backend.

## Creating a domain

- **Subdomain** — the host part, like `app` for `app.example.com`.
- **Zone** — the parent domain the record lives in.
- **Server** — the backend address the agent forwards to (grouped by agent).
- **Port** — the port your backend listens on.

## Proxy settings

- **Force HTTPS** — redirect plain `http://` requests to `https://`. On by default.
- **WebSocket** — allow long-lived connections (chat, live updates) to pass through.
- **Max body size** — the largest request the proxy accepts, e.g. `100mb`. Raise it
  for large uploads; leave blank for the default.
- **Custom request headers** — extra headers added to requests sent upstream.

## Advanced: manual Caddy config

The **Advanced** tab lets you edit the raw Caddy JSON for a domain. This overrides
the automatic config entirely. It's an expert escape hatch — the editor validates
the JSON before saving and tells you if it's malformed. Use **Reset to automatic**
to drop your overrides and go back to the generated config.

## Advanced: raw nginx config

On an nginx agent the Advanced tab holds the domain's nginx `server` block.
The agent's root helper only writes a raw nginx config that stays inside a
fixed policy, checked the way nginx itself reads the file:

- At most two `server` blocks: the proxied server with exactly one
  `location / { ... }`, and optionally a port-80 server that only does
  `return 301 https://$host$request_uri;`. No other blocks (`http`, `map`,
  `upstream`, `if`, nested or additional `location`s, `*_by_lua_block`, ...)
  and no directives outside the server blocks.
- The values NurProxy owns must match exactly: `server_name` (once) is the
  domain, `listen` is `80`, `[::]:80`, `443 ssl` or `[::]:443 ssl` (plus
  `http2` on old nginx), `ssl_certificate` / `ssl_certificate_key` are the
  agent's certificate paths, and `location /` has exactly one
  `proxy_pass http(s)://host:port;` without variables.

Directives allowed in the server block and in `location /`:

| Directive | Accepted values |
|-----------|-----------------|
| `client_max_body_size` | a size such as `50m`, `1g`, `0` |
| `client_body_buffer_size` | a size such as `128k` |
| `add_header` | name, value (plain or double-quoted), optional `always` |
| `proxy_set_header` | name, value (plain or double-quoted) |
| `proxy_hide_header` | a header name |
| `proxy_http_version` | `1.0` or `1.1` |
| `proxy_connect_timeout`, `proxy_send_timeout`, `proxy_read_timeout` | a time such as `60`, `30s`, `500ms`, `5m`, `1h` |
| `proxy_buffering`, `proxy_request_buffering`, `proxy_ssl_server_name` | `on` or `off` |
| `proxy_buffer_size`, `proxy_busy_buffers_size` | a size such as `16k` |
| `proxy_buffers` | a count and a size, e.g. `8 16k` |
| `proxy_redirect` | `off` |
| `gzip`, `gzip_vary` | `on` or `off` |
| `gzip_comp_level` | `1` to `9` |
| `gzip_min_length` | a size such as `1k` |
| `gzip_types` | MIME types such as `text/css application/json`, or `*` |
| `gzip_proxied` | nginx's flags (`off`, `expired`, `no-cache`, `no-store`, `private`, `no_last_modified`, `no_etag`, `auth`, `any`) |
| `access_log` | `off` |

Only in the server block: `allow` / `deny` (an address, CIDR or `all`),
`server_tokens on|off`, and `error_log /var/log/nginx/error.log <level>`
(level `info` … `emerg`, the same form the Logging setting renders). Only in
`location /`: `proxy_pass` and the `rewrite ... break` forms the path
settings render. The port-80 redirect server takes `listen`, `server_name`,
`return` and the two logging directives.

Everything else is refused: `include`, `root`, `alias`, `set`, Lua/Perl/njs,
any directive that names a file (an `access_log` path, `proxy_temp_path`,
`proxy_ssl_certificate`, ...), variables or quotes where a plain value is
expected, and basic auth (use the domain's Basic auth setting instead). A
refused config is only kept if exactly these bytes are already live on the
host; otherwise the domain goes to **Error** and its message names the line
and directive, for example:

```
privileged managed proxy reconciliation failed: local managed apply planning refused the desired state: raw nginx config for app.example.com: line 12: nginx directive "include" is not allowed in the server block; ...
```

## Status

- **Pending** — being created or synced.
- **Active** — DNS and proxy are live.
- **Error** — something failed; the domain's settings show the message.
- **Deleting** — being torn down.

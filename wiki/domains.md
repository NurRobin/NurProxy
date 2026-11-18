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

## Path routes

A domain normally sends every request to its server and port. The **Paths** tab
sends some request paths to other servers instead, for example
`/api/world` to `192.168.178.210:80` while everything else stays on
`192.168.178.210:2412`.

- **Prefix** `/api` matches `/api` and everything below it (`/api/users`),
  but not `/apix`. A prefix has no trailing slash, and `/` is not allowed (that
  is the domain's own server).
- **Exact** `/api/world` matches only that path. The query string does not
  matter.
- An exact route wins over any prefix, and the longest prefix wins. The order
  of the list does not change which route answers.
- **Strip path before forwarding** (prefix only) removes the prefix, so
  `/api/users` reaches the server as `/users` and `/api` as `/`.
- Each route has its own server, port, upstream scheme (http/https) and
  WebSocket switch. Request headers, timeouts, basic auth, IP lists, rate
  limit, body size and logging of the domain apply to every route. The
  domain's path rewrite and strip settings only apply to its own server.
- The server must belong to the same agent as the domain's server, because
  that agent proxies every path of the domain.
- Paths may only use letters, digits, `-`, `.`, `_` and `/`. Regular
  expressions are not supported: nginx, Apache and Caddy would read the same
  regex differently.
- The built-in Caddy compares paths case-insensitively (`/API` matches
  `/api`), nginx and Apache do not.

nginx, Apache and the built-in Caddy all support path routes. A custom engine
only does when its template declares `path_routes`. Agents that do not report
the capability (including agents older than this feature) are refused when you
save routes. If a route can no longer be served, for example because its
server was removed or the agent switched to a backend without path routes,
the domain goes to **Error** with the reason instead of being served without
that path.

A server that a path route uses cannot be deleted until the route is removed.

### Importing an existing nginx vhost

When an agent adopts an existing nginx config, the config view's form shows
its `location = /path` and `location /path/` blocks as path routes. Anything it
cannot carry over, such as a regex location, a location that serves files or
one with its own headers, is listed under **Not carried over into the form**
and kept in the raw text. Nothing is dropped without a note.

## Advanced: manual Caddy config

The **Advanced** tab lets you edit the raw Caddy JSON for a domain. This overrides
the automatic config entirely. It's an expert escape hatch — the editor validates
the JSON before saving and tells you if it's malformed. Use **Reset to automatic**
to drop your overrides and go back to the generated config.

## Status

- **Pending** — being created or synced.
- **Active** — DNS and proxy are live.
- **Error** — something failed; the domain's settings show the message.
- **Deleting** — being torn down.

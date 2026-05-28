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

## Status

- **Pending** — being created or synced.
- **Active** — DNS and proxy are live.
- **Error** — something failed; the domain's settings show the message.
- **Deleting** — being torn down.

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

## Zone wildcard certificate

By default every domain gets its own certificate. **Use the zone wildcard
certificate** switches a domain to one shared `*.<zone>` certificate instead,
for example `*.example.com` for `app.example.com`. All domains of the zone with
the setting on share that one certificate: it is issued once, renewed once, and
installed on each agent under the domain's own name, so the proxy config looks
the same as with a per-host certificate.

- Only a single label directly below the zone can use it. `app.example.com`
  works; `app.sub.example.com` and the zone apex (`example.com`, subdomain `@`)
  are refused, because `*.example.com` does not cover them. The apex keeps its
  own certificate.
- It needs central TLS (the default). A domain with TLS off or `self-acme` is
  refused.
- The same private key ends up on every agent that serves a wildcard domain of
  the zone. If one of those agents is compromised, the key is exposed for all of
  them. Per-host certificates avoid that, so turn this on only when you need it
  (for example to stay under Let's Encrypt's per-domain limits).
- An imported certificate for the host (`PUT /api/v1/domains/{id}/certificate`)
  still wins while it is valid for more than 30 days. After that the wildcard
  takes over; central renewal does not replace an imported certificate of a
  wildcard domain with a per-host one.
- The Cloudflare proxy setting is independent: a proxied wildcard domain serves
  the wildcard certificate to Cloudflare as its origin certificate.
- When the last wildcard domain of a zone is deleted, moves to another zone, or
  turns the setting off, the shared certificate is deleted on the next
  reconcile cycle. A domain that turns it off gets its own certificate issued.

API: the field is `proxy_config.tls_wildcard` (boolean). `POST /api/v1/domains`
and `PUT /api/v1/domains/{id}` also accept a top-level `tls_wildcard` as a
shortcut. A refused combination returns `400` with a message that starts with
`tls_wildcard:`. The shared certificate is stored and audited under the host
`*.<zone>`.

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

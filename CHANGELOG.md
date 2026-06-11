# Changelog

All notable changes to NurProxy are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-06-07

A hardening and developer-experience release: the control plane can now be
developed and validated end-to-end without touching live DNS, ACME, or
privileged ports, the security posture of the orchestrator is tightened, and
operators get IPv6 support, first-class backups, structured logging, and a
health endpoint that actually checks the database.

### Highlights

- **Security hardening** (#60): randomized session key, constant-time comparison
  for secrets, a tightened CORS policy, and brute-force protection on the login
  path. Several authentication and credential-handling paths were reviewed and
  fixed together. This release additionally tightens the runtime defaults:
  secure session cookies for non-localhost requests, global session revocation
  on logout and password change, a request-body size cap on the REST API,
  per-IP rate limiting on agent registration, and a hard separation between
  agent and admin credentials (see **Changed** below).
- **Dry-run / sandbox mode** (#94, #95): run the full control plane —
  orchestrator, agents, reconciler, DNS state machine, TLS issuance/renewal, the
  agent↔orchestrator stream, and route rendering — while every DNS and ACME call
  and the agent's proxy is simulated. No live Cloudflare zone, no Let's Encrypt,
  no `:80`/`:443`, no root, no rate-limit risk. `make dev-sandbox` brings the
  whole stack up in one command; `make test-sandbox` asserts convergence in CI.
- **IPv6 / AAAA records** (#61): agents with a public IPv6 address now publish an
  AAAA record alongside their A record, so dual-stack edges resolve over IPv6.
- **Backup & restore** (#63): `nurproxy backup` and `nurproxy restore` snapshot
  and recover the full orchestrator data directory (SQLite database, encrypted
  provider configs, and certificate store) from the CLI.
- **Structured logging** (#62): the orchestrator and agent emit structured
  `slog` output with the log level and format (text/JSON) controllable via
  environment variables.
- **Health DB check** (#65): `/api/v1/health` now performs a real database probe
  and returns `503` when the database is wedged, instead of reporting healthy
  regardless of backing-store state.

### Added

- Agent/orchestrator version-skew detection, surfaced in the dashboard (#67).
- Host-subnet detection that suggests reachable subnets in the Server dialog (#59).
- Inferred backend servers from existing nginx configuration (#56).
- Dashboard config view: search, filter, and agent→server grouping (#53).
- Inline command explanations and expanded wiki content.

### Changed

- TLS issuance retries transient failures with exponential backoff and parses an
  ACME rate-limit "retry after" instant into a typed `RateLimitError`.
- **Session cookies are marked `Secure` when the request arrives over HTTPS**
  (direct TLS or `X-Forwarded-Proto: https` from a TLS-terminating proxy), so the
  cookie is only sent back over HTTPS where that applies. A plain-HTTP deployment
  reached over its IP keeps working and is not locked out. The `secure_cookies`
  setting still forces the attribute on or off explicitly.
- **Logout and password change now force a global re-login.** Both perform
  server-side session revocation, so every existing session — across all
  browsers and devices — is invalidated, not just the current one.
- **REST API request bodies are now capped at ~4 MiB.** Oversized requests are
  rejected instead of being read into memory.
- **`/agents/register` is now rate-limited per source IP** to slow down
  registration abuse.
- **Agent bearer tokens can no longer reach admin/management endpoints**
  (H1 hardening): agent and admin credentials are now strictly separated. An
  agent token is accepted only on the agent protocol endpoints.
- `golang.org/x/net` bumped to v0.55.0.

### Fixed

- Audit log no longer re-logs `option_dropped` on every unchanged ACK.
- Deleting a server, agent, or zone that still has domains is now refused with
  `409` (the response lists the blocking domains). Previously the database's
  `ON DELETE CASCADE` hard-removed those domain rows before the reconciler could
  tear them down, orphaning their DNS records and certificates at the provider
  with no audit trail. Delete the domains first (each routes through the proper
  teardown), then the parent.
- **Built-in-Caddy agents no longer scrub the provided certificate of an active
  route.** The post-apply cert prune was fed only file-backend targets, so on a
  Caddy agent its keep set never matched any live route and it deleted every
  route's central-TLS cert on the apply after issuance — leaving `:443` unable to
  serve. The keep set now includes the applied Caddy route targets.
- **Built-in Caddy now actually serves HTTPS on central TLS** (#106). Three gaps
  on the real-Caddy path (which the dry/sandbox harness never exercises) stopped
  the default agent mode from terminating TLS: a TLS-strategy apply could create
  `srv0` with no `routes` array, so the route's `POST` was rejected as a
  `RouteList`; and with `automatic_https` disabled Caddy adds no TLS connection
  policy, so `srv0` served plaintext on `:443`. EnsureServer now seeds the routes
  array (and runs before the TLS strategy), and the strategy now sets a default
  `tls_connection_policies` so Caddy serves the provided cert by SNI. A built-in
  Caddy agent with central TLS now serves real HTTPS end to end.

## Upgrade notes

- **Back up before upgrading.** `nurproxy backup` ships *in* 0.3.0, so it is not
  available on the version you are upgrading from. Stop the orchestrator and copy
  its data directory (default `/var/lib/nurproxy`) before installing 0.3.0, so you
  can roll back if needed. From 0.3.0 onward, `nurproxy backup` does this for you.
- **Pre-0.3.0 DNS records are treated as adopted, not auto-deleted.** DNS records
  created by NurProxy before this release are now treated as *adopted* records.
  On teardown (deleting a domain or agent) they are left in place at your DNS
  provider rather than being automatically deleted, to avoid removing records the
  older code did not track ownership of. Remove such records manually if you no
  longer want them. Records created on 0.3.0 and later carry ownership metadata
  and are cleaned up on teardown as before.

### Security defaults that may require operator action

- **Secure session cookies now follow the request scheme.** The cookie is marked
  `Secure` only when the request reaches the orchestrator over HTTPS (direct TLS
  or `X-Forwarded-Proto: https`). Reaching the dashboard over plain HTTP, for
  example by IP, keeps working. If you terminate TLS at an upstream proxy, make
  sure it forwards `X-Forwarded-Proto`, or set the `secure_cookies` setting to
  `true` to force the attribute on.
- **All sessions are invalidated on logout and password change.** Both now
  perform server-side revocation, forcing a global re-login. After upgrading and
  on any logout or password change, every active session across all devices is
  signed out and users must authenticate again.
- **Agent tokens no longer work against admin/management APIs.** Agent bearer
  tokens are now rejected on admin/management endpoints. If any tooling or
  scripts used an agent token to call admin APIs, switch them to the admin API
  key.
- **REST API request bodies are capped at ~4 MiB and `/agents/register` is
  rate-limited per IP.** Clients sending larger payloads, or registering many
  agents from a single IP in a short window, may now be rejected.

[0.3.0]: https://github.com/NurRobin/NurProxy/releases/tag/v0.3.0

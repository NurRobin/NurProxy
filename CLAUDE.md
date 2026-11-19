# NurProxy Development Guide

## Build Commands
```bash
make build          # Build orchestrator
make build-agent    # Build agent
make build-all      # Build both
make test           # Run unit tests
make test-cover     # Tests with coverage report
make lint           # Run golangci-lint
```

## Project Layout
- `cmd/nurproxy/` — Orchestrator entry point
- `cmd/nurproxy-agent/` — Agent entry point
- `internal/orchestrator/` — Orchestrator logic (API, DB, reconciler, TLS issuance)
- `internal/agent/` — Agent logic (proxy management, adoption, heartbeat)
- `internal/agent/proxy/` — Proxy backend interface + Caddy, nginx, Apache implementations
- `internal/provider/` — DNS provider plugin system
- `internal/shared/` — Shared code (models, auth, crypto, route generation)
- `web/` — Dashboard (Vite + React + Tailwind)

## Dry-run / Sandbox mode (developing & validating features)

Dry-run runs the **full control plane** — orchestrator + agents, reconciler, DNS
state machine, TLS issuance/renewal, the agent↔orchestrator stream, route
rendering — while **simulating every DNS and ACME call and the agent's proxy**.
No live Cloudflare zone, no Let's Encrypt, no `:80`/`:443`, no root, no
rate-limit risk. This is the default way to develop and validate any feature that
lives in the control plane. Implemented in `internal/provider/dryrun` (DNS),
`internal/orchestrator/tls/dryrun.go` (ACME → self-signed cert), and the agent's
in-memory mock proxy path.

### Fastest path: the whole stack in one command
```bash
make dev-sandbox                 # orchestrator + 1 agent, seeded topology, dashboard up
make dev-sandbox AGENTS=3        # multiple agents on one box (no port conflicts)
PORT=9000 make dev-sandbox       # orchestrator on :9000
KEEP=0 make dev-sandbox          # seed then tear down (smoke check)
PROFILE=live make dev-sandbox    # agents run a REAL Caddy on 127.0.0.1:18080/18443 (needs caddy)
```
This builds both binaries, starts a dry orchestrator + N dry agents, and seeds a
provider (dummy token), zone, adopted agents, servers and central-TLS domains —
a fully populated, "live"-looking environment. Launcher: `scripts/dev-sandbox.sh`.

### Running the binaries dry by hand
```bash
# Orchestrator — both subsystems, or per-subsystem for partial testing:
NP_DRY_RUN=true ./nurproxy                 # mock DNS + ACME   (or: ./nurproxy -dry-run)
NP_DNS_DRY_RUN=true ./nurproxy             # mock DNS, real ACME (see caveat below)
NP_ACME_DRY_RUN=true ./nurproxy            # real DNS, mock ACME
NP_ACME_DRY_RUN=true NP_DRY_RUN_FAIL=ratelimit ./nurproxy   # inject ACME failure:
                                           #   ratelimit | challenge | propagation

# Agent — proxy simulated in-memory (no Caddy process, no :80/:443, unprivileged):
NP_DRY_RUN=true ./nurproxy-agent -orchestrator http://localhost:8080 -fqdn edge1.example.com
                                           # (or pass -dry-run). Data dir auto-relocates
                                           # to a per-FQDN temp dir; run many agents at once.
NP_DRY_RUN=true NP_DRY_RUN_DISK_CERTS=legacy.example.com ./nurproxy-agent ...
                                           # also report a simulated on-disk certbot bundle
                                           # for those names, to exercise cert adoption (#80)
```
Provider setup (validate + list-zones) is mocked too, so a Cloudflare provider
created with a dummy token works end-to-end.

> **Caveat — `NP_DNS_DRY_RUN` + real ACME always fails DNS-01.** Mock DNS keeps
> the challenge TXT record in the in-memory store only; it is never published to
> a resolvable zone. A real Let's Encrypt validation server therefore cannot see
> the `_acme-challenge` TXT and the DNS-01 order fails. Use this combination only
> to exercise non-issuance DNS paths; for end-to-end TLS testing run full dry-run
> (`NP_DRY_RUN`) or `NP_ACME_DRY_RUN` (real DNS, mock ACME) instead.

### How to use it when building a feature
1. Bring the stack up (`make dev-sandbox`), or boot the binaries dry by hand.
2. Drive it via the dashboard, the management CLI, or the REST API and watch the
   real flow converge: provider → zone → adopt → server → domain → simulated
   DNS-01 → self-signed cert → push → install → render → DNS records → `active`.
3. Inspect outcomes: `/api/v1/health` reports `dry_run`/`dns_dry_run`/`acme_dry_run`;
   the dashboard shows a persistent "Dry-run mode" banner; every simulated DNS/cert
   call is tagged `source=dryrun` in the audit log (real events stay `system`),
   and each would-be provider call is logged with its full record shape.
4. Add an end-to-end assertion to `test/sandbox` (build tag `sandbox`) and run
   `make test-sandbox` — it boots the whole dry stack and asserts convergence
   with zero external deps. It also runs in CI on every push/PR targeting
   `main`, `dev`, or a `release/**` branch.

### Live profile: real traffic through a real Caddy
`PROFILE=live make dev-sandbox` keeps the orchestrator dry (no external DNS or
ACME, no root) but runs each agent WITHOUT `-dry-run`: the agent starts a real
built-in Caddy bound to `127.0.0.1` on unprivileged ports and proxies to a small
fake upstream (`test/sandbox/fakeupstream`, started by the script):
```bash
PROFILE=live make dev-sandbox                    # needs caddy on PATH (or CADDY_BIN=...)
curl -k --resolve app1.sandbox.test:18443:127.0.0.1 https://app1.sandbox.test:18443/
PROFILE=live KEEP=0 AGENTS=2 make dev-sandbox    # smoke: exits non-zero unless every app<n> serves
make test-sandbox-live                           # scripted e2e (skips without caddy)
```
Knobs: `HTTP_PORT` (18080), `HTTPS_PORT` (18443), `ADMIN_PORT` (12019),
`UPSTREAM_PORT` (18081), `LISTEN_HOST` (127.0.0.1); agent n adds `10*(n-1)` to
each Caddy port. The agent side of this is three agent knobs, default unchanged:
`-caddy-http-port`, `-caddy-https-port`, `-caddy-listen-host` (env
`NP_CADDY_HTTP_PORT`/`NP_CADDY_HTTPS_PORT`/`NP_CADDY_LISTEN_HOST`, yaml
`caddy_http_port`/`caddy_https_port`/`caddy_listen_host`). Non-default ports are
also written to Caddy's `http_port`/`https_port`, which Caddy needs to know which
listener stays plaintext.

### Real-proxy checks in the sandbox tests
`test/sandbox` uses real proxy binaries when it finds them and skips those
checks (with a log line) when not:
- **caddy** (`NP_SANDBOX_CADDY` or PATH): the dry built-in agent's recorded routes
  + TLS strategy go through `caddy validate`, and `TestSandboxLiveTraffic` serves
  real HTTPS/HTTP through Caddy (cert = the dry-issued one, force_https redirect,
  live updates, a second domain's cert loading on a running Caddy).
- **nginx** (`NP_SANDBOX_DOCKER=1` runs `nginx:1.29-alpine` as your uid on the
  unchanged files; otherwise `NP_SANDBOX_NGINX` or PATH, and as non-root on copies
  whose `listen` ports below 1024 are moved, because `nginx -t` binds them): the
  existing-mode agent's rendered vhosts get `nginx -t` with their real cert paths.
CI installs a pinned, checksummed Caddy and sets `NP_SANDBOX_DOCKER=1`, so all of
these run on every push/PR.

### What it covers vs. what it doesn't
- **Covered (develop exactly like prod):** orchestrator/API/CLI/dashboard, the DNS
  state machine (create/adopt/drift/delete), TLS issuance + renewal-window logic,
  the agent protocol (register/adopt/heartbeat/stream/ACK), route rendering
  (real `caddygen` — artifacts identical to prod built-in Caddy), and multi-agent.
  With caddy installed also: Caddy accepting the rendered config, and real
  HTTP/TLS serving through the built-in Caddy (live profile). With nginx (or
  docker) also: `nginx -t` on the rendered vhosts.
- **Not covered:** certs are self-signed (no real chain) and DNS records are
  in-memory (not resolvable); the live profile serves loopback only, on
  non-standard ports; nginx/apache existing-mode reload and serving are not
  exercised (the existing-mode agent's nginx is a fixture, only `nginx -t` is
  real), and Apache output is not validated by the sandbox (the
  `-tags=integration` tests cover it against `httpd:alpine`).

## Conventions
- Go 1.25+, standard library preferred
- Table-driven tests, `_test.go` beside source
- No test frameworks — use `testing` package only
- Conventional commits: `feat:`, `fix:`, `chore:`, `docs:`, `test:`
- Error handling: return errors, don't panic in library code
- Context as first parameter where applicable

## Commit attribution
- Commits and PRs are authored **solely under the repository owner**. An AI
  assistant is a tool, not an author or co-owner — it gets no attribution.
- Never add `Co-Authored-By:`, `Co-developed-by:`, `Assisted-by:` or
  `Signed-off-by:` trailers for any AI assistant, and no "Generated with …"
  footer in PR descriptions. The human author takes full responsibility.

## Database
- SQLite via `modernc.org/sqlite` (pure Go, no CGo)
- Migrations in `internal/orchestrator/db/migrations.go`
- Provider configs encrypted with AES-256-GCM at rest

## DNS Providers
- Interface: `internal/provider/provider.go`
- Add new: implement interface, register in `init()`
- Cloudflare ships first: `internal/provider/cloudflare/`

## Releasing
- Full runbook: [RELEASING.md](RELEASING.md).
- Branch model: `dev` (integration) → `release/X.Y.Z` (freeze + RCs) → `main`
  (released code only, always == latest tag).
- Tag-driven: any `v*` tag runs `release.yml`. A `-rc`/`-beta` suffix builds a
  GitHub pre-release + versioned GHCR image + signed binaries for real testing,
  while `:latest`, Homebrew, AUR and the apt/yum repo stay on the last final tag.
- Final release: merge `release/X.Y.Z → main`, then tag `vX.Y.Z` (no suffix).

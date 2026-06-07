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
- `internal/proxy/` — Proxy backend interface + Caddy, nginx, Apache implementations
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
```
This builds both binaries, starts a dry orchestrator + N dry agents, and seeds a
provider (dummy token), zone, adopted agents, servers and central-TLS domains —
a fully populated, "live"-looking environment. Launcher: `scripts/dev-sandbox.sh`.

### Running the binaries dry by hand
```bash
# Orchestrator — both subsystems, or per-subsystem for partial testing:
NP_DRY_RUN=true ./nurproxy                 # mock DNS + ACME   (or: ./nurproxy -dry-run)
NP_DNS_DRY_RUN=true ./nurproxy             # mock DNS, real ACME
NP_ACME_DRY_RUN=true ./nurproxy            # real DNS, mock ACME
NP_ACME_DRY_RUN=true NP_DRY_RUN_FAIL=ratelimit ./nurproxy   # inject ACME failure:
                                           #   ratelimit | challenge | propagation

# Agent — proxy simulated in-memory (no Caddy process, no :80/:443, unprivileged):
NP_DRY_RUN=true ./nurproxy-agent -orchestrator http://localhost:8080 -fqdn edge1.example.com
                                           # (or pass -dry-run). Data dir auto-relocates
                                           # to a per-FQDN temp dir; run many agents at once.
```
Provider setup (validate + list-zones) is mocked too, so a Cloudflare provider
created with a dummy token works end-to-end.

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
   with zero external deps. It also runs in CI on every push/PR.

### What it covers vs. what it doesn't
- **Covered (develop exactly like prod):** orchestrator/API/CLI/dashboard, the DNS
  state machine (create/adopt/drift/delete), TLS issuance + renewal-window logic,
  the agent protocol (register/adopt/heartbeat/stream/ACK), route rendering
  (real `caddygen` — artifacts identical to prod built-in Caddy), and multi-agent.
- **Not covered (still needs a real Caddy/agent):** serving real traffic — the dry
  agent does not bind a listener or proxy real requests; certs are self-signed
  (no real chain) and DNS records are in-memory (not resolvable); nginx/apache
  existing-mode apply/reload is not exercised. See issue #96 (low-prio nice-to-have)
  for the optional live-traffic harness.

## Conventions
- Go 1.23+, standard library preferred
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

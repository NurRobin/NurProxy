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
- `internal/orchestrator/` — Orchestrator logic (API, DB, reconciler)
- `internal/agent/` — Agent logic (Caddy, adoption, heartbeat)
- `internal/provider/` — DNS provider plugin system
- `internal/shared/` — Shared code (models, auth, crypto, caddygen)
- `web/` — Dashboard (Vite + React + Tailwind)

## Conventions
- Go 1.23+, standard library preferred
- Table-driven tests, `_test.go` beside source
- No test frameworks — use `testing` package only
- Conventional commits: `feat:`, `fix:`, `chore:`, `docs:`, `test:`
- Error handling: return errors, don't panic in library code
- Context as first parameter where applicable

## Database
- SQLite via `modernc.org/sqlite` (pure Go, no CGo)
- Migrations in `internal/orchestrator/db/migrations.go`
- Provider configs encrypted with AES-256-GCM at rest

## DNS Providers
- Interface: `internal/provider/provider.go`
- Add new: implement interface, register in `init()`
- Cloudflare ships first: `internal/provider/cloudflare/`

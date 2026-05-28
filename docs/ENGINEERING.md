# Engineering Practices

This document captures the engineering standards, tooling, and processes for NurProxy. It is the single source of truth for how we build, test, and ship.

---

## Testing Strategy

### Unit Tests

- Place `_test.go` files beside the source files they test.
- Use the standard `testing` package only. No testify, no gomock, no third-party assertion libraries.
- Prefer table-driven tests for functions with multiple input/output combinations.
- Name tests `TestFunctionName_scenario_expectedBehavior`, for example:
  ```
  TestResolveProvider_unknownName_returnsError
  TestParseConfig_validYAML_setsDefaults
  ```
- Use interfaces and hand-written test implementations instead of mocking frameworks. If a dependency needs to be faked, define a small interface at the call site and provide a struct that satisfies it in the test file.
- Keep tests deterministic. No `time.Sleep`, no real network calls, no reliance on wall-clock time.

### Integration Tests

- Guard with `//go:build integration` at the top of the file.
- Run with `go test -tags integration ./...`.
- Test against real dependencies where practical:
  - SQLite: use an in-memory database (`:memory:`) to validate schema migrations and queries.
  - HTTP handlers: use `httptest.Server` to exercise the full handler chain including middleware.
- Integration tests may touch the filesystem via `t.TempDir()`.

### End-to-End Tests

- Guard with `//go:build e2e` at the top of the file.
- Run with `go test -tags e2e ./...`.
- Stand up the full orchestrator + agent topology with a mock DNS provider.
- Validate observable behavior: certificate issuance, proxy routing, health endpoints.
- These tests are slower and run only in CI, not in the default `go test` invocation.

### Coverage

- Target >70% line coverage for core packages:
  - `internal/shared/`
  - `internal/provider/`
  - `internal/orchestrator/db/`
- Coverage is informational, not a gate. A drop below 70% should prompt investigation but does not block a merge.
- Generate coverage with `go test -coverprofile=coverage.out ./...` and review with `go tool cover -func=coverage.out`.

### Frontend Tests

- Use Vitest for utility and hook tests.
- Use React Testing Library for component tests. Test behavior, not implementation details.
- No snapshot tests unless they guard a specific regression.

---

## CI/CD Pipeline

### `ci.yml` -- Pull Requests and Push to Main

Trigger: on `pull_request` and `push` to `main`.

Steps (target ~5 min total):

1. **Lint**
   - Go: `golangci-lint run ./...`
   - Frontend: `npx eslint .` and `npx prettier --check .`
2. **Test**
   - Go: `go test -race -tags integration ./...`
   - Frontend: `npx vitest run`
3. **Build**
   - Go: build both `nurproxy-orchestrator` and `nurproxy-agent` binaries.
   - Frontend: `npm run build` (ensures the production bundle compiles).

Caching:
- Cache `~/go/pkg/mod` keyed on `go.sum`.
- Cache `node_modules` keyed on `package-lock.json`.

### `release.yml` -- Tagged Releases

Trigger: on push of tags matching `v*`.

Steps:

1. Build frontend production bundle.
2. Embed frontend assets into the orchestrator binary.
3. Run goreleaser to cross-compile:
   - `linux/amd64`
   - `linux/arm64`
   - `linux/arm/v7`
4. Build and push multi-arch Docker images to `ghcr.io/nurrobin/nurproxy`.
5. Create a GitHub Release with auto-generated changelog and attached binaries.

---

## Release Plan

### Versioning

- Semantic versioning: `MAJOR.MINOR.PATCH`.
- During pre-1.0 development, use `v0.x.y`. Breaking changes bump MINOR, non-breaking changes bump PATCH.
- Pre-release versions follow the pattern `v0.1.0-alpha.1`, `v0.1.0-beta.1`, `v0.1.0-rc.1`.

### Release Process

1. Ensure `main` is green.
2. Tag the commit: `git tag v0.x.y && git push origin v0.x.y`.
3. The `release.yml` workflow handles the rest: build, package, publish.
4. Changelog is auto-generated from conventional commit messages since the previous tag.

### Artifacts

- **Binaries**: standalone Linux binaries for amd64, arm64, armv7 (via goreleaser).
- **Docker images**: multi-arch images pushed to `ghcr.io`.
- **GitHub Release**: binaries + checksums + changelog attached to the release page.

---

## Branch and PR Rules

### Branch Naming

| Purpose        | Pattern                    | Example                       |
|----------------|----------------------------|-------------------------------|
| Feature        | `feat/short-description`   | `feat/wildcard-certs`         |
| Bug fix        | `fix/short-description`    | `fix/renewal-race-condition`  |
| Chore/tooling  | `chore/short-description`  | `chore/upgrade-go-1.23`       |
| Documentation  | `docs/short-description`   | `docs/api-reference`          |

### Rules

- `main` is the default branch and is protected.
- All changes reach `main` through a pull request.
- PRs require at least one approving review before merge.
- Squash merge is the preferred merge strategy. The squash commit message should follow conventional commit format.
- Delete the source branch after merge.

### PR Expectations

- Fill in the PR template (Summary + Test plan).
- Keep PRs focused. One logical change per PR.
- If a PR touches both backend and frontend, that is acceptable as long as the changes are cohesive.

---

## Commit Conventions

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification.

### Format

```
<type>(<optional scope>): <description>
```

- **Imperative mood**, lowercase, no period at the end.
- Examples:
  ```
  feat(provider): add Cloudflare DNS-01 challenge support
  fix(agent): prevent duplicate certificate renewal requests
  chore: update Go to 1.23
  docs: add provider configuration examples
  test(orchestrator): add integration tests for certificate storage
  refactor: extract shared TLS utilities into internal/shared
  ```

### Types

| Type       | When to use                                      |
|------------|--------------------------------------------------|
| `feat`     | New feature or capability                        |
| `fix`      | Bug fix                                          |
| `chore`    | Maintenance, dependencies, CI config             |
| `docs`     | Documentation only                               |
| `test`     | Adding or updating tests                         |
| `refactor` | Code change that neither fixes a bug nor adds a feature |

### Scope

Scope is optional. Use it when the change is clearly within one area:

- `provider`, `orchestrator`, `agent`, `shared`, `frontend`, `ci`

---

## Code Style

### Go

- Format all code with `gofmt`. This is enforced by CI.
- Lint with `golangci-lint` using the project `.golangci.yml` config.
- **Errors are values.** Return errors; do not `panic` in library code. Reserve `panic` for truly unrecoverable situations in `main` or initialization.
- **Context as first parameter.** Functions that accept a `context.Context` take it as the first argument, named `ctx`.
- **No global mutable state.** The provider and notifier registries are the only acceptable globals, and they are populated at init-time only.
- **Struct initialization.** Use named fields. Do not rely on positional initialization.
- **Logging.** Use structured logging (`slog`). Include relevant context fields (certificate domain, provider name, agent ID).

### Frontend (TypeScript + React)

- Format with Prettier. Lint with ESLint.
- TypeScript in strict mode (`"strict": true` in `tsconfig.json`).
- Functional components only. No class components.
- Colocate component-specific styles with the component.
- Prefer named exports over default exports.

### General

- No abbreviations in public API names unless universally understood (`HTTP`, `TLS`, `DNS`, `ID`).
- Write comments that explain *why*, not *what*. The code should be clear enough to explain *what*.
- TODOs are acceptable in development but should reference an issue number: `// TODO(#42): handle renewal retry backoff`.

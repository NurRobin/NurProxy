# Contributing to NurProxy

## Branch model

NurProxy uses a two-tier protected-branch flow. **No one pushes directly to
`main` or `dev`** — every change lands through a pull request that passes CI.

| Branch        | Role                                  | Protected |
| ------------- | ------------------------------------- | --------- |
| `main`        | Release branch. Always deployable.    | yes       |
| `dev`         | Integration branch. Day-to-day target.| yes       |
| `feat/*` etc. | Short-lived work branches.            | no        |

### Everyday flow

1. Branch off **`dev`**:
   ```bash
   git checkout dev && git pull
   git checkout -b feat/my-change
   ```
2. Commit using [Conventional Commits](https://www.conventionalcommits.org/)
   (`feat:`, `fix:`, `chore:`, `docs:`, `test:`).
3. Open a PR into **`dev`**. CI (Lint, Test, Build) must pass before it can merge.
4. When `dev` is ready to ship, open a PR from **`dev` into `main`**. That merge
   is what cuts a release-ready `main`.

Tagging a `v*` tag on `main` triggers the release workflow (GoReleaser).

### Branch naming

`feat/…` features · `fix/…` bug fixes · `chore/…` tooling/infra · `docs/…` docs ·
`test/…` tests.

## Before you open a PR

```bash
make test    # go test -race ./...
make lint    # golangci-lint + frontend eslint
make build   # builds dashboard + both binaries
```

CI runs the same checks on every PR into `main` and `dev`; all three
(**Lint**, **Test**, **Build**) are required to merge.

## Protection rules (enforced on `main` and `dev`)

- Pull request required before merging (no direct pushes).
- Required status checks: `Lint`, `Test`, `Build` (branch must be up to date).
- Force-pushes and branch deletion are blocked.
- Conversation resolution required before merge.

`main` additionally enforces these rules for administrators.

# Releasing NurProxy

How we cut a release: branch model, the release-candidate flow, and what each
tag publishes. The pipeline is tag-driven — `release.yml` fires on any `v*` tag
and runs GoReleaser (`.goreleaser.yml`); `repo.yml` rebuilds the apt/yum repo.

## Branch model

| Branch | Role |
|--------|------|
| `dev` | Integration branch. All feature/fix PRs merge here. CI runs on every push/PR. |
| `release/X.Y.Z` | Short-lived freeze branch for a release. RCs are tagged here; review fixes land here. |
| `main` | **Released code only.** Always equals the latest shipped tag. Never receives un-reviewed work. |

Principle: **review happens before `main`, never after.** `main` is what people
check out and base work on — it must always be releasable.

## Versioning (pre-1.0, semver-ish)

- New features → **minor** (`0.2.x` → `0.3.0`).
- Bug fixes only → **patch** (`0.3.0` → `0.3.1`).
- Release candidates → suffix the target version: `v0.3.0-rc.1`, `-rc.2`, …
- Tags are always `v`-prefixed and annotated.

## What a tag publishes

`release.yml` triggers on every `v*` tag. GoReleaser's `prerelease: auto` treats
any tag with a `-rc`/`-beta`/`-alpha` suffix as a **pre-release**, which gates the
stable channels:

| Channel | Final tag (`v0.3.0`) | Pre-release (`v0.3.0-rc.1`) |
|---------|:---:|:---:|
| GitHub release | ✅ (Latest) | ✅ (marked *Pre-release*) |
| GHCR `…:<version>` image | ✅ | ✅ (`…:0.3.0-rc.1`) |
| GHCR `…:latest` image | ✅ | ❌ (`skip_push` on prerelease) |
| Binaries + checksums + cosign sig + SBOM | ✅ | ✅ |
| Homebrew tap | ✅ | ❌ (`skip_upload` gates prereleases) |
| AUR | ✅ | ❌ (same) |
| apt/yum repo (`repo.yml`) | ✅ | ❌ (`gh release list --exclude-pre-releases`) |

So an RC builds and publishes **every artifact for real testing** — versioned
container image, signed binaries, a GitHub pre-release — while leaving every
stable channel (`:latest`, Homebrew, AUR, apt/yum) untouched until the final tag.

## The flow

```
dev ──cut──▶ release/X.Y.Z ──tag rc──▶ test ──fix──▶ tag rc.2 ──▶ … ──▶ merge to main ──tag final──▶ ship
```

1. **Freeze.** Cut the release branch from a green `dev`:
   ```bash
   git fetch origin && git switch -c release/0.3.0 origin/dev
   git push -u origin release/0.3.0
   ```
   `dev` stays open for the next cycle; the release is now isolated.

2. **Review** the full `main..dev` diff — correctness and security:
   ```bash
   git diff origin/main...release/0.3.0     # what ships
   # then, in Claude Code, run the review skills over that diff:
   #   /code-review       — correctness + cleanup
   #   /security-review   — security pass
   ```
   Pay special attention to anything auth/crypto/network-facing and to new env
   defaults (e.g. dry-run must never be on in prod).

3. **Fix** review findings on the release branch (PRs into `release/0.3.0`, or
   direct commits for trivial ones). Never add new features here — freeze means
   freeze.

4. **Cut a release candidate** and let the pipeline build real artifacts:
   ```bash
   git tag -a v0.3.0-rc.1 -m "v0.3.0-rc.1" && git push origin v0.3.0-rc.1
   ```
   This produces a GitHub **pre-release** plus `ghcr.io/nurrobin/nurproxy:0.3.0-rc.1`
   (and the agent image), signed binaries and SBOMs — nothing on stable channels.

5. **Test the RC for real** — pull the versioned image / signed binary, run it,
   smoke-test the upgrade. More fixes? Land them on the branch and tag `-rc.2`.

6. **Finalize** once satisfied. Merge the release branch to `main` and tag the
   final version (no suffix) on `main`:
   ```bash
   gh pr create --base main --head release/0.3.0 --title "release: v0.3.0"
   # after merge:
   git fetch origin && git switch main && git pull
   git tag -a v0.3.0 -m "v0.3.0" && git push origin v0.3.0
   ```
   The final tag flips `:latest`, publishes Homebrew/AUR, and rebuilds the
   apt/yum repo. Issues referenced as `Closes #NN` close on the merge to `main`.

7. **Back-merge to dev** so any fixes made on the release branch are not lost:
   ```bash
   git switch dev && git pull && git merge origin/main && git push
   ```

## Hotfixes (after a release)

For an urgent fix to a shipped version: branch from `main`, fix, PR into `main`,
tag the patch (`v0.3.1`), then back-merge `main → dev`. Same tag-driven pipeline.

## Pipeline reference

- **`release.yml`** — on `v*` tag: builds the dashboard, runs GoReleaser
  (binaries, archives, nfpm deb/rpm, GHCR multi-arch images + manifests, Homebrew
  cask, AUR, checksums, cosign keyless signature, syft SBOM), then dispatches
  `repo.yml`.
- **`.goreleaser.yml`** — the build/publish matrix. `release.prerelease: auto`
  and the per-channel `skip_*` guards implement the RC isolation above.
- **`repo.yml`** — rebuilds the signed APT + YUM repository from **stable**
  releases' `.deb`/`.rpm` assets and publishes to GitHub Pages. Inert until
  `GPG_PRIVATE_KEY` is set.

Publishing secrets (set at the repo level; each channel stays inert until its
secret exists): `HOMEBREW_TAP_TOKEN`, `AUR_KEY`, `GPG_PRIVATE_KEY`
(+ `GPG_PASSPHRASE`).

# Private Orchestrator Data Permissions Implementation Plan

> **Request:** REQ-237  
> **Execution:** strict TDD, independent review, production canary only after all release gates pass.

## Goal

Keep the orchestrator data directory private across fresh installs, live SQLite
operation, backup/restore, package upgrades, and existing-install migrations,
without following links or changing unrelated files.

## Task 1: Lock down runtime creation and existing installs

- Add failing tests for a fresh `0700` data directory and `0600` database,
  WAL, SHM, keys, restore staging files, and backup archives under a permissive
  caller umask.
- Add a Unix dirfd-based hardener that opens the data directory and explicitly
  allowed entries with `O_NOFOLLOW`, accepts regular files only, changes modes
  through the opened descriptors, and is idempotent.
- Reject a linked data directory; skip and report linked, non-regular, or
  unrecognized entries without traversing them. Never recurse.
- Set process umask `0077` before creating runtime state, then run the hardener
  before and after opening SQLite so existing files and newly created sidecars
  converge to the invariant.

## Task 2: Lock down service and package installation

- Render `UMask=0077` in native systemd units and update both packaged units.
- Create orchestrator data directories as `0700`; preserve the agent's existing
  service-user access requirements separately.
- Make the package upgrade hook invoke the same safe permission migration before
  restart, and fail visibly if it cannot establish the invariant.
- Test renderer/package parity, fresh install, repeated upgrade, and failure
  propagation.

## Task 3: Backup, restore, documentation, and gates

- Ensure output archives remain `0600` even when overwriting an existing wider
  file, and restored final files plus staging files are `0600`.
- Document the invariant, upgrade diagnostics, verification commands, and the
  fact that chmod-only migration has no automatic mode rollback.
- Run focused race tests, full race tests, tagged integration/E2E/sandbox tests,
  vet, frontend gates, and diff checks; resolve every Critical/Important review
  finding.
- Deploy to `apps` with non-secret pre/post evidence: file types/modes, service
  health, SQLite integrity/schema, authenticated control-plane health, and agent
  reconnection. Keep a timestamped binary/unit/config backup and an explicit
  rollback command set.

# Certificate Downloads and Managed Agent Exports Implementation Plan

> **Request:** REQ-230  
> **Design:** `docs/superpowers/specs/2026-08-29-certificate-distribution-design.md`  
> **Execution rule:** implement each task test-first, obtain a focused code-quality review, and do not deploy until Task 11 is green.

## Goal

Add a dedicated Certificates workflow that can stream the current central certificate as PEM ZIP or password-protected PFX and can continuously deploy renewed material to multiple safe agent-side destinations. Symlink mode is the default; copy mode, custom ownership, and advanced hooks are explicitly confirmed compatibility features. All mutation is provenance-bound, snapshot-backed, validated, audited, and rollback-capable.

## Task 1: Define and validate the shared export contract

**Files:**

- Create: `internal/shared/certmodel/model.go`
- Create: `internal/shared/certmodel/model_test.go`
- Modify: `internal/shared/proxymodel/wire.go`
- Modify: `internal/shared/proxymodel/wire_test.go`

- [ ] Add typed `CertificateExport`, `Destination`, `PermissionPolicy`, `PostDeployAction`, `ExportStatus`, `ExportDeployment`, and agent capability models. Keep private material out of every status/history type.
- [ ] Add strict enums and `Validate` methods: bounded IDs/names, canonical host, absolute clean destination paths, unique destination kinds and paths, octal modes, owner/group syntax, bounded argv/timeout, and mutually exclusive systemd/command actions.
- [ ] Extend `IntentSet` with export specifications that refer to an existing `CertBundle` by host; add an export acknowledgement envelope with per-export desired fingerprint, phase, rollback result, and sanitized error code.
- [ ] Write negative tests first for traversal, duplicate targets, shell strings, relative executables, unknown enums, oversized fields, control characters, and accidental JSON serialization of key/password fields.
- [ ] Verify: `go test -race ./internal/shared/certmodel ./internal/shared/proxymodel && go vet ./internal/shared/certmodel ./internal/shared/proxymodel`.

## Task 2: Persist export definitions and deployment history

**Files:**

- Modify: `internal/orchestrator/db/migrations.go`
- Modify: `internal/orchestrator/db/migrations_test.go`
- Create: `internal/orchestrator/db/certificate_exports.go`
- Create: `internal/orchestrator/db/certificate_exports_test.go`
- Modify: `internal/shared/models/models.go`

- [ ] Add a migration for `certificate_exports` and append-only `certificate_export_deployments`; use foreign keys to certificates/agents, unique host+agent+name, timestamps, desired/applied fingerprints, and bounded status/error columns.
- [ ] Store destinations, permissions, and post-deploy argv as validated JSON. Never store archive bytes, plaintext private keys, PFX passwords, or command output containing secrets.
- [ ] Implement create/get/list/update/disable/delete and replay-safe deployment upsert/list methods. Updating or deleting an export must preserve history.
- [ ] Test migration from the immediately preceding schema, FK behavior, deterministic ordering, malformed stored JSON fail-closed, concurrent status updates, and disabled-export selection.
- [ ] Verify: `go test -race ./internal/orchestrator/db -run 'Migration|CertificateExport' && go vet ./internal/orchestrator/db`.

## Task 3: Build in-memory PEM ZIP and PFX downloads

**Files:**

- Create: `internal/orchestrator/certarchive/archive.go`
- Create: `internal/orchestrator/certarchive/archive_test.go`
- Modify: `go.mod`
- Modify: `go.sum`

- [ ] Parse and validate the stored leaf/chain and private key, prove key-pair equality, split `cert.pem` and `chain.pem`, and derive a safe hostname filename.
- [ ] Stream a deterministic ZIP containing only `cert.pem`, `chain.pem`, `fullchain.pem`, and `privkey.pem`; give the private-key entry restrictive metadata.
- [ ] Create standards-compatible PKCS#12 using a maintained Go library. Reject empty/oversized passwords and wipe temporary byte slices where practical.
- [ ] Test RSA and ECDSA keys, wrong keys, malformed chains, empty chain, password-required PFX import, archive entry names/modes, output bounds, and absence of passwords/private material in errors.
- [ ] Verify: `go test -race ./internal/orchestrator/certarchive && go vet ./internal/orchestrator/certarchive`.

## Task 4: Expose authenticated certificate/export APIs

**Files:**

- Create: `internal/orchestrator/api/certificates.go`
- Create: `internal/orchestrator/api/certificates_test.go`
- Modify: `internal/orchestrator/api/server.go`

- [ ] Register authenticated list/detail/download routes under `/api/v1/certificates` and CRUD/history routes under `/api/v1/certificate-exports`.
- [ ] Accept the PFX password only in the download request body, set `Cache-Control: no-store`, `Pragma: no-cache`, `X-Content-Type-Options: nosniff`, and a sanitized attachment name, then stream without logging the body.
- [ ] Return public certificate metadata without `KeyPEM`. Audit format and export-definition changes without recording key material, password, or archive bytes.
- [ ] Require an explicit confirmation token for copy mode, advanced ownership, new destination roots, and advanced commands; reuse the existing admin-op confirmation model rather than adding another package.
- [ ] Test auth, CSRF/session behavior, headers, safe error bodies, audit redaction, malformed requests, unavailable certs, and confirmation enforcement.
- [ ] Verify: `go test -race ./internal/orchestrator/api -run 'Certificate|Export|Download' && go vet ./internal/orchestrator/api`.

## Task 5: Create the durable agent export-generation store

**Files:**

- Create: `internal/agent/certexport/store.go`
- Create: `internal/agent/certexport/store_test.go`
- Create: `internal/agent/certexport/manifest.go`
- Create: `internal/agent/certexport/manifest_test.go`

- [ ] Write `cert.pem`, `chain.pem`, `fullchain.pem`, `privkey.pem`, and a non-secret manifest below `<agent-data>/cert-exports/<export-id>/generations/<fingerprint>` using 0700 directories and safe file defaults.
- [ ] Validate X.509 parse, hostname coverage, validity window, chain structure, and key-pair equality before publishing. Fingerprint the canonical public certificate, not secret key bytes.
- [ ] Persist each file and manifest through create-exclusive temporary files, fsync, rename, and parent sync. Atomically switch a relative `current` symlink only after a complete generation is durable.
- [ ] Reject symlink/hardlink/non-regular store entries and identity changes; make same-fingerprint creation idempotent.
- [ ] Test interrupted writes, restart discovery, tampered manifests/files, symlink swaps, hardlinks, modes, relative-current target, and concurrent same-export attempts.
- [ ] Verify: `go test -race ./internal/agent/certexport -run 'Store|Generation|Manifest' && go vet ./internal/agent/certexport`.

## Task 6: Safely deploy symlink and copy destinations

**Files:**

- Create: `internal/agent/certexport/pathguard.go`
- Create: `internal/agent/certexport/pathguard_test.go`
- Create: `internal/agent/certexport/deploy.go`
- Create: `internal/agent/certexport/deploy_test.go`
- Reuse: `internal/agent/recovery/snapshot.go`

- [ ] Enforce agent-local export roots after parent canonicalization. Resolve owner/group to numeric IDs during planning and recheck immediately before mutation.
- [ ] Mutate through opened parent directory descriptors with no-follow and inode/device checks. Never use a pathname-only recheck as the final authorization.
- [ ] In symlink mode create/replace only absent paths or links carrying the same export provenance and point stable destination links through that export's `current` link.
- [ ] In copy mode snapshot the complete destination set and metadata, write same-directory temporary files, apply uid/gid/mode, atomically rename, and restore all destinations on any failure.
- [ ] Preserve unrelated/operator files. Add explicit adoption as a separate snapshot-backed operation; a matching filename is not provenance.
- [ ] Test traversal, parent/final symlink races, hardlinks, device/socket/FIFO paths, cross-export links, unrelated regular files, partial rename failure, rollback, ownership/modes, and idempotent renewal.
- [ ] Verify: `go test -race ./internal/agent/certexport -run 'Path|Deploy|Copy|Symlink|Adopt|Rollback' && go vet ./internal/agent/certexport`.

## Task 7: Add allowlisted post-deploy actions

**Files:**

- Create: `internal/agent/certexport/action.go`
- Create: `internal/agent/certexport/action_test.go`
- Modify: `internal/agent/config/config.go`
- Modify: `internal/agent/config/config_test.go`
- Modify: `internal/agent/config/runtime.go`
- Modify: `internal/agent/config/runtime_test.go`

- [ ] Add local-only export roots, systemd service allowlist, executable allowlist, and bounded timeout settings. Orchestrator data cannot widen these lists.
- [ ] Implement typed systemd reload plus active-status check and absolute argv command execution without a shell. Supply only documented path environment variables.
- [ ] Reuse bounded sanitized command capture. Serialize actions per export, time out process groups, reject control characters and non-allowlisted service/executable values, and label allowlisted shell interpreters high risk.
- [ ] On action failure restore the previous generation/destination snapshot and invoke the previous-generation action once. Feed repeated failures into the recovery breaker.
- [ ] Test allowlist boundaries, argv preservation, environment contents, timeout/kill, bounded output, secret redaction, serialization, rollback action, and breaker behavior.
- [ ] Verify: `go test -race ./internal/agent/certexport ./internal/agent/config && go vet ./internal/agent/certexport ./internal/agent/config`.

## Task 8: Reconcile exports over the existing outbound agent stream

**Files:**

- Modify: `internal/orchestrator/reconciler/reconciler.go`
- Modify: `internal/orchestrator/reconciler/reconciler_test.go`
- Modify: `internal/orchestrator/api/agent_stream.go`
- Modify: `internal/orchestrator/api/agent_stream_test.go`
- Modify: `internal/agent/stream/stream.go`
- Modify: `internal/agent/stream/stream_test.go`
- Modify: `internal/agent/stream/report.go`
- Modify: `internal/agent/stream/report_test.go`

- [ ] Gather enabled exports per agent and attach only exports whose host has a matching pushed certificate bundle. Keep normal proxy installation behavior unchanged.
- [ ] Apply exports independently after certificate intake, report structured validating/applying/rolling-back outcomes, and persist acknowledgements replay-safely.
- [ ] Ensure a failed export cannot block other exports, proxy intent application, or renewal delivery. Reconnect must converge stale fingerprints idempotently.
- [ ] Trigger `PushAgentRoutes` after export CRUD and after renewal save so new certificate generations deploy without waiting for the periodic cycle.
- [ ] Test missing/offline agent, absent cert, duplicate stream event, stale/reordered ack, mixed success, renewal fingerprint change, disabled export, and no private material in reports.
- [ ] Verify: `go test -race ./internal/orchestrator/reconciler ./internal/orchestrator/api ./internal/agent/stream && go vet ./internal/orchestrator/reconciler ./internal/orchestrator/api ./internal/agent/stream`.

## Task 9: Build the Certificates UI and API client

**Files:**

- Create: `web/src/pages/Certificates.tsx`
- Create: `web/src/pages/Certificates.test.tsx`
- Create: `web/src/test/setup.ts`
- Create: `web/vitest.config.ts`
- Modify: `web/package.json`
- Modify: `web/package-lock.json`
- Modify: `web/src/App.tsx`
- Modify: `web/src/shells/nav.tsx`
- Modify: `web/src/lib/api.ts`
- Modify: `web/src/lib/types.ts`
- Modify: `web/src/locales/de.json`
- Modify: `web/src/locales/en.json`

- [ ] Add a Certificates navigation entry and page showing issuance/expiry, download, deployment health, generation, last error, rollback, and history.
- [ ] Reuse the cert-only domain creation fields but present them as a certificate wizard. Do not expose server/port fields.
- [ ] Download PEM ZIP directly. For PFX generate a cryptographically random password with Web Crypto or accept a custom password; show generated passwords once and clear them after download/dialog close.
- [ ] Build deployment wizard defaults for symlink mode, directory preset, safe permissions, no action, plus progressive disclosure for copy, custom paths/ownership, systemd, and argv. Review every resolved path/action before submit and use the existing second-confirmation flow for hard changes.
- [ ] Add accessible pending/error/success states and German/English copy that explains rollback and compatibility tradeoffs.
- [ ] Before the first component test, add the repository's missing lightweight Vitest + jsdom + Testing Library harness and a `test` script. Keep production dependencies unchanged.
- [ ] Test random-password lifecycle, custom password request handling, blob download cleanup, default-safe wizard, confirmation gates, path preview, no key/password persistence, and status/history rendering.
- [ ] Verify: `cd web && npm test -- --run && npm run build && npm run lint`.

## Task 10: Add integration, browser, and negative-security coverage

**Files:**

- Create: `test/integration/certificate_exports_test.go`
- Create: `test/e2e/certificate_exports_test.go`
- Modify: `docs/qa/25-fixtures-and-gotchas.md`
- Modify: `docs/qa/30-manual-integration-checklist.md`

- [ ] Exercise real RSA/ECDSA material, disposable filesystem roots, renewal-equivalent generation changes, symlink and copy installs, hook success/failure, rollback, retention, and unrelated-file preservation.
- [ ] Add tagged Go full-stack E2E for the API/agent path. Browser-test certificate creation, PEM/PFX downloads, one-time password display, deployment review, both confirmations, status, and history through the shared T3 browser against the isolated stack; retain screenshots/recorded observations in the QA evidence rather than introducing a second browser-runner package.
- [ ] Add adversarial fixtures for traversal, symlink swaps, hardlinks, FIFOs, oversized command output, wrong key, malformed certificate, and secret-search assertions over logs/audit/API responses.
- [ ] Verify: `go test -race -count=1 -tags=integration ./test/integration -run CertificateExport`; `go test -race -count=1 -tags=e2e ./test/e2e -run CertificateExport`; run the shared-browser flow against the isolated stack and record exact evidence in the QA docs.

## Task 11: Full release gates and reversible production canary

**Files:**

- Modify: `docs/qa/30-manual-integration-checklist.md`
- Modify: `docs/qa/40-production-validation.md`

- [ ] Run `gofmt`, `git diff --check`, `go test -race ./...`, `go vet ./...`, frontend test/build/lint, and container/config validation.
- [ ] Snapshot the apps VM database/config/binaries and each canary agent's service/config/export directories; record exact rollback commands without secrets.
- [ ] Deploy orchestrator first, then one agent at a time. Canary on `orax`, then `durox`, then a non-critical apps-VM target.
- [ ] For each canary prove initial symlink install, a renewal-equivalent generation switch, systemd or disposable-process reload, forced validation/hook failure with rollback, reconnect convergence, and unrelated-file preservation.
- [ ] Exercise the UI through the shared browser: create a disposable cert-only certificate, download/import PEM ZIP and password-protected PFX, create/edit/disable an export, inspect history, then remove only tagged fixtures.
- [ ] Compare service health and logs before/after. Roll back immediately on schema, stream, proxy, certificate, or unrelated-service regression.

## Task 12: Documentation, retention cleanup, and final review

**Files:**

- Modify: `README.md`
- Modify: `docs/qa/25-fixtures-and-gotchas.md`
- Modify: `docs/qa/40-production-validation.md`
- Modify: `.ghosttree/requests/open/REQ-230*.md` through ghosttree tools only

- [ ] Document supported formats, path-root setup, permission presets, post-deploy allowlists, failure recovery, and the fact that passwords are never stored.
- [ ] Verify deletion removes only provenance-matching destinations, keeps seven-day recovery snapshots, and never follows symlinks during retention.
- [ ] Obtain independent specification-compliance and code-quality reviews; resolve all Critical/Important findings.
- [ ] Repeat the full release gates from Task 11 and mark REQ-230 criteria complete only with captured unit, integration, browser, and production-canary evidence.

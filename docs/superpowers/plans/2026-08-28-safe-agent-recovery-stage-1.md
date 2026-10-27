# Safe Agent Recovery Stage 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Turn proxy failures into structured diagnostics and safely repair only proven NurProxy-owned faults, with snapshots, validation, rollback, bounded retries, direct UI execution, settings, and production E2E proof.

**Architecture:** Add a shared recovery contract, typed proxy failures, and an unprivileged agent-side coordinator. Persist diagnostics and operations centrally, deliver manual requests over the existing outbound SSE stream, report progress over agent-authenticated REST, and render it in the existing Agents and Settings pages. Stage 1 mutates only canonicalized NurProxy-managed files; operator and system changes remain diagnosis-only.

**Tech Stack:** Go 1.24, SQLite/modernc, SSE and REST, React 19, TypeScript 6, Vite 8, Prometheus client, real nginx/Apache integration fixtures, production systemd deployments.

## Global Constraints

- Implement only Stage 1 from docs/superpowers/specs/2026-08-28-safe-agent-recovery-design.md. Do not add the privileged helper, systemd socket, package/firewall/user/group mutation, or arbitrary command execution.
- Use TDD: write the named failing test, run it, then add the smallest implementation.
- Preserve prune-before-validation and current atomic apply rollback.
- Never mutate manual, adopted, drifted, review-pending, operator-owned, system-owned, or ambiguous resources.
- Never accept commands, environment variables, service names, or arbitrary paths from REST, SSE, or UI.
- Sanitize evidence and cap it at 8 KiB. Never persist config bodies, keys, tokens, environment values, or credentials.
- Canonicalize paths and Lstat again immediately before mutation. A managed basename alone is not ownership proof.
- Keep the agent systemd sandbox and package layout unchanged.
- Metrics labels must be bounded enums, never host, path, IDs, or error text.
- Never put production credentials or certificate material in code, docs, tests, shell history, or logs.

---

### Task 1: Define the shared recovery contract

**Files:**

- Create: internal/shared/recoverymodel/model.go
- Create: internal/shared/recoverymodel/model_test.go
- Modify: internal/shared/proxymodel/wire.go
- Modify: internal/shared/proxymodel/wire_test.go

- [ ] Write table tests for JSON round trips, enum validation, stable diagnostic IDs, evidence truncation/redaction, and unknown action/state rejection. Confirm the package/type failures:

~~~bash
go test ./internal/shared/recoverymodel ./internal/shared/proxymodel
~~~

- [ ] Add string enums Code, Severity, Ownership, Action, OperationState, RequestSource. Define all 14 approved codes, four ownership values, five Stage 1 actions, every state, and automatic/user sources. Add fail-closed Valid methods.

- [ ] Add these shapes with matching snake-case JSON tags:

~~~go
const MaxEvidenceBytes = 8 << 10

type Diagnostic struct {
    ID string
    Code Code
    Subsystem string
    Severity Severity
    Ownership Ownership
    Summary string
    Evidence string
    AffectedPaths []string
    ResourceFingerprint string
    ProposedAction Action
    AutoRepairEligible bool
    HardChange bool
    FirstSeenAt time.Time
    LastSeenAt time.Time
    Occurrences int
}

type Capability struct {
    Stage int
    Actions []Action
}

type RepairRequest struct {
    OperationID string
    DiagnosticID string
    Action Action
}

type OperationReport struct {
    OperationID string
    DiagnosticID string
    Action Action
    Source RequestSource
    State OperationState
    Steps []Step
    SnapshotReference string
    ValidationOutcome string
    RollbackOutcome string
    Error string
    StartedAt time.Time
    FinishedAt *time.Time
}
~~~

- [ ] Implement StableDiagnosticID using SHA-256 over length-delimited agent, code, and fingerprint with a diag_ prefix. Sanitize secret patterns/control characters and truncate without splitting UTF-8.

- [ ] Extend proxymodel with RecoveryPolicy, RecoveryReport, and typed request/report envelopes. They contain no browser-supplied path or command.

- [ ] Verify and commit:

~~~bash
go test ./internal/shared/recoverymodel ./internal/shared/proxymodel
git add internal/shared/recoverymodel internal/shared/proxymodel
git commit -m "feat(recovery): define typed diagnostics contract"
~~~

### Task 2: Add migration 23, persistence, and settings inheritance

**Files:**

- Modify: internal/orchestrator/db/migrations.go
- Modify: internal/orchestrator/db/migrations_test.go
- Modify: internal/orchestrator/db/db_test.go
- Modify: internal/shared/models/models.go
- Modify: internal/orchestrator/db/agents.go
- Modify: internal/orchestrator/db/agents_test.go
- Create: internal/orchestrator/db/recovery.go
- Create: internal/orchestrator/db/recovery_test.go

- [ ] First expect schema 23, preserved legacy rows, safe_auto_repair=true, nullable override, empty recovery tables, and idempotent reopen:

~~~bash
go test ./internal/orchestrator/db -run 'TestMigration|TestRecovery|TestAgentSafeAutoRepair'
~~~

- [ ] Add migration 23:

~~~sql
ALTER TABLE agents ADD COLUMN safe_auto_repair_override INTEGER;
ALTER TABLE agents ADD COLUMN recovery_capability TEXT;
INSERT OR IGNORE INTO settings (key, value) VALUES ('safe_auto_repair', 'true');
CREATE TABLE recovery_diagnostics (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  code TEXT NOT NULL,
  subsystem TEXT NOT NULL,
  severity TEXT NOT NULL,
  ownership TEXT NOT NULL,
  summary TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '',
  affected_paths TEXT NOT NULL DEFAULT '[]',
  resource_fingerprint TEXT NOT NULL,
  proposed_action TEXT NOT NULL DEFAULT '',
  auto_repair_eligible INTEGER NOT NULL DEFAULT 0,
  hard_change INTEGER NOT NULL DEFAULT 0,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  occurrences INTEGER NOT NULL DEFAULT 1,
  resolved_at TEXT
);
CREATE UNIQUE INDEX idx_recovery_diagnostics_identity
  ON recovery_diagnostics(agent_id, code, resource_fingerprint);
CREATE INDEX idx_recovery_diagnostics_agent_active
  ON recovery_diagnostics(agent_id, resolved_at, severity);
CREATE TABLE recovery_operations (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  diagnostic_id TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_fingerprint TEXT NOT NULL,
  risk TEXT NOT NULL DEFAULT 'safe',
  request_source TEXT NOT NULL,
  state TEXT NOT NULL,
  step_summaries TEXT NOT NULL DEFAULT '[]',
  snapshot_reference TEXT NOT NULL DEFAULT '',
  validation_outcome TEXT NOT NULL DEFAULT '',
  rollback_outcome TEXT NOT NULL DEFAULT '',
  error TEXT NOT NULL DEFAULT '',
  started_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  finished_at TEXT
);
CREATE INDEX idx_recovery_operations_agent_started
  ON recovery_operations(agent_id, started_at DESC);
CREATE INDEX idx_recovery_operations_breaker
  ON recovery_operations(agent_id, action, resource_fingerprint, state, started_at);
~~~

Use explicit columns for enums, timestamps, occurrence, validation, and rollback; JSON only for paths/steps. Do not cascade agent deletion: explicitly remove recovery rows in the existing delete transaction.

- [ ] Add SafeAutoRepairOverride *bool, computed SafeAutoRepairEffective bool, and RecoveryCapability *recoverymodel.Capability to Agent. Update agentColumns, inserts, scans, updates, and narrow setters without collapsing NULL to false.

- [ ] Implement and test:

~~~go
SetAgentSafeAutoRepairOverride(id string, enabled *bool) error
UpdateAgentRecoveryCapability(id string, cap *recoverymodel.Capability) error
UpsertDiagnostic(agentID string, diag recoverymodel.Diagnostic) error
ResolveMissingDiagnostics(agentID string, activeIDs []string, at time.Time) error
ListDiagnostics(agentID string, includeResolved bool) ([]recoverymodel.Diagnostic, error)
GetDiagnostic(agentID, diagnosticID string) (*recoverymodel.Diagnostic, error)
CreateRepairOperation(agentID string, op recoverymodel.OperationReport, fingerprint string) error
AdvanceRepairOperation(agentID string, op recoverymodel.OperationReport) error
ListRepairOperations(agentID string, limit int) ([]recoverymodel.OperationReport, error)
CountRecentRepairFailures(agentID string, action recoverymodel.Action, fingerprint string, since time.Time) (int, error)
~~~

AdvanceRepairOperation enforces legal forward transitions and idempotent duplicate ACKs. UpsertDiagnostic increments occurrences and last_seen_at.

- [ ] Implement EffectiveSafeAutoRepair(global string, override *bool), accepting only true/false and testing inherit/enabled/disabled/missing/invalid.

- [ ] Verify and commit:

~~~bash
go test ./internal/orchestrator/db
git add internal/orchestrator/db internal/shared/models/models.go
git commit -m "feat(recovery): persist diagnostics and repair operations"
~~~

### Task 3: Export typed nginx and Apache failures

**Files:**

- Create: internal/agent/proxy/failure.go
- Create: internal/agent/proxy/failure_test.go
- Modify: internal/agent/proxy/nginx/nginx.go
- Modify: internal/agent/proxy/nginx/nginx_test.go
- Modify: internal/agent/proxy/nginx/attribution_test.go
- Modify: internal/agent/proxy/apache/apache.go
- Modify: internal/agent/proxy/apache/apache_test.go
- Modify: internal/agent/proxy/apache/attribution.go
- Modify: internal/agent/proxy/apache/attribution_test.go

- [ ] Add failing tests proving errors.As exposes backend, phase, bounded output, file, line, managed hint, permission denial, missing cert/runtime-key, mismatch, and reload failure.

- [ ] Add proxy.Failure with FailurePhase validate/reload/cert_install and fields Backend, Output, File, Line, Located, ManagedHint, Permission, MissingCert, MissingRuntimeKey, RuntimeKeyMismatch, and wrapped Err. Error remains concise and Unwrap returns Err.

- [ ] Replace private commandError types while keeping attribution parsers pure. Extend Apache permission detection to nginx parity.

- [ ] Recognize only tested real backend messages for missing certificate, runtime key, key mismatch, binary missing, and reload failure. Unknown text sets no repair hint.

- [ ] Verify and commit:

~~~bash
go test ./internal/agent/proxy/... -run 'Failure|Attribution|Apply|Validate|Reload'
git add internal/agent/proxy
git commit -m "feat(proxy): expose structured validation failures"
~~~

### Task 4: Classify failures and prove ownership

**Files:**

- Create: internal/agent/recovery/classifier.go
- Create: internal/agent/recovery/classifier_test.go
- Create: internal/agent/recovery/pathguard.go
- Create: internal/agent/recovery/pathguard_test.go

- [ ] Write failing tables for every code/ownership class, traversal, outside root, symlink escape, deceptive name, manual/adopted/drifted/review state, absent bundle, and unknown error.

- [ ] Define DesiredResource with artifact ID, host, target, source, drifted, apply state, and valid-bundle flag. Define classifier Context with agent ID, proxy.Info, managed roots, agent data root, and desired resources.

- [ ] Implement PathGuard with absolute configured roots, EvalSymlinks on existing parents, Lstat final entries, and a later identity recheck. Return canonical paths or reject.

- [ ] ManagedHint is evidence only. Require a desired artifact or managed marker plus resolved layout. Missing cert/key is eligible only with a valid bundle. Permission, sandbox, service, port, binary, operator, and unknown failures are diagnosis-only.

- [ ] Fingerprint code, canonical paths, backend, and non-secret evidence class—not raw text. Sanitize before returning Diagnostic.

- [ ] Verify and commit:

~~~bash
go test ./internal/agent/recovery -run 'Classifier|PathGuard'
git add internal/agent/recovery
git commit -m "feat(recovery): classify failures with ownership proof"
~~~

### Task 5: Add snapshots, rollback, retention, and breaker

**Files:**

- Create: internal/agent/recovery/snapshot.go
- Create: internal/agent/recovery/snapshot_test.go
- Create: internal/agent/recovery/breaker.go
- Create: internal/agent/recovery/breaker_test.go
- Create: internal/agent/recovery/state.go
- Create: internal/agent/recovery/state_test.go

- [ ] Test regular/absent files, symlinks, modes, atomic manifests, interrupted applying, restart recovery, seven-day/newest-20 retention, active preservation, three failures/15 minutes, one-hour open, manual retry, and success clear.

- [ ] Store operations below agent-data-dir/recovery/operations/operation-id. Manifest contains typed metadata, canonical paths, modes, symlink targets, hashes, timestamps, and state only. Use 0700 directories and 0600 snapshots.

- [ ] Persist transitions with temp write, fsync, rename, and parent sync. Resume only validating/rolling_back. Convert indeterminate applying to rollback before new mutation.

- [ ] Breaker key is action plus fingerprint. Three failed/rolled-back outcomes in 15 minutes suppress automatic attempts for one hour. Manual retry bypasses only time. rollback_failed stays open until successful manual validation.

- [ ] Retention never follows symlinks or deletes active operations.

- [ ] Verify and commit:

~~~bash
go test ./internal/agent/recovery -run 'Snapshot|Rollback|Retention|Breaker|Transition'
git add internal/agent/recovery
git commit -m "feat(recovery): add durable snapshots and circuit breaker"
~~~

### Task 6: Expose managed-file recovery adapters

**Files:**

- Modify: internal/agent/proxy/proxy.go
- Modify: internal/agent/proxy/holder.go
- Modify: internal/agent/proxy/holder_test.go
- Modify: internal/agent/proxy/nginx/nginx.go
- Modify: internal/agent/proxy/nginx/nginx_test.go
- Modify: internal/agent/proxy/apache/apache.go
- Modify: internal/agent/proxy/apache/apache_test.go
- Modify: internal/agent/proxy/caddy/caddy.go
- Modify: internal/agent/proxy/caddy/caddy_test.go
- Modify: internal/agent/proxy/generic/generic.go
- Modify: internal/agent/proxy/generic/generic_test.go
- Modify: internal/agent/proxy/certstore/certstore.go
- Modify: internal/agent/proxy/certstore/certstore_test.go

- [ ] Test read-only inspection and identity/symlink rejection. Cover orphan vhost/link/auth sidecar, stale temp, cert sidecars, missing/mismatched runtime key, and absent bundle.

- [ ] Add optional RecoveryInspector so fake/custom backends remain compatible:

~~~go
type RecoveryInspector interface {
    InspectRecovery(context.Context, RecoveryDesired) ([]RecoveryCandidate, error)
    ExecuteRecovery(context.Context, RecoveryCandidate, map[string]CertBundle) error
}

type RecoveryDesired struct {
    KeepTargets []Target
    KeepCertHosts []string
    ActiveOperationPaths []string
}
~~~

Candidate contains typed action, host, canonical paths, and pre-mutation identity (mode, inode/device where supported, symlink target, hash), never a command.

- [ ] Implement nginx/Apache adapters using resolved layouts, markers, sidecars, certstore, Validate, and reload. Caddy supports cert/runtime-key recovery only. Generic remains diagnosis-only unless equivalent guarantees are configured.

- [ ] Certstore inspection verifies the certificate/private-key pair cryptographically and atomically refreshes .key.plain without returning key bytes.

- [ ] Preserve Prune as normal desired-state convergence. Share internal deletion logic with recovery, but only recovery gets snapshots/history. Domain deletion still works when optional auto recovery is off.

- [ ] Verify and commit:

~~~bash
go test ./internal/agent/proxy/...
git add internal/agent/proxy
git commit -m "feat(proxy): expose safe managed recovery actions"
~~~

### Task 7: Implement and integrate the coordinator

**Files:**

- Create: internal/agent/recovery/coordinator.go
- Create: internal/agent/recovery/coordinator_test.go
- Create: internal/agent/recovery/reporter.go
- Create: internal/agent/recovery/reporter_test.go
- Modify: internal/agent/stream/stream.go
- Modify: internal/agent/stream/stream_test.go
- Modify: internal/agent/health/health.go
- Modify: internal/agent/health/health_test.go
- Modify: internal/agent/ddns/ddns.go
- Modify: internal/agent/ddns/ddns_test.go
- Modify: cmd/nurproxy-agent/main.go

- [ ] Test diagnosis-only, automatic success, disabled policy, snapshot failure, validation failure with rollback, rollback failure, suppression, concurrency, replay, and crash recovery.

- [ ] Implement one mutex-serialized Coordinator with Observe, Inspect, AutoRepair, HandleRequest, SetPolicy, and Capability. Its inputs are backend, durable store, reporter, clock, policy, and current desired state.

- [ ] Enforce planned to snapshotted to applying to validating to succeeded; failure runs rolling_back to rolled_back or rollback_failed. Validate the full proxy after mutation and restore; reload only after validation.

- [ ] Add a bounded reporter with retry/backoff and idempotent IDs. Queue typed sanitized records only; retain final failures over progress when full.

- [ ] In stream.applyIntents inspect before apply, preserve routine prune ordering, classify cert/render/apply/reload failures, and recover eligible out-of-band candidates. Allow one fresh reconcile after success, never recursion.

- [ ] Handle SSE recovery_policy and repair_request; reject unknown values, action mismatch, reused ID, and wrong-agent request. Old agents keep ignoring these events.

- [ ] Advertise capability in heartbeat and parse safe_auto_repair_effective in its response. Initialize fail-closed until first policy. Derive last_error from highest-severity active diagnostic compatibly.

- [ ] Verify and commit:

~~~bash
go test ./internal/agent/recovery ./internal/agent/stream ./internal/agent/health ./internal/agent/ddns ./cmd/nurproxy-agent
git add internal/agent cmd/nurproxy-agent
git commit -m "feat(agent): coordinate safe automatic recovery"
~~~

### Task 8: Add orchestrator transport and authenticated APIs

**Files:**

- Modify: internal/orchestrator/agenthub/hub.go
- Modify: internal/orchestrator/agenthub/hub_test.go
- Create: internal/orchestrator/api/recovery.go
- Create: internal/orchestrator/api/recovery_test.go
- Modify: internal/orchestrator/api/agents.go
- Modify: internal/orchestrator/api/agents_test.go
- Modify: internal/orchestrator/api/server.go
- Modify: internal/orchestrator/api/system.go
- Modify: internal/orchestrator/api/system_test.go

- [ ] Test user auth, agent self-scope, inheritance, capability, coalescing, idempotency, transitions, concurrency, breaker, action mismatch, hard/operator rejection, unknown action, and audit.

- [ ] Add EventRecoveryPolicy, EventRepairRequest, and typed publish helpers.

- [ ] Register:

~~~text
GET  /api/v1/agents/{id}/diagnostics
GET  /api/v1/agents/{id}/repairs?limit=50
POST /api/v1/agents/{id}/repairs
POST /api/v1/agents/{id}/recovery/report
POST /api/v1/agents/{id}/repairs/{opId}/ack
PUT  /api/v1/agents/{id}/safe-auto-repair
~~~

List/manual/setting use user auth. Report/ACK use agent auth scoped to the same ID.

- [ ] Manual repair accepts only diagnostic_id/action. Reload diagnostic, recompute predicates, require connected capable agent, persist UUID operation, audit, then publish. Return 409 for active/breaker and 422 with stable predicate code for unsafe requests.

- [ ] Heartbeat accepts/persists recovery_capability and returns safe_auto_repair_effective. Global setting accepts true/false; agent endpoint accepts inherit/enabled/disabled. Publish policy changes immediately.

- [ ] Resolve omitted active diagnostics while preserving history. Audit first detection/state change, not every repeat; audit operation transitions.

- [ ] Verify and commit:

~~~bash
go test ./internal/orchestrator/agenthub ./internal/orchestrator/api
git add internal/orchestrator/agenthub internal/orchestrator/api
git commit -m "feat(api): expose safe recovery control plane"
~~~

### Task 9: Add bounded metrics

**Files:**

- Modify: internal/orchestrator/metrics/metrics.go
- Modify: internal/orchestrator/metrics/metrics_test.go
- Modify: internal/orchestrator/db/recovery.go
- Modify: internal/orchestrator/db/recovery_test.go

- [ ] Test values, auth, DB degradation, and that descriptors contain no host/path/ID/error labels.

- [ ] Add durable DB aggregates and:

~~~text
nurproxy_recovery_diagnostics_active{code,severity,ownership}
nurproxy_recovery_operations_total{action,outcome,request_source}
nurproxy_recovery_operations_in_progress{action}
nurproxy_recovery_circuit_breakers_open{action}
~~~

- [ ] Verify and commit:

~~~bash
go test ./internal/orchestrator/metrics ./internal/orchestrator/db -run 'Metric|RecoveryAggregate'
git add internal/orchestrator/metrics internal/orchestrator/db/recovery.go internal/orchestrator/db/recovery_test.go
git commit -m "feat(metrics): expose bounded recovery health"
~~~

### Task 10: Build direct-execution UI and settings

**Files:**

- Modify: web/src/lib/types.ts
- Modify: web/src/lib/api.ts
- Create: web/src/components/RecoveryPanel.tsx
- Modify: web/src/pages/Agents.tsx
- Modify: web/src/pages/Settings.tsx
- Modify: web/src/locales/en.json
- Modify: web/src/locales/de.json

- [ ] Mirror Go types and add API methods for diagnostics, history, repair, and settings.

- [ ] Add RecoveryPanel to agent detail. Poll only while visible or non-terminal. Show cause, code, severity, ownership, file/line, sanitized evidence, paths, eligibility reason, progress, snapshot/validation/rollback, breaker, and history.

- [ ] Eligible Stage 1 actions use one ConfirmDialog labeled Reparieren/Repair. Show typed action/paths, never commands. Disable while active and show persisted progress.

- [ ] Hard/system actions remain visible but disabled. Do not add the second Sicher? dialog until Stage 2 makes them executable.

- [ ] Add global Sichere automatische Reparaturen default-on and per-agent Erben/Aktiviert/Deaktiviert. Show effective state and capability/upgrade warning.

- [ ] Keep permission commands in the existing advanced disclosure because Stage 1 cannot execute external/hard changes.

- [ ] Keep locale key sets aligned, verify, and commit:

~~~bash
cd web
npm run lint
npm run build
git add src
git commit -m "feat(web): add diagnosis and recovery controls"
~~~

### Task 11: Run security, native proxy, API, and browser E2E

**Files:**

- Create: test/integration/recovery_nginx_test.go
- Create: test/integration/recovery_apache_test.go
- Create: test/e2e/recovery_test.go
- Modify: test/sandbox/sandbox_test.go
- Modify: docs/qa/15-permissions-and-remediation.md
- Create: docs/qa/26-safe-recovery.md

- [ ] Real nginx/Apache fixtures skip precisely when absent. Inject missing cert, stale vhost, invalid generated/operator config, reload failure, interruption, and rollback failure. Assert operator/unrelated bytes remain identical.

- [ ] API E2E covers settings, reports, real hub delivery, ACK, replay, reconnect/idempotency, rollback history, and last_error compatibility.

- [ ] Sandbox injects safe stale temp and unknown error: safe heals when enabled, unknown remains diagnosis-only. State that sandbox does not prove native validation.

- [ ] Use shared T3 preview against the local full stack for rendering, history, inheritance, one-confirm repair, progress, rollback, and disabled hard action. Do not add a third frontend runner solely for this stage.

- [ ] Document injections, state assertions, rollback, breaker, and production checklist in docs/qa/26-safe-recovery.md.

- [ ] Run full gate and commit:

~~~bash
gofmt -w internal test cmd
go test -race -count=1 ./...
go test -race -count=1 -tags=integration ./...
go test -race -count=1 -tags=e2e ./...
make test-sandbox
golangci-lint run ./...
cd web && npm run lint && npm run build
git add ../../test ../../docs/qa ../../internal ../../cmd .
git commit -m "test(recovery): cover rollback and end-to-end flows"
~~~

### Task 12: Review, deploy, and perform production canaries

**Files:**

- Modify only for review findings: files above
- Update evidence: docs/qa/26-safe-recovery.md

- [ ] Use requesting-code-review. Resolve all Critical/Important findings and rerun focused tests.

- [ ] Use verification-before-completion and fresh output from Task 11. Confirm git status contains only intended changes.

- [ ] Build release-stamped production binaries. Verify file, SHA-256, and version. Load the authorized API key from its existing secret source into a short-lived variable; never commit or echo it.

- [ ] Deploy orchestrator first via apps SSH alias. Before swap: health, DB backup, timestamped binary backup, active agent/domain/error counts. After: schema 23, service active, health, authenticated recovery API, reconnected agents, live-site smoke.

- [ ] Keep global auto repair false during rollout. Deploy agent to orax first with timestamped binary/config recovery backups. Check nginx -t, systemctl is-active nginx nurproxy-agent, capability, stream, and a live HTTPS control route before enabling its override.

- [ ] Create a unique temporary domain on orax through NurProxy. Wait for authoritative Cloudflare DNS, valid ACME, active DB state, valid nginx, and HTTPS/backend success.

- [ ] Inject one at a time in a dedicated managed canary: stale temp, missing runtime key with encrypted source, stale managed vhost, and generated invalid config forcing rollback. Assert code, snapshot, state sequence, post-check/rollback, bounded attempts, unchanged operator files, continuous control route, and nginx -t afterward.

- [ ] Execute one eligible repair in the real UI. Verify typed action, progress across reload, replay idempotency, and disabled hard action. Disable auto repair and prove diagnosis without execution; re-enable and prove healing.

- [ ] Delete the canary through NurProxy. Verify DB, authoritative DNS, vhost/link/sidecars/certs, diagnostics, and operation state converge while control traffic stays live.

- [ ] Only after orax passes, deploy durox and run abbreviated safe-fault/rollback/delete. Monitor journals, metrics, errors, traffic, and nginx -t.

- [ ] On failure: set global auto repair false, stop new mutations, preserve evidence, restore affected agent binary, restore orchestrator binary if needed, and do not downgrade the additive DB. Revalidate services/traffic.

- [ ] Record timestamps, versions, checksums, non-secret IDs, assertions, and rollback result in docs/qa/26-safe-recovery.md. Update REQ-228 only with concrete evidence.

- [ ] Final smoke and evidence commit:

~~~bash
git status --short
go test -race -count=1 ./...
cd web && npm run lint && npm run build
git add docs/qa/26-safe-recovery.md
git commit -m "docs(qa): record safe recovery production canary"
~~~

## Completion Evidence

Stage 1 is complete only when all focused/full tests pass freshly; real nginx and Apache prove repair, rollback, rollback failure, and operator preservation; UI/API prove typed execution, settings, idempotency, capability gating, and disabled hard actions; metrics use bounded labels; orax then durox canaries pass with a healthy control route; retention/breaker are observed; and no package, broad privilege, arbitrary command, or operator mutation was introduced.

# Config Artifacts: Versioning, Drift Review, Adoption & Log Tail
> **Scope:** the central config-artifact store and its drift workflow — artifact model + version history, list/filter, accept/reject/rollback/bulk, raw edit + reset-to-model + structured mask, heartbeat-driven drift detection/healing, per-agent auto-reconcile, and on-demand log tail.
> **Code:** `internal/orchestrator/api/artifacts.go`, `internal/orchestrator/api/artifacts_adopt.go`, `internal/orchestrator/api/artifact_mask.go`, `internal/orchestrator/api/logs.go`, `internal/orchestrator/api/agents.go` (heartbeat → `reconcileArtifactChecksums`), `internal/orchestrator/db/config_artifacts.go`, `internal/orchestrator/db/agents.go` (`SetAgentAutoReconcileConfig`), `internal/orchestrator/reconciler/reconciler.go` (drift gate), `internal/shared/models/models.go` (`ConfigArtifact`, enums), `internal/shared/proxymodel/wire.go` (wire shapes), `internal/agent/stream/stream.go` (`ManagedChecksums`), `internal/agent/stream/report.go` (`ReportAdopted`), `internal/agent/logtail/logtail.go`, `web/src/pages/Config.tsx`.
> **Coverage legend:** D = coverable dry, R = needs a real run.

## Prerequisites
- Both binaries built: `make build-all` (produces `./nurproxy` and `./nurproxy-agent`).
- A running control plane. Fastest: `make dev-sandbox` (orchestrator + 1 dry agent, seeded provider/zone/server + one **central-TLS domain per agent**, which produces one **generated `dom-N` artifact** per agent once the route push converges). For multi-agent drift/bulk tests use `make dev-sandbox AGENTS=3`.
- An auth session for the REST calls. The dashboard is at the orchestrator URL (default `:8080`); for `curl`, log in and reuse the session cookie. The sandbox launcher's `api` helper already holds a cookie — mirror its login flow, or copy the cookie from a browser session.
- `curl` and `jq` on PATH.
- **Real-only:** an existing-mode agent against a real **nginx**/**apache** (config file backend) for adoption, on-disk drift, and reset-to-model on a file backend. A real proxy binary in PATH and write/reload permission. The dry agent simulates the proxy in memory and **does not write files**, so on-disk drift and file-backend adoption are not exercised dry (see Pitfalls).
- Convenience for the examples below:
  ```bash
  ORCH=http://localhost:8080
  COOKIE=/tmp/np.cookies          # a logged-in session cookie jar
  ```

## Features covered
- [ ] Artifact model + enums: `source` (`generated`|`manual`), `apply_state` (`live`|`apply_failed`|`drifted`), `target.kind` (`file`|`caddy-route`), `drifted` flag mirrors `apply_state==drifted`, nullable `domain_id`, `live_version`, `drift_content`, `last_error`, `enabled`, `checksum`.
- [ ] List + filter: `GET /artifacts` with `agent_id` / `source` / `apply_state` / `domain_id` / `drifted`.
- [ ] Single artifact: `GET /artifacts/{id}`.
- [ ] Append-only version history: `GET /artifacts/{id}/versions`.
- [ ] Accept drift: `POST /artifacts/{id}/accept`.
- [ ] Reject drift (re-push accepted): `POST /artifacts/{id}/reject`.
- [ ] Rollback to a prior version: `POST /artifacts/{id}/rollback`.
- [ ] Bulk accept-all / reject-all: `POST /artifacts/bulk`.
- [ ] Raw edit (`generated` → `manual`): `PUT /artifacts/{id}/content`.
- [ ] Reset to model (re-render from domain intent): `POST /artifacts/{id}/reset-to-model`.
- [ ] Structured mask (read-only view): `GET /artifacts/{id}/mask`.
- [ ] Adoption ingest (agent reads host config into the store): `POST /agents/{id}/artifacts/adopt`.
- [ ] Heartbeat-driven drift detection/healing (`artifact_checksums`; file backends re-read each beat; manual non-NurProxy files untouched).
- [ ] Per-agent auto-reconcile policy: `PUT /agents/{id}/auto-reconcile`.
- [ ] On-demand log tail: `POST /agents/{id}/logs/tail`, `GET …/tail/{session}?cursor=N`, `DELETE …/tail/{session}`, agent chunk ingress `POST /agents/{id}/logs/chunk`.

## Tests

### Artifact model + enum values
- **Must:** an artifact carries `id`, `agent_id`, `backend` (`caddy`|`nginx`|`apache`), `target.kind` (`file` or `caddy-route`), `target.path`, `source` (`generated`|`manual`), nullable `domain_id`, `content`, `checksum`, `live_version`, `enabled`, `drifted`, `apply_state` (`live`|`apply_failed`|`drifted`), `last_error`, `drift_content` (only while drifted), `updated_at`. `drifted` mirrors `apply_state == drifted` (`models.go:497-501`, kept consistent in `SetConfigArtifactApplyState`, `db/config_artifacts.go:507-511`).
- **Access:** REST `GET /api/v1/artifacts/{id}`; Dashboard Config page (select an artifact → detail pane).
- **Prerequisites:** at least one artifact (sandbox seeds a `dom-N` generated artifact after convergence).
- **Steps:**
  ```bash
  curl -s -b $COOKIE $ORCH/api/v1/artifacts | jq '.[0]'
  ```
- **Pass:** the seeded artifact has `source:"generated"`, a non-null `domain_id`, `apply_state:"live"`, `drifted:false`, `live_version>=1`, `target.kind` one of `file`/`caddy-route`, and a non-empty `checksum`. Enum values are exactly `generated`/`manual` and `live`/`apply_failed`/`drifted` — **never** `pending` or `applied` (those are `AdminOpStatus` values for pending admin ops, not artifact states; `models.go:589-591`).
- **Coverage:** D.
- **Pitfalls:** the built-in Caddy artifact has `target.kind:"caddy-route"` and `target.path` like `caddy:route:<id>`; its `content` is **route JSON**, not a file (`models.go:461-467`). Only a file backend has a real on-disk path.

### List + filter — `GET /artifacts`
- **Must:** the list endpoint returns all artifacts and honours the filters `agent_id`, `source`, `apply_state`, `domain_id` (int), `drifted` (`true`/`1`). Empty result is `[]`, never `null` (`artifacts.go:23-49`). Order is `updated_at DESC, id` (`db/config_artifacts.go:194`).
- **Access:** REST `GET /api/v1/artifacts?…`; Dashboard Config page (free-text search box + "drifted only" toggle, `Config.tsx:196,207`).
- **Steps:**
  ```bash
  curl -s -b $COOKIE "$ORCH/api/v1/artifacts" | jq 'length'
  curl -s -b $COOKIE "$ORCH/api/v1/artifacts?source=generated" | jq '[.[].source]|unique'
  curl -s -b $COOKIE "$ORCH/api/v1/artifacts?drifted=true" | jq 'length'
  curl -s -b $COOKIE "$ORCH/api/v1/artifacts?apply_state=live" | jq '[.[].apply_state]|unique'
  # domain_id must be an integer; a non-numeric value is silently ignored (no filter)
  curl -s -b $COOKIE "$ORCH/api/v1/artifacts?domain_id=1" | jq '[.[].domain_id]|unique'
  ```
- **Pass:** each filtered set contains only matching rows; `source=generated` returns only `"generated"`; `drifted=true` returns only drifted; an unmatched filter returns `[]`.
- **Coverage:** D.
- **Pitfalls:** `drifted` is true only for the literal strings `true` or `1`; anything else is treated as `false` (`artifacts.go:36`). A non-integer `domain_id` is dropped without error (`artifacts.go:31-33`), so the filter silently does nothing — verify the count changed, don't assume the filter applied.

### Version history — `GET /artifacts/{id}/versions`
- **Must:** append-only history, **newest version first**, each entry has `version`, full `content`, `checksum`, `source`, `actor`, `note`, `created_at` (`artifacts.go:64-79`, `db/config_artifacts.go:311-334`). A new version is written **only on semantic change** (`configeq.Equal` per backend) — re-serialized-but-equal content writes **no** version (`db/config_artifacts.go:252-268`). History is never pruned.
- **Access:** REST; Dashboard Config detail pane (version list + diff view, `Config.tsx:18-20`).
- **Steps:**
  ```bash
  AID=$(curl -s -b $COOKIE $ORCH/api/v1/artifacts | jq -r '.[0].id')
  curl -s -b $COOKIE $ORCH/api/v1/artifacts/$AID/versions | jq '[.[].version]'
  ```
- **Pass:** versions sorted descending; version 1 exists; each rollback/edit/accept appends exactly one new version with a descriptive `note` and an `actor`. A 404 for an unknown id.
- **Coverage:** D.
- **Pitfalls:** the semantic-equality gate means an Accept/rollback to content equal to live writes **no** new version and instead just clears drift and returns the existing live version (`db/config_artifacts.go:255-268`) — don't assert "version count +1" for a no-op accept.

### Raw edit — `PUT /artifacts/{id}/content` (generated → manual)
- **Must:** editing an artifact's raw text records a new version with `source:"manual"`. Editing a **generated** artifact **flips its source to manual** (it can no longer be re-rendered without losing the edit) and the version note becomes `raw edit (generated → manual)`; an already-manual edit notes `raw edit` (`artifact_mask.go:83-118`). The owning agent is re-pushed so the edit reaches the host (`reapplyArtifact` → `pushAgent`).
- **Access:** REST `PUT /api/v1/artifacts/{id}/content` body `{"content":"…"}`; Dashboard Config detail pane → Raw view → edit + save (`Config.tsx:382`).
- **Steps:**
  ```bash
  AID=$(curl -s -b $COOKIE "$ORCH/api/v1/artifacts?source=generated" | jq -r '.[0].id')
  curl -s -b $COOKIE -X PUT $ORCH/api/v1/artifacts/$AID/content \
    -H 'Content-Type: application/json' -d '{"content":"# hand edited\n"}' | jq
  curl -s -b $COOKIE $ORCH/api/v1/artifacts/$AID | jq '{source,live_version}'
  ```
- **Pass:** response is the new version (incremented `version`, `source:"manual"`); the artifact's `source` is now `"manual"` and `live_version` incremented; a new history entry notes `raw edit (generated → manual)`.
- **Coverage:** D (state flip + version + audit all happen in the orchestrator). The actual on-host re-apply is best-effort and only observable end-to-end with a connected agent — R for the host side.
- **Pitfalls:** once flipped to `manual`, the reconciler pushes the **stored bytes verbatim** instead of re-rendering from the domain (`reconciler.go:488-498`); reset-to-model is the only way back to generated.

### Reset to model — `POST /artifacts/{id}/reset-to-model`
- **Must:** re-render the artifact from its domain intent and re-attach it as `source:"generated"`, discarding the manual edit; records a new generated version, re-pushes (`artifact_mask.go:124-153`). **Only valid for model-backed artifacts** (`domain_id` set) — otherwise `400 "artifact is not model-backed (no domain); cannot reset to model"`. For `caddy` it stores the regenerated route JSON; for `nginx` the orchestrator cannot byte-faithfully render, so it stores a marker comment and the **agent re-renders on the next apply** (`artifact_mask.go:161-194`).
- **Access:** REST; Dashboard Config detail pane → "Reset to model" (confirm dialog, `Config.tsx:447-456`).
- **Steps:**
  ```bash
  # AID = the artifact you flipped to manual above (still has domain_id set)
  curl -s -b $COOKIE -X POST $ORCH/api/v1/artifacts/$AID/reset-to-model | jq
  curl -s -b $COOKIE $ORCH/api/v1/artifacts/$AID | jq '{source,domain_id}'
  # negative: a manual/adopted artifact with no domain → 400
  MID=$(curl -s -b $COOKIE "$ORCH/api/v1/artifacts?source=manual" | jq -r '[.[]|select(.domain_id==null)][0].id')
  curl -s -b $COOKIE -o /dev/null -w '%{http_code}\n' -X POST $ORCH/api/v1/artifacts/$MID/reset-to-model
  ```
- **Pass:** the model-backed reset returns a new version and the artifact `source` is back to `"generated"`; a non-model-backed reset returns `400`. A re-render that fails (domain/server/zone lookup) returns `422` (`artifact_mask.go:138`).
- **Coverage:** D for `caddy` (route JSON is rendered orchestrator-side). The `nginx` path stores only a marker until an apply-ACK lands the real bytes — confirming the byte-faithful re-render is **R** (needs a real nginx agent).
- **Pitfalls:** the `caddy` mask/reset path is the only one the orchestrator renders itself; for nginx the stored content right after reset is a one-line `# regenerated from model for <host>; agent re-renders on apply` marker (`artifact_mask.go:190`) — don't mistake that for the final config.

### Structured mask — `GET /artifacts/{id}/mask`
- **Must:** a **pure read** (never mutates) returning `{backend, ok, route, unparsed[], notes[]}`. For `nginx` it best-effort parses into the structured Route; `ok=false` keeps raw authoritative and the form advisory; `unparsed` preserves verbatim bytes the parser couldn't map (`artifact_mask.go:49-77`). For `caddy` it always returns `ok:false` with a note `structured mask not yet available for the caddy backend; edit raw`. Any other backend → `ok:false`, note `no structured mask for backend "<x>"; edit raw`.
- **Access:** REST `GET /api/v1/artifacts/{id}/mask`; Dashboard Config detail pane → Form/Raw toggle (mask fetched lazily on first switch to Form, `Config.tsx:379-421`).
- **Steps:**
  ```bash
  AID=$(curl -s -b $COOKIE $ORCH/api/v1/artifacts | jq -r '.[0].id')
  curl -s -b $COOKIE $ORCH/api/v1/artifacts/$AID/mask | jq '{backend,ok,notes}'
  ```
- **Pass:** caddy artifacts return `ok:false` with the caddy note; nginx artifacts return a parsed `route` with `ok` reflecting round-trip success; the artifact is unchanged afterward (`GET /artifacts/{id}` `updated_at` unchanged).
- **Coverage:** D (caddy/default). The nginx parse quality is best validated against a real adopted nginx file — R.
- **Pitfalls:** the mask is never a lossy owner — on a non-OK parse the **raw text stays authoritative** (`artifact_mask.go:26-27`). Don't treat the form as the source of truth when `ok:false`.

### Adoption ingest — `POST /agents/{id}/artifacts/adopt`
- **Must:** an agent ingests config it read off its host into the central store. Agent auth, and the caller agent ID must equal the path `{id}` (else `403`, `artifacts_adopt.go:27-30`). First sighting creates **version 1**; a re-report appends a version **only on semantic change** (no phantom versions). Operator-authored files (`Adopted:true`) are stored `source:"manual"` and never auto-overwritten; generated files keep `source:"generated"` for drift tracking (`artifacts_adopt.go:73-77`). A file already tracked under a different artifact ID (a generated `dom-N` re-read) is **skipped** to avoid violating the unique-target constraint (`artifacts_adopt.go:88-91`). Ownership guard: an agent cannot mutate another agent's artifact even on an ID collision (`artifacts_adopt.go:116-119`). The on-host `enabled` flag is updated directly (it can change without a content change, `artifacts_adopt.go:125-129`). Audited as `source=agent` (`auditAs`). The endpoint returns a per-batch summary `{received, created, updated}` (`artifacts_adopt.go:52-56`); a semantic-equal re-report counts as neither created nor updated.
- **Access:** REST (agent auth only — agent bearer token, not the user session). Body shape: `proxymodel.AdoptedArtifactReport` `{host, artifacts:[{artifact_id,backend,target_kind,target_path,content,checksum,enabled,adopted}]}` (`wire.go:201-229`). Artifact IDs are agent-scoped, `adopt-<agentID>-<backend>-<sanitized-path>` (`AdoptedArtifactID`, `wire.go:241`). On the agent side this is `ReportAdopted` driven by the backend's `ReadManaged` (`report.go:29`).
- **Prerequisites:** an existing-mode agent against a real nginx/apache with at least one config file to read.
- **Steps (real):** start an existing-mode agent (`NP_DRY_RUN` unset) pointed at a host with nginx config; on startup it calls `ReportAdopted`. Then:
  ```bash
  curl -s -b $COOKIE "$ORCH/api/v1/artifacts?source=manual" | jq '[.[]|{id,target:.target.path,enabled}]'
  ```
- **Pass:** operator files appear with `source:"manual"`, correct `target.path`, and `enabled` reflecting the sites-enabled symlink; re-running adoption with unchanged files adds **no** new versions; toggling a vhost enabled/disabled (without content change) flips `enabled` without a new version.
- **Coverage:** R (the dry agent simulates the proxy in memory and does not read real host files; adoption-ingest is a real-nginx/apache capability). The endpoint's auth/ownership guards can be unit-checked, but a meaningful end-to-end adoption needs a real backend.
- **Pitfalls:** adoption is **independent of the apply path** — an agent reports what it can READ even when it lacks reload permission, so config surfaces under Config regardless (`artifacts_adopt.go:13-16`). Don't expect adoption to imply the agent can reload.

### Heartbeat-driven drift detection & healing
- **Must:** each heartbeat ships `artifact_checksums` (`[{artifact_id,checksum,content?}]`, `wire.go:177-188`). The orchestrator compares each reported on-disk checksum against the accepted (stored) checksum (`agents.go:514-519` → `ReconcileArtifactChecksum`, `db/config_artifacts.go:397-465`):
  - divergence with no prior drift → set `drifted=1`, `apply_state=drifted`, **capture the on-disk bytes into `drift_content`** (the agent ships `content` only when it diverges), audit `drifted` as `source=agent`. The stored/accepted `content` and `checksum` are **never overwritten** (`db/config_artifacts.go:438-450`).
  - matching checksum after a drift → clear back to `live`, wipe `drift_content`, audit `drift_resolved` (`db/config_artifacts.go:427-437`).
  - still-drifted re-edit with new bytes → refresh `drift_content` (not a flag transition, `db/config_artifacts.go:451-460`).
  - an artifact in `apply_failed` is left untouched (failure owns the state, `db/config_artifacts.go:421-423`).
  For a **file backend** the agent re-reads and re-checksums `target_path` **every beat**, so a manual on-disk edit surfaces as drift; the **admin-API built-in Caddy** keeps its in-memory apply-time checksum (the route JSON is itself the live state, no file, `stream.go:141-178`). Healing: on **Reject** (or auto-reconcile) the orchestrator re-pushes the accepted content over the on-disk change; a manual non-NurProxy file is never in the desired set, so it is left untouched and not pruned (`reconciler.go:469-485`).
- **Access:** the agent heartbeat (`POST /api/v1/agents/{id}/heartbeat`, agent auth) with `artifact_checksums`; observe state via `GET /artifacts?drifted=true` and the audit log; Dashboard Config "drifted only" toggle + per-artifact diff (`Config.tsx:545`).
- **Prerequisites for the real path:** a connected file-backend agent (real nginx). For a **dry/handler-level** check you can POST a heartbeat with a crafted divergent checksum (this is exactly what `artifacts_test.go:214` `TestHeartbeat_ChecksumFlagsAndClearsDrift` does).
- **Steps (real):** with an existing-nginx agent serving a generated `nurproxy-<host>.conf`:
  ```bash
  # append a marker to the managed conf on the agent host, then wait ~30–60 s
  # (one heartbeat cycle), and re-query:
  curl -s -b $COOKIE "$ORCH/api/v1/artifacts?drifted=true" | jq '[.[]|{id,apply_state,drift_content}]'
  ```
- **Pass:** the edited managed artifact shows `drifted:true`, `apply_state:"drifted"`, and `drift_content` containing the on-disk bytes (including the marker); a matching/healed beat clears it back to `live` with `drift_content` empty; an unrelated operator file (`zzz-manual.conf`) never appears drifted and is never removed.
- **Coverage:** R for genuine on-disk drift (the dry agent does not write files, so `ManagedChecksums` has no real file to diverge — it re-reports the apply-time checksum). The heartbeat→flag→clear handler logic itself is covered by `TestHeartbeat_ChecksumFlagsAndClearsDrift` (D).
- **Pitfalls:** healing is **heartbeat-driven** — the agent reports checksums on its beat, the orchestrator detects + re-pushes — so **allow a full cycle (~30–60 s)** before asserting (folded from RELEASE-QA §2.7). An unknown/absent artifact ID in the heartbeat is expected before its first apply-ACK and is logged, not fatal (`agents.go:520-524`). The on-disk `content` rides the beat **only on divergence** (matching beats are bandwidth-free), so don't expect `drift_content` to populate from a matching beat.

### Accept drift — `POST /artifacts/{id}/accept`
- **Must:** accept the on-disk content as the new live `manual` version, clearing drift. Body `{"content":"…"}`; when empty it falls back to `drift_content` (the captured on-disk bytes), then to the already-stored `content` (`artifacts.go:88-123`). Records a new version with note `accept drift`, audited `accept`.
- **Access:** REST `POST /api/v1/artifacts/{id}/accept`; Dashboard Config detail pane → "Accept" (one-click; persists the operator's actual on-disk edit, `Config.tsx:462`).
- **Prerequisites:** a drifted artifact (real path) — or drive the accept handler directly on any artifact.
- **Steps:**
  ```bash
  AID=$(curl -s -b $COOKIE "$ORCH/api/v1/artifacts?drifted=true" | jq -r '.[0].id')
  curl -s -b $COOKIE -X POST $ORCH/api/v1/artifacts/$AID/accept \
    -H 'Content-Type: application/json' -d '{}' | jq
  curl -s -b $COOKIE $ORCH/api/v1/artifacts/$AID | jq '{drifted,apply_state,source,live_version}'
  ```
- **Pass:** `drifted:false`, `apply_state:"live"`, `source:"manual"`; a new version with note `accept drift` and the operator's bytes; subsequent heartbeats (now matching the accepted checksum) keep it `live`.
- **Coverage:** D for the handler/version/audit; R to confirm the captured `drift_content` matches a real on-disk edit.
- **Pitfalls:** with an empty body and **no** captured `drift_content` (e.g. admin-API Caddy whose route is its own live state), Accept just re-affirms the existing stored content — it does **not** invent on-disk bytes (`artifacts.go:107-113`).

### Reject drift — `POST /artifacts/{id}/reject`
- **Must:** revert by clearing drift **without** writing a new version (the stored content IS the accepted state) and **re-push** the owning agent so the accepted content overwrites the on-disk change (`artifacts.go:128-138`, `db/config_artifacts.go:472-488`).
- **Access:** REST; Dashboard Config detail pane → "Reject" (`Config.tsx:476`).
- **Steps:**
  ```bash
  AID=$(curl -s -b $COOKIE "$ORCH/api/v1/artifacts?drifted=true" | jq -r '.[0].id')
  curl -s -b $COOKIE -X POST $ORCH/api/v1/artifacts/$AID/reject | jq '{id,drifted,apply_state}'
  ```
- **Pass:** returns the artifact with `drifted:false`, `apply_state:"live"`, **no** new version appended; with a connected agent the on-disk file is restored to the accepted bytes on the next push.
- **Coverage:** D for the state clear + version-count-unchanged; the actual on-host restore is R.
- **Pitfalls:** the re-push is **best-effort** — a no-op when streaming isn't wired or the agent is disconnected; it converges on the next reconcile (`artifacts.go:267-283`). Don't fail the test if the host isn't instantly restored when the agent is offline.

### Rollback — `POST /artifacts/{id}/rollback`
- **Must:** promote a prior version's content to a new live version and re-apply it. Body `{"version": N}` with `N>0` (else `400 "version must be a positive integer"`, `artifacts.go:151-153`). History stays append-only — the rollback is itself a new version with note `rollback to version N` (`db/config_artifacts.go:490-502`). The semantic-equality gate still applies (rolling back to content equal to live writes no phantom version, just clears drift).
- **Access:** REST; Dashboard Config detail pane → version list → "Rollback" on a version (`Config.tsx:490`).
- **Steps:**
  ```bash
  AID=$(curl -s -b $COOKIE $ORCH/api/v1/artifacts | jq -r '.[0].id')
  curl -s -b $COOKIE -X POST $ORCH/api/v1/artifacts/$AID/rollback \
    -H 'Content-Type: application/json' -d '{"version":1}' | jq
  curl -s -b $COOKIE $ORCH/api/v1/artifacts/$AID/versions | jq '[.[]|{version,note}]'
  ```
- **Pass:** a new live version whose content equals version 1's, noted `rollback to version 1 (new live version M)` in audit; history shows the appended rollback version (newest first).
- **Coverage:** D.
- **Pitfalls:** a non-existent target version returns `400` (the version lookup fails, `artifacts.go:158-160`). `version:0` or negative is rejected up front. If version 1 equals the current live content, the rollback no-ops on the version gate (returns the existing live version, no append).

### Bulk accept-all / reject-all — `POST /artifacts/bulk`
- **Must:** resolve **all currently-drifted** artifacts in one call. Body `{"action":"accept"|"reject","agent_id":"…"}`; `agent_id` scopes the action to one agent, omit to resolve every drifted artifact (`artifacts.go:176-239`). `action` must be exactly `accept` or `reject` (else `400`). accept-all appends each artifact's captured `drift_content` (falling back to stored content) as a fresh `manual` version; reject-all reverts each and re-pushes **once per affected agent**. Returns `{action, resolved, total}`.
- **Access:** REST; Dashboard Config page → bulk-review modal, shown when more than the threshold drift at once (`BULK_THRESHOLD`/`bulkBannerTitle`, `Config.tsx:168-173,282-304`) with "Accept all" / "Reject all" buttons.
- **Prerequisites:** several drifted artifacts (use `make dev-sandbox AGENTS=3` + drive drift on a real agent, or test the handler against a seeded drifted set).
- **Steps:**
  ```bash
  curl -s -b $COOKIE -X POST $ORCH/api/v1/artifacts/bulk \
    -H 'Content-Type: application/json' -d '{"action":"reject"}' | jq
  curl -s -b $COOKIE "$ORCH/api/v1/artifacts?drifted=true" | jq 'length'   # expect 0
  ```
- **Pass:** `resolved` equals the number that were drifted; `GET /artifacts?drifted=true` returns `[]` afterward; for reject-all the handler de-dupes pushes into one per affected agent (`artifacts.go:228-232`). `TestArtifacts_BulkReject` (`artifacts_test.go:157`) asserts `resolved==4` and the drifted list empties; `TestArtifacts_BulkBadAction` (`:185`) asserts the `400` on a bad `action`. The push-count de-dup is code-level (the test server has no live pusher).
- **Coverage:** D for the handler over a seeded drifted set; the host-side re-apply is R.
- **Pitfalls:** scope carefully — omitting `agent_id` resolves **every** drifted artifact across all agents. The dashboard only surfaces the bulk modal past the threshold; the REST endpoint has no threshold and acts immediately.

### Per-agent auto-reconcile — `PUT /agents/{id}/auto-reconcile`
- **Must:** toggle the opt-in `auto_reconcile_config` policy (default **off** = manual review). Body `{"enabled": true|false}` → audited `auto_reconcile_config enabled=<bool>` (`artifacts.go:243-262`, persisted `db/agents.go:581`). When **off**, a drifted artifact is **not** pushed by the reconciler — the operator's on-disk change stays until Accept/Reject, and its path is retained so the agent's prune doesn't remove it (`reconciler.go:476-485`). When **on**, the artifact is pushed normally and the generated content re-applied over the drift (hands-off auto-correction). DNS reconciliation is **unaffected** by this gate either way.
- **Access:** REST `PUT /api/v1/agents/{id}/auto-reconcile`; the policy field is on the agent row (`AutoReconcileConfig`).
- **Steps:**
  ```bash
  AGID=$(curl -s -b $COOKIE $ORCH/api/v1/agents | jq -r '.[0].id')
  curl -s -b $COOKIE -X PUT $ORCH/api/v1/agents/$AGID/auto-reconcile \
    -H 'Content-Type: application/json' -d '{"enabled":true}' | jq
  # unknown agent → 404
  curl -s -b $COOKIE -o /dev/null -w '%{http_code}\n' -X PUT \
    $ORCH/api/v1/agents/does-not-exist/auto-reconcile \
    -H 'Content-Type: application/json' -d '{"enabled":true}'
  ```
- **Pass:** returns `{"enabled":true}`; the audit log records `auto_reconcile_config enabled=true`; the value round-trips on the agent (covered by `TestSetAgentAutoReconcileConfig_roundTrips`, `config_artifacts_drift_test.go:310`; unknown-agent error by `TestSetAgentAutoReconcileConfig_missingAgent:339`). The handler-level toggle/audit is `TestArtifacts_AutoReconcileToggle`, `artifacts_test.go:195`. With it on, a drifted file-backend artifact is auto-corrected on the next reconcile; with it off, drift persists for review.
- **Coverage:** D for the toggle/persist/audit + the reconciler gate decision (sandbox reconciler runs). The auto-correction of a genuine on-disk drift is R (needs a real file-backend agent).
- **Pitfalls:** default is **off** — manual review is the intended posture (drift = review, not bulldoze, invariant #3). Turning it on restores the old hands-off behaviour; don't enable it during a drift-review QA pass or you'll lose the artifact to auto-correct before you can inspect it.

### On-demand log tail — start / poll / stop / chunk ingress
- **Must:** open a bounded, on-demand tail of an agent log (no continuous firehose). `POST /agents/{id}/logs/tail` `{"path":"…","lines":N}` validates `path` against the agent's last-reported log paths (`proxy_log_paths` via detection); a path outside that set → `403 "path is not one of this agent's reported log paths"` (`logs.go:84-87`, `pathIsKnownLog` `logs.go:178-188`). Requires live streaming (`503` if the hub is off) and a connected agent (`409` if not connected). Empty path → `400 "path is required"`. Mints an opaque `session_id`, registers the session, and pushes a `log_tail` event down the agent's existing stream (the agent dials out; no inbound probe, invariant #2). The agent re-checks its own allowlist (defense in depth) and POSTs chunks back via `POST /agents/{id}/logs/chunk` (agent auth; caller must own the session, else `403`). Poll `GET /agents/{id}/logs/tail/{session}?cursor=N` returns lines past the cursor and **refreshes activity** so an actively-watched tail is never reaped. `DELETE …/tail/{session}` stops the session and pushes `log_tail_stop`. Idle/abandoned sessions are swept every **30 s** (`logReapInterval`, `logs.go:21`) and the agent told to stop the orphaned tail. A chunk for an unknown session → the agent is told to stop and the response is `{"status":"unknown_session"}` (the view closed, `logs.go:163-170`); a chunk for a live session returns `{"status":"ok"}`.
- **Access:** REST (all four endpoints above); Dashboard agent log view (opens tail → polls → closes on view exit). Agent flag: `-proxy-log-paths` (comma-separated, surfaced as `LogPaths`, `cmd/nurproxy-agent/main.go:59,378`). Backlog defaults: `lines:0` → backend default 200, capped at 2000; chunks bounded to 200 lines (`logtail.go:33,36,43`).
- **Cross-link:** the allowlist is the agent's `proxy_log_paths` / detection `log_paths` — see the proxy-backends QA file for how each backend reports its log paths. A path is tailable only if it appears in the agent's reported `LogPaths`.
- **Prerequisites:** live streaming enabled, a connected agent that reported at least one log path.
- **Steps:**
  ```bash
  AGID=$(curl -s -b $COOKIE $ORCH/api/v1/agents | jq -r '.[0].id')
  # discover the agent's reported log paths:
  curl -s -b $COOKIE $ORCH/api/v1/agents/$AGID | jq '.proxy_detection.log_paths'
  # negative: a path NOT in the allowlist → 403
  curl -s -b $COOKIE -o /dev/null -w '%{http_code}\n' -X POST \
    $ORCH/api/v1/agents/$AGID/logs/tail \
    -H 'Content-Type: application/json' -d '{"path":"/etc/shadow","lines":10}'
  # start a tail on an allowed path:
  SID=$(curl -s -b $COOKIE -X POST $ORCH/api/v1/agents/$AGID/logs/tail \
    -H 'Content-Type: application/json' \
    -d '{"path":"<an-allowed-path>","lines":50}' | jq -r '.session_id')
  curl -s -b $COOKIE "$ORCH/api/v1/agents/$AGID/logs/tail/$SID?cursor=0" | jq
  curl -s -b $COOKIE -X DELETE $ORCH/api/v1/agents/$AGID/logs/tail/$SID | jq
  ```
- **Pass:** an allowed path returns a `session_id` and polling returns buffered lines (cursor advances); a disallowed path returns `403`; empty path `400`; with no live hub `503`; with a disconnected agent `409`; DELETE returns `{"status":"ok"}` and the agent stops tailing; an idle session is reaped within ~30 s.
- **Coverage:** D for the allowlist gate, session lifecycle, reaper, and error codes (the dry agent reports `LogPaths` and participates in the stream). Tailing **real log content** off a live proxy is R.
- **Pitfalls:** the server-side allowlist is the agent's *last-reported* `log_paths` — if the agent hasn't reported detection yet, `pathIsKnownLog` returns `false` for everything (fail-closed, `logs.go:178-182`). The agent's empty `proxy_log_paths` means **no** tail is permitted (fail-closed on the agent too — `logtail.PathAllowed`, `logtail.go:70-72`). The agent's allowlist also accepts a path that is a **file directly inside** a configured *directory* entry (not nested deeper), and cleans both sides to absolute paths so `../` tricks can't escape (`logtail.go:63-93`) — so a tailable path need not be a literal allowlist entry if its parent dir is listed. The tail is on-demand only — there's no continuous stream; a closed view that stops polling is reaped, and an unclean close (tab crash) is swept by the reaper, not instantly. Session IDs are opaque random tokens (`tail-<hex>`, `logs.go:191-200`); one open view owns one session.

## Acceptance checklist

### Dry (every RC)
- [ ] `GET /artifacts` returns seeded `dom-N` with `source:generated`, `apply_state:live`, non-null `domain_id`, `live_version>=1`.
- [ ] Enum values confirmed exactly `generated`/`manual` and `live`/`apply_failed`/`drifted` (no `pending`/`applied`).
- [ ] Filters `source`, `apply_state`, `drifted`, `domain_id`, `agent_id` each narrow correctly; empty result is `[]`.
- [ ] `GET /artifacts/{id}/versions` is newest-first, append-only; semantic-equal re-content writes no version.
- [ ] Raw edit flips a generated artifact to `manual` and appends a version noted `raw edit (generated → manual)`.
- [ ] Reset-to-model returns generated again for a model-backed (caddy) artifact; 400 for a no-domain artifact; 422 on render failure.
- [ ] Mask: caddy/default `ok:false` with the right note; artifact unchanged after the read.
- [ ] Heartbeat with a divergent checksum flags `drifted`/`apply_state:drifted` + captures `drift_content`; a matching checksum clears it (`TestHeartbeat_ChecksumFlagsAndClearsDrift`).
- [ ] Accept clears drift → `manual`, new version `accept drift`; Reject clears drift with no new version; Rollback appends a version noted `rollback to version N`.
- [ ] Bulk reject resolves all drifted (`resolved==total`), `drifted=true` list then empty; handler de-dupes pushes to one per affected agent.
- [ ] `PUT /agents/{id}/auto-reconcile` round-trips `{enabled}`, audits, defaults off; 404 for unknown agent; reconciler skips push for a drifted artifact when off.
- [ ] Log tail: allowed path → `session_id` + polled lines; disallowed → 403; empty path → 400; no hub → 503; disconnected agent → 409; DELETE stops; idle session reaped within ~30 s.

### Real run (before final)
- [ ] Existing-mode adoption ingests operator nginx/apache files as `source:manual` with correct `enabled`; re-report adds no phantom versions; cross-agent ownership guard holds.
- [ ] A genuine on-disk edit to a managed `nurproxy-<host>.conf` flags drift within one heartbeat cycle (~30–60 s) with the on-disk bytes in `drift_content`; a manual non-NurProxy file (`zzz-manual.conf`) is never flagged or pruned.
- [ ] Reject (and auto-reconcile when on) restores the managed file to the accepted bytes on the host on the next push.
- [ ] Reset-to-model on an **nginx** artifact yields the agent-rendered bytes after the next apply-ACK (not just the marker comment).
- [ ] Log tail streams real lines off a live proxy log, respecting the agent's own `proxy_log_paths` allowlist.

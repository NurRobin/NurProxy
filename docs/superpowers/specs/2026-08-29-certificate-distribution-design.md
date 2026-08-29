# Certificate Downloads and Managed Agent Exports

**Date:** 2026-08-29

**Status:** Approved direction; implementation follows the existing cert-only and agent-stream architecture

**Request:** REQ-230

## Goal

Turn NurProxy's existing centrally issued, automatically renewed certificates
into a general distribution feature for non-proxy consumers such as mail
servers, project deployments, appliances, and manual downloads.

An administrator can:

- create a cert-only certificate from the UI;
- download it as a PEM ZIP or password-protected PKCS#12/PFX;
- deploy the same certificate to multiple paths on one or more agents;
- keep every enabled deployment current after renewal;
- reload a selected service or run an explicitly approved post-deploy command;
- see target health, the last successful generation, and rollback history.

The feature must never turn an arbitrary UI path or command into an unchecked
root operation. Existing operator files are not overwritten merely because a
path was entered in the dashboard.

## Chosen approach

Each agent owns a protected, versioned certificate-export store. A successful
deployment writes and validates a complete new generation before atomically
switching a `current` symlink. Destination paths use symlinks into that current
generation by default. Direct file copies are an explicit compatibility mode
for software that refuses symlinks and use per-file snapshots, same-directory
temporary files, atomic renames, validation, and rollback.

This combines Certbot-style stable paths with NurProxy's existing central
issuance and agent-initiated delivery. It is preferred over scattering direct
private-key copies or exposing only one fixed Certbot-compatible directory.

## Resource model

The existing cert-only domain and certificate records remain the source of
issuance and renewal. The UI presents them through a dedicated Certificates
workflow rather than requiring users to understand the proxy-domain form.

A `CertificateExport` belongs to one certificate host and one agent and has:

- stable export ID and display name;
- enabled state;
- deployment mode: `symlink` or `copy`;
- optional absolute destinations for `cert.pem`, `chain.pem`, `fullchain.pem`,
  and `privkey.pem`;
- ownership/mode policy for public material and the private key;
- post-deploy action: none, systemd service reload, or advanced argv command;
- last desired certificate fingerprint and last successfully deployed
  generation;
- health, last error, validation result, and rollback outcome.

The orchestrator sends each agent a full desired export inventory, not merely
the enabled rows. Every snapshot has a monotonically increasing revision and a
keep set. Disabled or deleted exports are represented by durable cleanup
intents until that agent acknowledges removal. Consequently an offline agent
converges on reconnect instead of retaining an export forever. Cleanup removes
only destinations whose protected provenance still matches, records a recovery
snapshot, and reports preserved operator replacements separately.

Destination paths are individual file paths so existing services such as
Postfix can retain their conventional configuration. The UI also offers a
directory preset that fills all four names below one directory.

## Agent-side store and deployment

The default store is below the agent data directory:

~~~text
cert-exports/<export-id>/
  generations/<certificate-fingerprint>/
    cert.pem
    chain.pem
    fullchain.pem
    privkey.pem
    manifest.json
  current -> generations/<certificate-fingerprint>
~~~

Directories are `0700`. Private keys are `0600` unless an explicitly selected
policy requires a service group. Public material defaults to `0644`. The
manifest contains identifiers, public certificate fingerprints, paths, modes,
and state; it never contains private-key bytes, hook secrets, or passwords.

For symlink mode the destination links remain stable and point to files below
`current`. Renewal writes a new generation, validates the certificate chain and
key pair, fsyncs it, atomically replaces `current`, validates every destination,
and only then performs the post-deploy action. A failed post-check or reload
switches `current` back and retries the prior service reload.

For copy mode the agent snapshots every existing destination and its metadata,
writes same-directory temporary files, applies owner/group/mode, renames all
files, validates them, and performs the post-deploy action. Failure restores
the entire snapshot set. The UI warns that services reading separate paths
during the short multi-file rename window may observe mixed generations;
symlink mode is the recommended default.

Generation creation is idempotent by certificate fingerprint. Retention keeps
the current and previous successful generation plus any generation referenced
by an active rollback operation. Other generations expire after seven days.
The same no-follow retention pass keeps the newest 20 inactive generations as
a second safety bound and never removes an active transaction, cleanup
tombstone, or snapshot younger than seven days.

Generation creation and publication are separate operations. A transaction
stages and validates a generation, records the previous `current` identity,
deploys destinations, switches `current`, validates destinations, and runs the
hook under one per-export lock. Only then is the new generation committed.
Failure restores the previous `current` link and destination set before the
prior hook is retried.

## Path ownership and permissions

Every agent has explicit certificate-export roots. A destination must be an
absolute, clean path under one of those roots after parent-symlink
canonicalization. The local agent setting is authoritative; an orchestrator
cannot widen it silently.

The UI can request a new root, but enabling it is a hard host-level change with
a second confirmation and a clear preview of affected paths. The agent rejects
root, traversal, control characters, symlink escapes, device files, sockets,
directories used as files, and identity changes between inspection and
mutation.

NurProxy may create an absent destination. It may replace only:

- a symlink that already points into the same export's store;
- a file carrying the same export's provenance record; or
- an existing path explicitly adopted through a one-time snapshot-and-confirm
  flow.

Arbitrary existing files remain diagnosis-only. Mutation uses opened parent
directory descriptors with no-follow and identity checks; a pathname recheck
alone is insufficient.

Copy-mode ownership is recorded in the protected export manifest as a binding
of export ID, canonical destination, deployed generation, content hash,
device/inode identity, mode, uid/gid, and link count. Before replacement the
agent opens the destination without following links, requires a regular file
with link count one, recomputes its content hash, and compares identity and
metadata with that binding. After atomic rename it records the new identity in
the same transaction. A stale/spoofed manifest, hardlink, or operator
replacement breaks provenance and is preserved.

The normal UI offers presets:

- root-only;
- public certificate plus root-only private key;
- public certificate plus service-group-readable private key.

Advanced owner, group, and modes are validated on the agent and require a
second confirmation. User/group names are resolved to numeric IDs during
planning and rechecked during apply.

Planning is an agent round trip. The orchestrator sends a typed, non-mutating
plan request over the outbound stream. The agent returns resolved roots,
canonical destinations, uid/gid, modes, action allowlist result, risks, and a
short-lived freshness token bound to the exact normalized export specification
and local capability revision. Saving the definition presents this result in a
second in-UI confirmation and submits the token; apply still revalidates every
predicate fail-closed. Widening the agent-local root or allowlists is different:
the UI may prepare a typed host-presence admin operation and display its
one-time claim command, but the operation is applied only when claimed locally
on that agent. Its payload is a closed set, persisted atomically in the agent
config, and never accepts raw config text or an implicit widening from export
CRUD.

## Post-deploy actions

`systemd service` is the safe default. The service must be selected from an
agent-local allowlist. The agent performs a typed reload operation with a
timeout, bounded sanitized output, and a status check. It does not accept a
service name extracted from certificate or process error text.

`advanced command` stores an argv vector, not a shell string. The executable
must be absolute and agent-allowlisted. Arguments are fixed; certificate values
are supplied only through documented environment variables containing paths,
never private material. The UI provides a static parse/allowlist/identity
preview, timeout selection within a bounded range, and a second confirmation.
It never executes user-supplied argv while merely planning or opening the
wizard. Shell
interpreters are rejected unless the operator separately allowlists that exact
interpreter locally, in which case the UI labels the action high risk.

An operator may request an actual hook test only as a separate high-impact
operation after confirmation. It uses the same snapshot, timeout, audit,
serialization, failure, and rollback contract as deployment. Systemd preflight
is limited to typed read-only unit/status/capability queries; reload is likewise
never used as a planning probe.

Output is captured with the existing bounded/sanitized command-capture
contract. Hooks never run concurrently for the same export. A failed hook makes
the deployment fail and triggers rollback; the previous-generation hook is
then run once. Repeated failures open the recovery circuit breaker.

The export package owns its filesystem transaction store and a small breaker
interface. It does not import operation-specific recovery internals. Once the
safe-recovery engine is present, an adapter supplies its breaker implementation;
until then a compatible local implementation keeps the package independently
testable.

## Browser downloads

Only an authenticated administrator can download private material. The API
decrypts the stored key in memory, validates the certificate/key pair, streams
the selected format, and discards buffers. Responses use `Cache-Control:
no-store`, a safe attachment filename, and never pass through audit details,
application logs, metrics labels, or error text.

PEM ZIP contains `cert.pem`, `chain.pem`, `fullchain.pem`, and `privkey.pem`.
PFX uses a password supplied for that request. The UI can generate a
cryptographically random password client-side or accept a user-defined one;
the password is never persisted and a generated password is shown only once.
Empty PFX passwords are rejected. Downloads are audited without recording the
key, archive, or password.

There is no persistent downloadable archive. A later download creates a fresh
archive from the currently stored certificate.

Certificate list/detail queries select public metadata only and never read or
decrypt the encrypted key column. Only a request for one exact authenticated
download fetches and decrypts that certificate's key.

## Data flow

1. The administrator creates or selects a cert-only certificate.
2. Central issuance and renewal continue through the existing DNS-01 manager.
3. Before save, a typed plan exchange lets the agent resolve paths,
   ownership, capabilities, and actions and returns a spec-bound freshness token.
4. The reconciler includes certificate bundles plus a revisioned full desired
   export inventory, including durable cleanup tombstones, in the existing
   outbound agent stream.
5. The agent validates paths, ownership, capabilities, permissions, and actions
   and reports a diagnosis without mutation if any predicate fails.
6. The agent snapshots, deploys one complete generation, post-validates, runs
   the post-deploy action, and reports structured progress and history.
7. Renewal repeats the same idempotent flow and fans out to every distinct agent
   with an enabled export. Active exports count as certificate consumers for
   renewal and prevent last-domain teardown from deleting their certificate.
8. Offline agents converge cleanup and deployment on reconnect; one failed
   target does not block other agents or exports for the same certificate.

Stream JSON is decoded strictly and every envelope is validated. The contract
sets aggregate limits for exports, destinations, certificate bundles, PEM bytes,
argv and total event bytes; duplicate export IDs, hosts, and destinations are
rejected. When the bounded SSE frame would be exceeded, the orchestrator emits
revision-bound chunks that the agent assembles under a total cap before apply.
Older peers negotiate capability and receive only the legacy intent payload.

## UI

The Certificates page separates three concerns:

- **Certificate:** host, zone/provider, issuance and renewal status;
- **Download:** PEM ZIP or PFX, password choice, one-time secret handling;
- **Deployments:** agent, paths/directory preset, symlink/copy mode,
  permissions, reload action, static preflight, explicitly confirmed live hook
  test, current generation, and history.

The default wizard chooses symlink mode, the agent's standard export root,
safe permissions, and no hook. Advanced paths, copy mode, custom ownership, and
commands are progressively disclosed. A review screen shows every filesystem
path, resolved owner/mode, executable/service, and rollback behavior before the
request is saved.

Ordinary high-impact choices use a one-time, short-lived server nonce bound to
the reviewed plan and are confirmed entirely in the UI. This is distinct from
the existing agent admin-op claim code. Only widening local export roots or
allowlists uses the host-presence claim workflow.

## Failure handling and recovery

- Invalid certificate or key material is rejected before filesystem mutation.
- Snapshot failure prevents deployment.
- Path identity or ownership changes abort before mutation.
- Validation or post-deploy failure rolls back the previous generation and
  records both the original and rollback result.
- Rollback failure is critical, opens the breaker, and requires manual retry.
- Missing service, insufficient permission, sandbox restrictions, and unknown
  hook failures remain diagnosis-only; NurProxy does not rewrite sudoers or
  service units automatically.
- Deleting an export removes only links/files with matching provenance and
  retains a recovery snapshot for seven days.

## Test and rollout gates

Unit and negative-security tests cover archive contents, PFX passwords,
certificate/key validation, path traversal, parent and final symlink swaps,
hardlinks, existing unrelated files, provenance, uid/gid/modes, argv parsing,
output bounds, secret redaction, rollback, breaker behavior, retention, and
idempotent renewal.

Agent integration tests use real filesystem permissions and disposable systemd
or process fixtures. Browser E2E covers certificate creation, PEM and PFX
download, random-password one-time display, deployment review, safe and
advanced confirmations, health, and history.

Production rollout is canary-first: one disposable cert-only host and export on
`orax`, then `durox`, then a non-critical target on the apps VM. Each canary
proves initial install, renewal-equivalent generation switch, service reload,
forced validation failure, rollback, and unrelated-file preservation before
the next host is enabled.

## Explicit non-goals

- Importing third-party private keys into NurProxy.
- Automatically editing service configuration files to reference exports.
- Automatically widening sudoers, systemd sandboxing, or export roots.
- Passing private key bytes to hooks or exposing them through MCP/audit APIs.
- Treating a user-entered path, filename, or command as ownership proof.

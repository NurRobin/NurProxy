# Safe recovery QA

## Sandbox recovery assertions

The sandbox keeps DNS and ACME in dry-run mode but runs its agent in existing
nginx mode against a temporary `conf.d`. A build-tagged, hermetic executable
implements only the fixed nginx version, config-test, and reload argument
shapes. It requires no installed proxy package, shell, privileged write, bound
proxy port, or service manager.

The harness writes an exact-marker NurProxy temporary file, triggers a normal
intent push, and requires an automatic `remove_managed_temp` operation to record
the detected, planned, snapshotted, applying, validating, and succeeded states.
It also requires a snapshot reference, a valid post-check, removal of the
temporary file, and a resolved structured diagnostic.

A second push makes the fixture validator return an unclassified error. The
agent must classify it as `unknown_proxy_error` with unknown ownership, no
proposed action, and no automatic-repair eligibility. No additional repair
operation may be created, and both an operator-owned file and the previous
managed bytes must remain identical after the ordinary apply rollback.

The fixture does not parse nginx syntax or operate a native service. Therefore
these assertions prove control-plane delivery, real file-backend inspection,
classification, snapshots, guarded mutation, validation/reload sequencing,
rollback, and reporting, but they do not prove native `nginx -t`, Apache
validation, or live traffic behavior. Tagged native integration tests and the
hardware canary provide that separate evidence.

## Hardware canary

On `hlpvpngw` (`10.42.0.2`), a native nginx canary detected and automatically
removed one exact-marker owned stale temporary file. The recorded operation
included a snapshot and a successful native nginx config test before reaching
`succeeded`. A separate unmarked invalid `conf.d` file produced
`unknown_proxy_error` with unknown ownership and automatic repair disabled; no
repair operation was created. After the operator-style fixture was removed, the
diagnostic resolved. No secret material or machine-local certificate paths are
part of this record.

## API E2E assertions

The tagged API E2E exercises the real HTTP and SSE control plane. It checks
policy delivery, diagnostic reporting, live repair delivery, reconnect replay,
ACK transitions, duplicate terminal-ACK idempotency, rollback history, and
compatibility with the agent's existing `last_error`. Live and replayed repair
requests must equal the complete persisted request, including their initial
step and timestamps. History after a duplicate terminal ACK must equal the
complete terminal operation report.

## Dashboard recovery projection bounds

The diagnostics endpoint returns every active diagnostic plus at most 100
resolved entries by default (caller-selectable from 0 through 200). Breaker
projection accepts arbitrarily many returned keys in portable SQLite-sized
chunks: latest success/latch metadata uses indexed lookups, while each terminal
failure state contributes at most 256 recent receipts per key. This keeps work
independent of older unbounded operation history without changing the scalar
breaker semantics. Every recovery-history card summary includes operation
state, action, request source, and relative start time, including while older
cards remain collapsed.

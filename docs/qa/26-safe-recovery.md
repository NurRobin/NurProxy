# Safe recovery QA

## Sandbox limitation

The `sandbox` build runs the agent with the in-memory Caddy backend. It does not
create native nginx or Apache configuration files, temporary managed files, or
invoke a native proxy validator. With no certificate store configured, its
Caddy recovery inspector also returns no file-recovery candidates.

Consequently, the sandbox harness cannot legitimately inject and heal a stale
managed temporary file, and it cannot prove `nginx -t`, `apachectl -t`, reload,
snapshot, or rollback behavior. The Task 11 sandbox stale-temp criterion remains
open until the harness gains a recovery-aware dry backend or an equivalent
native fixture. A broad advertised capability must not be treated as evidence
that this dry backend actually inspected or repaired a file.

The sandbox test currently proves only that a preclassified, diagnosis-only
diagnostic can cross the authenticated agent report endpoint and be read back
without gaining an action or automatic-repair eligibility. Classification and
repair execution are covered by the agent recovery and native integration
tests, not by that report round-trip.

## API E2E assertions

The tagged API E2E exercises the real HTTP and SSE control plane. It checks
policy delivery, diagnostic reporting, live repair delivery, reconnect replay,
ACK transitions, duplicate terminal-ACK idempotency, rollback history, and
compatibility with the agent's existing `last_error`. Live and replayed repair
requests must equal the complete persisted request, including their initial
step and timestamps. History after a duplicate terminal ACK must equal the
complete terminal operation report.

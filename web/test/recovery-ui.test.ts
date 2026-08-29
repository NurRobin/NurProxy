import assert from 'node:assert/strict';
import test from 'node:test';
import {
  diagnosticLocation,
  diagnosticActionVisible,
  diagnosticBreaker,
  recoveryErrorCode,
  recoveryHistory,
  recoveryOperationTerminal,
  repairAvailability,
  recoveryOperationDetails,
} from '../src/lib/recovery-ui.ts';
import { pollingActive } from '../src/lib/usePolling.ts';
import type { Agent, RecoveryDiagnostic, RecoveryOperation } from '../src/lib/types.ts';

const agent = {
  id: 'agent-1',
  status: 'adopted',
  recovery_capability: { stage: 1, actions: ['remove_managed_temp'] },
} as Agent;

const diagnostic = {
  id: 'diag-1',
  ownership: 'nurproxy',
  auto_repair_eligible: true,
  hard_change: false,
  proposed_action: 'remove_managed_temp',
} as RecoveryDiagnostic;

test('only final recovery states stop progress polling', () => {
  for (const state of ['diagnosis_only', 'succeeded', 'rolled_back', 'rollback_failed', 'suppressed']) {
    assert.equal(recoveryOperationTerminal({ state } as RecoveryOperation), true, state);
  }
  for (const state of ['detected', 'planned', 'snapshotted', 'applying', 'validating', 'rolling_back']) {
    assert.equal(recoveryOperationTerminal({ state } as RecoveryOperation), false, state);
  }
});

test('safe typed repairs are executable when the capable agent is available', () => {
  assert.deepEqual(repairAvailability(agent, diagnostic, []), { enabled: true });
});

test('authoritative open breaker disables a safe manual repair', () => {
  assert.deepEqual(repairAvailability(agent, { ...diagnostic, breaker: { open: true, reason: 'failure_threshold' } }, []), {
    enabled: false,
    reason: 'circuit_breaker_open',
  });
});

test('missing breaker projection is transitionally treated as closed', () => {
  assert.deepEqual(diagnosticBreaker({ ...diagnostic, breaker: undefined }), { open: false });
});

test('rollback-failed latch keeps the explicit manual validation escape available', () => {
  assert.deepEqual(repairAvailability(agent, { ...diagnostic, breaker: { open: true, reason: 'rollback_failed_latched' } }, []), {
    enabled: true,
  });
});

test('hard changes stay visible but disabled in stage one', () => {
  assert.deepEqual(repairAvailability(agent, { ...diagnostic, hard_change: true }, []), {
    enabled: false,
    reason: 'hard_change',
  });
});

test('active repairs and missing capabilities disable duplicate execution', () => {
  const active = [{ diagnostic_id: diagnostic.id, state: 'applying' }] as RecoveryOperation[];
  assert.deepEqual(repairAvailability(agent, diagnostic, active), {
    enabled: false,
    reason: 'operation_active',
  });
  assert.deepEqual(repairAvailability({ ...agent, recovery_capability: undefined }, diagnostic, []), {
    enabled: false,
    reason: 'recovery_capability_unavailable',
  });
});

test('structured API error codes survive for actionable UI feedback', () => {
  assert.equal(recoveryErrorCode({ data: { code: 'circuit_breaker_open' } }), 'circuit_breaker_open');
  assert.equal(recoveryErrorCode(new Error('network')), 'unknown');
});

test('file and line are extracted only for an affected path', () => {
  assert.equal(diagnosticLocation({
    ...diagnostic,
    affected_paths: ['/etc/nginx/sites-enabled/app.conf'],
    evidence: 'nginx: [emerg] unexpected } in /etc/nginx/sites-enabled/app.conf:42:9',
  }), '/etc/nginx/sites-enabled/app.conf:42:9');
  assert.equal(diagnosticLocation({
    ...diagnostic,
    affected_paths: ['/etc/apache2/sites-enabled/app.conf'],
    evidence: 'Syntax error on line 17 of /etc/apache2/sites-enabled/app.conf:\nInvalid command',
  }), '/etc/apache2/sites-enabled/app.conf:17');
  assert.equal(diagnosticLocation({ ...diagnostic, affected_paths: [], evidence: 'somewhere:7' }), null);
});

test('production-shaped hard, operator, and system diagnoses stay visible without a typed action', () => {
  for (const candidate of [
    { ownership: 'nurproxy', hard_change: true, reason: 'hard_change' },
    { ownership: 'operator', hard_change: false, reason: 'ownership_not_nurproxy' },
    { ownership: 'system', hard_change: false, reason: 'ownership_not_nurproxy' },
  ] as const) {
    const shaped = {
      ...diagnostic,
      ownership: candidate.ownership,
      hard_change: candidate.hard_change,
      auto_repair_eligible: false,
      proposed_action: '',
    } as RecoveryDiagnostic;
    assert.equal(diagnosticActionVisible(shaped), true, candidate.ownership);
    assert.deepEqual(repairAvailability(agent, shaped, []), { enabled: false, reason: candidate.reason });
  }
});

test('repair history is scoped to the selected diagnostic', () => {
  const history = [
    { operation_id: 'new', diagnostic_id: 'diag-1' },
    { operation_id: 'other', diagnostic_id: 'diag-2' },
    { operation_id: 'old', diagnostic_id: 'diag-1' },
  ] as RecoveryOperation[];
  assert.deepEqual(recoveryHistory(history, 'diag-1').map((item) => item.operation_id), ['new', 'old']);
});

test('historical operation details retain source and every audit field', () => {
  const operation = {
    operation_id: 'op-full', diagnostic_id: 'diag-1', action: 'remove_managed_temp', source: 'automatic', state: 'rolled_back',
    steps: [{ name: 'rollback', summary: 'restored', state: 'rolled_back', at: '2026-08-29T05:00:02Z' }],
    snapshot_reference: 'recovery/op-full', validation_outcome: 'invalid', rollback_outcome: 'restored', error: 'sanitized',
    started_at: '2026-08-29T05:00:00Z', finished_at: '2026-08-29T05:00:02Z',
  } as RecoveryOperation;
  assert.deepEqual(recoveryOperationDetails(operation), operation);
});

test('hidden polling continues only while a recovery operation is active', () => {
  assert.equal(pollingActive('hidden', true), true);
  assert.equal(pollingActive('hidden', false), false);
  assert.equal(pollingActive('visible', false), true);
});

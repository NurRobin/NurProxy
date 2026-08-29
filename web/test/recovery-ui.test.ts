import assert from 'node:assert/strict';
import test from 'node:test';
import {
  diagnosticLocation,
  recoveryErrorCode,
  recoveryHistory,
  recoveryOperationTerminal,
  repairAvailability,
} from '../src/lib/recovery-ui.ts';
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
    evidence: 'nginx: [emerg] unexpected } in /etc/nginx/sites-enabled/app.conf:42',
  }), '/etc/nginx/sites-enabled/app.conf:42');
  assert.equal(diagnosticLocation({ ...diagnostic, affected_paths: [], evidence: 'somewhere:7' }), null);
});

test('repair history is scoped to the selected diagnostic', () => {
  const history = [
    { operation_id: 'new', diagnostic_id: 'diag-1' },
    { operation_id: 'other', diagnostic_id: 'diag-2' },
    { operation_id: 'old', diagnostic_id: 'diag-1' },
  ] as RecoveryOperation[];
  assert.deepEqual(recoveryHistory(history, 'diag-1').map((item) => item.operation_id), ['new', 'old']);
});

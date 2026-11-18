import assert from 'node:assert/strict';
import test from 'node:test';
import { outdatedAgents, rolloutRunning, upgradeActive, upgradeAvailability, upgradeTone } from '../src/lib/upgrade.ts';
import type { Agent, AgentUpgrade, AgentUpgradeState } from '../src/lib/types.ts';

const upgrade = (state: AgentUpgradeState) => ({ id: 'u1', agent_id: 'a1', state } as AgentUpgrade);
const agent = (extra: Partial<Agent>) => ({ id: 'a1', status: 'adopted', ...extra } as Agent);

test('upgradeActive covers exactly the non-terminal states', () => {
  for (const s of ['requested', 'downloading', 'installed', 'restarting'] as const) assert.equal(upgradeActive(upgrade(s)), true, s);
  for (const s of ['done', 'failed', 'rolled_back'] as const) assert.equal(upgradeActive(upgrade(s)), false, s);
  assert.equal(upgradeActive(undefined), false);
});

test('upgradeTone maps states to progress, success and danger', () => {
  assert.equal(upgradeTone('downloading'), 'progress');
  assert.equal(upgradeTone('done'), 'success');
  assert.equal(upgradeTone('failed'), 'danger');
  assert.equal(upgradeTone('rolled_back'), 'danger');
});

test('upgradeAvailability', () => {
  assert.deepEqual(upgradeAvailability(agent({})), { allowed: true });
  assert.deepEqual(upgradeAvailability(agent({ status: 'pending' })), { allowed: false, reason: 'not_adopted' });
  assert.deepEqual(upgradeAvailability(agent({ upgrade: upgrade('restarting') })), { allowed: false, reason: 'in_progress' });
  assert.deepEqual(upgradeAvailability(agent({ upgrade: upgrade('failed') })), { allowed: true });
  assert.deepEqual(
    upgradeAvailability(agent({ self_update: { supported: false, reason: 'running in a container' } })),
    { allowed: false, reason: 'unsupported', detail: 'running in a container' },
  );
  assert.deepEqual(upgradeAvailability(agent({ self_update: { supported: true } })), { allowed: true });
});

test('outdatedAgents skips pending agents', () => {
  const list = [
    agent({ id: 'a', version_status: 'outdated' }),
    agent({ id: 'b', version_status: 'current' }),
    agent({ id: 'c', status: 'pending', version_status: 'outdated' }),
  ];
  assert.deepEqual(outdatedAgents(list).map((a) => a.id), ['a']);
});

test('rolloutRunning', () => {
  assert.equal(rolloutRunning(null), false);
  assert.equal(rolloutRunning({ state: 'running' } as never), true);
  assert.equal(rolloutRunning({ state: 'failed' } as never), false);
});

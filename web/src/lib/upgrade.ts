import type { Agent, AgentUpgrade, AgentUpgradeState, UpgradeRollout } from './types';

const ACTIVE_STATES: ReadonlySet<AgentUpgradeState> = new Set(['requested', 'downloading', 'installed', 'restarting']);

/** True while an upgrade has not reached done, failed or rolled_back. */
export function upgradeActive(upgrade: AgentUpgrade | undefined | null): boolean {
  return !!upgrade && ACTIVE_STATES.has(upgrade.state);
}

/** True for a release version with a pre-release suffix such as -rc.1 or -beta.2. */
export function isPrerelease(version: string | undefined | null): boolean {
  return !!version && /^v?\d+\.\d+\.\d+-[0-9A-Za-z.-]+$/.test(version.trim());
}

export type UpgradeTone = 'progress' | 'success' | 'danger';

export function upgradeTone(state: AgentUpgradeState): UpgradeTone {
  if (ACTIVE_STATES.has(state)) return 'progress';
  return state === 'done' ? 'success' : 'danger';
}

export type UpgradeAvailability =
  | { allowed: true }
  | { allowed: false; reason: 'unsupported'; detail?: string }
  | { allowed: false; reason: 'in_progress' | 'not_adopted' };

/**
 * Whether the dashboard should offer a manual upgrade. An agent that never
 * reported self_update (older build) is still offered the button; the server
 * then answers with the actual reason.
 */
export function upgradeAvailability(agent: Agent): UpgradeAvailability {
  if (agent.status === 'pending') return { allowed: false, reason: 'not_adopted' };
  if (upgradeActive(agent.upgrade)) return { allowed: false, reason: 'in_progress' };
  if (agent.self_update && !agent.self_update.supported) {
    return { allowed: false, reason: 'unsupported', detail: agent.self_update.reason };
  }
  return { allowed: true };
}

/** Agents that a bulk "upgrade all outdated" rollout would pick up. */
export function outdatedAgents(agents: Agent[]): Agent[] {
  return agents.filter((a) => a.status !== 'pending' && a.version_status === 'outdated');
}

export function rolloutRunning(rollout: UpgradeRollout | null | undefined): boolean {
  return rollout?.state === 'running';
}

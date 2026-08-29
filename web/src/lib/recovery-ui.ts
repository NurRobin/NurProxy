import { createElement } from 'react';
import type { Agent, RecoveryDiagnostic, RecoveryOperation } from './types';
import type { RecoveryBreaker } from './types';

export interface RepairAvailability {
  enabled: boolean;
  reason?: string;
}

export function diagnosticActionVisible(diagnostic: RecoveryDiagnostic): boolean {
  return diagnostic.proposed_action !== '' || diagnostic.hard_change || diagnostic.ownership !== 'nurproxy';
}

export function diagnosticBreaker(diagnostic: RecoveryDiagnostic): RecoveryBreaker {
  return diagnostic.breaker ?? { open: false };
}

export function RecoveryHistoryCardSummary({
  operation,
  translate,
  formatTime,
}: {
  operation: RecoveryOperation;
  translate: (key: string) => string;
  formatTime: (value: string) => string;
}) {
  return createElement('span', null,
    `${translate(`recovery.states.${operation.state}`)} · `,
    `${translate(`recovery.actions.${operation.action}`)} · `,
    `${translate(`recovery.sources.${operation.source}`)} · `,
    formatTime(operation.started_at),
  );
}

export function recoveryHistory(operations: RecoveryOperation[], diagnosticID: string): RecoveryOperation[] {
  return operations.filter((operation) => operation.diagnostic_id === diagnosticID);
}

export function diagnosticLocation(diagnostic: RecoveryDiagnostic): string | null {
  for (const path of diagnostic.affected_paths) {
    const marker = `${path}:`;
    const offset = diagnostic.evidence.indexOf(marker);
    if (offset < 0) continue;
    const suffix = diagnostic.evidence.slice(offset + marker.length);
    const line = /^(\d+)(?::\d+)?/.exec(suffix)?.[0];
    if (line) return `${path}:${line}`;

    const apacheMarker = ` of ${path}:`;
    const apacheOffset = diagnostic.evidence.indexOf(apacheMarker);
    if (apacheOffset < 0) continue;
    const apachePrefix = diagnostic.evidence.slice(0, apacheOffset);
    const apacheLine = /Syntax error on line (\d+)\s*$/i.exec(apachePrefix)?.[1];
    if (apacheLine) return `${path}:${apacheLine}`;
  }
  return null;
}

export function recoveryOperationTerminal(_operation: RecoveryOperation): boolean {
  return ['diagnosis_only', 'succeeded', 'rolled_back', 'rollback_failed', 'suppressed'].includes(_operation.state);
}

export function repairAvailability(
  _agent: Agent,
  _diagnostic: RecoveryDiagnostic,
  _operations: RecoveryOperation[],
): RepairAvailability {
  if (_diagnostic.hard_change) return { enabled: false, reason: 'hard_change' };
  if (_diagnostic.ownership !== 'nurproxy') return { enabled: false, reason: 'ownership_not_nurproxy' };
  if (!_diagnostic.auto_repair_eligible || !_diagnostic.proposed_action) {
    return { enabled: false, reason: 'not_safe_repair_eligible' };
  }
  if (_operations.some((operation) => operation.diagnostic_id === _diagnostic.id && !recoveryOperationTerminal(operation))) {
    return { enabled: false, reason: 'operation_active' };
  }
  const breaker = diagnosticBreaker(_diagnostic);
  if (breaker.open && breaker.reason !== 'rollback_failed_latched') {
    return { enabled: false, reason: 'circuit_breaker_open' };
  }
  if (_agent.status === 'offline' || _agent.status === 'pending') {
    return { enabled: false, reason: 'agent_disconnected' };
  }
  if (!_agent.recovery_capability || _agent.recovery_capability.stage < 1) {
    return { enabled: false, reason: 'recovery_capability_unavailable' };
  }
  if (!_agent.recovery_capability.actions.includes(_diagnostic.proposed_action)) {
    return { enabled: false, reason: 'action_unsupported' };
  }
  return { enabled: true };
}

export function recoveryErrorCode(error: unknown): string {
  if (typeof error === 'object' && error !== null && 'data' in error) {
    const data = error.data;
    if (typeof data === 'object' && data !== null && 'code' in data && typeof data.code === 'string') {
      return data.code;
    }
  }
  return 'unknown';
}

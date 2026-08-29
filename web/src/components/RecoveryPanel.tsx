import { useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { Agent, RecoveryDiagnostic, RecoveryOperation } from '../lib/types';
import { api } from '../lib/api';
import { formatRelativeTime } from '../lib/utils';
import { diagnosticActionVisible, diagnosticLocation, recoveryErrorCode, recoveryHistory, recoveryOperationTerminal, repairAvailability } from '../lib/recovery-ui';
import { usePolling } from '../lib/usePolling';
import { useToast, errMessage } from './toast-context';
import Button from './Button';
import Callout from './Callout';
import ConfirmDialog from './ConfirmDialog';
import { Select } from './Field';

interface RecoveryPanelProps {
  agent: Agent;
  onAgentChanged: () => void;
}

const severityTone = (severity: RecoveryDiagnostic['severity']) =>
  severity === 'critical' || severity === 'error' ? 'danger' : severity === 'warning' ? 'warning' : 'info';

function OperationDetails({ operation }: { operation: RecoveryOperation }) {
  const { t } = useTranslation();
  return (
    <div className="mt-2 pl-3">
      <dl className="grid gap-2 text-xs sm:grid-cols-2">
        <div><dt className="text-fg-faint">{t('recovery.action')}</dt><dd className="text-fg-muted">{t(`recovery.actions.${operation.action}`)}</dd></div>
        <div><dt className="text-fg-faint">{t('recovery.operationId')}</dt><dd className="break-all font-mono text-fg-muted">{operation.operation_id}</dd></div>
        <div><dt className="text-fg-faint">{t('recovery.started')}</dt><dd className="text-fg-muted">{new Date(operation.started_at).toLocaleString()}</dd></div>
        <div><dt className="text-fg-faint">{t('recovery.finished')}</dt><dd className="text-fg-muted">{operation.finished_at ? new Date(operation.finished_at).toLocaleString() : t('recovery.inProgress')}</dd></div>
        <div><dt className="text-fg-faint">{t('recovery.snapshot')}</dt><dd className="break-all text-fg-muted">{operation.snapshot_reference || '—'}</dd></div>
        <div><dt className="text-fg-faint">{t('recovery.validation')}</dt><dd className="text-fg-muted">{operation.validation_outcome || '—'}</dd></div>
        <div><dt className="text-fg-faint">{t('recovery.rollback')}</dt><dd className="text-fg-muted">{operation.rollback_outcome || '—'}</dd></div>
        <div><dt className="text-fg-faint">{t('recovery.operationError')}</dt><dd className={operation.error ? 'text-danger-fg' : 'text-fg-muted'}>{operation.error || '—'}</dd></div>
      </dl>
      <p className="mt-3 text-xs font-medium text-fg-muted">{t('recovery.steps')}</p>
      {operation.steps.length > 0 ? (
        <ol className="mt-1 space-y-1 border-l border-border pl-3">
          {operation.steps.map((step, index) => (
            <li key={`${step.at}-${index}`} className="text-xs text-fg-muted">
              <span className="font-medium text-fg">{t(`recovery.states.${step.state}`)}</span> — {step.summary} · {new Date(step.at).toLocaleString()}
            </li>
          ))}
        </ol>
      ) : <p className="mt-1 text-xs text-fg-faint">—</p>}
    </div>
  );
}

export default function RecoveryPanel({ agent, onAgentChanged }: RecoveryPanelProps) {
  const { t } = useTranslation();
  const toast = useToast();
  const [active, setActive] = useState<RecoveryDiagnostic[]>([]);
  const [diagnostics, setDiagnostics] = useState<RecoveryDiagnostic[]>([]);
  const [operations, setOperations] = useState<RecoveryOperation[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [repair, setRepair] = useState<RecoveryDiagnostic | null>(null);
  const [repairing, setRepairing] = useState(false);
  const [operationError, setOperationError] = useState<{ code: string; message: string } | null>(null);
  const [policySaving, setPolicySaving] = useState(false);

  const fetchRecovery = useCallback(async () => {
    try {
      const [activeList, allList, operationList] = await Promise.all([
        api.listRecoveryDiagnostics(agent.id, false),
        api.listRecoveryDiagnostics(agent.id, true),
        api.listRecoveryOperations(agent.id),
      ]);
      setActive(activeList);
      setDiagnostics(allList);
      setOperations(operationList);
      setLoadError('');
    } catch (error) {
      setLoadError(errMessage(error, t('recovery.loadFailed')));
    } finally {
      setLoading(false);
    }
  }, [agent.id, t]);

  const nonTerminal = operations.some((operation) => !recoveryOperationTerminal(operation));
  usePolling(fetchRecovery, 3000, { keepAliveWhenHidden: nonTerminal });

  const activeIDs = useMemo(() => new Set(active.map((diagnostic) => diagnostic.id)), [active]);

  async function confirmRepair() {
    if (!repair || !repair.proposed_action) return;
    setRepairing(true);
    setOperationError(null);
    try {
      const operation = await api.createRecoveryRepair(agent.id, repair.id, repair.proposed_action);
      setOperations((current) => [operation, ...current.filter((item) => item.operation_id !== operation.operation_id)]);
      setRepair(null);
      toast.success(t('recovery.repairStarted'));
      await fetchRecovery();
    } catch (error) {
      const code = recoveryErrorCode(error);
      setOperationError({ code, message: errMessage(error, t('recovery.repairFailed')) });
      setRepair(null);
    } finally {
      setRepairing(false);
    }
  }

  async function updatePolicy(mode: 'inherit' | 'enabled' | 'disabled') {
    setPolicySaving(true);
    try {
      await api.setAgentSafeAutoRepair(agent.id, mode);
      toast.success(t('recovery.policySaved'));
      onAgentChanged();
    } catch (error) {
      toast.error(errMessage(error, t('recovery.policySaveFailed')));
    } finally {
      setPolicySaving(false);
    }
  }

  const overrideMode = agent.safe_auto_repair_override == null
    ? 'inherit'
    : agent.safe_auto_repair_override ? 'enabled' : 'disabled';

  return (
    <section className="mt-6 border-t border-border pt-6" aria-live={nonTerminal ? 'polite' : undefined}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="font-semibold text-fg">{t('recovery.title')}</h3>
          <p className="mt-0.5 text-sm text-fg-muted">{t('recovery.subtitle')}</p>
        </div>
        <div className="min-w-52">
          <label className="text-xs font-medium text-fg-muted" htmlFor={`recovery-policy-${agent.id}`}>{t('recovery.agentPolicy')}</label>
          <Select
            id={`recovery-policy-${agent.id}`}
            className="mt-1"
            value={overrideMode}
            disabled={policySaving}
            onChange={(event) => updatePolicy(event.target.value as 'inherit' | 'enabled' | 'disabled')}
          >
            <option value="inherit">{t('recovery.policyInherit')}</option>
            <option value="enabled">{t('recovery.policyEnabled')}</option>
            <option value="disabled">{t('recovery.policyDisabled')}</option>
          </Select>
          <p className={`mt-1 text-xs ${agent.safe_auto_repair_effective ? 'text-success-fg' : 'text-fg-faint'}`}>
            {t(agent.safe_auto_repair_effective ? 'recovery.effectiveEnabled' : 'recovery.effectiveDisabled')}
          </p>
        </div>
      </div>

      {!agent.recovery_capability && (
        <div className="mt-4"><Callout tone="warning" title={t('recovery.upgradeRequired')}>{t('recovery.upgradeRequiredBody')}</Callout></div>
      )}
      {operationError && (
        <div className="mt-4"><Callout tone="danger" title={t('recovery.repairFailed')}>
          <p>{operationError.message}</p>
          <code className="mt-1 block font-mono text-xs">{operationError.code}</code>
        </Callout></div>
      )}
      {loadError && <div className="mt-4"><Callout tone="danger">{loadError}</Callout></div>}

      {loading ? (
        <p className="mt-4 text-sm text-fg-faint">{t('common.loading')}</p>
      ) : diagnostics.length === 0 ? (
        <div className="mt-4"><Callout tone="success" title={t('recovery.healthy')}>{t('recovery.healthyBody')}</Callout></div>
      ) : (
        <div className="mt-4 space-y-3">
          {diagnostics.map((diagnostic) => {
            const isActive = activeIDs.has(diagnostic.id);
            const related = recoveryHistory(operations, diagnostic.id);
            const availability = isActive
              ? repairAvailability(agent, diagnostic, operations)
              : { enabled: false, reason: 'diagnostic_resolved' };
            const location = diagnosticLocation(diagnostic);
            const validationEscape = diagnostic.breaker.open && diagnostic.breaker.reason === 'rollback_failed_latched';
            return (
              <article key={diagnostic.id} className="rounded-lg border border-border bg-surface-2 p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`rounded px-2 py-0.5 text-xs font-medium ${
                        severityTone(diagnostic.severity) === 'danger' ? 'bg-danger-soft text-danger-fg' :
                        severityTone(diagnostic.severity) === 'warning' ? 'bg-warning-soft text-warning-fg' : 'bg-info-soft text-info-fg'
                      }`}>{t(`recovery.severity.${diagnostic.severity}`)}</span>
                      <code className="font-mono text-xs text-fg-faint">{diagnostic.code}</code>
                      {!isActive && <span className="text-xs text-success-fg">{t('recovery.resolved')}</span>}
                    </div>
                    <p className="mt-2 font-medium text-fg">{diagnostic.summary}</p>
                    <p className="mt-1 text-xs text-fg-faint">
                      {t('recovery.ownership')}: {t(`recovery.ownershipValues.${diagnostic.ownership}`)} · {diagnostic.subsystem} · {formatRelativeTime(diagnostic.last_seen_at)} · {t('recovery.occurrences', { count: diagnostic.occurrences })}
                    </p>
                    <p className="mt-1 text-xs text-fg-faint">{t('recovery.firstSeen')}: {new Date(diagnostic.first_seen_at).toLocaleString()}</p>
                    <p className="mt-1 break-all font-mono text-xs text-fg-faint">{t('recovery.fingerprint')}: {diagnostic.resource_fingerprint}</p>
                    {location && <p className="mt-1 break-all font-mono text-xs text-fg-muted">{t('recovery.location')}: {location}</p>}
                  </div>
                  {diagnosticActionVisible(diagnostic) && (
                    <Button size="sm" disabled={!availability.enabled} onClick={() => setRepair(diagnostic)} title={availability.reason ? t(`recovery.reasons.${availability.reason}`) : undefined}>
                      {diagnostic.hard_change || diagnostic.ownership !== 'nurproxy' || !diagnostic.proposed_action
                        ? t('recovery.hardDisabled')
                        : validationEscape ? t('recovery.validateRepair') : t('recovery.repair')}
                    </Button>
                  )}
                </div>

                {diagnostic.evidence && (
                  <pre className="mt-3 max-h-40 overflow-auto whitespace-pre-wrap break-words rounded bg-surface px-3 py-2 font-mono text-xs text-fg-muted">{diagnostic.evidence}</pre>
                )}
                {diagnostic.affected_paths.length > 0 && (
                  <div className="mt-3">
                    <p className="text-xs font-medium text-fg-muted">{t('recovery.affectedPaths')}</p>
                    <ul className="mt-1 space-y-1">{diagnostic.affected_paths.map((path) => <li key={path}><code className="break-all font-mono text-xs text-fg-faint">{path}</code></li>)}</ul>
                  </div>
                )}
                {!availability.enabled && availability.reason && isActive && (
                  <p className="mt-3 text-xs text-fg-faint">{t(`recovery.reasons.${availability.reason}`)}</p>
                )}

                {diagnostic.breaker.open && (
                  <div className="mt-3"><Callout tone="danger" title={t('recovery.breakerOpen')}>
                    <p>{t(`recovery.breakerReasons.${diagnostic.breaker.reason ?? 'failure_threshold'}`)}</p>
                    {diagnostic.breaker.expires_at && <p className="mt-1 text-xs">{t('recovery.breakerExpires', { time: new Date(diagnostic.breaker.expires_at).toLocaleString() })}</p>}
                    {validationEscape && <p className="mt-1 font-semibold">{t('recovery.manualValidationEscape')}</p>}
                  </Callout></div>
                )}

                {related.length > 0 && (
                  <div className="mt-4 border-t border-border pt-3">
                    <p className="text-sm font-medium text-fg">{t('recovery.history', { count: related.length })}</p>
                    <div className="mt-2 space-y-2">
                      {related.map((operation, index) => index === 0 ? (
                        <div key={operation.operation_id} className="rounded border border-border bg-surface p-3">
                          <p className="text-sm font-medium text-fg">{t(`recovery.states.${operation.state}`)} · {t(`recovery.sources.${operation.source}`)}</p>
                          <OperationDetails operation={operation} />
                        </div>
                      ) : (
                        <details key={operation.operation_id} className="rounded border border-border bg-surface p-3">
                          <summary className="cursor-pointer text-sm font-medium text-fg-muted">{t(`recovery.states.${operation.state}`)} · {t(`recovery.actions.${operation.action}`)} · {formatRelativeTime(operation.started_at)}</summary>
                          <OperationDetails operation={operation} />
                        </details>
                      ))}
                    </div>
                  </div>
                )}
              </article>
            );
          })}
        </div>
      )}

      <ConfirmDialog
        open={repair !== null}
        onClose={() => !repairing && setRepair(null)}
        onConfirm={confirmRepair}
        title={t(repair?.breaker.reason === 'rollback_failed_latched' ? 'recovery.confirmValidationTitle' : 'recovery.confirmTitle')}
        message={t(repair?.breaker.reason === 'rollback_failed_latched' ? 'recovery.confirmValidationMessage' : 'recovery.confirmMessage', {
          action: repair?.proposed_action ? t(`recovery.actions.${repair.proposed_action}`) : '',
          paths: repair?.affected_paths.join(', ') || t('recovery.noPaths'),
        })}
        confirmLabel={t(repair?.breaker.reason === 'rollback_failed_latched' ? 'recovery.validateRepair' : 'recovery.repair')}
        loading={repairing}
      />
    </section>
  );
}

import { useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { Agent, RecoveryDiagnostic, RecoveryOperation } from '../lib/types';
import { api } from '../lib/api';
import { formatRelativeTime } from '../lib/utils';
import { diagnosticLocation, recoveryErrorCode, recoveryHistory, recoveryOperationTerminal, repairAvailability } from '../lib/recovery-ui';
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

  usePolling(fetchRecovery, 3000);

  const activeIDs = useMemo(() => new Set(active.map((diagnostic) => diagnostic.id)), [active]);
  const nonTerminal = operations.some((operation) => !recoveryOperationTerminal(operation));

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
            const latest = related[0];
            const availability = isActive
              ? repairAvailability(agent, diagnostic, operations)
              : { enabled: false, reason: 'diagnostic_resolved' };
            const location = diagnosticLocation(diagnostic);
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
                    {location && <p className="mt-1 break-all font-mono text-xs text-fg-muted">{t('recovery.location')}: {location}</p>}
                  </div>
                  {diagnostic.proposed_action && (
                    <Button size="sm" disabled={!availability.enabled} onClick={() => setRepair(diagnostic)} title={availability.reason ? t(`recovery.reasons.${availability.reason}`) : undefined}>
                      {diagnostic.hard_change ? t('recovery.hardDisabled') : t('recovery.repair')}
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

                {latest && (
                  <div className="mt-4 border-t border-border pt-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="text-sm font-medium text-fg">{t('recovery.latestOperation')}</p>
                      <code className="font-mono text-xs text-fg-faint">{latest.operation_id}</code>
                    </div>
                    <p className="mt-1 text-sm text-fg-muted">{t(`recovery.states.${latest.state}`)} · {t(`recovery.sources.${latest.source}`)}</p>
                    {latest.steps.length > 0 && (
                      <ol className="mt-2 space-y-1 border-l border-border pl-3">
                        {latest.steps.map((step, index) => <li key={`${step.at}-${index}`} className="text-xs text-fg-muted"><span className="font-medium text-fg">{t(`recovery.states.${step.state}`)}</span> — {step.summary}</li>)}
                      </ol>
                    )}
                    <dl className="mt-2 grid gap-1 text-xs sm:grid-cols-3">
                      {latest.snapshot_reference && <div><dt className="text-fg-faint">{t('recovery.snapshot')}</dt><dd className="break-all text-fg-muted">{latest.snapshot_reference}</dd></div>}
                      {latest.validation_outcome && <div><dt className="text-fg-faint">{t('recovery.validation')}</dt><dd className="text-fg-muted">{latest.validation_outcome}</dd></div>}
                      {latest.rollback_outcome && <div><dt className="text-fg-faint">{t('recovery.rollback')}</dt><dd className="text-fg-muted">{latest.rollback_outcome}</dd></div>}
                    </dl>
                    {latest.error && <p className="mt-2 text-xs text-danger-fg">{latest.error}</p>}
                    {latest.state === 'rollback_failed' && <p className="mt-2 text-xs font-medium text-danger-fg">{t('recovery.breakerOpen')}</p>}
                  </div>
                )}
                {related.length > 1 && (
                  <details className="mt-3 border-t border-border pt-3">
                    <summary className="cursor-pointer text-sm font-medium text-fg-muted">{t('recovery.history', { count: related.length })}</summary>
                    <ol className="mt-2 space-y-2">
                      {related.map((operation) => (
                        <li key={operation.operation_id} className="flex flex-wrap items-center justify-between gap-2 text-xs">
                          <span className="text-fg-muted">{t(`recovery.states.${operation.state}`)} · {t(`recovery.sources.${operation.source}`)} · {formatRelativeTime(operation.started_at)}</span>
                          <code className="font-mono text-fg-faint">{operation.operation_id}</code>
                        </li>
                      ))}
                    </ol>
                  </details>
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
        title={t('recovery.confirmTitle')}
        message={t('recovery.confirmMessage', {
          action: repair?.proposed_action ? t(`recovery.actions.${repair.proposed_action}`) : '',
          paths: repair?.affected_paths.join(', ') || t('recovery.noPaths'),
        })}
        confirmLabel={t('recovery.repair')}
        loading={repairing}
      />
    </section>
  );
}

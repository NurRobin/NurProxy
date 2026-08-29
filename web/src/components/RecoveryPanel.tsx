import { useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { Agent, HardRecoveryPlan, RecoveryDiagnostic, RecoveryHelperStatus, RecoveryOperation } from '../lib/types';
import { api } from '../lib/api';
import { formatRelativeTime } from '../lib/utils';
import { diagnosticActionVisible, diagnosticBreaker, diagnosticLocation, diagnosticResolutionLabelKey, diagnosticStateLabelKey, hardPlanAvailability, newestHardPlan, recoveryErrorCode, recoveryHistory, RecoveryHistoryCardSummary, recoveryOperationTerminal, repairAvailability } from '../lib/recovery-ui';
import { usePolling } from '../lib/usePolling';
import { useToast, errMessage } from './toast-context';
import Button from './Button';
import Callout from './Callout';
import ConfirmDialog from './ConfirmDialog';
import { Select, Textarea } from './Field';

interface RecoveryPanelProps {
  agent: Agent;
  onAgentChanged: () => void;
}

const severityTone = (severity: RecoveryDiagnostic['severity']) =>
  severity === 'critical' || severity === 'error' ? 'danger' : severity === 'warning' ? 'warning' : 'info';

function OperationDetails({ operation }: { operation: RecoveryOperation }) {
  const { t } = useTranslation();
  const details = operation;
  return (
    <div className="mt-2 pl-3">
      <dl className="grid gap-2 text-xs sm:grid-cols-2">
        <div><dt className="text-fg-faint">{t('recovery.action')}</dt><dd className="text-fg-muted">{t(`recovery.actions.${details.action}`)}</dd></div>
        <div><dt className="text-fg-faint">{t('recovery.source')}</dt><dd className="text-fg-muted">{t(`recovery.sources.${details.source}`)}</dd></div>
        <div><dt className="text-fg-faint">{t('recovery.operationId')}</dt><dd className="break-all font-mono text-fg-muted">{details.operation_id}</dd></div>
        <div><dt className="text-fg-faint">{t('recovery.started')}</dt><dd className="text-fg-muted">{new Date(details.started_at).toLocaleString()}</dd></div>
        <div><dt className="text-fg-faint">{t('recovery.finished')}</dt><dd className="text-fg-muted">{details.finished_at ? new Date(details.finished_at).toLocaleString() : t('recovery.inProgress')}</dd></div>
        <div><dt className="text-fg-faint">{t('recovery.snapshot')}</dt><dd className="break-all text-fg-muted">{details.snapshot_reference || '—'}</dd></div>
        <div><dt className="text-fg-faint">{t('recovery.validation')}</dt><dd className="text-fg-muted">{details.validation_outcome || '—'}</dd></div>
        <div><dt className="text-fg-faint">{t('recovery.rollback')}</dt><dd className="text-fg-muted">{details.rollback_outcome || '—'}</dd></div>
        <div><dt className="text-fg-faint">{t('recovery.operationError')}</dt><dd className={details.error ? 'text-danger-fg' : 'text-fg-muted'}>{details.error || '—'}</dd></div>
      </dl>
      <p className="mt-3 text-xs font-medium text-fg-muted">{t('recovery.steps')}</p>
      {details.steps.length > 0 ? (
        <ol className="mt-1 space-y-1 border-l border-border pl-3">
          {details.steps.map((step, index) => (
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
  const [hardPlans, setHardPlans] = useState<HardRecoveryPlan[]>([]);
  const [helperStatus, setHelperStatus] = useState<RecoveryHelperStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [repair, setRepair] = useState<RecoveryDiagnostic | null>(null);
  const [repairing, setRepairing] = useState(false);
  const [operationError, setOperationError] = useState<{ code: string; message: string } | null>(null);
  const [policySaving, setPolicySaving] = useState(false);
  const [hardConfirm, setHardConfirm] = useState<{ plan: HardRecoveryPlan; phase: 1 | 2 } | null>(null);
  const [hardConfirming, setHardConfirming] = useState(false);
  const [helperHello, setHelperHello] = useState('');
  const [helperEnrolling, setHelperEnrolling] = useState(false);

  const fetchRecovery = useCallback(async () => {
    try {
      const [activeList, allList, operationList, hardPlanList, currentHelperStatus] = await Promise.all([
        api.listRecoveryDiagnostics(agent.id, false),
        api.listRecoveryDiagnostics(agent.id, true, 100),
        api.listRecoveryOperations(agent.id),
        api.listHardRecoveryPlans(agent.id),
        api.getRecoveryHelperStatus(agent.id),
      ]);
      setActive(activeList);
      setDiagnostics(allList);
      setOperations(operationList);
      setHardPlans(hardPlanList);
      setHelperStatus(currentHelperStatus);
      setLoadError('');
    } catch (error) {
      setLoadError(errMessage(error, t('recovery.loadFailed')));
    } finally {
      setLoading(false);
    }
  }, [agent.id, t]);

  const hardExecutionActive = hardPlans.some((plan) => !plan.signed_helper_receipt && (!!plan.signed_execution_grant || plan.confirmation_event_ids.length > 0));
  const nonTerminal = operations.some((operation) => !recoveryOperationTerminal(operation)) || hardExecutionActive;
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

  async function confirmHardRepair(freshPassword?: string) {
    if (!hardConfirm) return;
    setHardConfirming(true);
    setOperationError(null);
    try {
      const updated = await api.confirmHardRecoveryPlan(
        agent.id,
        hardConfirm.plan.helper_plan_id,
        hardConfirm.phase,
        crypto.randomUUID(),
        hardConfirm.plan.display_plan_hash,
        freshPassword,
      );
      setHardPlans((current) => [updated, ...current.filter((plan) => plan.helper_plan_id !== updated.helper_plan_id)]);
      setHardConfirm(null);
      toast.success(t(hardConfirm.phase === 1 ? 'recovery.hardFirstConfirmed' : 'recovery.hardExecutionAuthorized'));
      await fetchRecovery();
    } catch (error) {
      setOperationError({ code: recoveryErrorCode(error), message: errMessage(error, t('recovery.hardConfirmFailed')) });
      setHardConfirm(null);
    } finally {
      setHardConfirming(false);
    }
  }

  async function enrollHelper() {
    setHelperEnrolling(true);
    setOperationError(null);
    try {
      const signedHello = JSON.parse(helperHello) as unknown;
      await api.enrollRecoveryHelper(agent.id, signedHello);
      setHelperHello('');
      toast.success(t('recovery.helperEnrolled'));
      await fetchRecovery();
    } catch (error) {
      setOperationError({ code: recoveryErrorCode(error), message: errMessage(error, t('recovery.helperEnrollFailed')) });
    } finally {
      setHelperEnrolling(false);
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
      {helperStatus?.enrolled ? (
        <div className="mt-4 rounded-lg border border-success-border bg-success-soft p-3 text-xs text-success-fg">
          <p className="font-medium">{t('recovery.helperEnrolled')}</p>
          <p className="mt-1 font-mono">{helperStatus.helper.helper_instance_id} · {helperStatus.helper.helper_build_id} · {helperStatus.helper.attestation_key_id}</p>
        </div>
      ) : helperStatus ? (
        <div className="mt-4 rounded-lg border border-warning-border bg-warning-soft p-4">
          <h4 className="font-medium text-warning-fg">{t('recovery.helperEnrollmentTitle')}</h4>
          <p className="mt-1 text-sm text-fg-muted">{t('recovery.helperEnrollmentBody')}</p>
          <Textarea
            value={helperHello}
            onChange={(event) => setHelperHello(event.target.value)}
            rows={5}
            className="mt-3 font-mono text-xs"
            spellCheck={false}
            placeholder={t('recovery.helperEnrollmentPlaceholder')}
          />
          <Button className="mt-3" size="sm" disabled={helperHello.trim() === ''} loading={helperEnrolling} onClick={enrollHelper}>
            {t('recovery.helperEnrollAction')}
          </Button>
        </div>
      ) : null}
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
            const breaker = diagnosticBreaker(diagnostic);
            const validationEscape = breaker.open && breaker.reason === 'rollback_failed_latched';
            const hardPlan = newestHardPlan(hardPlans, diagnostic.id);
            const hardAvailability = hardPlanAvailability(diagnostic, hardPlan);
            const resolutionLabelKey = diagnosticResolutionLabelKey(diagnostic);
            return (
              <article key={diagnostic.id} className="rounded-lg border border-border bg-surface-2 p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`rounded px-2 py-0.5 text-xs font-semibold ${isActive ? 'bg-warning-soft text-warning-fg' : 'bg-success-soft text-success-fg'}`}>
                        {t(diagnosticStateLabelKey(isActive))}
                      </span>
                      <span className={`rounded px-2 py-0.5 text-xs font-medium ${
                        severityTone(diagnostic.severity) === 'danger' ? 'bg-danger-soft text-danger-fg' :
                        severityTone(diagnostic.severity) === 'warning' ? 'bg-warning-soft text-warning-fg' : 'bg-info-soft text-info-fg'
                      }`}>{t(`recovery.severity.${diagnostic.severity}`)}</span>
                      <code className="font-mono text-xs text-fg-faint">{diagnostic.code}</code>
                    </div>
                    <p className="mt-2 font-medium text-fg">{diagnostic.summary}</p>
                    <p className="mt-1 text-xs text-fg-faint">
                      {t('recovery.ownership')}: {t(`recovery.ownershipValues.${diagnostic.ownership}`)}
                      {diagnostic.ownership_confidence && ` (${t(`recovery.ownershipConfidence.${diagnostic.ownership_confidence}`)})`}
                      {' · '}{diagnostic.subsystem} · {t('recovery.lastSeen')} {formatRelativeTime(diagnostic.last_seen_at)} · {t('recovery.occurrences', { count: diagnostic.occurrences })}
                    </p>
                    {!isActive && resolutionLabelKey && (
                      <p className="mt-2 text-xs font-medium text-success-fg">{t('recovery.resolvedBecause')}: {t(resolutionLabelKey)}</p>
                    )}
                    {related[0] && (
                      <p className="mt-2 text-xs text-fg-muted"><RecoveryHistoryCardSummary operation={related[0]} translate={(key) => t(key)} formatTime={formatRelativeTime} /></p>
                    )}
                  </div>
                  {diagnosticActionVisible(diagnostic) && (
                    diagnostic.hard_change ? (
                      <Button
                        size="sm"
                        disabled={!hardAvailability.enabled || !hardPlan || !hardAvailability.phase}
                        onClick={() => hardPlan && hardAvailability.phase && setHardConfirm({ plan: hardPlan, phase: hardAvailability.phase })}
                        title={hardAvailability.reason ? t(`recovery.reasons.${hardAvailability.reason}`, { defaultValue: hardAvailability.reason }) : undefined}
                      >
                        {hardPlan && hardAvailability.phase
                          ? t(hardAvailability.phase === 1 ? `recovery.hardActions.${hardPlan.action}` : 'recovery.hardConfirmAction', { action: t(`recovery.hardActions.${hardPlan.action}`) })
                          : t('recovery.hardDisabled')}
                      </Button>
                    ) : (
                      <Button size="sm" disabled={!availability.enabled} onClick={() => setRepair(diagnostic)} title={availability.reason ? t(`recovery.reasons.${availability.reason}`) : undefined}>
                        {diagnostic.ownership !== 'nurproxy' || !diagnostic.proposed_action
                          ? t('recovery.hardDisabled')
                          : validationEscape ? t('recovery.validateRepair') : t('recovery.repair')}
                      </Button>
                    )
                  )}
                </div>

                {isActive && diagnostic.hard_change && !hardAvailability.enabled && hardAvailability.reason && (
                  <p className="mt-3 text-xs text-fg-faint">{t(`recovery.reasons.${hardAvailability.reason}`, { defaultValue: diagnostic.repair_refusal_code || hardAvailability.reason })}</p>
                )}
                {isActive && !diagnostic.hard_change && !availability.enabled && availability.reason && (
                  <p className="mt-3 text-xs text-fg-faint">{t(`recovery.reasons.${availability.reason}`)}</p>
                )}

                {diagnostic.hard_change && hardPlan && (
                  <div className="mt-3 rounded border border-warning-border bg-warning-soft p-3 text-xs">
                    <p className="font-semibold text-warning-fg">{t(`recovery.hardActions.${hardPlan.action}`)}</p>
                    <p className="mt-1 text-fg-muted">{t('recovery.hardTarget')}: <code>{hardPlan.logical_target}</code> · {t('recovery.rollback')}: {hardPlan.rollback_coverage}</p>
                    <ol className="mt-2 list-decimal space-y-1 pl-5 text-fg-muted">
                      {hardPlan.signed_plan.envelope.payload.steps.map((step, index) => <li key={`${step.kind}-${index}`}>{step.summary}</li>)}
                    </ol>
                    <p className="mt-2 break-all font-mono text-fg-faint">{t('recovery.planHash')}: {hardPlan.display_plan_hash}</p>
                    <p className="mt-1 text-fg-faint">{t('recovery.planExpires')}: {new Date(hardPlan.expires_at).toLocaleString()} · {t('recovery.confirmations')}: {hardPlan.confirmation_event_ids.length}/2</p>
                  </div>
                )}

                {breaker.open && (
                  <div className="mt-3"><Callout tone="danger" title={t('recovery.breakerOpen')}>
                    <p>{t(`recovery.breakerReasons.${breaker.reason ?? 'failure_threshold'}`)}</p>
                    {breaker.expires_at && <p className="mt-1 text-xs">{t('recovery.breakerExpires', { time: new Date(breaker.expires_at).toLocaleString() })}</p>}
                    {validationEscape && <p className="mt-1 font-semibold">{t('recovery.manualValidationEscape')}</p>}
                  </Callout></div>
                )}

                <details className="mt-4 border-t border-border pt-3">
                  <summary className="cursor-pointer text-sm font-medium text-fg-muted">{t('recovery.viewDetails')}</summary>
                  <div className="mt-3 space-y-3">
                    <dl className="grid gap-2 text-xs sm:grid-cols-2">
                      <div><dt className="text-fg-faint">{t('recovery.firstSeen')}</dt><dd className="text-fg-muted">{new Date(diagnostic.first_seen_at).toLocaleString()}</dd></div>
                      <div><dt className="text-fg-faint">{t('recovery.lastSeen')}</dt><dd className="text-fg-muted">{new Date(diagnostic.last_seen_at).toLocaleString()}</dd></div>
                      {diagnostic.resolved_at && <div><dt className="text-fg-faint">{t('recovery.resolvedAt')}</dt><dd className="text-fg-muted">{new Date(diagnostic.resolved_at).toLocaleString()}</dd></div>}
                      {diagnostic.resolution_operation_id && <div><dt className="text-fg-faint">{t('recovery.resolutionOperation')}</dt><dd className="break-all font-mono text-fg-muted">{diagnostic.resolution_operation_id}</dd></div>}
                    </dl>
                    <p className="break-all font-mono text-xs text-fg-faint">{t('recovery.fingerprint')}: {diagnostic.resource_fingerprint}</p>
                    {location && <p className="break-all font-mono text-xs text-fg-muted">{t('recovery.location')}: {location}</p>}
                    {diagnostic.evidence && (
                      <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-words rounded bg-surface px-3 py-2 font-mono text-xs text-fg-muted">{diagnostic.evidence}</pre>
                    )}
                    {diagnostic.affected_paths.length > 0 && (
                      <div>
                        <p className="text-xs font-medium text-fg-muted">{t('recovery.affectedPaths')}</p>
                        <ul className="mt-1 space-y-1">{diagnostic.affected_paths.map((path) => <li key={path}><code className="break-all font-mono text-xs text-fg-faint">{path}</code></li>)}</ul>
                      </div>
                    )}
                    {related.length > 0 && (
                      <div>
                        <p className="text-sm font-medium text-fg">{t('recovery.history', { count: related.length })}</p>
                        <div className="mt-2 space-y-2">
                          {related.map((operation) => (
                            <details key={operation.operation_id} className="rounded border border-border bg-surface p-3">
                              <summary className="cursor-pointer text-sm font-medium text-fg-muted"><RecoveryHistoryCardSummary operation={operation} translate={(key) => t(key)} formatTime={formatRelativeTime} /></summary>
                              <OperationDetails operation={operation} />
                            </details>
                          ))}
                        </div>
                      </div>
                    )}
                    </div>
                </details>
              </article>
            );
          })}
        </div>
      )}

      <ConfirmDialog
        open={repair !== null}
        onClose={() => !repairing && setRepair(null)}
        onConfirm={confirmRepair}
        title={t(repair && diagnosticBreaker(repair).reason === 'rollback_failed_latched' ? 'recovery.confirmValidationTitle' : 'recovery.confirmTitle')}
        message={t(repair && diagnosticBreaker(repair).reason === 'rollback_failed_latched' ? 'recovery.confirmValidationMessage' : 'recovery.confirmMessage', {
          action: repair?.proposed_action ? t(`recovery.actions.${repair.proposed_action}`) : '',
          paths: repair?.affected_paths.join(', ') || t('recovery.noPaths'),
        })}
        confirmLabel={t(repair && diagnosticBreaker(repair).reason === 'rollback_failed_latched' ? 'recovery.validateRepair' : 'recovery.repair')}
        loading={repairing}
      />
      <ConfirmDialog
        open={hardConfirm !== null}
        onClose={() => !hardConfirming && setHardConfirm(null)}
        onConfirm={confirmHardRepair}
        title={hardConfirm ? t(hardConfirm.phase === 1 ? 'recovery.hardConfirmTitle' : 'recovery.hardFinalConfirmTitle', { action: t(`recovery.hardActions.${hardConfirm.plan.action}`) }) : ''}
        message={hardConfirm ? t(hardConfirm.phase === 1 ? 'recovery.hardConfirmMessage' : 'recovery.hardFinalConfirmMessage', {
          action: t(`recovery.hardActions.${hardConfirm.plan.action}`),
          target: hardConfirm.plan.logical_target,
          coverage: hardConfirm.plan.rollback_coverage,
          steps: hardConfirm.plan.signed_plan.envelope.payload.steps.map((step) => step.summary).join(' → '),
        }) : ''}
        confirmLabel={hardConfirm ? (hardConfirm.phase === 1
          ? t(`recovery.hardActions.${hardConfirm.plan.action}`)
          : t('recovery.hardConfirmAction', { action: t(`recovery.hardActions.${hardConfirm.plan.action}`) })) : ''}
        loading={hardConfirming}
        freshPasswordLabel={hardConfirm?.phase === 2 && (hardConfirm.plan.action === 'install_supported_proxy_package' || hardConfirm.plan.action === 'open_proxy_firewall_ports')
          ? t('recovery.freshPasswordLabel')
          : undefined}
      />
    </section>
  );
}

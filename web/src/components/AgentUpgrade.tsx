import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Check, Circle, CircleCheck, CircleX, Minus, X } from 'lucide-react';
import { api } from '../lib/api';
import type { Agent, AgentUpgrade, UpgradeRollout, UpgradeRolloutAgent } from '../lib/types';
import { upgradeActive, upgradeAvailability, upgradeTone } from '../lib/upgrade';
import { formatRelativeTime } from '../lib/utils';
import Button, { Spinner } from './Button';
import Modal from './Modal';
import { Checkbox, Field, Input } from './Field';
import { useToast, errMessage } from './toast-context';

/** One-line state of an upgrade attempt: spinner while running, check or cross once terminal. */
export function UpgradeStatusLine({ upgrade }: { upgrade: AgentUpgrade }) {
  const { t } = useTranslation();
  const tone = upgradeTone(upgrade.state);
  const color = tone === 'success' ? 'text-success-fg' : tone === 'danger' ? 'text-danger-fg' : 'text-fg';
  return (
    <div className={`text-sm ${color}`}>
      <p className="flex items-center gap-2">
        {tone === 'progress' && <Spinner className="h-4 w-4 flex-shrink-0" />}
        {tone === 'success' && <CircleCheck className="h-4 w-4 flex-shrink-0" aria-hidden="true" />}
        {tone === 'danger' && <CircleX className="h-4 w-4 flex-shrink-0" aria-hidden="true" />}
        <span>
          {t(`agents.upgrade.state.${upgrade.state}`, { from: upgrade.from_version, to: upgrade.target_version })}
        </span>
      </p>
      {upgrade.error && <p className="mt-1 break-words pl-6 text-xs">{upgrade.error}</p>}
      <p className="mt-0.5 pl-6 text-xs text-fg-faint">
        {t(`agents.upgrade.trigger.${upgrade.trigger}`)} · {formatRelativeTime(upgrade.updated_at)}
      </p>
    </div>
  );
}

interface AgentUpgradePanelProps {
  agent: Agent;
  /** The orchestrator's version, used as the default target. */
  orchestratorVersion?: string;
  onAgentChanged: () => void | Promise<void>;
}

/** Upgrade section of the agent detail: latest attempt, manual upgrade, auto-upgrade opt-in, history. */
export function AgentUpgradePanel({ agent, orchestratorVersion, onAgentChanged }: AgentUpgradePanelProps) {
  const { t } = useTranslation();
  const toast = useToast();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [version, setVersion] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [autoSaving, setAutoSaving] = useState<boolean | null>(null);
  const [history, setHistory] = useState<AgentUpgrade[] | null>(null);

  const availability = upgradeAvailability(agent);
  const outdated = agent.version_status === 'outdated';
  const disabledHint = availability.allowed
    ? undefined
    : availability.reason === 'unsupported'
      ? availability.detail || t('agents.upgrade.unsupported')
      : t(`agents.upgrade.disabled.${availability.reason}`);

  function openDialog() {
    setVersion('');
    setDialogOpen(true);
  }

  async function submit() {
    setSubmitting(true);
    try {
      const target = version.trim();
      await api.upgradeAgent(agent.id, target || undefined);
      toast.success(t('agents.upgrade.requested', { name: agent.name }));
      setDialogOpen(false);
      setHistory(null);
      await onAgentChanged();
    } catch (err) {
      toast.error(errMessage(err, t('agents.upgrade.requestFailed')));
    } finally {
      setSubmitting(false);
    }
  }

  async function toggleAuto(enabled: boolean) {
    setAutoSaving(enabled);
    try {
      const res = await api.setAgentAutoUpgrade(agent.id, enabled);
      toast.success(t(res.auto_upgrade ? 'agents.upgrade.autoEnabled' : 'agents.upgrade.autoDisabled'));
      await onAgentChanged();
    } catch (err) {
      toast.error(errMessage(err, t('agents.upgrade.autoFailed')));
    } finally {
      setAutoSaving(null);
    }
  }

  async function loadHistory() {
    try {
      setHistory(await api.listAgentUpgrades(agent.id));
    } catch (err) {
      toast.error(errMessage(err, t('agents.upgrade.historyFailed')));
    }
  }

  const autoChecked = autoSaving ?? !!agent.auto_upgrade;

  return (
    <section className="mt-6 border-t border-border pt-6" aria-live={upgradeActive(agent.upgrade) ? 'polite' : undefined}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="font-semibold text-fg">{t('agents.upgrade.title')}</h3>
          <p className="mt-0.5 text-sm text-fg-muted">
            {outdated
              ? t('agents.upgrade.subtitleOutdated', { version: agent.version, target: orchestratorVersion || '?' })
              : t('agents.upgrade.subtitle')}
          </p>
        </div>
        {/* A disabled button swallows hover in some browsers, so the tooltip sits on a wrapper. */}
        <span title={disabledHint}>
          <Button
            size="sm"
            variant={outdated ? 'primary' : 'secondary'}
            disabled={!availability.allowed}
            onClick={openDialog}
          >
            {t('agents.upgrade.button')}
          </Button>
        </span>
      </div>

      {!availability.allowed && availability.reason === 'unsupported' && (
        <p className="mt-2 text-xs text-fg-faint">{disabledHint}</p>
      )}

      {agent.upgrade && (
        <div className="mt-4 rounded-lg bg-surface-2 px-3 py-2.5">
          <UpgradeStatusLine upgrade={agent.upgrade} />
        </div>
      )}

      <div className="mt-4">
        <Checkbox
          label={t('agents.upgrade.auto')}
          checked={autoChecked}
          disabled={autoSaving !== null}
          onChange={(e) => toggleAuto(e.target.checked)}
        />
        <p className="mt-1 pl-6 text-xs text-fg-faint">{t('agents.upgrade.autoHint')}</p>
      </div>

      <details
        className="mt-4 text-sm"
        onToggle={(e) => { if ((e.currentTarget as HTMLDetailsElement).open) loadHistory(); }}
      >
        <summary className="cursor-pointer text-xs font-medium text-fg-muted hover:text-fg">{t('agents.upgrade.history')}</summary>
        {history === null ? (
          <p className="mt-2 text-xs text-fg-faint">{t('common.loading')}</p>
        ) : history.length === 0 ? (
          <p className="mt-2 text-xs text-fg-faint">{t('agents.upgrade.historyEmpty')}</p>
        ) : (
          <div className="mt-2 space-y-2">
            {history.map((u) => (
              <div key={u.id} className="rounded-lg bg-surface-2 px-3 py-2">
                <UpgradeStatusLine upgrade={u} />
              </div>
            ))}
          </div>
        )}
      </details>

      <Modal
        open={dialogOpen}
        onClose={() => setDialogOpen(false)}
        title={t('agents.upgrade.dialogTitle', { name: agent.name })}
        description={agent.fqdn}
      >
        <div className="space-y-4">
          <p className="text-sm leading-relaxed text-fg-muted">
            {t('agents.upgrade.dialogBody', { version: agent.version || '?' })}
          </p>
          <Field
            label={t('agents.upgrade.versionLabel')}
            htmlFor="upgrade-version"
            hint={t('agents.upgrade.versionHint', { version: orchestratorVersion || '?' })}
          >
            <Input
              id="upgrade-version"
              value={version}
              onChange={(e) => setVersion(e.target.value)}
              placeholder={orchestratorVersion || ''}
              className="font-mono"
              autoComplete="off"
            />
          </Field>
          <div className="flex justify-end gap-3">
            <Button variant="secondary" onClick={() => setDialogOpen(false)}>{t('common.cancel')}</Button>
            <Button onClick={submit} loading={submitting}>{t('agents.upgrade.confirm')}</Button>
          </div>
        </div>
      </Modal>
    </section>
  );
}

function RolloutAgentIcon({ state }: { state: UpgradeRolloutAgent['state'] }) {
  switch (state) {
    case 'upgrading': return <Spinner className="h-4 w-4 flex-shrink-0 text-fg" />;
    case 'done': return <Check className="h-4 w-4 flex-shrink-0 text-success-fg" aria-hidden="true" />;
    case 'failed': return <X className="h-4 w-4 flex-shrink-0 text-danger-fg" aria-hidden="true" />;
    case 'skipped': return <Minus className="h-4 w-4 flex-shrink-0 text-fg-faint" aria-hidden="true" />;
    default: return <Circle className="h-4 w-4 flex-shrink-0 text-fg-faint" aria-hidden="true" />;
  }
}

/** Compact progress of the latest bulk upgrade rollout, one line per agent. */
export function UpgradeRolloutPanel({ rollout, onDismiss }: { rollout: UpgradeRollout; onDismiss?: () => void }) {
  const { t } = useTranslation();
  const finished = rollout.agents.filter((a) => a.state === 'done').length;
  const border = rollout.state === 'failed' ? 'border-danger/40' : rollout.state === 'done' ? 'border-success/35' : 'border-border';
  return (
    <div className={`rounded-xl border ${border} bg-surface p-4 shadow-card`} aria-live={rollout.state === 'running' ? 'polite' : undefined}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="flex items-center gap-2 text-sm font-semibold text-fg">
            {rollout.state === 'running' && <Spinner className="h-4 w-4" />}
            {rollout.state === 'done' && <CircleCheck className="h-4 w-4 text-success-fg" aria-hidden="true" />}
            {rollout.state === 'failed' && <CircleX className="h-4 w-4 text-danger-fg" aria-hidden="true" />}
            {t(`agents.upgrade.rollout.${rollout.state}`, { version: rollout.target_version })}
          </p>
          <p className="mt-0.5 text-xs text-fg-faint">
            {t('agents.upgrade.rollout.progress', { done: finished, total: rollout.agents.length })}
            {' · '}
            {formatRelativeTime(rollout.finished_at || rollout.started_at)}
          </p>
        </div>
        {rollout.state !== 'running' && onDismiss && (
          <button
            type="button"
            onClick={onDismiss}
            aria-label={t('agents.upgrade.rollout.dismiss')}
            title={t('agents.upgrade.rollout.dismiss')}
            className="rounded p-1 text-fg-faint transition-colors hover:text-fg"
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>
      {rollout.error && <p className="mt-2 break-words text-sm text-danger-fg">{rollout.error}</p>}
      {rollout.agents.length > 0 && (
        <ul className="mt-3 space-y-1.5">
          {rollout.agents.map((a) => (
            <li key={a.agent_id} className="text-sm">
              <div className="flex items-center gap-2">
                <RolloutAgentIcon state={a.state} />
                <span className="min-w-0 truncate text-fg">{a.name}</span>
                <span className="font-mono text-xs text-fg-faint">{a.from_version}</span>
                <span className={`ml-auto text-xs ${a.state === 'failed' ? 'text-danger-fg' : 'text-fg-muted'}`}>
                  {t(`agents.upgrade.rollout.agentState.${a.state}`)}
                </span>
              </div>
              {a.error && <p className="mt-0.5 break-words pl-6 text-xs text-danger-fg">{a.error}</p>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

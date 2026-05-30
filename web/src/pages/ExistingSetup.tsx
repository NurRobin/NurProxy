import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Check, ChevronDown, ChevronRight, Copy, Loader2 } from 'lucide-react';
import Modal from '../components/Modal';
import Button from '../components/Button';
import Callout from '../components/Callout';
import { Field, Input, Select } from '../components/Field';
import { copyText } from '../lib/clipboard';
import { api } from '../lib/api';
import { usePolling } from '../lib/usePolling';
import type { Agent, ProxyDetection, PreparedAdminOp } from '../lib/types';

type ProxyKind = 'nginx' | 'apache' | 'caddy';

interface Defaults {
  configDir: string;
  logPaths: string[];
  reloadCmd: string;
  testCmd: string;
  service: string;
}

// OS defaults per backend, mirroring §9 of the design (Debian/Ubuntu first
// target). These are only the *fallback* when detection (§2.1) didn't surface a
// value, so the guided flow is always pre-filled — confirm-not-type.
const DEFAULTS: Record<ProxyKind, Defaults> = {
  nginx: {
    configDir: '/etc/nginx/sites-available',
    logPaths: ['/var/log/nginx/error.log', '/var/log/nginx/access.log'],
    reloadCmd: 'nginx -s reload',
    testCmd: 'nginx -t',
    service: 'nginx',
  },
  apache: {
    configDir: '/etc/apache2/sites-available',
    logPaths: ['/var/log/apache2/error.log', '/var/log/apache2/access.log'],
    reloadCmd: 'apachectl graceful',
    testCmd: 'apachectl configtest',
    service: 'apache2',
  },
  caddy: {
    configDir: '/etc/caddy',
    logPaths: ['/var/log/caddy/access.log'],
    reloadCmd: 'caddy reload --config /etc/caddy/Caddyfile',
    testCmd: 'caddy validate --config /etc/caddy/Caddyfile',
    service: 'caddy',
  },
};

const KINDS: ProxyKind[] = ['nginx', 'apache', 'caddy'];

// Placeholder container name for the docker apply command. The host operator
// adjusts it to their actual container; a hint says so next to the command.
const DOCKER_CONTAINER = 'nurproxy-agent';

function asKind(k?: string): ProxyKind {
  return k === 'nginx' || k === 'apache' || k === 'caddy' ? k : 'nginx';
}

// Build the agent-side config the operator pastes on the host. proxy_mode is an
// agent config key (§9) — it lives on the agent, not in the orchestrator DB —
// so the *advanced* fallback hands the operator the exact, ready-to-apply config
// for editing agent.yaml by hand.
function buildYaml(kind: ProxyKind, v: Defaults): string {
  const logs = v.logPaths.length
    ? `proxy_log_paths:\n${v.logPaths.map((p) => `  - ${p}`).join('\n')}`
    : 'proxy_log_paths: []';
  return [
    'proxy_mode: existing',
    `proxy_type: ${kind}`,
    `proxy_config_dir: ${v.configDir}`,
    `proxy_reload_cmd: ${v.reloadCmd}`,
    `proxy_test_cmd: ${v.testCmd}`,
    `proxy_service: ${v.service}`,
    logs,
  ].join('\n');
}

// Build the least-privilege permission grants for THIS form (§12/§19): a
// group-owned config dir plus a scoped sudoers line for exactly the test +
// reload commands. <agent-user> and group nurproxy are placeholders — the exact
// commands for the host (with the detected user) are printed by `apply`.
function buildPermBlock(configDir: string, testCmd: string, reloadCmd: string): string {
  const cmds = [testCmd, reloadCmd].filter(Boolean).join(', ');
  return [
    'sudo groupadd -f nurproxy',
    'sudo usermod -aG nurproxy <agent-user>',
    `sudo chgrp -R nurproxy ${configDir} && sudo chmod -R g+w ${configDir} && sudo chmod g+s ${configDir}`,
    `echo '<agent-user> ALL=(root) NOPASSWD: ${cmds}' | sudo tee /etc/sudoers.d/nurproxy-agent`,
    'sudo chmod 0440 /etc/sudoers.d/nurproxy-agent',
  ].join('\n');
}

// Local HH:MM in the user's timezone, for the expiry hint.
function localTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

interface Props {
  agent: Agent;
  open: boolean;
  onClose: () => void;
}

/**
 * ExistingSetup is the guided "switch this agent to Existing" flow (§2, §2.1,
 * §19): pick the proxy, confirm the paths that matter (config dir, logs, reload
 * + test commands, service), then **Prepare** a pending admin op. The operator
 * receives a one-time confirmation code plus two ready-to-run apply commands;
 * the privileged apply stays gated on local shell presence on the host. The
 * raw-YAML snippet remains as an advanced, edit-by-hand fallback.
 */
export default function ExistingSetup({ agent, open, onClose }: Props) {
  const { t } = useTranslation();
  const det: ProxyDetection | undefined = agent.proxy_detection;

  const [kind, setKind] = useState<ProxyKind>(asKind(det?.kind));
  const [configDir, setConfigDir] = useState('');
  const [reloadCmd, setReloadCmd] = useState('');
  const [testCmd, setTestCmd] = useState('');
  const [service, setService] = useState('');
  const [logPaths, setLogPaths] = useState('');

  const [prepared, setPrepared] = useState<PreparedAdminOp | null>(null);
  const [preparing, setPreparing] = useState(false);
  const [prepareError, setPrepareError] = useState('');
  // Becomes true once the prepared op is no longer pending (claimed/applied) or
  // the op vanished from the pending list (the agent applied it).
  const [applied, setApplied] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);

  // Re-seed every field from detection (falling back to OS defaults) whenever the
  // dialog opens or the chosen proxy kind changes. Detection wins so the operator
  // confirms reality, not a guess. Re-opening also clears any prior prepared op.
  useEffect(() => {
    if (!open) return;
    const def = DEFAULTS[kind];
    const detKindMatches = asKind(det?.kind) === kind;
    setConfigDir((detKindMatches && det?.config_dir) || def.configDir);
    setLogPaths(((detKindMatches && det?.log_paths) || def.logPaths).join('\n'));
    setReloadCmd(def.reloadCmd);
    setTestCmd(def.testCmd);
    setService(def.service);
  }, [open, kind, det]);

  // Clearing a prepared op when the dialog closes keeps the next open clean
  // (the code is single-use and short-lived anyway).
  useEffect(() => {
    if (!open) {
      setPrepared(null);
      setPrepareError('');
      setApplied(false);
      setAdvancedOpen(false);
    }
  }, [open]);

  const logList = useMemo(
    () => logPaths.split('\n').map((l) => l.trim()).filter(Boolean),
    [logPaths],
  );

  const yaml = useMemo(
    () => buildYaml(kind, { configDir, logPaths: logList, reloadCmd, testCmd, service }),
    [kind, configDir, logList, reloadCmd, testCmd, service],
  );

  const permBlock = useMemo(
    () => buildPermBlock(configDir, testCmd, reloadCmd),
    [configDir, testCmd, reloadCmd],
  );

  const binaryCmd = prepared ? `nurproxy-agent apply ${prepared.code}` : '';
  const dockerCmd = prepared
    ? `docker exec ${DOCKER_CONTAINER} nurproxy-agent apply ${prepared.code}`
    : '';

  // Whether each field came pre-filled from real detection (vs. an OS default) —
  // drives the "confirmed from detection" affordance so the flow reads as
  // confirm-not-type.
  const detKindMatches = asKind(det?.kind) === kind;
  const fromDetection = (val: string | undefined) => detKindMatches && !!val;

  async function prepare() {
    setPreparing(true);
    setPrepareError('');
    setApplied(false);
    try {
      const res = await api.prepareAdminOp(agent.id, 'set_proxy_mode', {
        proxy_mode: 'existing',
        proxy_type: kind,
        proxy_config_dir: configDir,
        proxy_reload_cmd: reloadCmd,
        proxy_test_cmd: testCmd,
        proxy_service: service,
        proxy_log_paths: logList,
      });
      setPrepared(res);
    } catch (e) {
      setPrepareError(e instanceof Error ? e.message : String(e));
    } finally {
      setPreparing(false);
    }
  }

  // Poll the agent's pending ops while we have a prepared op that isn't applied
  // yet. The op disappears from the pending list (or flips out of "pending")
  // once the host runs `apply`; either signal flips us to applied. The agent
  // model doesn't surface proxy_mode, so the pending-list is the source of truth.
  const poll = useCallback(async () => {
    if (!prepared || applied) return;
    try {
      const { ops } = await api.listAdminOps(agent.id);
      const mine = ops.find((o) => o.id === prepared.id);
      if (!mine || mine.status !== 'pending') setApplied(true);
    } catch {
      // Transient errors are fine — we just retry on the next tick.
    }
  }, [prepared, applied, agent.id]);

  const shouldPoll = !!prepared && !applied;
  usePolling(shouldPoll ? poll : NOOP, 4000);

  async function cancel() {
    if (!prepared) return;
    try {
      await api.cancelAdminOp(agent.id, prepared.id);
    } catch {
      // If it already vanished (expired/claimed) the panel reset is enough.
    }
    setPrepared(null);
    setApplied(false);
  }

  return (
    <Modal open={open} onClose={onClose} title={t('existing.title')} description={agent.fqdn} wide>
      <div className="space-y-5">
        <Callout tone="info">{t('existing.intro')}</Callout>

        {det?.installed && detKindMatches ? (
          <Callout tone="success" title={t('existing.detectedTitle')}>
            {t('existing.detectedBody', {
              name: det.version ? `${det.kind} ${det.version}` : det.kind,
            })}
          </Callout>
        ) : (
          <Callout tone="warning">{t('existing.noDetection')}</Callout>
        )}

        <Field label={t('existing.proxyKind')} hint={t('existing.proxyKindHint')}>
          <Select
            value={kind}
            onChange={(e) => setKind(e.target.value as ProxyKind)}
            disabled={!!prepared}
          >
            {KINDS.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </Select>
        </Field>

        <div className="grid gap-4 sm:grid-cols-2">
          <ConfirmField
            label={t('existing.configDir')}
            value={configDir}
            onChange={setConfigDir}
            confirmed={fromDetection(det?.config_dir)}
            disabled={!!prepared}
            mono
          />
          <ConfirmField
            label={t('existing.service')}
            value={service}
            onChange={setService}
            confirmed={false}
            disabled={!!prepared}
            mono
          />
          <ConfirmField
            label={t('existing.testCmd')}
            value={testCmd}
            onChange={setTestCmd}
            confirmed={false}
            disabled={!!prepared}
            mono
          />
          <ConfirmField
            label={t('existing.reloadCmd')}
            value={reloadCmd}
            onChange={setReloadCmd}
            confirmed={false}
            disabled={!!prepared}
            mono
          />
        </div>

        <Field label={t('existing.logPaths')} hint={t('existing.logPathsHint')}>
          <textarea
            value={logPaths}
            onChange={(e) => setLogPaths(e.target.value)}
            rows={Math.max(2, logList.length)}
            disabled={!!prepared}
            className="block w-full rounded-lg border border-border bg-surface px-3 py-2 font-mono text-xs text-fg placeholder:text-fg-faint transition-colors focus:border-accent focus:ring-2 focus:ring-accent/30 focus-visible:outline-none disabled:opacity-60"
          />
          {det && detKindMatches && (det.log_paths?.length ?? 0) > 0 && (
            <p className="mt-1.5 flex items-center gap-1 text-xs text-success-fg">
              <Check className="h-3 w-3" /> {t('existing.confirmedFromDetection')}
            </p>
          )}
        </Field>

        {prepareError && <Callout tone="danger">{prepareError}</Callout>}

        {prepared && (
          <ResultPanel
            code={prepared.code}
            expiresAt={prepared.expires_at}
            binaryCmd={binaryCmd}
            dockerCmd={dockerCmd}
            permBlock={permBlock}
            applied={applied}
            onCancel={cancel}
          />
        )}

        {/* Advanced fallback: the raw agent.yaml snippet, for operators who
            prefer editing the file by hand instead of running `apply`. */}
        <div className="rounded-lg border border-border">
          <button
            type="button"
            onClick={() => setAdvancedOpen((v) => !v)}
            aria-expanded={advancedOpen}
            className="flex w-full items-center gap-2 px-3.5 py-2.5 text-left text-sm font-medium text-fg-muted transition-colors hover:text-fg"
          >
            {advancedOpen ? (
              <ChevronDown className="h-4 w-4" />
            ) : (
              <ChevronRight className="h-4 w-4" />
            )}
            {t('existing.advancedTitle')}
          </button>
          {advancedOpen && (
            <div className="border-t border-border px-3.5 py-3">
              <p className="mb-2 text-xs text-fg-faint">{t('existing.advancedHint')}</p>
              <CommandBlock text={yaml} label={t('existing.applyTitle')} />
            </div>
          )}
        </div>

        <div className="flex justify-end gap-3 pt-1">
          <Button variant="secondary" onClick={onClose}>
            {t('common.close')}
          </Button>
          {!prepared && (
            <Button onClick={prepare} loading={preparing}>
              {t('existing.prepare')}
            </Button>
          )}
        </div>
      </div>
    </Modal>
  );
}

const NOOP = () => {};

// ResultPanel renders the §19 prepare result: the one-time code, the two apply
// commands, the least-privilege permission grants, and a live pending/applied
// status with a Cancel affordance while pending.
function ResultPanel({
  code,
  expiresAt,
  binaryCmd,
  dockerCmd,
  permBlock,
  applied,
  onCancel,
}: {
  code: string;
  expiresAt: string;
  binaryCmd: string;
  dockerCmd: string;
  permBlock: string;
  applied: boolean;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  const at = localTime(expiresAt);

  return (
    <div className="space-y-4 rounded-lg border border-accent/40 bg-accent-soft/40 p-4">
      <div>
        <p className="text-sm font-medium text-fg">{t('existing.codeTitle')}</p>
        <p className="mt-2 select-all font-mono text-2xl font-semibold tracking-widest text-accent">
          {code}
        </p>
        <p className="mt-1 text-xs text-fg-faint">
          {at ? t('existing.expiresAt', { time: at }) : t('existing.expiresSoon')}
        </p>
      </div>

      <div>
        <p className="mb-1 text-sm font-medium text-fg">{t('existing.runTitle')}</p>
        <p className="mb-2 text-xs text-fg-faint">{t('existing.runHint')}</p>
        <CommandBlock text={binaryCmd} label={t('existing.cmdBinary')} />
        <div className="mt-3">
          <CommandBlock text={dockerCmd} label={t('existing.cmdDocker')} />
          <p className="mt-1 text-xs text-fg-faint">{t('existing.dockerHint')}</p>
        </div>
      </div>

      <div>
        <p className="mb-1 text-sm font-medium text-fg">{t('existing.permsTitle')}</p>
        <p className="mb-2 text-xs text-fg-faint">{t('existing.permsIntro')}</p>
        <CommandBlock text={permBlock} label={t('existing.permsTitle')} />
        <p className="mt-1.5 text-xs text-fg-faint">{t('existing.permsHostNote')}</p>
        <p className="mt-1 text-xs text-fg-faint">{t('existing.permsWiki')}</p>
      </div>

      <div className="border-t border-border pt-3">
        {applied ? (
          <p className="flex items-center gap-1.5 text-sm font-medium text-success-fg">
            <Check className="h-4 w-4" /> {t('existing.statusApplied')}
          </p>
        ) : (
          <div className="flex items-center justify-between gap-3">
            <p className="flex items-center gap-1.5 text-sm text-fg-muted">
              <Loader2 className="h-4 w-4 animate-spin" /> {t('existing.statusWaiting')}
            </p>
            <Button variant="danger-ghost" size="sm" onClick={onCancel}>
              {t('common.cancel')}
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}

// CommandBlock is a <pre> with a working copy button (copyText) — used for the
// apply commands, the permission block, and the advanced YAML.
function CommandBlock({ text, label }: { text: string; label: string }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);

  async function copy() {
    // copyText works over plain http too (hidden-textarea fallback); the text
    // also stays visible in the <pre> for manual selection if it fails.
    if (await copyText(text)) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  return (
    <div>
      <div className="mb-1 flex items-center justify-between gap-2">
        <span className="text-xs font-medium text-fg-muted">{label}</span>
        <button
          type="button"
          onClick={copy}
          className="inline-flex items-center gap-1 rounded-md border border-border bg-surface px-2 py-1 text-xs font-medium text-fg-muted transition-colors hover:text-fg"
        >
          {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
          {copied ? t('common.copied') : t('common.copy')}
        </button>
      </div>
      <pre className="overflow-x-auto rounded-lg border border-border bg-surface-2 p-3 font-mono text-xs leading-relaxed text-fg">
        {text}
      </pre>
    </div>
  );
}

// ConfirmField is a labelled input that signals when its value was pre-filled
// from live detection (a green check) — reinforcing the confirm-not-type flow —
// while still allowing an override.
function ConfirmField({
  label,
  value,
  onChange,
  confirmed,
  disabled,
  mono,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  confirmed: boolean;
  disabled?: boolean;
  mono?: boolean;
}) {
  const { t } = useTranslation();
  return (
    <Field label={label}>
      <Input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        className={mono ? 'font-mono text-xs' : ''}
      />
      {confirmed && (
        <p className="mt-1.5 flex items-center gap-1 text-xs text-success-fg">
          <Check className="h-3 w-3" /> {t('existing.confirmedFromDetection')}
        </p>
      )}
    </Field>
  );
}

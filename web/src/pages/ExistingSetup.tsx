import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Check, Copy } from 'lucide-react';
import Modal from '../components/Modal';
import Button from '../components/Button';
import Callout from '../components/Callout';
import { Field, Input, Select } from '../components/Field';
import { copyText } from '../lib/clipboard';
import type { Agent, ProxyDetection } from '../lib/types';

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

function asKind(k?: string): ProxyKind {
  return k === 'nginx' || k === 'apache' || k === 'caddy' ? k : 'nginx';
}

// Build the agent-side config the operator pastes on the host. proxy_mode is an
// agent config key (§9) — it lives on the agent, not in the orchestrator DB —
// so the guided flow ends by handing the operator the exact, ready-to-apply
// config rather than mutating anything server-side.
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

interface Props {
  agent: Agent;
  open: boolean;
  onClose: () => void;
}

/**
 * ExistingSetup is the guided "switch this agent to Existing" flow (§2, §2.1):
 * pick the proxy, then confirm the paths that matter (config dir, logs, reload +
 * test commands, service). Detection pre-fills every field so adoption is a
 * confirm-not-type flow; the result is the agent config snippet to apply on the
 * host.
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
  const [copied, setCopied] = useState(false);

  // Re-seed every field from detection (falling back to OS defaults) whenever the
  // dialog opens or the chosen proxy kind changes. Detection wins so the operator
  // confirms reality, not a guess.
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

  const logList = useMemo(
    () => logPaths.split('\n').map((l) => l.trim()).filter(Boolean),
    [logPaths],
  );

  const yaml = useMemo(
    () => buildYaml(kind, { configDir, logPaths: logList, reloadCmd, testCmd, service }),
    [kind, configDir, logList, reloadCmd, testCmd, service],
  );

  // Whether each field came pre-filled from real detection (vs. an OS default) —
  // drives the "confirmed from detection" affordance so the flow reads as
  // confirm-not-type.
  const detKindMatches = asKind(det?.kind) === kind;
  const fromDetection = (val: string | undefined) => detKindMatches && !!val;

  async function copy() {
    // copyText works over plain http too (hidden-textarea fallback); the snippet
    // also stays visible in the <pre> below for manual selection if it fails.
    if (await copyText(yaml)) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
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
          <Select value={kind} onChange={(e) => setKind(e.target.value as ProxyKind)}>
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
            mono
          />
          <ConfirmField
            label={t('existing.service')}
            value={service}
            onChange={setService}
            confirmed={false}
            mono
          />
          <ConfirmField
            label={t('existing.testCmd')}
            value={testCmd}
            onChange={setTestCmd}
            confirmed={false}
            mono
          />
          <ConfirmField
            label={t('existing.reloadCmd')}
            value={reloadCmd}
            onChange={setReloadCmd}
            confirmed={false}
            mono
          />
        </div>

        <Field
          label={t('existing.logPaths')}
          hint={t('existing.logPathsHint')}
        >
          <textarea
            value={logPaths}
            onChange={(e) => setLogPaths(e.target.value)}
            rows={Math.max(2, logList.length)}
            className="block w-full rounded-lg border border-border bg-surface px-3 py-2 font-mono text-xs text-fg placeholder:text-fg-faint transition-colors focus:border-accent focus:ring-2 focus:ring-accent/30 focus-visible:outline-none"
          />
          {det && detKindMatches && (det.log_paths?.length ?? 0) > 0 && (
            <p className="mt-1.5 flex items-center gap-1 text-xs text-success-fg">
              <Check className="h-3 w-3" /> {t('existing.confirmedFromDetection')}
            </p>
          )}
        </Field>

        <div>
          <div className="mb-1 flex items-center justify-between">
            <span className="text-sm font-medium text-fg">{t('existing.applyTitle')}</span>
            <button
              type="button"
              onClick={copy}
              className="inline-flex items-center gap-1 rounded-md border border-border bg-surface px-2 py-1 text-xs font-medium text-fg-muted transition-colors hover:text-fg"
            >
              {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
              {copied ? t('common.copied') : t('common.copy')}
            </button>
          </div>
          <p className="mb-2 text-xs text-fg-faint">{t('existing.applyHint')}</p>
          <pre className="overflow-x-auto rounded-lg border border-border bg-surface-2 p-3 font-mono text-xs leading-relaxed text-fg">
            {yaml}
          </pre>
        </div>

        <Callout tone="neutral">{t('existing.permsNote')}</Callout>

        <div className="flex justify-end gap-3 pt-1">
          <Button variant="secondary" onClick={onClose}>
            {t('common.close')}
          </Button>
          <Button onClick={copy}>{copied ? t('common.copied') : t('existing.copyConfig')}</Button>
        </div>
      </div>
    </Modal>
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
  mono,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  confirmed: boolean;
  mono?: boolean;
}) {
  const { t } = useTranslation();
  return (
    <Field label={label}>
      <Input
        value={value}
        onChange={(e) => onChange(e.target.value)}
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

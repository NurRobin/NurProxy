import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ArrowUp, X } from 'lucide-react';
import { api } from '../lib/api';
import type { Agent, Domain, DomainFailoverStatus, Server } from '../lib/types';
import { formatRelativeTime } from '../lib/utils';
import Button from './Button';
import Callout from './Callout';
import { Field, Select } from './Field';
import { useToast, errMessage } from './toast-context';

interface ServerOption extends Server {
  agentName: string;
}

// The most backups a domain may have; mirrors failover.MaxBackups.
const MAX_BACKUPS = 3;

/**
 * Failover tab of the domain dialog (#74): shows which agents can serve the
 * domain and which one its DNS record points at, and edits the ordered list
 * of backup servers on other agents.
 */
export default function DomainFailoverPanel({ domain, servers, agents, onSaved }: {
  domain: Domain;
  servers: ServerOption[];
  agents: Agent[];
  onSaved: () => void;
}) {
  const { t } = useTranslation();
  const toast = useToast();
  const [status, setStatus] = useState<DomainFailoverStatus | null>(null);
  const [loadError, setLoadError] = useState('');
  const [backups, setBackups] = useState<string[]>(domain.backup_server_ids ?? []);
  const [adding, setAdding] = useState('');
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState('');

  const load = useCallback(async () => {
    try {
      setStatus(await api.getDomainFailover(domain.id));
      setLoadError('');
    } catch (err) {
      setLoadError(errMessage(err, t('failover.loadFailed')));
    }
  }, [domain.id, t]);

  useEffect(() => {
    load();
    const timer = window.setInterval(load, 10000);
    return () => window.clearInterval(timer);
  }, [load]);

  if (domain.cert_only) {
    return <Callout tone="info">{t('failover.certOnly')}</Callout>;
  }

  const serverById = (id: string) => servers.find((s) => s.id === id);
  const primaryAgent = serverById(domain.server_id)?.agent_id;
  const usedAgents = new Set(backups.map((id) => serverById(id)?.agent_id));
  const servesZone = (agentId: string) => {
    const zones = agents.find((a) => a.id === agentId)?.zones;
    return !zones || zones.some((z) => z.id === domain.zone_id);
  };
  const choices = servers.filter((s) =>
    s.agent_id !== primaryAgent && !usedAgents.has(s.agent_id) && s.id !== domain.server_id);
  const dirty = backups.join(',') !== (domain.backup_server_ids ?? []).join(',');

  function move(i: number) {
    if (i === 0) return;
    const next = [...backups];
    [next[i - 1], next[i]] = [next[i], next[i - 1]];
    setBackups(next);
  }

  async function save() {
    setSaving(true);
    setSaveError('');
    try {
      setStatus(await api.setDomainBackups(domain.id, backups));
      toast.success(t('failover.saved'));
      onSaved();
    } catch (err) {
      setSaveError(errMessage(err, t('failover.saveFailed')));
    } finally {
      setSaving(false);
    }
  }

  const pendingAgent = status?.candidates.find((c) => c.server_id === status.pending_server_id)?.agent_name;

  return (
    <div className="space-y-5">
      <p className="text-sm text-fg-muted">{t('failover.intro')}</p>

      {loadError && <Callout tone="danger">{loadError}</Callout>}
      {status?.all_down && <Callout tone="danger">{t('failover.allDown')}</Callout>}
      {status && pendingAgent && status.pending_since && (
        <Callout tone="info">{t('failover.pending', { agent: pendingAgent, since: formatRelativeTime(status.pending_since) })}</Callout>
      )}

      {status && (
        <div>
          <p className="mb-2 text-sm font-medium text-fg">{t('failover.candidates')}</p>
          <ul className="divide-y divide-border rounded-lg border border-border">
            {status.candidates.map((c) => (
              <li key={c.server_id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm">
                <span className="w-20 text-xs font-medium text-fg-faint">
                  {c.primary ? t('failover.primary') : t('failover.backup', { n: c.priority })}
                </span>
                <span className="font-medium text-fg">{c.agent_name}</span>
                <span className="font-mono text-xs text-fg-muted">{c.agent_fqdn}</span>
                <span className="text-xs text-fg-faint">{c.server_name}</span>
                <span className="ml-auto flex items-center gap-2">
                  <span className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${c.healthy ? 'bg-success-soft text-success-fg' : 'bg-danger-soft text-danger-fg'}`}
                    title={c.reason}>
                    {c.healthy ? t('failover.healthy') : t('failover.down')}
                  </span>
                  {c.active && (
                    <span className="rounded-full bg-accent-soft px-2 py-0.5 text-[11px] font-medium text-accent">{t('failover.active')}</span>
                  )}
                </span>
              </li>
            ))}
          </ul>
          {status.switches > 0 && status.switched_at && (
            <p className="mt-2 text-xs text-fg-faint">{t('failover.switches', { count: status.switches, time: formatRelativeTime(status.switched_at) })}</p>
          )}
        </div>
      )}

      <Field label={t('failover.backups')} hint={t('failover.backupsHint')}>
        <div className="space-y-2">
          {backups.length === 0 && <p className="text-sm text-fg-faint">{t('failover.noBackups')}</p>}
          {backups.map((id, i) => {
            const srv = serverById(id);
            return (
              <div key={id} className="flex items-center gap-2 rounded-lg border border-border px-3 py-2 text-sm">
                <span className="w-6 text-xs text-fg-faint">{i + 1}.</span>
                <span className="text-fg">{srv ? `${srv.agentName} · ${srv.name} (${srv.address})` : id}</span>
                <span className="ml-auto flex gap-1">
                  <button type="button" onClick={() => move(i)} disabled={i === 0} aria-label={t('failover.moveUp')} title={t('failover.moveUp')}
                    className="rounded p-1 text-fg-faint hover:text-fg disabled:opacity-30">
                    <ArrowUp className="h-4 w-4" />
                  </button>
                  <button type="button" onClick={() => setBackups(backups.filter((x) => x !== id))} aria-label={t('failover.remove')} title={t('failover.remove')}
                    className="rounded p-1 text-fg-faint hover:text-danger-fg">
                    <X className="h-4 w-4" />
                  </button>
                </span>
              </div>
            );
          })}
          {backups.length < MAX_BACKUPS && choices.length > 0 && (
            <div className="flex gap-2">
              <Select value={adding} onChange={(e) => setAdding(e.target.value)} aria-label={t('failover.add')}>
                <option value="">{t('failover.selectServer')}</option>
                {choices.map((s) => (
                  <option key={s.id} value={s.id} disabled={!servesZone(s.agent_id)}>
                    {s.agentName} · {s.name} ({s.address}){servesZone(s.agent_id) ? '' : ` — ${t('failover.notInZone')}`}
                  </option>
                ))}
              </Select>
              <Button variant="secondary" disabled={!adding} onClick={() => { setBackups([...backups, adding]); setAdding(''); }}>
                {t('failover.add')}
              </Button>
            </div>
          )}
        </div>
      </Field>

      {saveError && <Callout tone="danger">{saveError}</Callout>}
      <div className="flex justify-end">
        <Button onClick={save} loading={saving} disabled={!dirty}>{t('failover.save')}</Button>
      </div>
    </div>
  );
}

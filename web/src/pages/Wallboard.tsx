import { useState, useCallback } from 'react';
import i18n from '../lib/i18n';
import { useTranslation } from 'react-i18next';
import { api } from '../lib/api';
import type { Agent, Domain } from '../lib/types';
import { formatRelativeTime } from '../lib/utils';
import { usePolling } from '../lib/usePolling';
import { statusMeta } from '../lib/status';

const count = (arr: { status: string }[], s: string) => arr.filter((x) => x.status === s).length;
const seen = (d?: string) => (d ? formatRelativeTime(d) : i18n.t('time.neverLower'));

export default function Wallboard() {
  const { t } = useTranslation();
  const [agents, setAgents] = useState<Agent[]>([]);
  const [domains, setDomains] = useState<Domain[]>([]);
  const [loaded, setLoaded] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const [a, d] = await Promise.all([api.listAgents(), api.listDomains()]);
      setAgents(a); setDomains(d); setLoaded(true);
    } catch { setLoaded(true); }
  }, []);

  usePolling(fetchData, 30000);

  if (!loaded) return <div className="flex h-[80vh] items-center justify-center text-fg-muted">{t('wallboard.loading')}</div>;

  const errs = count(agents, 'error') + count(domains, 'error');
  const offline = count(agents, 'offline');
  const healthy = errs === 0 && offline === 0;

  return (
    <div className="space-y-5">
      <div className={`flex items-center gap-4 rounded-2xl border p-5 ${healthy ? 'border-success/40 bg-success-soft/50' : 'border-danger/40 bg-danger-soft/50'}`}>
        <span className={`h-4 w-4 flex-shrink-0 rounded-full ${healthy ? 'bg-success' : 'bg-danger'} ${healthy ? '' : 'animate-pulse'}`} />
        <div>
          <p className="font-display text-2xl font-bold tracking-tight text-fg">
            {healthy ? t('wallboard.allNormal') : t('wallboard.attention', { count: errs + offline })}
          </p>
          <p className="text-sm text-fg-muted">{t('wallboard.summary', { agents: t('counts.agents', { count: agents.length }), domains: t('counts.domains', { count: domains.length }), active: count(domains, 'active') })}</p>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {agents.map((a) => {
          const m = statusMeta(a.status);
          return (
            <div key={a.id} className="rounded-2xl border border-border bg-surface p-5 shadow-card">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="truncate text-lg font-semibold text-fg">{a.name}</p>
                  <p className="truncate font-mono text-xs text-fg-faint">{a.fqdn}</p>
                </div>
                <span className={`h-3.5 w-3.5 flex-shrink-0 rounded-full ${m.dot} ${m.pulse ? 'animate-pulse' : ''}`} />
              </div>
              <p className={`mt-4 text-3xl font-bold tracking-tight ${a.status === 'error' ? 'text-danger-fg' : a.status === 'offline' ? 'text-fg-faint' : 'text-fg'}`}>{t(`status.${a.status}`)}</p>
              <p className="mt-1 text-xs text-fg-faint">{a.public_ip ?? '—'} · {t('overview.seen', { time: seen(a.last_seen) })}</p>
            </div>
          );
        })}

        <div className="rounded-2xl border border-border bg-surface p-5 shadow-card">
          <p className="text-sm font-semibold uppercase tracking-wide text-fg-faint">{t('wallboard.domains')}</p>
          <p className="mt-4 text-3xl font-bold tracking-tight text-fg">{count(domains, 'active')}<span className="text-lg font-medium text-fg-faint">{t('wallboard.ofActive', { total: domains.length })}</span></p>
          <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-fg-muted">
            {count(domains, 'pending') > 0 && <span>{t('wallboard.pending', { count: count(domains, 'pending') })}</span>}
            {count(domains, 'error') > 0 && <span className="text-danger-fg">{t('wallboard.error', { count: count(domains, 'error') })}</span>}
            {count(domains, 'deleting') > 0 && <span>{t('wallboard.deleting', { count: count(domains, 'deleting') })}</span>}
          </div>
        </div>
      </div>
    </div>
  );
}

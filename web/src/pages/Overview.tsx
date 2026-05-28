import { useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { CircleCheck, TriangleAlert } from 'lucide-react';
import { api } from '../lib/api';
import { usePolling } from '../lib/usePolling';
import type { Agent, Domain, AuditLogEntry } from '../lib/types';
import { formatRelativeTime } from '../lib/utils';
import { buttonClass } from '../components/button-styles';
import StatusBadge from '../components/StatusBadge';
import EmptyState from '../components/EmptyState';

function seen(date?: string) {
  return date ? formatRelativeTime(date) : 'Never';
}

export default function Overview() {
  const { t } = useTranslation();
  const [agents, setAgents] = useState<Agent[]>([]);
  const [domains, setDomains] = useState<Domain[]>([]);
  const [auditLog, setAuditLog] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);
  const [stale, setStale] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const [a, d, log] = await Promise.all([
        api.listAgents(),
        api.listDomains(),
        api.getAuditLog({ limit: '15' }),
      ]);
      setAgents(a);
      setDomains(d);
      setAuditLog(log.entries ?? []);
      setUpdatedAt(new Date().toISOString());
      setStale(false);
    } catch {
      setStale(true); // surface the outage instead of showing stale data as fresh
    } finally {
      setLoading(false);
    }
  }, []);

  usePolling(fetchData, 30000);

  const count = (arr: { status: string }[], s: string) => arr.filter((x) => x.status === s).length;
  const errors = count(agents, 'error') + count(domains, 'error');
  const offline = count(agents, 'offline');
  const pendingAgents = count(agents, 'pending');
  const healthy = errors === 0 && offline === 0;

  if (loading) {
    return <div className="py-12 text-center text-sm text-fg-muted">{t('common.loading')}</div>;
  }

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-3xl font-bold tracking-tight text-fg">{t('overview.title')}</h1>
          <p className="mt-1 text-sm text-fg-muted">
            {updatedAt && !stale ? t('overview.updated', { time: seen(updatedAt) }) : t('overview.glance')}
            {stale && <span className="text-danger-fg"> · {t('overview.staleNote')}</span>}
          </p>
        </div>
        <Link to="/domains" className={buttonClass('primary')}>{t('overview.newDomain')}</Link>
      </div>

      {/* Health summary — one panel, not a wall of identical metric cards. */}
      <section className="rounded-xl border border-border bg-surface p-5 shadow-card">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className={`flex h-9 w-9 items-center justify-center rounded-full ${healthy ? 'bg-success-soft text-success-fg' : 'bg-warning-soft text-warning-fg'}`}>
              {healthy ? <CircleCheck className="h-5 w-5" /> : <TriangleAlert className="h-5 w-5" />}
            </span>
            <div>
              <p className="font-medium text-fg">
                {healthy ? t('overview.allNormal') : t('overview.attention', { count: errors + offline })}
              </p>
              <p className="text-sm text-fg-muted">
                {t('overview.summary', { agents: t('counts.agents', { count: agents.length }), domains: t('counts.domains', { count: domains.length }) })}
                {pendingAgents > 0 && <> · {t('overview.awaiting', { count: pendingAgents })}</>}
              </p>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {errors > 0 && (
              <Link to="/domains" className="rounded-lg bg-danger-soft px-3 py-1.5 text-sm font-medium text-danger-fg hover:brightness-105">
                {t('overview.errorsLink', { count: errors })}
              </Link>
            )}
            {offline > 0 && (
              <Link to="/agents" className="rounded-lg bg-surface-2 px-3 py-1.5 text-sm font-medium text-fg-muted hover:text-fg">
                {t('overview.offlineLink', { count: offline })}
              </Link>
            )}
            {pendingAgents > 0 && (
              <Link to="/agents" className="rounded-lg bg-warning-soft px-3 py-1.5 text-sm font-medium text-warning-fg hover:brightness-105">
                {t('overview.reviewPending', { count: pendingAgents })}
              </Link>
            )}
          </div>
        </div>
      </section>

      {/* Agents */}
      {agents.length === 0 ? (
        <EmptyState
          title={t('overview.noAgents')}
          description={t('overview.noAgentsBody')}
          action={<Link to="/agents" className={buttonClass('primary')}>{t('overview.connectAgent')}</Link>}
        />
      ) : (
        <section>
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-fg-faint">{t('overview.agents')}</h2>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {agents.map((agent) => (
              <Link
                key={agent.id}
                to="/agents"
                className="group rounded-xl border border-border bg-surface p-4 shadow-card transition-colors hover:border-border-strong"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="truncate font-medium text-fg">{agent.name}</p>
                    <p className="truncate text-sm text-fg-muted">{agent.fqdn}</p>
                  </div>
                  <StatusBadge status={agent.status} />
                </div>
                <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-fg-faint">
                  {agent.public_ip && <span className="font-mono">{agent.public_ip}</span>}
                  <span>{t('overview.seen', { time: seen(agent.last_seen) })}</span>
                  {agent.version && <span>v{agent.version}</span>}
                </div>
              </Link>
            ))}
          </div>
        </section>
      )}

      {/* Recent activity */}
      {auditLog.length > 0 && (
        <section>
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-fg-faint">{t('overview.recentActivity')}</h2>
          <div className="overflow-hidden rounded-xl border border-border bg-surface shadow-card">
            <ul className="divide-y divide-border">
              {auditLog.map((entry) => (
                <li key={entry.id} className="flex items-center justify-between gap-4 px-4 py-3">
                  <p className="min-w-0 truncate text-sm text-fg-muted">
                    <span className="font-medium text-fg">{entry.action}</span>{' '}
                    <span>{entry.entity_type}</span>
                    {entry.details && <span className="text-fg-faint"> — {entry.details}</span>}
                  </p>
                  <span className="flex-shrink-0 text-xs text-fg-faint">{seen(entry.created_at)}</span>
                </li>
              ))}
            </ul>
          </div>
        </section>
      )}
    </div>
  );
}

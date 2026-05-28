import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';
import type { Agent, Domain, AuditLogEntry } from '../lib/types';
import { formatRelativeTime } from '../lib/utils';
import { buttonClass } from '../components/button-styles';
import StatusBadge from '../components/StatusBadge';
import EmptyState from '../components/EmptyState';

function seen(date?: string) {
  return date ? formatRelativeTime(date) : 'Never';
}

export default function Overview() {
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

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const count = (arr: { status: string }[], s: string) => arr.filter((x) => x.status === s).length;
  const errors = count(agents, 'error') + count(domains, 'error');
  const offline = count(agents, 'offline');
  const pendingAgents = count(agents, 'pending');
  const healthy = errors === 0 && offline === 0;

  if (loading) {
    return <div className="py-12 text-center text-sm text-fg-muted">Loading your dashboard…</div>;
  }

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-3xl font-bold tracking-tight text-fg">Overview</h1>
          <p className="mt-1 text-sm text-fg-muted">
            {updatedAt && !stale ? `Updated ${seen(updatedAt)}` : 'Your proxy at a glance'}
            {stale && <span className="text-danger-fg"> · couldn’t refresh — check the orchestrator</span>}
          </p>
        </div>
        <Link to="/domains" className={buttonClass('primary')}>New domain</Link>
      </div>

      {/* Health summary — one panel, not a wall of identical metric cards. */}
      <section className="rounded-xl border border-border bg-surface p-5 shadow-card">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className={`flex h-9 w-9 items-center justify-center rounded-full ${healthy ? 'bg-success-soft text-success-fg' : 'bg-warning-soft text-warning-fg'}`}>
              <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
                {healthy
                  ? <path strokeLinecap="round" strokeLinejoin="round" d="m9 12.75 2.25 2.25L15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z" />
                  : <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m0 3.75h.007M12 3l9 16H3l9-16z" />}
              </svg>
            </span>
            <div>
              <p className="font-medium text-fg">
                {healthy ? 'All systems normal' : `${errors + offline} thing${errors + offline !== 1 ? 's' : ''} need attention`}
              </p>
              <p className="text-sm text-fg-muted">
                {agents.length} agent{agents.length !== 1 ? 's' : ''} · {domains.length} domain{domains.length !== 1 ? 's' : ''}
                {pendingAgents > 0 && <> · {pendingAgents} awaiting adoption</>}
              </p>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {errors > 0 && (
              <Link to="/domains" className="rounded-lg bg-danger-soft px-3 py-1.5 text-sm font-medium text-danger-fg hover:brightness-105">
                {errors} error{errors !== 1 ? 's' : ''} →
              </Link>
            )}
            {offline > 0 && (
              <Link to="/agents" className="rounded-lg bg-surface-2 px-3 py-1.5 text-sm font-medium text-fg-muted hover:text-fg">
                {offline} offline →
              </Link>
            )}
            {pendingAgents > 0 && (
              <Link to="/agents" className="rounded-lg bg-warning-soft px-3 py-1.5 text-sm font-medium text-warning-fg hover:brightness-105">
                Review {pendingAgents} pending →
              </Link>
            )}
          </div>
        </div>
      </section>

      {/* Agents */}
      {agents.length === 0 ? (
        <EmptyState
          title="No agents connected yet"
          description="Install the NurProxy agent on an edge server. It registers itself and shows up here for approval."
          action={<Link to="/agents" className={buttonClass('primary')}>Connect an agent</Link>}
        />
      ) : (
        <section>
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-fg-faint">Agents</h2>
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
                  <span>Seen {seen(agent.last_seen)}</span>
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
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-fg-faint">Recent activity</h2>
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

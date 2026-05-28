import { useState, useCallback } from 'react';
import { api } from '../lib/api';
import type { Agent, Domain, AuditLogEntry } from '../lib/types';
import { formatRelativeTime } from '../lib/utils';
import { usePolling } from '../lib/usePolling';

const count = (arr: { status: string }[], s: string) => arr.filter((x) => x.status === s).length;

export default function TerminalOverview() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [domains, setDomains] = useState<Domain[]>([]);
  const [log, setLog] = useState<AuditLogEntry[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [stale, setStale] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const [a, d, l] = await Promise.all([api.listAgents(), api.listDomains(), api.getAuditLog({ limit: '12' })]);
      setAgents(a); setDomains(d); setLog(l.entries ?? []); setStale(false); setLoaded(true);
    } catch { setStale(true); setLoaded(true); }
  }, []);

  usePolling(fetchData, 30000);

  if (!loaded) return <div className="font-mono text-sm text-fg-muted">loading…</div>;

  const errs = count(agents, 'error') + count(domains, 'error');
  const row = (k: string, v: string) => (
    <div className="flex gap-3"><span className="w-24 text-fg-faint">{k}</span><span className="text-fg">{v}</span></div>
  );

  return (
    <div className="space-y-6 font-mono text-sm">
      <div className="rounded-xl border border-border bg-surface p-5 shadow-card">
        <div className="mb-3 flex items-center gap-2">
          <span className={`h-2.5 w-2.5 rounded-full ${errs > 0 ? 'bg-danger' : 'bg-success'}`} />
          <span className="font-semibold text-fg">nurproxy status</span>
          {stale && <span className="text-danger-fg">· unreachable</span>}
        </div>
        <div className="space-y-1">
          {row('agents', `${agents.length}  (${count(agents, 'adopted')} adopted, ${count(agents, 'pending')} pending, ${count(agents, 'offline')} offline)`)}
          {row('domains', `${domains.length}  (${count(domains, 'active')} active, ${count(domains, 'pending')} pending, ${count(domains, 'error')} error)`)}
          {row('errors', errs === 0 ? 'none' : String(errs))}
        </div>
        <p className="mt-4 text-xs text-fg-faint">Press <kbd className="rounded border border-border px-1">⌘K</kbd> to navigate or act.</p>
      </div>

      <div>
        <p className="mb-2 text-xs uppercase tracking-wide text-fg-faint">recent activity</p>
        <div className="rounded-xl border border-border bg-surface shadow-card">
          {log.length === 0 ? (
            <p className="px-4 py-3 text-fg-faint">no recent events.</p>
          ) : (
            <ul className="divide-y divide-border">
              {log.map((e) => (
                <li key={e.id} className="flex items-center justify-between gap-4 px-4 py-2">
                  <span className="truncate text-fg-muted"><span className="text-fg">{e.action}</span> {e.entity_type}{e.details ? ` — ${e.details}` : ''}</span>
                  <span className="flex-shrink-0 text-xs text-fg-faint">{formatRelativeTime(e.created_at)}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}

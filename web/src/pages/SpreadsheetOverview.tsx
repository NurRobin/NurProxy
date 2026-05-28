import { useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';
import type { Agent, Domain, Server, Zone } from '../lib/types';
import { formatRelativeTime } from '../lib/utils';
import { usePolling } from '../lib/usePolling';
import StatusBadge from '../components/StatusBadge';
import { buttonClass } from '../components/button-styles';

interface ServerWithAgent extends Server { agentName: string }
type SortKey = 'fqdn' | 'target' | 'agent' | 'status' | 'synced';

function SortHeader({ label, sortKey, current, dir, onSort, right }: {
  label: string; sortKey: SortKey; current: SortKey; dir: 1 | -1; onSort: (k: SortKey) => void; right?: boolean;
}) {
  return (
    <th className={`px-4 py-2.5 font-semibold ${right ? 'text-right' : ''}`}>
      <button onClick={() => onSort(sortKey)} className="inline-flex items-center gap-1 hover:text-fg">
        {label}
        {current === sortKey && <span className="text-[10px]">{dir === 1 ? '▲' : '▼'}</span>}
      </button>
    </th>
  );
}

const count = (arr: { status: string }[], s: string) => arr.filter((x) => x.status === s).length;

export default function SpreadsheetOverview() {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const [allServers, setAllServers] = useState<ServerWithAgent[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: 'fqdn', dir: 1 });

  const fetchData = useCallback(async () => {
    try {
      const [d, a, z] = await Promise.all([api.listDomains(), api.listAgents(), api.listAllZones()]);
      setDomains(d); setAgents(a); setZones(z);
      const managed = a.filter((ag) => ag.status === 'adopted' || ag.status === 'offline');
      const entries = await Promise.all(managed.map(async (ag) => {
        try { return (await api.listServers(ag.id)).map((s) => ({ ...s, agentName: ag.name })); }
        catch { return [] as ServerWithAgent[]; }
      }));
      setAllServers(entries.flat());
    } catch { /* surfaced elsewhere */ }
    finally { setLoaded(true); }
  }, []);

  usePolling(fetchData, 30000);

  const zoneName = (id: string) => zones.find((z) => z.id === id)?.name ?? '';
  const srvOf = (id: string) => allServers.find((s) => s.id === id);
  const fqdn = (d: Domain) => { const z = zoneName(d.zone_id); return z ? `${d.subdomain}.${z}` : d.subdomain; };
  const target = (d: Domain) => { const s = srvOf(d.server_id); return s ? `${s.address}:${d.port}` : `:${d.port}`; };

  const val = (d: Domain, k: SortKey): string => {
    switch (k) {
      case 'fqdn': return fqdn(d);
      case 'target': return target(d);
      case 'agent': return srvOf(d.server_id)?.agentName ?? '';
      case 'status': return d.status;
      case 'synced': return d.last_synced ?? '';
    }
  };
  const rows = [...domains].sort((a, b) => val(a, sort.key).localeCompare(val(b, sort.key)) * sort.dir);
  const toggleSort = (k: SortKey) => setSort((s) => (s.key === k ? { key: k, dir: (s.dir * -1) as 1 | -1 } : { key: k, dir: 1 }));
  const th = (k: SortKey, label: string, right?: boolean) => (
    <SortHeader label={label} sortKey={k} current={sort.key} dir={sort.dir} onSort={toggleSort} right={right} />
  );

  if (!loaded) return <div className="py-12 text-center text-sm text-fg-muted">Loading…</div>;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-fg-muted">
          <span className="font-medium text-fg">{agents.length}</span> agents ·{' '}
          <span className="font-medium text-fg">{domains.length}</span> domains ·{' '}
          {count(domains, 'active')} active{count(domains, 'error') > 0 && <span className="text-danger-fg"> · {count(domains, 'error')} error</span>}
        </p>
        <Link to="/domains" className={buttonClass('primary', 'sm')}>Manage domains</Link>
      </div>

      {domains.length === 0 ? (
        <div className="rounded-xl border border-dashed border-border py-12 text-center text-sm text-fg-muted">No domains yet.</div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-border bg-surface shadow-card">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-border text-xs uppercase tracking-wide text-fg-faint">
              <tr>
                {th('fqdn', 'Domain')}
                {th('target', 'Target')}
                {th('agent', 'Agent')}
                {th('status', 'Status')}
                {th('synced', 'Synced', true)}
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {rows.map((d) => (
                <tr key={d.id} className="transition-colors hover:bg-surface-2">
                  <td className="px-4 py-2.5 font-medium text-fg">{fqdn(d)}</td>
                  <td className="px-4 py-2.5 font-mono text-xs text-fg-muted">{target(d)}</td>
                  <td className="px-4 py-2.5 text-fg-muted">{srvOf(d.server_id)?.agentName ?? '—'}</td>
                  <td className="px-4 py-2.5"><StatusBadge status={d.status} /></td>
                  <td className="px-4 py-2.5 text-right text-xs text-fg-faint">{d.last_synced ? formatRelativeTime(d.last_synced) : 'never'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

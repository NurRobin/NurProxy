import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../lib/api';
import type { Agent, Server, Domain, Zone } from '../lib/types';
import { formatRelativeTime } from '../lib/utils';
import StatusBadge from '../components/StatusBadge';
import EmptyState from '../components/EmptyState';
import Button from '../components/Button';
import { buttonClass } from '../components/button-styles';
import ConfirmDialog from '../components/ConfirmDialog';
import ContextMenu, { type MenuState } from '../components/ContextMenu';
import { useToast, errMessage } from '../components/toast-context';

type NodeKind = 'internet' | 'agent' | 'server' | 'domain';
interface Selection { kind: NodeKind; id: string }
interface Edge { from: string; to: string; active: boolean }

const seen = (d?: string) => (d ? formatRelativeTime(d) : 'never');

export default function Topology() {
  const toast = useToast();
  const navigate = useNavigate();

  const [agents, setAgents] = useState<Agent[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const [domains, setDomains] = useState<Domain[]>([]);
  const [serversByAgent, setServersByAgent] = useState<Record<string, Server[]>>({});
  const [loading, setLoading] = useState(true);

  const [selected, setSelected] = useState<Selection | null>(null);
  const [menu, setMenu] = useState<MenuState | null>(null);
  const [del, setDel] = useState<{ title: string; message: string; run: () => Promise<void>; confirmText?: string } | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const [a, z, d] = await Promise.all([api.listAgents(), api.listAllZones(), api.listDomains()]);
      setAgents(a); setZones(z); setDomains(d);
      const managed = a.filter((ag) => ag.status === 'adopted' || ag.status === 'offline');
      const entries = await Promise.all(managed.map(async (ag) => {
        try { return [ag.id, await api.listServers(ag.id)] as const; }
        catch { return [ag.id, [] as Server[]] as const; }
      }));
      setServersByAgent(Object.fromEntries(entries));
    } catch (err) {
      toast.error(errMessage(err, 'Couldn’t load topology.'));
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => { fetchData(); const t = setInterval(fetchData, 30000); return () => clearInterval(t); }, [fetchData]);

  const allServers = useMemo(() => Object.values(serversByAgent).flat(), [serversByAgent]);
  const zoneName = (id: string) => zones.find((z) => z.id === id)?.name ?? '';
  const fqdn = (d: Domain) => { const z = zoneName(d.zone_id); return z ? `${d.subdomain}.${z}` : d.subdomain; };

  // Ordered columns (grouped so connectors cross as little as possible).
  const orderedServers = useMemo(() => agents.flatMap((a) => serversByAgent[a.id] ?? []), [agents, serversByAgent]);
  const orderedDomains = useMemo(() => {
    const byServer = new Map<string, Domain[]>();
    const orphans: Domain[] = [];
    for (const d of domains) {
      if (allServers.some((s) => s.id === d.server_id)) {
        byServer.set(d.server_id, [...(byServer.get(d.server_id) ?? []), d]);
      } else orphans.push(d);
    }
    return [...orderedServers.flatMap((s) => byServer.get(s.id) ?? []), ...orphans];
  }, [domains, orderedServers, allServers]);

  const edges = useMemo<Edge[]>(() => {
    const e: Edge[] = [];
    for (const a of agents) e.push({ from: 'internet', to: `agent:${a.id}`, active: a.status === 'adopted' });
    for (const a of agents) for (const s of serversByAgent[a.id] ?? []) e.push({ from: `agent:${a.id}`, to: `server:${s.id}`, active: a.status === 'adopted' });
    for (const d of domains) { if (allServers.some((s) => s.id === d.server_id)) e.push({ from: `server:${d.server_id}`, to: `domain:${d.id}`, active: d.status === 'active' }); }
    return e;
  }, [agents, serversByAgent, domains, allServers]);

  // ---- connector geometry ----
  const containerRef = useRef<HTMLDivElement>(null);
  const nodeRefs = useRef<Map<string, HTMLElement>>(new Map());
  const setNodeRef = (id: string) => (el: HTMLElement | null) => { if (el) nodeRefs.current.set(id, el); else nodeRefs.current.delete(id); };
  const [paths, setPaths] = useState<{ id: string; d: string; active: boolean }[]>([]);
  const [size, setSize] = useState({ w: 0, h: 0 });

  const measure = useCallback(() => {
    const c = containerRef.current; if (!c) return;
    const cr = c.getBoundingClientRect();
    const next: { id: string; d: string; active: boolean }[] = [];
    for (const e of edges) {
      const f = nodeRefs.current.get(e.from); const t = nodeRefs.current.get(e.to);
      if (!f || !t) continue;
      const fr = f.getBoundingClientRect(); const tr = t.getBoundingClientRect();
      const x1 = fr.right - cr.left + c.scrollLeft; const y1 = fr.top - cr.top + c.scrollTop + fr.height / 2;
      const x2 = tr.left - cr.left + c.scrollLeft; const y2 = tr.top - cr.top + c.scrollTop + tr.height / 2;
      const mx = x1 + (x2 - x1) / 2;
      next.push({ id: `${e.from}->${e.to}`, d: `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`, active: e.active });
    }
    setPaths(next);
    setSize({ w: c.scrollWidth, h: c.scrollHeight });
  }, [edges]);

  useLayoutEffect(() => { measure(); }, [measure, agents, orderedServers, orderedDomains]);
  useEffect(() => {
    const c = containerRef.current; if (!c) return;
    const ro = new ResizeObserver(() => measure());
    ro.observe(c);
    window.addEventListener('resize', measure);
    const t = setTimeout(measure, 60); // catch late layout/fonts
    return () => { ro.disconnect(); window.removeEventListener('resize', measure); clearTimeout(t); };
  }, [measure]);

  // ---- actions ----
  async function rejectAgent(id: string) {
    try { await api.rejectAgent(id); toast.success('Agent rejected.'); fetchData(); }
    catch (err) { toast.error(errMessage(err, 'Failed to reject.')); }
  }
  function confirmDelete(title: string, message: string, run: () => Promise<void>, confirmText?: string) { setDel({ title, message, run, confirmText }); }

  function openMenu(e: React.MouseEvent, sel: Selection) {
    e.preventDefault();
    setSelected(sel);
    const items: MenuState['items'] = [{ label: 'Inspect', onSelect: () => setSelected(sel), icon: <Dot /> }];
    if (sel.kind === 'agent') {
      const a = agents.find((x) => x.id === sel.id);
      items.push({ label: 'Open in Agents', onSelect: () => navigate('/agents') });
      if (a?.status === 'adopted' || a?.status === 'offline') {
        items.push({ label: 'Add server', onSelect: () => navigate('/servers') });
      }
      if (a?.status === 'pending') {
        items.push({ label: 'Approve…', onSelect: () => navigate('/agents') });
        items.push({ label: 'Reject', danger: true, onSelect: () => rejectAgent(sel.id) });
      } else {
        items.push({ label: 'Delete agent', danger: true, onSelect: () => confirmDelete('Delete agent', `Delete “${a?.name}”? Removes its servers and domains too.`, async () => { await api.deleteAgent(sel.id); }, a?.name) });
      }
    } else if (sel.kind === 'server') {
      const s = allServers.find((x) => x.id === sel.id);
      items.push({ label: 'Add domain here', onSelect: () => navigate('/domains') });
      items.push({ label: 'Remove server', danger: true, onSelect: () => confirmDelete('Remove server', `Remove “${s?.name}”? Domains using it are affected.`, async () => { await api.deleteServer(sel.id); }) });
    } else if (sel.kind === 'domain') {
      const d = domains.find((x) => String(x.id) === sel.id);
      items.push({ label: 'Edit in Domains', onSelect: () => navigate('/domains') });
      if (d) items.push({ label: 'Delete domain', danger: true, onSelect: () => confirmDelete('Delete domain', `Delete “${d.subdomain}”? DNS record and proxy config are removed.`, async () => { await api.deleteDomain(d.id); }) });
    }
    setMenu({ x: e.clientX, y: e.clientY, title: labelFor(sel), items });
  }

  function labelFor(sel: Selection): string {
    if (sel.kind === 'internet') return 'Internet';
    if (sel.kind === 'agent') return agents.find((a) => a.id === sel.id)?.name ?? 'Agent';
    if (sel.kind === 'server') return allServers.find((s) => s.id === sel.id)?.name ?? 'Server';
    const d = domains.find((x) => String(x.id) === sel.id);
    return d ? fqdn(d) : 'Domain';
  }

  if (loading) return <div className="py-12 text-center text-sm text-fg-muted">Loading topology…</div>;

  const hasAnything = agents.length > 0;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-3xl font-bold tracking-tight text-fg">Topology</h1>
          <p className="mt-1 text-sm text-fg-muted">Your edge agents, upstreams, and domains. Click to inspect · right-click for actions.</p>
        </div>
        <button onClick={() => navigate('/domains')} className={buttonClass('primary')}>New domain</button>
      </div>

      {!hasAnything ? (
        <EmptyState
          title="Nothing to map yet"
          description="Connect an agent and add a domain — they’ll appear here as a live graph of your setup."
          action={<button onClick={() => navigate('/agents')} className={buttonClass('primary')}>Connect an agent</button>}
        />
      ) : (
        <div ref={containerRef} className="relative overflow-x-auto rounded-xl border border-border bg-surface/40 p-5">
          <svg width={size.w} height={size.h} className="pointer-events-none absolute left-0 top-0" style={{ overflow: 'visible' }}>
            {paths.map((p) => (
              <path key={p.id} d={p.d} fill="none" strokeWidth={1.5}
                stroke={p.active ? 'var(--accent)' : 'var(--border-strong)'} strokeOpacity={p.active ? 0.7 : 0.9} />
            ))}
          </svg>

          <div className="relative z-10 flex min-w-[44rem] items-start gap-10">
            <Column title="Internet">
              <NodeCard innerRef={setNodeRef('internet')} selected={selected?.kind === 'internet'}
                onClick={() => setSelected({ kind: 'internet', id: 'internet' })}
                onContextMenu={(e) => openMenu(e, { kind: 'internet', id: 'internet' })}
                icon={<GlobeIcon />} title="Public internet" sub="inbound traffic" />
            </Column>

            <Column title="Edge agents">
              {agents.map((a) => (
                <NodeCard key={a.id} innerRef={setNodeRef(`agent:${a.id}`)} selected={selected?.kind === 'agent' && selected.id === a.id}
                  onClick={() => setSelected({ kind: 'agent', id: a.id })}
                  onContextMenu={(e) => openMenu(e, { kind: 'agent', id: a.id })}
                  status={a.status} title={a.name} sub={a.fqdn} />
              ))}
            </Column>

            <Column title="Upstreams">
              {orderedServers.length === 0 ? <Hint>No servers</Hint> : orderedServers.map((s) => (
                <NodeCard key={s.id} innerRef={setNodeRef(`server:${s.id}`)} selected={selected?.kind === 'server' && selected.id === s.id}
                  onClick={() => setSelected({ kind: 'server', id: s.id })}
                  onContextMenu={(e) => openMenu(e, { kind: 'server', id: s.id })}
                  icon={<ServerIcon />} title={s.name} sub={s.address} />
              ))}
            </Column>

            <Column title="Domains">
              {orderedDomains.length === 0 ? <Hint>No domains</Hint> : orderedDomains.map((d) => (
                <NodeCard key={d.id} innerRef={setNodeRef(`domain:${d.id}`)} selected={selected?.kind === 'domain' && selected.id === String(d.id)}
                  onClick={() => setSelected({ kind: 'domain', id: String(d.id) })}
                  onContextMenu={(e) => openMenu(e, { kind: 'domain', id: String(d.id) })}
                  status={d.status} title={fqdn(d)} sub={`:${d.port}`} />
              ))}
            </Column>
          </div>
        </div>
      )}

      {/* Inspector drawer (fixed, does not reflow the map) */}
      {selected && (
        <Inspector
          onClose={() => setSelected(null)}
          title={labelFor(selected)}
          body={renderInspector(selected, { agents, allServers, domains, serversByAgent, zoneName, fqdn })}
          onManage={() => navigate(selected.kind === 'domain' ? '/domains' : selected.kind === 'server' ? '/domains' : '/agents')}
          manageLabel={selected.kind === 'internet' ? undefined : selected.kind === 'domain' ? 'Edit in Domains' : selected.kind === 'server' ? 'Manage in Domains' : 'Manage in Agents'}
        />
      )}

      <ContextMenu menu={menu} onClose={() => setMenu(null)} />

      <ConfirmDialog
        open={del !== null}
        onClose={() => setDel(null)}
        onConfirm={async () => { if (!del) return; try { await del.run(); toast.success('Done.'); setSelected(null); fetchData(); } catch (err) { toast.error(errMessage(err)); } finally { setDel(null); } }}
        title={del?.title ?? ''}
        message={del?.message ?? ''}
        confirmLabel="Delete"
        danger
        confirmText={del?.confirmText}
      />
    </div>
  );
}

// ---- inspector content ----
interface InspectorCtx {
  agents: Agent[]; allServers: Server[]; domains: Domain[];
  serversByAgent: Record<string, Server[]>;
  zoneName: (id: string) => string; fqdn: (d: Domain) => string;
}

function renderInspector(sel: Selection, ctx: InspectorCtx) {
  if (sel.kind === 'internet') {
    return <Rows rows={[['Role', 'Entry point'], ['Agents', String(ctx.agents.length)]]} note="Inbound requests resolve via DNS to an edge agent." />;
  }
  if (sel.kind === 'agent') {
    const a = ctx.agents.find((x) => x.id === sel.id); if (!a) return null;
    const servers = ctx.serversByAgent[a.id] ?? [];
    return (
      <div className="space-y-3">
        <StatusBadge status={a.status} />
        <Rows rows={[
          ['FQDN', a.fqdn], ['DNS mode', a.dns_mode || 'static'], ['IP', a.public_ip || '—'],
          ['Version', a.version || '—'], ['Last seen', seen(a.last_seen)], ['Servers', String(servers.length)],
        ]} />
      </div>
    );
  }
  if (sel.kind === 'server') {
    const s = ctx.allServers.find((x) => x.id === sel.id); if (!s) return null;
    const agent = ctx.agents.find((a) => a.id === s.agent_id);
    const doms = ctx.domains.filter((d) => d.server_id === s.id);
    return (
      <div className="space-y-3">
        <Rows rows={[['Address', s.address], ['Agent', agent?.name ?? '—'], ['Domains', String(doms.length)], ...(s.notes ? [['Notes', s.notes] as [string, string]] : [])]} />
      </div>
    );
  }
  const d = ctx.domains.find((x) => String(x.id) === sel.id); if (!d) return null;
  const srv = ctx.allServers.find((s) => s.id === d.server_id);
  return (
    <div className="space-y-3">
      <StatusBadge status={d.status} />
      {d.error_msg && <div className="rounded-lg border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger-fg">{d.error_msg}</div>}
      <Rows rows={[
        ['Target', srv ? `${srv.address}:${d.port}` : `:${d.port}`], ['Zone', ctx.zoneName(d.zone_id) || '—'],
        ['Force HTTPS', d.force_https ? 'on' : 'off'], ['WebSocket', d.websocket ? 'on' : 'off'], ['Last synced', seen(d.last_synced)],
      ]} />
    </div>
  );
}

// ---- presentational bits ----
function Column({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="flex min-w-44 flex-col gap-3">
      <span className="px-1 text-xs font-semibold uppercase tracking-wide text-fg-faint">{title}</span>
      {children}
    </div>
  );
}

function NodeCard({ innerRef, title, sub, icon, status, selected, onClick, onContextMenu }: {
  innerRef: (el: HTMLElement | null) => void;
  title: string; sub?: string; icon?: React.ReactNode; status?: string;
  selected?: boolean; onClick: () => void; onContextMenu: (e: React.MouseEvent) => void;
}) {
  const dot = status ? statusDot(status) : null;
  return (
    <button
      ref={innerRef as (el: HTMLButtonElement | null) => void}
      onClick={onClick}
      onContextMenu={onContextMenu}
      className={`group flex w-full items-center gap-2.5 rounded-lg border bg-surface px-3 py-2.5 text-left shadow-card transition-colors ${
        selected ? 'border-accent ring-2 ring-accent/30' : 'border-border hover:border-border-strong'
      }`}
    >
      {dot ?? (icon && <span className="flex h-4 w-4 items-center justify-center text-fg-faint">{icon}</span>)}
      <span className="min-w-0">
        <span className="block truncate text-sm font-medium text-fg">{title}</span>
        {sub && <span className="block truncate font-mono text-xs text-fg-faint">{sub}</span>}
      </span>
    </button>
  );
}

function statusDot(status: string) {
  const color = status === 'active' || status === 'adopted' ? 'bg-success'
    : status === 'pending' ? 'bg-warning' : status === 'error' ? 'bg-danger'
    : status === 'deleting' ? 'bg-info' : 'bg-fg-faint';
  const pulse = status === 'pending' || status === 'deleting';
  return <span className={`h-2.5 w-2.5 flex-shrink-0 rounded-full ${color} ${pulse ? 'animate-pulse' : ''}`} />;
}

function Hint({ children }: { children: React.ReactNode }) {
  return <span className="px-1 text-sm text-fg-faint">{children}</span>;
}

function Rows({ rows, note }: { rows: [string, string][]; note?: string }) {
  return (
    <div>
      <dl className="space-y-2 text-sm">
        {rows.map(([k, v]) => (
          <div key={k} className="flex justify-between gap-4">
            <dt className="text-fg-faint">{k}</dt>
            <dd className="min-w-0 truncate text-right text-fg">{v}</dd>
          </div>
        ))}
      </dl>
      {note && <p className="mt-3 text-xs leading-relaxed text-fg-faint">{note}</p>}
    </div>
  );
}

function Inspector({ title, body, onClose, onManage, manageLabel }: {
  title: string; body: React.ReactNode; onClose: () => void; onManage: () => void; manageLabel?: string;
}) {
  return (
    <div className="fixed inset-y-0 right-0 z-40 flex w-full max-w-sm flex-col border-l border-border bg-surface shadow-pop animate-pop-in">
      <div className="flex items-center justify-between gap-3 border-b border-border px-5 py-4">
        <h2 className="truncate font-display text-lg font-semibold text-fg">{title}</h2>
        <button onClick={onClose} aria-label="Close" className="rounded-lg p-1.5 text-fg-faint hover:bg-surface-2 hover:text-fg">
          <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" /></svg>
        </button>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto px-5 py-5">{body}</div>
      {manageLabel && (
        <div className="border-t border-border px-5 py-4">
          <Button variant="secondary" onClick={onManage} className="w-full justify-center">{manageLabel}</Button>
        </div>
      )}
    </div>
  );
}

function Dot() { return <span className="h-2 w-2 rounded-full bg-fg-faint" />; }
function GlobeIcon() { return <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.7}><path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zm0 0a8.95 8.95 0 0 0 0-18M3.6 9h16.8M3.6 15h16.8" /></svg>; }
function ServerIcon() { return <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.7}><path strokeLinecap="round" strokeLinejoin="round" d="M5.25 14.25h13.5m-13.5 0a3 3 0 0 1-3-3V6a3 3 0 0 1 3-3h13.5a3 3 0 0 1 3 3v5.25a3 3 0 0 1-3 3M8.25 6.75h.008v.008H8.25z" /></svg>; }

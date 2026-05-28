import { useState, useEffect, useCallback } from 'react';
import { api } from '../lib/api';
import type { Domain, Agent, Server, Zone } from '../lib/types';
import { formatRelativeTime } from '../lib/utils';
import StatusBadge from '../components/StatusBadge';
import Modal from '../components/Modal';
import ConfirmDialog from '../components/ConfirmDialog';
import EmptyState from '../components/EmptyState';
import Button from '../components/Button';
import Callout from '../components/Callout';
import HelpTip from '../components/HelpTip';
import { Field, Input, Select, Textarea, Checkbox } from '../components/Field';
import { useToast, errMessage } from '../components/toast-context';
import { useUndoableDelete } from '../lib/undo';

function seen(date?: string) {
  return date ? formatRelativeTime(date) : 'Never';
}

interface ServerWithAgent extends Server {
  agentName: string;
}

type EditTab = 'general' | 'headers' | 'advanced';
const STATUS_FILTERS = ['all', 'active', 'pending', 'error', 'deleting'];

export default function Domains() {
  const toast = useToast();
  const [domains, setDomains] = useState<Domain[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const [allServers, setAllServers] = useState<ServerWithAgent[]>([]);
  const [loading, setLoading] = useState(true);

  const [statusFilter, setStatusFilter] = useState('all');
  const [agentFilter, setAgentFilter] = useState('all');

  // Create
  const [showCreate, setShowCreate] = useState(false);
  const [createSub, setCreateSub] = useState('');
  const [createZone, setCreateZone] = useState('');
  const [createServer, setCreateServer] = useState('');
  const [createPort, setCreatePort] = useState('80');
  const [createWebsocket, setCreateWebsocket] = useState(false);
  const [createForceHttps, setCreateForceHttps] = useState(true);
  const [createLoading, setCreateLoading] = useState(false);
  const [createError, setCreateError] = useState('');

  // Detail / edit
  const [detailDomain, setDetailDomain] = useState<Domain | null>(null);
  const [editTab, setEditTab] = useState<EditTab>('general');
  const [editWebsocket, setEditWebsocket] = useState(false);
  const [editForceHttps, setEditForceHttps] = useState(true);
  const [editMaxBody, setEditMaxBody] = useState('');
  const [editHeaders, setEditHeaders] = useState<Array<{ key: string; value: string }>>([]);
  const [editRawConfig, setEditRawConfig] = useState('');
  const [advancedError, setAdvancedError] = useState('');
  const [editLoading, setEditLoading] = useState(false);

  const undoableDelete = useUndoableDelete();
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [bulkConfirm, setBulkConfirm] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const [d, a, z] = await Promise.all([api.listDomains(), api.listAgents(), api.listAllZones()]);
      setDomains(d); setAgents(a); setZones(z);
      const adopted = a.filter((ag) => ag.status === 'adopted' || ag.status === 'offline');
      const serverResults = await Promise.all(
        adopted.map(async (ag) => {
          try {
            const srvs = await api.listServers(ag.id);
            return srvs.map((s) => ({ ...s, agentName: ag.name }));
          } catch { return [] as ServerWithAgent[]; }
        }),
      );
      setAllServers(serverResults.flat());
    } catch (err) {
      toast.error(errMessage(err, 'Couldn’t load domains.'));
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const getZoneName = (zoneId: string) => zones.find((z) => z.id === zoneId)?.name ?? '';
  const getServerInfo = (serverId: string) => allServers.find((s) => s.id === serverId);

  const filtered = domains.filter((d) => {
    if (statusFilter !== 'all' && d.status !== statusFilter) return false;
    if (agentFilter !== 'all') {
      const srv = getServerInfo(d.server_id);
      if (!srv || srv.agent_id !== agentFilter) return false;
    }
    return true;
  });

  async function handleCreate() {
    if (!createZone) { setCreateError('Please select a DNS zone.'); return; }
    setCreateLoading(true);
    setCreateError('');
    try {
      await api.createDomain({
        subdomain: createSub, zone_id: createZone, server_id: createServer,
        port: parseInt(createPort, 10), websocket: createWebsocket, force_https: createForceHttps,
      });
      toast.success(`${createSub}.${getZoneName(createZone)} created.`);
      setShowCreate(false);
      setCreateSub(''); setCreateZone(''); setCreateServer(''); setCreatePort('80');
      setCreateWebsocket(false); setCreateForceHttps(true);
      fetchData();
    } catch (err) {
      setCreateError(errMessage(err, 'Failed to create domain.'));
    } finally {
      setCreateLoading(false);
    }
  }

  function openDetail(d: Domain) {
    setDetailDomain(d);
    setEditTab('general');
    setEditWebsocket(d.websocket || d.proxy_config?.websocket || false);
    setEditForceHttps(d.force_https || d.proxy_config?.force_https || false);
    setEditMaxBody(d.proxy_config?.max_body_size ?? '');
    setEditHeaders(d.proxy_config?.custom_request_headers
      ? Object.entries(d.proxy_config.custom_request_headers).map(([key, value]) => ({ key, value }))
      : []);
    setEditRawConfig('');
    setAdvancedError('');
  }

  async function handleSaveDetail() {
    if (!detailDomain) return;
    setEditLoading(true);
    try {
      const customHeaders: Record<string, string> = {};
      for (const h of editHeaders) if (h.key.trim()) customHeaders[h.key.trim()] = h.value;
      await api.updateDomain(detailDomain.id, {
        websocket: editWebsocket, force_https: editForceHttps,
        proxy_config: {
          websocket: editWebsocket, force_https: editForceHttps,
          max_body_size: editMaxBody || undefined,
          custom_request_headers: Object.keys(customHeaders).length > 0 ? customHeaders : undefined,
        },
      });
      toast.success('Domain updated.');
      setDetailDomain(null);
      fetchData();
    } catch (err) {
      toast.error(errMessage(err, 'Failed to save domain.'));
    } finally {
      setEditLoading(false);
    }
  }

  async function openAdvanced() {
    if (!detailDomain) return;
    setEditTab('advanced');
    setAdvancedError('');
    try {
      const cfg = await api.getDomainConfig(detailDomain.id);
      setEditRawConfig(JSON.stringify(cfg.config, null, 2));
    } catch (err) {
      setAdvancedError(errMessage(err, 'Failed to load config.'));
    }
  }

  async function handleSaveAdvanced() {
    if (!detailDomain) return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(editRawConfig);
    } catch (e) {
      setAdvancedError(`Invalid JSON: ${e instanceof Error ? e.message : 'could not parse'}`);
      return;
    }
    setAdvancedError('');
    setEditLoading(true);
    try {
      await api.updateDomainConfig(detailDomain.id, parsed);
      toast.success('Manual config saved.');
      setDetailDomain(null);
      fetchData();
    } catch (err) {
      setAdvancedError(errMessage(err, 'Failed to save config.'));
    } finally {
      setEditLoading(false);
    }
  }

  async function handleResetConfig() {
    if (!detailDomain) return;
    setEditLoading(true);
    try {
      await api.resetDomainConfig(detailDomain.id);
      toast.success('Config reset to automatic.');
      setDetailDomain(null);
      fetchData();
    } catch (err) {
      setAdvancedError(errMessage(err, 'Failed to reset config.'));
    } finally {
      setEditLoading(false);
    }
  }

  function removeDomain(d: Domain) {
    setDomains((prev) => prev.filter((x) => x.id !== d.id));
    setSelected((prev) => { const n = new Set(prev); n.delete(d.id); return n; });
    if (detailDomain?.id === d.id) setDetailDomain(null);
    undoableDelete({
      message: `Deleted ${d.subdomain}.${getZoneName(d.zone_id)}`,
      doDelete: async () => { await api.deleteDomain(d.id); },
      onUndo: () => setDomains((prev) => (prev.some((x) => x.id === d.id) ? prev : [...prev, d])),
      failMessage: 'Failed to delete domain.',
    });
  }

  function toggleSelected(id: number) {
    setSelected((prev) => { const n = new Set(prev); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  }

  async function handleBulkDelete() {
    const ids = [...selected];
    setBulkConfirm(false);
    setDomains((prev) => prev.filter((x) => !selected.has(x.id)));
    setSelected(new Set());
    let ok = 0, fail = 0;
    for (const id of ids) {
      try { await api.deleteDomain(id); ok++; } catch { fail++; }
    }
    if (fail === 0) toast.success(`Deleted ${ok} domain${ok !== 1 ? 's' : ''}.`);
    else { toast.error(`Deleted ${ok}, ${fail} failed.`); fetchData(); }
  }

  if (loading) return <div className="py-12 text-center text-sm text-fg-muted">Loading domains…</div>;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-3xl font-bold tracking-tight text-fg">Domains</h1>
          <p className="mt-1 text-sm text-fg-muted">Subdomains proxied to your servers.</p>
        </div>
        <Button onClick={() => { setShowCreate(true); setCreateError(''); }}>New domain</Button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex flex-wrap gap-1">
          {STATUS_FILTERS.map((s) => (
            <button key={s} onClick={() => setStatusFilter(s)}
              className={`rounded-full px-3 py-1 text-xs font-medium capitalize transition-colors ${
                statusFilter === s ? 'bg-accent text-accent-fg' : 'bg-surface-2 text-fg-muted hover:bg-surface-3 hover:text-fg'
              }`}>
              {s}
            </button>
          ))}
        </div>
        <Select value={agentFilter} onChange={(e) => setAgentFilter(e.target.value)} className="w-auto py-1.5 text-xs">
          <option value="all">All agents</option>
          {agents.filter((a) => a.status !== 'pending').map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
        </Select>
        {selected.size > 0 && (
          <div className="ml-auto flex items-center gap-3">
            <span className="text-xs text-fg-muted">{selected.size} selected</span>
            <Button variant="danger" size="sm" onClick={() => setBulkConfirm(true)}>Delete selected</Button>
            <button onClick={() => setSelected(new Set())} className="text-xs text-fg-faint hover:text-fg">Clear</button>
          </div>
        )}
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <EmptyState
          title={domains.length === 0 ? 'No domains yet' : 'No matches'}
          description={domains.length === 0 ? 'Create your first domain to start proxying traffic to a server.' : 'No domains match the current filters.'}
          action={domains.length === 0 ? <Button onClick={() => setShowCreate(true)}>Create domain</Button> : undefined}
        />
      ) : (
        <div className="overflow-x-auto rounded-xl border border-border bg-surface shadow-card">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-border text-xs uppercase tracking-wide text-fg-faint">
              <tr>
                <th className="w-10 px-4 py-3">
                  <input
                    type="checkbox"
                    aria-label="Select all domains"
                    className="h-4 w-4 accent-[var(--accent)]"
                    checked={filtered.length > 0 && filtered.every((d) => selected.has(d.id))}
                    onChange={(e) => setSelected(e.target.checked ? new Set(filtered.map((d) => d.id)) : new Set())}
                  />
                </th>
                <th className="px-4 py-3 font-semibold">Domain</th>
                <th className="px-4 py-3 font-semibold">Target</th>
                <th className="px-4 py-3 font-semibold">Agent</th>
                <th className="px-4 py-3 font-semibold">Status</th>
                <th className="px-4 py-3 font-semibold">Synced</th>
                <th className="px-4 py-3 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map((d) => {
                const zone = getZoneName(d.zone_id);
                const srv = getServerInfo(d.server_id);
                return (
                  <tr key={d.id} className={`transition-colors ${selected.has(d.id) ? 'bg-accent-soft/50' : 'hover:bg-surface-2'}`}>
                    <td className="px-4 py-3">
                      <input
                        type="checkbox"
                        aria-label={`Select ${d.subdomain}`}
                        className="h-4 w-4 accent-[var(--accent)]"
                        checked={selected.has(d.id)}
                        onChange={() => toggleSelected(d.id)}
                      />
                    </td>
                    <td className="px-4 py-3 font-medium text-fg">{zone ? `${d.subdomain}.${zone}` : d.subdomain}</td>
                    <td className="px-4 py-3 font-mono text-xs text-fg-muted">{srv ? `${srv.address}:${d.port}` : `:${d.port}`}</td>
                    <td className="px-4 py-3 text-fg-muted">{srv?.agentName ?? '—'}</td>
                    <td className="px-4 py-3"><StatusBadge status={d.status} /></td>
                    <td className="px-4 py-3 text-xs text-fg-faint">{seen(d.last_synced)}</td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-3">
                        <button onClick={() => openDetail(d)} className="text-xs font-medium text-accent hover:underline">Edit</button>
                        <button onClick={() => removeDomain(d)} className="text-xs font-medium text-danger-fg hover:underline">Delete</button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Create modal */}
      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Create domain">
        <div className="space-y-4">
          {createError && <Callout tone="danger">{createError}</Callout>}
          <Field label="Subdomain" hint={createSub && createZone ? `FQDN: ${createSub}.${getZoneName(createZone)}` : undefined}>
            <Input value={createSub} onChange={(e) => setCreateSub(e.target.value)} placeholder="app, blog, api…" />
          </Field>
          <Field label="Zone" help="zone">
            <Select value={createZone} onChange={(e) => setCreateZone(e.target.value)}>
              <option value="">Select a zone</option>
              {zones.map((z) => <option key={z.id} value={z.id}>{z.name}</option>)}
            </Select>
          </Field>
          <Field label="Server" help="server">
            <Select value={createServer} onChange={(e) => setCreateServer(e.target.value)}>
              <option value="">Select a server</option>
              {agents.filter((a) => a.status !== 'pending').map((a) => {
                const agentSrvs = allServers.filter((s) => s.agent_id === a.id);
                if (agentSrvs.length === 0) return null;
                return <optgroup key={a.id} label={a.name}>{agentSrvs.map((s) => <option key={s.id} value={s.id}>{s.name} ({s.address})</option>)}</optgroup>;
              })}
            </Select>
          </Field>
          <Field label="Port">
            <Input type="number" value={createPort} onChange={(e) => setCreatePort(e.target.value)} min={1} max={65535} />
          </Field>
          <div className="flex flex-wrap gap-6">
            <span className="flex items-center gap-1.5"><Checkbox label="WebSocket" checked={createWebsocket} onChange={(e) => setCreateWebsocket(e.target.checked)} /><HelpTip term="websocket" /></span>
            <span className="flex items-center gap-1.5"><Checkbox label="Force HTTPS" checked={createForceHttps} onChange={(e) => setCreateForceHttps(e.target.checked)} /><HelpTip term="force-https" /></span>
          </div>
          <div className="flex justify-end gap-3 pt-1">
            <Button variant="secondary" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button onClick={handleCreate} loading={createLoading} disabled={!createSub || !createZone || !createServer}>Create</Button>
          </div>
        </div>
      </Modal>

      {/* Detail / edit modal — tabbed */}
      <Modal open={detailDomain !== null} onClose={() => setDetailDomain(null)} title="Domain settings" description={detailDomain ? `${detailDomain.subdomain}.${getZoneName(detailDomain.zone_id)}` : undefined} wide>
        {detailDomain && (
          <div className="space-y-5">
            <div className="flex flex-wrap items-center gap-3">
              <StatusBadge status={detailDomain.status} />
              <span className="text-xs text-fg-faint">Last synced {seen(detailDomain.last_synced)}</span>
              {detailDomain.dns_record_id && <span className="truncate font-mono text-xs text-fg-faint">DNS {detailDomain.dns_record_id}</span>}
            </div>

            {detailDomain.error_msg && <Callout tone="danger">{detailDomain.error_msg}</Callout>}

            {/* Tabs */}
            <div className="flex gap-1 border-b border-border">
              {(['general', 'headers', 'advanced'] as EditTab[]).map((t) => (
                <button key={t} onClick={() => (t === 'advanced' ? openAdvanced() : setEditTab(t))}
                  className={`-mb-px border-b-2 px-3 py-2 text-sm font-medium capitalize transition-colors ${
                    editTab === t ? 'border-accent text-accent' : 'border-transparent text-fg-muted hover:text-fg'
                  }`}>
                  {t === 'advanced' ? 'Advanced' : t}
                </button>
              ))}
            </div>

            {editTab === 'general' && (
              <div className="space-y-4">
                <div className="flex flex-wrap gap-6">
                  <span className="flex items-center gap-1.5"><Checkbox label="WebSocket" checked={editWebsocket} onChange={(e) => setEditWebsocket(e.target.checked)} /><HelpTip term="websocket" /></span>
                  <span className="flex items-center gap-1.5"><Checkbox label="Force HTTPS" checked={editForceHttps} onChange={(e) => setEditForceHttps(e.target.checked)} /><HelpTip term="force-https" /></span>
                </div>
                <Field label="Max body size" help="max-body-size" hint="Leave blank for the default.">
                  <Input value={editMaxBody} onChange={(e) => setEditMaxBody(e.target.value)} placeholder="e.g. 100mb" />
                </Field>
                <div className="flex justify-end gap-3 pt-1">
                  <Button variant="danger-ghost" onClick={() => removeDomain(detailDomain)}>Delete</Button>
                  <Button onClick={handleSaveDetail} loading={editLoading}>Save</Button>
                </div>
              </div>
            )}

            {editTab === 'headers' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <p className="text-sm font-medium text-fg">Custom request headers</p>
                  <button onClick={() => setEditHeaders([...editHeaders, { key: '', value: '' }])} className="text-xs font-medium text-accent hover:underline">+ Add header</button>
                </div>
                {editHeaders.length === 0 && <p className="text-sm text-fg-faint">No custom headers.</p>}
                {editHeaders.map((h, i) => (
                  <div key={i} className="flex gap-2">
                    <Input value={h.key} onChange={(e) => { const n = [...editHeaders]; n[i] = { ...n[i], key: e.target.value }; setEditHeaders(n); }} placeholder="Header name" />
                    <Input value={h.value} onChange={(e) => { const n = [...editHeaders]; n[i] = { ...n[i], value: e.target.value }; setEditHeaders(n); }} placeholder="Value" />
                    <button onClick={() => setEditHeaders(editHeaders.filter((_, j) => j !== i))} aria-label="Remove header" className="flex-shrink-0 rounded-lg px-2 text-fg-faint hover:text-danger-fg">
                      <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" /></svg>
                    </button>
                  </div>
                ))}
                <div className="flex justify-end pt-1">
                  <Button onClick={handleSaveDetail} loading={editLoading}>Save</Button>
                </div>
              </div>
            )}

            {editTab === 'advanced' && (
              <div className="space-y-4">
                <Callout tone="warning" title="Manual config">
                  Editing the raw Caddy JSON overrides the automatic config for this domain. Reset to automatic anytime.
                </Callout>
                {advancedError && <Callout tone="danger">{advancedError}</Callout>}
                <Textarea value={editRawConfig} onChange={(e) => { setEditRawConfig(e.target.value); setAdvancedError(''); }} rows={14} className="font-mono text-xs" spellCheck={false} />
                <div className="flex justify-between">
                  <Button variant="secondary" onClick={handleResetConfig} loading={editLoading}>Reset to automatic</Button>
                  <Button onClick={handleSaveAdvanced} loading={editLoading}>Save manual config</Button>
                </div>
              </div>
            )}
          </div>
        )}
      </Modal>

      <ConfirmDialog
        open={bulkConfirm}
        onClose={() => setBulkConfirm(false)}
        onConfirm={handleBulkDelete}
        title="Delete domains"
        message={`Delete ${selected.size} domain${selected.size !== 1 ? 's' : ''}? Their DNS records and proxy configs will be removed.`}
        confirmLabel={`Delete ${selected.size}`}
        danger
      />
    </div>
  );
}

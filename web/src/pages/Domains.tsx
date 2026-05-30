import { useState, useEffect, useCallback } from 'react';
import i18n from '../lib/i18n';
import { useTranslation } from 'react-i18next';
import { X } from 'lucide-react';
import { api } from '../lib/api';
import type { Domain, Agent, Server, Zone, ProxyCapabilities } from '../lib/types';
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
  return date ? formatRelativeTime(date) : i18n.t('time.never');
}

interface ServerWithAgent extends Server {
  agentName: string;
}

type EditTab = 'general' | 'headers' | 'advanced';
const STATUS_FILTERS = ['all', 'active', 'pending', 'error', 'deleting'];

export default function Domains() {
  const { t } = useTranslation();
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
  const [editConfigBackend, setEditConfigBackend] = useState('caddy');
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
      toast.error(errMessage(err, t('domains.loadFailed')));
    } finally {
      setLoading(false);
    }
  }, [toast, t]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const getZoneName = (zoneId: string) => zones.find((z) => z.id === zoneId)?.name ?? '';
  const getServerInfo = (serverId: string) => allServers.find((s) => s.id === serverId);

  // Resolve the agent that will serve a domain (via its server) so the edit form
  // can grey out options the agent's selected backend can't honor (§8). Returns
  // undefined when the agent is unknown or hasn't reported its capability matrix
  // yet — in which case every option stays enabled (no false negatives).
  const getAgentForDomain = (d: Domain): Agent | undefined => {
    const srv = getServerInfo(d.server_id);
    if (!srv) return undefined;
    return agents.find((a) => a.id === srv.agent_id);
  };
  const detailAgent = detailDomain ? getAgentForDomain(detailDomain) : undefined;
  const caps = detailAgent?.proxy_capabilities;
  // A capability is "supported" unless the agent reported it false. With no
  // reported matrix we leave everything enabled.
  const supports = (key: keyof ProxyCapabilities) => !caps || caps[key];
  const backendName = detailAgent?.proxy_capabilities
    ? detailAgent.proxy_detection?.kind ?? t('domains.capBackendGeneric')
    : '';
  const unsupportedHint = (key: keyof ProxyCapabilities) =>
    supports(key) ? undefined : t('domains.capUnsupported', { backend: backendName });

  const filtered = domains.filter((d) => {
    if (statusFilter !== 'all' && d.status !== statusFilter) return false;
    if (agentFilter !== 'all') {
      const srv = getServerInfo(d.server_id);
      if (!srv || srv.agent_id !== agentFilter) return false;
    }
    return true;
  });

  async function handleCreate() {
    if (!createZone) { setCreateError(t('domains.selectDnsZone')); return; }
    setCreateLoading(true);
    setCreateError('');
    try {
      await api.createDomain({
        subdomain: createSub, zone_id: createZone, server_id: createServer,
        port: parseInt(createPort, 10), websocket: createWebsocket, force_https: createForceHttps,
      });
      toast.success(t('domains.created', { fqdn: `${createSub}.${getZoneName(createZone)}` }));
      setShowCreate(false);
      setCreateSub(''); setCreateZone(''); setCreateServer(''); setCreatePort('80');
      setCreateWebsocket(false); setCreateForceHttps(true);
      fetchData();
    } catch (err) {
      setCreateError(errMessage(err, t('domains.createFailed')));
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
    setEditConfigBackend('caddy');
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
      toast.success(t('domains.updated'));
      setDetailDomain(null);
      fetchData();
    } catch (err) {
      toast.error(errMessage(err, t('domains.saveFailed')));
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
      const backend = cfg.backend || 'caddy';
      setEditConfigBackend(backend);
      // Caddy config is a JSON object; nginx/apache configs are native text.
      setEditRawConfig(
        typeof cfg.config === 'string' ? cfg.config : JSON.stringify(cfg.config, null, 2),
      );
    } catch (err) {
      setAdvancedError(errMessage(err, t('domains.loadConfigFailed')));
    }
  }

  async function handleSaveAdvanced() {
    if (!detailDomain) return;
    let payload: unknown;
    if (editConfigBackend === 'caddy') {
      try {
        payload = JSON.parse(editRawConfig);
      } catch (e) {
        setAdvancedError(t('domains.invalidJson', { msg: e instanceof Error ? e.message : 'could not parse' }));
        return;
      }
    } else {
      // nginx/apache: the override is native config text, sent as a JSON string.
      payload = editRawConfig;
    }
    setAdvancedError('');
    setEditLoading(true);
    try {
      await api.updateDomainConfig(detailDomain.id, payload);
      toast.success(t('domains.manualSaved'));
      setDetailDomain(null);
      fetchData();
    } catch (err) {
      setAdvancedError(errMessage(err, t('domains.saveConfigFailed')));
    } finally {
      setEditLoading(false);
    }
  }

  async function handleResetConfig() {
    if (!detailDomain) return;
    setEditLoading(true);
    try {
      await api.resetDomainConfig(detailDomain.id);
      toast.success(t('domains.configReset'));
      setDetailDomain(null);
      fetchData();
    } catch (err) {
      setAdvancedError(errMessage(err, t('domains.resetFailed')));
    } finally {
      setEditLoading(false);
    }
  }

  function removeDomain(d: Domain) {
    setDomains((prev) => prev.filter((x) => x.id !== d.id));
    setSelected((prev) => { const n = new Set(prev); n.delete(d.id); return n; });
    if (detailDomain?.id === d.id) setDetailDomain(null);
    undoableDelete({
      message: t('domains.deleted', { fqdn: `${d.subdomain}.${getZoneName(d.zone_id)}` }),
      doDelete: async () => { await api.deleteDomain(d.id); },
      onUndo: () => setDomains((prev) => (prev.some((x) => x.id === d.id) ? prev : [...prev, d])),
      failMessage: t('domains.deleteFailed'),
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
    if (fail === 0) toast.success(t('domains.bulkDone', { count: ok }));
    else { toast.error(t('domains.bulkPartial', { ok, fail })); fetchData(); }
  }

  if (loading) return <div className="py-12 text-center text-sm text-fg-muted">{t('common.loading')}</div>;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-3xl font-bold tracking-tight text-fg">{t('domains.title')}</h1>
          <p className="mt-1 text-sm text-fg-muted">{t('domains.subtitle')}</p>
        </div>
        <Button onClick={() => { setShowCreate(true); setCreateError(''); }}>{t('domains.newDomain')}</Button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex flex-wrap gap-1">
          {STATUS_FILTERS.map((s) => (
            <button key={s} onClick={() => setStatusFilter(s)}
              className={`rounded-full px-3 py-1 text-xs font-medium capitalize transition-colors ${
                statusFilter === s ? 'bg-accent text-accent-fg' : 'bg-surface-2 text-fg-muted hover:bg-surface-3 hover:text-fg'
              }`}>
              {s === 'all' ? t('domains.filterAll') : t('status.' + s)}
            </button>
          ))}
        </div>
        <Select value={agentFilter} onChange={(e) => setAgentFilter(e.target.value)} className="w-auto py-1.5 text-xs">
          <option value="all">{t('domains.allAgents')}</option>
          {agents.filter((a) => a.status !== 'pending').map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
        </Select>
        {selected.size > 0 && (
          <div className="ml-auto flex items-center gap-3">
            <span className="text-xs text-fg-muted">{t('domains.selected', { count: selected.size })}</span>
            <Button variant="danger" size="sm" onClick={() => setBulkConfirm(true)}>{t('domains.deleteSelected')}</Button>
            <button onClick={() => setSelected(new Set())} className="text-xs text-fg-faint hover:text-fg">{t('common.clear')}</button>
          </div>
        )}
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <EmptyState
          title={domains.length === 0 ? t('domains.noneYet') : t('domains.noMatches')}
          description={domains.length === 0 ? t('domains.noneYetBody') : t('domains.noMatchesBody')}
          action={domains.length === 0 ? <Button onClick={() => setShowCreate(true)}>{t('domains.createDomain')}</Button> : undefined}
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
                <th className="px-4 py-3 font-semibold">{t('domains.colDomain')}</th>
                <th className="px-4 py-3 font-semibold">{t('domains.colTarget')}</th>
                <th className="px-4 py-3 font-semibold">{t('domains.colAgent')}</th>
                <th className="px-4 py-3 font-semibold">{t('domains.colStatus')}</th>
                <th className="px-4 py-3 font-semibold">{t('domains.colSynced')}</th>
                <th className="px-4 py-3 font-semibold text-right">{t('domains.colActions')}</th>
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
                        <button onClick={() => openDetail(d)} className="text-xs font-medium text-accent hover:underline">{t('domains.edit')}</button>
                        <button onClick={() => removeDomain(d)} className="text-xs font-medium text-danger-fg hover:underline">{t('common.delete')}</button>
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
      <Modal open={showCreate} onClose={() => setShowCreate(false)} title={t('domains.createTitle')}>
        <div className="space-y-4">
          {createError && <Callout tone="danger">{createError}</Callout>}
          <Field label={t('domains.subdomain')} hint={createSub && createZone ? t('domains.fqdnPreview', { fqdn: `${createSub}.${getZoneName(createZone)}` }) : undefined}>
            <Input value={createSub} onChange={(e) => setCreateSub(e.target.value)} placeholder={t('domains.subdomainPh')} />
          </Field>
          <Field label={t('domains.zone')} help="zone">
            <Select value={createZone} onChange={(e) => setCreateZone(e.target.value)}>
              <option value="">{t('domains.selectZone')}</option>
              {zones.map((z) => <option key={z.id} value={z.id}>{z.name}</option>)}
            </Select>
          </Field>
          <Field label={t('domains.server')} help="server">
            <Select value={createServer} onChange={(e) => setCreateServer(e.target.value)}>
              <option value="">{t('domains.selectServer')}</option>
              {agents.filter((a) => a.status !== 'pending').map((a) => {
                const agentSrvs = allServers.filter((s) => s.agent_id === a.id);
                if (agentSrvs.length === 0) return null;
                return <optgroup key={a.id} label={a.name}>{agentSrvs.map((s) => <option key={s.id} value={s.id}>{s.name} ({s.address})</option>)}</optgroup>;
              })}
            </Select>
          </Field>
          <Field label={t('domains.port')}>
            <Input type="number" value={createPort} onChange={(e) => setCreatePort(e.target.value)} min={1} max={65535} />
          </Field>
          <div className="flex flex-wrap gap-6">
            <span className="flex items-center gap-1.5"><Checkbox label={t('domains.websocket')} checked={createWebsocket} onChange={(e) => setCreateWebsocket(e.target.checked)} /><HelpTip term="websocket" /></span>
            <span className="flex items-center gap-1.5"><Checkbox label={t('domains.forceHttps')} checked={createForceHttps} onChange={(e) => setCreateForceHttps(e.target.checked)} /><HelpTip term="force-https" /></span>
          </div>
          <div className="flex justify-end gap-3 pt-1">
            <Button variant="secondary" onClick={() => setShowCreate(false)}>{t('common.cancel')}</Button>
            <Button onClick={handleCreate} loading={createLoading} disabled={!createSub || !createZone || !createServer}>{t('domains.create')}</Button>
          </div>
        </div>
      </Modal>

      {/* Detail / edit modal — tabbed */}
      <Modal open={detailDomain !== null} onClose={() => setDetailDomain(null)} title={t('domains.settingsTitle')} description={detailDomain ? `${detailDomain.subdomain}.${getZoneName(detailDomain.zone_id)}` : undefined} wide>
        {detailDomain && (
          <div className="space-y-5">
            <div className="flex flex-wrap items-center gap-3">
              <StatusBadge status={detailDomain.status} />
              <span className="text-xs text-fg-faint">{t('domains.lastSynced', { time: seen(detailDomain.last_synced) })}</span>
              {detailDomain.dns_record_id && <span className="truncate font-mono text-xs text-fg-faint">{t('domains.dns', { id: detailDomain.dns_record_id })}</span>}
            </div>

            {detailDomain.error_msg && <Callout tone="danger">{detailDomain.error_msg}</Callout>}

            {/* Tabs */}
            <div className="flex gap-1 border-b border-border">
              {(['general', 'headers', 'advanced'] as EditTab[]).map((tab) => (
                <button key={tab} onClick={() => (tab === 'advanced' ? openAdvanced() : setEditTab(tab))}
                  className={`-mb-px border-b-2 px-3 py-2 text-sm font-medium capitalize transition-colors ${
                    editTab === tab ? 'border-accent text-accent' : 'border-transparent text-fg-muted hover:text-fg'
                  }`}>
                  {tab === 'general' ? t('domains.tabGeneral') : tab === 'headers' ? t('domains.tabHeaders') : t('domains.tabAdvanced')}
                </button>
              ))}
            </div>

            {editTab === 'general' && (
              <div className="space-y-4">
                <div className="flex flex-wrap gap-6">
                  <span className="flex items-center gap-1.5" title={unsupportedHint('websocket')}><Checkbox label={t('domains.websocket')} checked={editWebsocket} disabled={!supports('websocket')} onChange={(e) => setEditWebsocket(e.target.checked)} /><HelpTip term="websocket" /></span>
                  <span className="flex items-center gap-1.5" title={unsupportedHint('force_https')}><Checkbox label={t('domains.forceHttps')} checked={editForceHttps} disabled={!supports('force_https')} onChange={(e) => setEditForceHttps(e.target.checked)} /><HelpTip term="force-https" /></span>
                </div>
                <Field label={t('domains.maxBodySize')} help="max-body-size" hint={supports('reverse_proxy') ? t('domains.maxBodyHint') : unsupportedHint('reverse_proxy')}>
                  <Input value={editMaxBody} onChange={(e) => setEditMaxBody(e.target.value)} placeholder={t('domains.maxBodyPh')} />
                </Field>
                <div className="flex justify-end gap-3 pt-1">
                  <Button variant="danger-ghost" onClick={() => removeDomain(detailDomain)}>{t('common.delete')}</Button>
                  <Button onClick={handleSaveDetail} loading={editLoading}>{t('common.save')}</Button>
                </div>
              </div>
            )}

            {editTab === 'headers' && (
              <div className="space-y-4">
                {!supports('custom_headers') && (
                  <Callout tone="warning">{unsupportedHint('custom_headers')}</Callout>
                )}
                <div className="flex items-center justify-between">
                  <p className="text-sm font-medium text-fg">{t('domains.customHeaders')}</p>
                  <button onClick={() => setEditHeaders([...editHeaders, { key: '', value: '' }])} disabled={!supports('custom_headers')} className="text-xs font-medium text-accent hover:underline disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:no-underline">{t('domains.addHeader')}</button>
                </div>
                {editHeaders.length === 0 && <p className="text-sm text-fg-faint">{t('domains.noHeaders')}</p>}
                {editHeaders.map((h, i) => (
                  <div key={i} className="flex gap-2">
                    <Input value={h.key} disabled={!supports('custom_headers')} onChange={(e) => { const n = [...editHeaders]; n[i] = { ...n[i], key: e.target.value }; setEditHeaders(n); }} placeholder={t('domains.headerName')} />
                    <Input value={h.value} disabled={!supports('custom_headers')} onChange={(e) => { const n = [...editHeaders]; n[i] = { ...n[i], value: e.target.value }; setEditHeaders(n); }} placeholder={t('domains.headerValue')} />
                    <button onClick={() => setEditHeaders(editHeaders.filter((_, j) => j !== i))} aria-label="Remove header" className="flex-shrink-0 rounded-lg px-2 text-fg-faint hover:text-danger-fg">
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                ))}
                <div className="flex justify-end pt-1">
                  <Button onClick={handleSaveDetail} loading={editLoading}>{t('common.save')}</Button>
                </div>
              </div>
            )}

            {editTab === 'advanced' && (
              <div className="space-y-4">
                <Callout tone="warning" title={t('domains.manualConfig')}>
                  {t('domains.manualConfigBody')}
                </Callout>
                {advancedError && <Callout tone="danger">{advancedError}</Callout>}
                <p className="text-xs text-fg-faint">
                  {t('domains.configBackend', { backend: editConfigBackend })}
                </p>
                <Textarea value={editRawConfig} onChange={(e) => { setEditRawConfig(e.target.value); setAdvancedError(''); }} rows={14} className="font-mono text-xs" spellCheck={false} />
                <div className="flex justify-between">
                  <Button variant="secondary" onClick={handleResetConfig} loading={editLoading}>{t('domains.resetAuto')}</Button>
                  <Button onClick={handleSaveAdvanced} loading={editLoading}>{t('domains.saveManual')}</Button>
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
        title={t('domains.bulkTitle')}
        message={t('domains.bulkMsg', { count: selected.size })}
        confirmLabel={t('domains.bulkConfirm', { count: selected.size })}
        danger
      />
    </div>
  );
}

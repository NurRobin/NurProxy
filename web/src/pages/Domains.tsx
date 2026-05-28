import { useState, useEffect, useCallback } from 'react';
import { api } from '../lib/api';
import type { Domain, Agent, Server, Provider } from '../lib/types';
import StatusBadge from '../components/StatusBadge';
import Modal from '../components/Modal';
import ConfirmDialog from '../components/ConfirmDialog';
import EmptyState from '../components/EmptyState';

function timeAgo(dateStr: string | undefined): string {
  if (!dateStr) return 'Never';
  const diff = Date.now() - new Date(dateStr).getTime();
  const secs = Math.floor(diff / 1000);
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

interface ServerWithAgent extends Server {
  agentName: string;
}

export default function Domains() {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [providers, setProviders] = useState<Provider[]>([]);
  const [allServers, setAllServers] = useState<ServerWithAgent[]>([]);
  const [loading, setLoading] = useState(true);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [agentFilter, setAgentFilter] = useState<string>('all');

  // Create modal
  const [showCreate, setShowCreate] = useState(false);
  const [createSub, setCreateSub] = useState('');
  const [createServer, setCreateServer] = useState('');
  const [createPort, setCreatePort] = useState('80');
  const [createWebsocket, setCreateWebsocket] = useState(false);
  const [createForceHttps, setCreateForceHttps] = useState(true);
  const [createLoading, setCreateLoading] = useState(false);
  const [createError, setCreateError] = useState('');

  // Detail / edit
  const [detailDomain, setDetailDomain] = useState<Domain | null>(null);
  const [editWebsocket, setEditWebsocket] = useState(false);
  const [editForceHttps, setEditForceHttps] = useState(true);
  const [editMaxBody, setEditMaxBody] = useState('');
  const [editHeaders, setEditHeaders] = useState<Array<{ key: string; value: string }>>([]);
  const [editRawConfig, setEditRawConfig] = useState('');
  const [editShowAdvanced, setEditShowAdvanced] = useState(false);
  const [editLoading, setEditLoading] = useState(false);

  // Delete
  const [deleteDomain, setDeleteDomain] = useState<Domain | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const [d, a, p] = await Promise.all([
        api.listDomains(),
        api.listAgents(),
        api.listProviders(),
      ]);
      setDomains(d);
      setAgents(a);
      setProviders(p);

      // Load servers for all adopted agents
      const adopted = a.filter((ag) => ag.status === 'adopted' || ag.status === 'offline');
      const serverResults = await Promise.all(
        adopted.map(async (ag) => {
          try {
            const srvs = await api.listServers(ag.id);
            return srvs.map((s) => ({ ...s, agentName: ag.name }));
          } catch {
            return [] as ServerWithAgent[];
          }
        })
      );
      setAllServers(serverResults.flat());
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  function getProviderZone(providerId: string): string {
    const p = providers.find((pr) => pr.id === providerId);
    return p?.zone_name ?? '';
  }

  function getServerInfo(serverId: string): ServerWithAgent | undefined {
    return allServers.find((s) => s.id === serverId);
  }

  const filtered = domains.filter((d) => {
    if (statusFilter !== 'all' && d.status !== statusFilter) return false;
    if (agentFilter !== 'all') {
      const srv = getServerInfo(d.server_id);
      if (!srv) return false;
      if (srv.agent_id !== agentFilter) return false;
    }
    return true;
  });

  async function handleCreate() {
    const srv = allServers.find((s) => s.id === createServer);
    if (!srv) return;
    // Find the provider — use the agent's provider or the default
    const agent = agents.find((a) => a.id === srv.agent_id);
    const providerId = agent?.provider_id || providers.find((p) => p.is_default)?.id || providers[0]?.id;
    if (!providerId) {
      setCreateError('No DNS provider available. Set up a provider in Settings first.');
      return;
    }

    setCreateLoading(true);
    setCreateError('');
    try {
      await api.createDomain({
        subdomain: createSub,
        provider_id: providerId,
        server_id: createServer,
        port: parseInt(createPort, 10),
        websocket: createWebsocket,
        force_https: createForceHttps,
      });
      setShowCreate(false);
      setCreateSub('');
      setCreateServer('');
      setCreatePort('80');
      setCreateWebsocket(false);
      setCreateForceHttps(true);
      fetchData();
    } catch (err) {
      setCreateError(err instanceof Error ? err.message : 'Failed to create domain');
    } finally {
      setCreateLoading(false);
    }
  }

  function openDetail(d: Domain) {
    setDetailDomain(d);
    setEditWebsocket(d.websocket || d.proxy_config?.websocket || false);
    setEditForceHttps(d.force_https || d.proxy_config?.force_https || false);
    setEditMaxBody(d.proxy_config?.max_body_size ?? '');
    const headers = d.proxy_config?.custom_request_headers
      ? Object.entries(d.proxy_config.custom_request_headers).map(([key, value]) => ({ key, value }))
      : [];
    setEditHeaders(headers);
    setEditRawConfig('');
    setEditShowAdvanced(false);
  }

  async function handleSaveDetail() {
    if (!detailDomain) return;
    setEditLoading(true);
    try {
      const customHeaders: Record<string, string> = {};
      for (const h of editHeaders) {
        if (h.key.trim()) customHeaders[h.key.trim()] = h.value;
      }
      await api.updateDomain(detailDomain.id, {
        websocket: editWebsocket,
        force_https: editForceHttps,
        proxy_config: {
          websocket: editWebsocket,
          force_https: editForceHttps,
          max_body_size: editMaxBody || undefined,
          custom_request_headers: Object.keys(customHeaders).length > 0 ? customHeaders : undefined,
        },
      });
      setDetailDomain(null);
      fetchData();
    } catch {
      // ignore
    } finally {
      setEditLoading(false);
    }
  }

  async function handleLoadAdvanced() {
    if (!detailDomain) return;
    try {
      const cfg = await api.getDomainConfig(detailDomain.id);
      setEditRawConfig(JSON.stringify(cfg.config, null, 2));
      setEditShowAdvanced(true);
    } catch {
      setEditRawConfig('Failed to load config');
      setEditShowAdvanced(true);
    }
  }

  async function handleSaveAdvanced() {
    if (!detailDomain) return;
    setEditLoading(true);
    try {
      const parsed = JSON.parse(editRawConfig);
      await api.updateDomainConfig(detailDomain.id, parsed);
      setDetailDomain(null);
      fetchData();
    } catch {
      // ignore
    } finally {
      setEditLoading(false);
    }
  }

  async function handleResetConfig() {
    if (!detailDomain) return;
    setEditLoading(true);
    try {
      await api.resetDomainConfig(detailDomain.id);
      setDetailDomain(null);
      fetchData();
    } catch {
      // ignore
    } finally {
      setEditLoading(false);
    }
  }

  async function handleDeleteDomain() {
    if (!deleteDomain) return;
    try {
      await api.deleteDomain(deleteDomain.id);
      setDeleteDomain(null);
      if (detailDomain?.id === deleteDomain.id) setDetailDomain(null);
      fetchData();
    } catch {
      // ignore
    }
  }

  if (loading) {
    return <div className="text-gray-400">Loading...</div>;
  }

  const statusFilters = ['all', 'active', 'pending', 'error', 'deleting'];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Domains</h1>
        <button
          onClick={() => {
            setShowCreate(true);
            setCreateError('');
          }}
          className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
        >
          New Domain
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex gap-1">
          {statusFilters.map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`rounded-full px-3 py-1 text-xs font-medium capitalize transition-colors ${
                statusFilter === s
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700 hover:text-gray-200'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
        <select
          value={agentFilter}
          onChange={(e) => setAgentFilter(e.target.value)}
          className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-gray-300 focus:border-blue-500 focus:outline-none"
        >
          <option value="all">All agents</option>
          {agents.filter((a) => a.status !== 'pending').map((a) => (
            <option key={a.id} value={a.id}>{a.name}</option>
          ))}
        </select>
      </div>

      {/* Domain table */}
      {filtered.length === 0 ? (
        <EmptyState
          title="No domains found"
          description={domains.length === 0 ? "Create your first domain to start proxying traffic." : "No domains match the current filters."}
          action={
            domains.length === 0 ? (
              <button
                onClick={() => setShowCreate(true)}
                className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
              >
                Create Domain
              </button>
            ) : undefined
          }
        />
      ) : (
        <div className="overflow-x-auto rounded-xl border border-gray-800">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-gray-800 bg-gray-900/80">
              <tr>
                <th className="px-4 py-3 font-medium text-gray-400">Subdomain</th>
                <th className="px-4 py-3 font-medium text-gray-400">FQDN</th>
                <th className="px-4 py-3 font-medium text-gray-400">Target</th>
                <th className="px-4 py-3 font-medium text-gray-400">Agent</th>
                <th className="px-4 py-3 font-medium text-gray-400">Status</th>
                <th className="px-4 py-3 font-medium text-gray-400">Synced</th>
                <th className="px-4 py-3 font-medium text-gray-400">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800 bg-gray-900">
              {filtered.map((d) => {
                const zone = getProviderZone(d.provider_id);
                const srv = getServerInfo(d.server_id);
                return (
                  <tr key={d.id} className="hover:bg-gray-800/50">
                    <td className="px-4 py-3 font-medium text-white">{d.subdomain}</td>
                    <td className="px-4 py-3 text-gray-300">{zone ? `${d.subdomain}.${zone}` : d.subdomain}</td>
                    <td className="px-4 py-3 text-gray-300">
                      {srv ? `${srv.address}:${d.port}` : `:${d.port}`}
                    </td>
                    <td className="px-4 py-3 text-gray-400">{srv?.agentName ?? '—'}</td>
                    <td className="px-4 py-3"><StatusBadge status={d.status} /></td>
                    <td className="px-4 py-3 text-gray-500 text-xs">{timeAgo(d.last_synced)}</td>
                    <td className="px-4 py-3">
                      <div className="flex gap-2">
                        <button
                          onClick={() => openDetail(d)}
                          className="text-xs text-blue-400 hover:text-blue-300"
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => setDeleteDomain(d)}
                          className="text-xs text-red-400 hover:text-red-300"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Create Domain Modal */}
      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Create Domain">
        <div className="space-y-4">
          {createError && (
            <div className="rounded-lg bg-red-900/30 border border-red-800 px-3 py-2 text-sm text-red-400">{createError}</div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-300">Subdomain</label>
            <input
              value={createSub}
              onChange={(e) => setCreateSub(e.target.value)}
              className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
              placeholder="e.g. app, blog, api"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300">Server</label>
            <select
              value={createServer}
              onChange={(e) => setCreateServer(e.target.value)}
              className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            >
              <option value="">Select a server</option>
              {agents
                .filter((a) => a.status !== 'pending')
                .map((a) => {
                  const agentSrvs = allServers.filter((s) => s.agent_id === a.id);
                  if (agentSrvs.length === 0) return null;
                  return (
                    <optgroup key={a.id} label={a.name}>
                      {agentSrvs.map((s) => (
                        <option key={s.id} value={s.id}>{s.name} ({s.address})</option>
                      ))}
                    </optgroup>
                  );
                })}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300">Port</label>
            <input
              type="number"
              value={createPort}
              onChange={(e) => setCreatePort(e.target.value)}
              min={1}
              max={65535}
              className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
            />
          </div>

          <div className="flex gap-6">
            <label className="flex items-center gap-2 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={createWebsocket}
                onChange={(e) => setCreateWebsocket(e.target.checked)}
                className="rounded border-gray-600 accent-blue-500"
              />
              WebSocket
            </label>
            <label className="flex items-center gap-2 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={createForceHttps}
                onChange={(e) => setCreateForceHttps(e.target.checked)}
                className="rounded border-gray-600 accent-blue-500"
              />
              Force HTTPS
            </label>
          </div>

          <div className="flex justify-end gap-3 pt-2">
            <button
              onClick={() => setShowCreate(false)}
              className="rounded-lg border border-gray-600 px-4 py-2 text-sm font-medium text-gray-300 hover:bg-gray-800"
            >
              Cancel
            </button>
            <button
              onClick={handleCreate}
              disabled={createLoading || !createSub || !createServer}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
            >
              {createLoading ? 'Creating...' : 'Create'}
            </button>
          </div>
        </div>
      </Modal>

      {/* Domain Detail Modal */}
      <Modal open={detailDomain !== null} onClose={() => setDetailDomain(null)} title="Domain Settings" wide>
        {detailDomain && (
          <div className="space-y-5">
            {/* Info */}
            <div className="flex items-center gap-3">
              <span className="text-lg font-medium text-white">{detailDomain.subdomain}.{getProviderZone(detailDomain.provider_id)}</span>
              <StatusBadge status={detailDomain.status} />
            </div>

            {detailDomain.error_msg && (
              <div className="rounded-lg bg-red-900/30 border border-red-800 px-3 py-2 text-sm text-red-400">
                {detailDomain.error_msg}
              </div>
            )}

            <div className="grid grid-cols-2 gap-3 text-sm">
              <div className="text-gray-500">Last synced</div>
              <div className="text-gray-300">{timeAgo(detailDomain.last_synced)}</div>
              {detailDomain.dns_record_id && (
                <>
                  <div className="text-gray-500">DNS Record ID</div>
                  <div className="truncate text-gray-300">{detailDomain.dns_record_id}</div>
                </>
              )}
            </div>

            {/* Simple config */}
            {!editShowAdvanced && (
              <div className="space-y-4">
                <h3 className="text-sm font-semibold text-gray-300">Proxy Settings</h3>
                <div className="flex gap-6">
                  <label className="flex items-center gap-2 text-sm text-gray-300">
                    <input
                      type="checkbox"
                      checked={editWebsocket}
                      onChange={(e) => setEditWebsocket(e.target.checked)}
                      className="accent-blue-500"
                    />
                    WebSocket
                  </label>
                  <label className="flex items-center gap-2 text-sm text-gray-300">
                    <input
                      type="checkbox"
                      checked={editForceHttps}
                      onChange={(e) => setEditForceHttps(e.target.checked)}
                      className="accent-blue-500"
                    />
                    Force HTTPS
                  </label>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300">Max Body Size</label>
                  <input
                    value={editMaxBody}
                    onChange={(e) => setEditMaxBody(e.target.value)}
                    className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
                    placeholder="e.g. 100mb"
                  />
                </div>

                {/* Custom headers */}
                <div>
                  <div className="flex items-center justify-between">
                    <label className="block text-sm font-medium text-gray-300">Custom Request Headers</label>
                    <button
                      onClick={() => setEditHeaders([...editHeaders, { key: '', value: '' }])}
                      className="text-xs text-blue-400 hover:text-blue-300"
                    >
                      + Add
                    </button>
                  </div>
                  {editHeaders.map((h, i) => (
                    <div key={i} className="mt-2 flex gap-2">
                      <input
                        value={h.key}
                        onChange={(e) => {
                          const next = [...editHeaders];
                          next[i] = { ...next[i], key: e.target.value };
                          setEditHeaders(next);
                        }}
                        className="block w-1/2 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
                        placeholder="Header name"
                      />
                      <input
                        value={h.value}
                        onChange={(e) => {
                          const next = [...editHeaders];
                          next[i] = { ...next[i], value: e.target.value };
                          setEditHeaders(next);
                        }}
                        className="block w-1/2 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
                        placeholder="Value"
                      />
                      <button
                        onClick={() => setEditHeaders(editHeaders.filter((_, j) => j !== i))}
                        className="text-xs text-red-400 hover:text-red-300"
                      >
                        Remove
                      </button>
                    </div>
                  ))}
                </div>

                <div className="flex justify-between pt-2">
                  <button
                    onClick={handleLoadAdvanced}
                    className="text-xs text-gray-400 hover:text-gray-200"
                  >
                    Show Advanced (raw Caddy config)
                  </button>
                  <div className="flex gap-3">
                    <button
                      onClick={() => setDeleteDomain(detailDomain)}
                      className="rounded-lg border border-red-800 px-3 py-1.5 text-sm text-red-400 hover:bg-red-900/30"
                    >
                      Delete
                    </button>
                    <button
                      onClick={handleSaveDetail}
                      disabled={editLoading}
                      className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
                    >
                      {editLoading ? 'Saving...' : 'Save'}
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Advanced config */}
            {editShowAdvanced && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-gray-300">Advanced Config (raw Caddy JSON)</h3>
                  <button
                    onClick={() => setEditShowAdvanced(false)}
                    className="text-xs text-gray-400 hover:text-gray-200"
                  >
                    Back to simple
                  </button>
                </div>
                <textarea
                  value={editRawConfig}
                  onChange={(e) => setEditRawConfig(e.target.value)}
                  rows={15}
                  className="block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 font-mono text-xs text-gray-200 focus:border-blue-500 focus:outline-none"
                />
                <div className="flex justify-between">
                  <button
                    onClick={handleResetConfig}
                    disabled={editLoading}
                    className="rounded-lg border border-gray-600 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-800"
                  >
                    Reset to Auto
                  </button>
                  <button
                    onClick={handleSaveAdvanced}
                    disabled={editLoading}
                    className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
                  >
                    {editLoading ? 'Saving...' : 'Save Manual Config'}
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </Modal>

      {/* Delete Confirm */}
      <ConfirmDialog
        open={deleteDomain !== null}
        onClose={() => setDeleteDomain(null)}
        onConfirm={handleDeleteDomain}
        title="Delete Domain"
        message={`Are you sure you want to delete "${deleteDomain?.subdomain}"? The DNS record and proxy configuration will be removed.`}
        confirmLabel="Delete"
        danger
      />
    </div>
  );
}

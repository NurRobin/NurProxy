import { useState, useEffect, useCallback } from 'react';
import { api } from '../lib/api';
import type { Agent, Zone, Server, Domain } from '../lib/types';
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

export default function Agents() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const [domains, setDomains] = useState<Domain[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [servers, setServers] = useState<Record<string, Server[]>>({});

  // Adopt modal state
  const [adoptAgent, setAdoptAgent] = useState<Agent | null>(null);
  const [adoptName, setAdoptName] = useState('');
  const [adoptZoneIds, setAdoptZoneIds] = useState<Set<string>>(new Set());
  const [adoptDnsMode, setAdoptDnsMode] = useState<'static' | 'ddns'>('static');
  const [adoptDdnsInterval, setAdoptDdnsInterval] = useState(60);
  const [adoptLoading, setAdoptLoading] = useState(false);

  // Delete confirm
  const [deleteAgent, setDeleteAgent] = useState<Agent | null>(null);
  const [deleteLoading, setDeleteLoading] = useState(false);

  // Server form
  const [serverFormAgent, setServerFormAgent] = useState<string | null>(null);
  const [serverName, setServerName] = useState('');
  const [serverAddress, setServerAddress] = useState('');
  const [serverNotes, setServerNotes] = useState('');
  const [serverLoading, setServerLoading] = useState(false);

  // Delete server confirm
  const [deleteServerId, setDeleteServerId] = useState<string | null>(null);

  const [error, setError] = useState('');

  const fetchData = useCallback(async () => {
    try {
      const [a, z, d] = await Promise.all([
        api.listAgents(),
        api.listAllZones(),
        api.listDomains(),
      ]);
      setAgents(a);
      setZones(z);
      setDomains(d);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const loadServers = useCallback(async (agentId: string) => {
    try {
      const s = await api.listServers(agentId);
      setServers((prev) => ({ ...prev, [agentId]: s }));
    } catch {
      // ignore
    }
  }, []);

  function toggleExpand(agentId: string) {
    if (expandedId === agentId) {
      setExpandedId(null);
    } else {
      setExpandedId(agentId);
      if (!servers[agentId]) {
        loadServers(agentId);
      }
    }
  }

  async function handleAdopt() {
    if (!adoptAgent) return;
    setAdoptLoading(true);
    setError('');
    try {
      await api.adoptAgent(adoptAgent.id, {
        name: adoptName || undefined,
        zone_ids: adoptZoneIds.size > 0 ? [...adoptZoneIds] : undefined,
        dns_mode: adoptDnsMode,
        ddns_interval: adoptDnsMode === 'ddns' ? adoptDdnsInterval : undefined,
      });
      setAdoptAgent(null);
      fetchData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to adopt agent');
    } finally {
      setAdoptLoading(false);
    }
  }

  async function handleReject(id: string) {
    try {
      await api.rejectAgent(id);
      fetchData();
    } catch {
      // ignore
    }
  }

  async function handleDelete() {
    if (!deleteAgent) return;
    setDeleteLoading(true);
    try {
      await api.deleteAgent(deleteAgent.id);
      setDeleteAgent(null);
      if (expandedId === deleteAgent.id) setExpandedId(null);
      fetchData();
    } catch {
      // ignore
    } finally {
      setDeleteLoading(false);
    }
  }

  async function handleCreateServer() {
    if (!serverFormAgent || !serverName || !serverAddress) return;
    setServerLoading(true);
    try {
      await api.createServer(serverFormAgent, {
        name: serverName,
        address: serverAddress,
        notes: serverNotes || undefined,
      });
      setServerFormAgent(null);
      setServerName('');
      setServerAddress('');
      setServerNotes('');
      loadServers(serverFormAgent);
    } catch {
      // ignore
    } finally {
      setServerLoading(false);
    }
  }

  async function handleDeleteServer() {
    if (!deleteServerId) return;
    try {
      await api.deleteServer(deleteServerId);
      // Reload servers for expanded agent
      if (expandedId) loadServers(expandedId);
      setDeleteServerId(null);
    } catch {
      // ignore
    }
  }

  const pendingAgents = agents.filter((a) => a.status === 'pending');
  const otherAgents = agents.filter((a) => a.status !== 'pending');

  if (loading) {
    return <div className="text-gray-400">Loading...</div>;
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-white">Agents</h1>

      {/* Pending agents banner */}
      {pendingAgents.length > 0 && (
        <div className="rounded-xl border border-yellow-600/40 bg-yellow-900/20 p-4">
          <h2 className="mb-3 text-sm font-semibold text-yellow-400">
            {pendingAgents.length} pending agent{pendingAgents.length !== 1 ? 's' : ''}
          </h2>
          <div className="space-y-3">
            {pendingAgents.map((agent) => (
              <div key={agent.id} className="flex items-center justify-between rounded-lg bg-gray-900/60 px-4 py-3">
                <div>
                  <p className="font-medium text-white">{agent.fqdn}</p>
                  <p className="text-xs text-gray-400">
                    {agent.public_ip && `IP: ${agent.public_ip}`}
                    {agent.version && ` | v${agent.version}`}
                  </p>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => {
                      setAdoptAgent(agent);
                      setAdoptName(agent.fqdn);
                      setAdoptZoneIds(new Set());
                      setAdoptDnsMode('static');
                      setAdoptDdnsInterval(60);
                      setError('');
                    }}
                    className="rounded-lg bg-green-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-green-700"
                  >
                    Adopt
                  </button>
                  <button
                    onClick={() => handleReject(agent.id)}
                    className="rounded-lg border border-gray-600 px-3 py-1.5 text-sm font-medium text-gray-300 hover:bg-gray-800"
                  >
                    Reject
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Agent list */}
      {otherAgents.length === 0 && pendingAgents.length === 0 ? (
        <EmptyState
          title="No agents registered"
          description="Install the NurProxy agent on your servers. They will appear here for adoption."
        />
      ) : (
        <div className="space-y-3">
          {otherAgents.map((agent) => {
            const expanded = expandedId === agent.id;
            const agentServers = servers[agent.id] ?? [];
            const agentDomains = domains.filter(
              (d) => agentServers.some((s) => s.id === d.server_id) && d.status !== 'deleting'
            );

            return (
              <div key={agent.id} className="rounded-xl border border-gray-800 bg-gray-900">
                {/* Header row */}
                <button
                  onClick={() => toggleExpand(agent.id)}
                  className="flex w-full items-center justify-between px-5 py-4 text-left"
                >
                  <div className="flex items-center gap-4">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="font-medium text-white">{agent.name}</p>
                        <StatusBadge status={agent.status} />
                      </div>
                      <p className="mt-0.5 text-sm text-gray-400">{agent.fqdn}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-6 text-xs text-gray-500">
                    {agent.public_ip && <span>{agent.public_ip}</span>}
                    <span>Seen: {timeAgo(agent.last_seen)}</span>
                    <span>{agentServers.length} server{agentServers.length !== 1 ? 's' : ''}</span>
                    <svg
                      className={`h-4 w-4 text-gray-500 transition-transform ${expanded ? 'rotate-180' : ''}`}
                      fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                    </svg>
                  </div>
                </button>

                {/* Expanded detail */}
                {expanded && (
                  <div className="border-t border-gray-800 px-5 py-4">
                    <div className="grid gap-6 sm:grid-cols-2">
                      {/* Info */}
                      <div className="space-y-3">
                        <h3 className="text-sm font-semibold text-gray-300">Details</h3>
                        <dl className="space-y-2 text-sm">
                          <div className="flex justify-between">
                            <dt className="text-gray-500">DNS Mode</dt>
                            <dd className="text-gray-200">{agent.dns_mode || 'static'}</dd>
                          </div>
                          {agent.dns_mode === 'ddns' && (
                            <div className="flex justify-between">
                              <dt className="text-gray-500">DDNS Interval</dt>
                              <dd className="text-gray-200">{agent.ddns_interval}s</dd>
                            </div>
                          )}
                          {agent.zones && agent.zones.length > 0 && (
                            <div className="flex justify-between">
                              <dt className="text-gray-500">Zones</dt>
                              <dd className="text-gray-200">{agent.zones.map(z => z.name).join(', ')}</dd>
                            </div>
                          )}
                          {agent.version && (
                            <div className="flex justify-between">
                              <dt className="text-gray-500">Version</dt>
                              <dd className="text-gray-200">{agent.version}</dd>
                            </div>
                          )}
                          <div className="flex justify-between">
                            <dt className="text-gray-500">ID</dt>
                            <dd className="truncate text-gray-200 max-w-[200px]" title={agent.id}>{agent.id}</dd>
                          </div>
                        </dl>
                        <button
                          onClick={() => setDeleteAgent(agent)}
                          className="mt-2 rounded-lg border border-red-800 px-3 py-1.5 text-xs font-medium text-red-400 hover:bg-red-900/30"
                        >
                          Delete Agent
                        </button>
                      </div>

                      {/* Servers */}
                      <div>
                        <div className="flex items-center justify-between">
                          <h3 className="text-sm font-semibold text-gray-300">Servers</h3>
                          <button
                            onClick={() => {
                              setServerFormAgent(agent.id);
                              setServerName('');
                              setServerAddress('');
                              setServerNotes('');
                            }}
                            className="text-xs text-blue-400 hover:text-blue-300"
                          >
                            + Add Server
                          </button>
                        </div>
                        {agentServers.length === 0 ? (
                          <p className="mt-2 text-sm text-gray-500">No servers yet</p>
                        ) : (
                          <div className="mt-2 space-y-2">
                            {agentServers.map((srv) => (
                              <div key={srv.id} className="flex items-center justify-between rounded-lg bg-gray-800 px-3 py-2">
                                <div>
                                  <p className="text-sm font-medium text-gray-200">{srv.name}</p>
                                  <p className="text-xs text-gray-500">{srv.address}</p>
                                </div>
                                <button
                                  onClick={() => setDeleteServerId(srv.id)}
                                  className="text-xs text-red-400 hover:text-red-300"
                                >
                                  Remove
                                </button>
                              </div>
                            ))}
                          </div>
                        )}

                        {/* Domains on this agent */}
                        {agentDomains.length > 0 && (
                          <div className="mt-4">
                            <h4 className="text-sm font-semibold text-gray-300">Domains</h4>
                            <div className="mt-2 space-y-1">
                              {agentDomains.map((d) => (
                                <div key={d.id} className="flex items-center justify-between text-sm">
                                  <span className="text-gray-300">{d.subdomain}</span>
                                  <StatusBadge status={d.status} />
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Adopt Modal */}
      <Modal open={adoptAgent !== null} onClose={() => setAdoptAgent(null)} title="Adopt Agent">
        {adoptAgent && (
          <div className="space-y-4">
            <p className="text-sm text-gray-400">
              Adopting <span className="font-medium text-white">{adoptAgent.fqdn}</span>
            </p>

            {error && (
              <div className="rounded-lg bg-red-900/30 border border-red-800 px-3 py-2 text-sm text-red-400">{error}</div>
            )}

            <div>
              <label className="block text-sm font-medium text-gray-300">Name</label>
              <input
                value={adoptName}
                onChange={(e) => setAdoptName(e.target.value)}
                className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
                placeholder="Agent display name"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300">DNS Zones</label>
              {zones.length === 0 ? (
                <p className="mt-1 text-sm text-gray-500">No zones available. Add a provider in Settings first.</p>
              ) : (
                <div className="mt-1 space-y-1 max-h-36 overflow-y-auto rounded-lg border border-gray-700 bg-gray-800 p-2">
                  {zones.map((z) => (
                    <label
                      key={z.id}
                      className={`flex items-center gap-3 rounded-md px-3 py-2 cursor-pointer transition-colors ${
                        adoptZoneIds.has(z.id) ? 'bg-blue-900/30' : 'hover:bg-gray-700/50'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={adoptZoneIds.has(z.id)}
                        onChange={() => {
                          setAdoptZoneIds(prev => {
                            const next = new Set(prev);
                            if (next.has(z.id)) next.delete(z.id);
                            else next.add(z.id);
                            return next;
                          });
                        }}
                        className="accent-blue-500 h-4 w-4"
                      />
                      <span className="text-sm text-white">{z.name}</span>
                    </label>
                  ))}
                </div>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300">DNS Mode</label>
              <div className="mt-1 flex gap-4">
                <label className="flex items-center gap-2 text-sm text-gray-300">
                  <input
                    type="radio"
                    checked={adoptDnsMode === 'static'}
                    onChange={() => setAdoptDnsMode('static')}
                    className="accent-blue-500"
                  />
                  Static
                </label>
                <label className="flex items-center gap-2 text-sm text-gray-300">
                  <input
                    type="radio"
                    checked={adoptDnsMode === 'ddns'}
                    onChange={() => setAdoptDnsMode('ddns')}
                    className="accent-blue-500"
                  />
                  DDNS
                </label>
              </div>
            </div>

            {adoptDnsMode === 'ddns' && (
              <div>
                <label className="block text-sm font-medium text-gray-300">
                  DDNS Interval: {adoptDdnsInterval}s
                </label>
                <input
                  type="range"
                  min={30}
                  max={600}
                  step={10}
                  value={adoptDdnsInterval}
                  onChange={(e) => setAdoptDdnsInterval(Number(e.target.value))}
                  className="mt-1 w-full accent-blue-500"
                />
                <div className="flex justify-between text-xs text-gray-500">
                  <span>30s</span>
                  <span>600s</span>
                </div>
              </div>
            )}

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setAdoptAgent(null)}
                className="rounded-lg border border-gray-600 px-4 py-2 text-sm font-medium text-gray-300 hover:bg-gray-800"
              >
                Cancel
              </button>
              <button
                onClick={handleAdopt}
                disabled={adoptLoading}
                className="rounded-lg bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-700 disabled:opacity-50"
              >
                {adoptLoading ? 'Adopting...' : 'Adopt'}
              </button>
            </div>
          </div>
        )}
      </Modal>

      {/* Add Server Modal */}
      <Modal open={serverFormAgent !== null} onClose={() => setServerFormAgent(null)} title="Add Server">
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300">Name</label>
            <input
              value={serverName}
              onChange={(e) => setServerName(e.target.value)}
              className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
              placeholder="e.g. Web Server"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300">Address</label>
            <input
              value={serverAddress}
              onChange={(e) => setServerAddress(e.target.value)}
              className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
              placeholder="e.g. 192.168.1.100 or hostname"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300">Notes (optional)</label>
            <input
              value={serverNotes}
              onChange={(e) => setServerNotes(e.target.value)}
              className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
              placeholder="Description"
            />
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <button
              onClick={() => setServerFormAgent(null)}
              className="rounded-lg border border-gray-600 px-4 py-2 text-sm font-medium text-gray-300 hover:bg-gray-800"
            >
              Cancel
            </button>
            <button
              onClick={handleCreateServer}
              disabled={serverLoading || !serverName || !serverAddress}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
            >
              {serverLoading ? 'Adding...' : 'Add Server'}
            </button>
          </div>
        </div>
      </Modal>

      {/* Delete Agent Confirm */}
      <ConfirmDialog
        open={deleteAgent !== null}
        onClose={() => setDeleteAgent(null)}
        onConfirm={handleDelete}
        title="Delete Agent"
        message={`Are you sure you want to delete "${deleteAgent?.name}"? This will also remove all servers and domains associated with this agent.`}
        confirmLabel="Delete"
        danger
        loading={deleteLoading}
      />

      {/* Delete Server Confirm */}
      <ConfirmDialog
        open={deleteServerId !== null}
        onClose={() => setDeleteServerId(null)}
        onConfirm={handleDeleteServer}
        title="Remove Server"
        message="Are you sure you want to remove this server? Domains using this server will be affected."
        confirmLabel="Remove"
        danger
      />
    </div>
  );
}

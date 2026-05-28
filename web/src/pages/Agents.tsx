import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';
import type { Agent, Zone, Server, Domain } from '../lib/types';
import { formatRelativeTime } from '../lib/utils';
import StatusBadge from '../components/StatusBadge';
import Modal from '../components/Modal';
import ConfirmDialog from '../components/ConfirmDialog';
import EmptyState from '../components/EmptyState';
import Button from '../components/Button';
import Callout from '../components/Callout';
import HelpTip from '../components/HelpTip';
import MultiSelect from '../components/MultiSelect';
import { Field, Input } from '../components/Field';
import { useToast, errMessage } from '../components/toast-context';

function seen(date?: string) {
  return date ? formatRelativeTime(date) : 'Never';
}

export default function Agents() {
  const toast = useToast();
  const [agents, setAgents] = useState<Agent[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const [domains, setDomains] = useState<Domain[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [servers, setServers] = useState<Record<string, Server[]>>({});

  const [adoptAgent, setAdoptAgent] = useState<Agent | null>(null);
  const [adoptName, setAdoptName] = useState('');
  const [adoptZoneIds, setAdoptZoneIds] = useState<Set<string>>(new Set());
  const [adoptDnsMode, setAdoptDnsMode] = useState<'static' | 'ddns'>('static');
  const [adoptDdnsInterval, setAdoptDdnsInterval] = useState(60);
  const [adoptLoading, setAdoptLoading] = useState(false);
  const [adoptError, setAdoptError] = useState('');

  const [deleteAgent, setDeleteAgent] = useState<Agent | null>(null);
  const [deleteLoading, setDeleteLoading] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const [a, z, d] = await Promise.all([api.listAgents(), api.listAllZones(), api.listDomains()]);
      setAgents(a); setZones(z); setDomains(d);
    } catch (err) {
      toast.error(errMessage(err, 'Couldn’t load agents.'));
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const loadServers = useCallback(async (agentId: string) => {
    try {
      const list = await api.listServers(agentId);
      setServers((prev) => ({ ...prev, [agentId]: list }));
    } catch (err) {
      toast.error(errMessage(err, 'Couldn’t load servers.'));
    }
  }, [toast]);

  function toggleExpand(agentId: string) {
    if (expandedId === agentId) { setExpandedId(null); return; }
    setExpandedId(agentId);
    if (!servers[agentId]) loadServers(agentId);
  }

  async function handleAdopt() {
    if (!adoptAgent) return;
    setAdoptLoading(true);
    setAdoptError('');
    try {
      await api.adoptAgent(adoptAgent.id, {
        name: adoptName || undefined,
        zone_ids: adoptZoneIds.size > 0 ? [...adoptZoneIds] : undefined,
        dns_mode: adoptDnsMode,
        ddns_interval: adoptDnsMode === 'ddns' ? adoptDdnsInterval : undefined,
      });
      toast.success(`${adoptName || adoptAgent.fqdn} adopted.`);
      setAdoptAgent(null);
      fetchData();
    } catch (err) {
      setAdoptError(errMessage(err, 'Failed to adopt agent.'));
    } finally {
      setAdoptLoading(false);
    }
  }

  async function handleReject(id: string) {
    try { await api.rejectAgent(id); toast.success('Agent rejected.'); fetchData(); }
    catch (err) { toast.error(errMessage(err, 'Failed to reject agent.')); }
  }

  async function handleDelete() {
    if (!deleteAgent) return;
    setDeleteLoading(true);
    try {
      await api.deleteAgent(deleteAgent.id);
      toast.success('Agent deleted.');
      if (expandedId === deleteAgent.id) setExpandedId(null);
      setDeleteAgent(null);
      fetchData();
    } catch (err) {
      toast.error(errMessage(err, 'Failed to delete agent.'));
    } finally {
      setDeleteLoading(false);
    }
  }

  const pendingAgents = agents.filter((a) => a.status === 'pending');
  const otherAgents = agents.filter((a) => a.status !== 'pending');

  if (loading) return <div className="py-12 text-center text-sm text-fg-muted">Loading agents…</div>;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-display text-3xl font-bold tracking-tight text-fg">Agents</h1>
        <p className="mt-1 flex items-center gap-1.5 text-sm text-fg-muted">
          Edge servers running NurProxy <HelpTip term="agent" />
        </p>
      </div>

      {pendingAgents.length > 0 && (
        <section className="rounded-xl border border-warning/40 bg-warning-soft/60 p-4">
          <h2 className="mb-3 flex items-center gap-1.5 text-sm font-semibold text-warning-fg">
            {pendingAgents.length} agent{pendingAgents.length !== 1 ? 's' : ''} waiting for approval <HelpTip term="adoption" />
          </h2>
          <div className="space-y-3">
            {pendingAgents.map((agent) => (
              <div key={agent.id} className="flex items-center justify-between gap-3 rounded-lg border border-border bg-surface px-4 py-3">
                <div className="min-w-0">
                  <p className="truncate font-medium text-fg">{agent.fqdn}</p>
                  <p className="text-xs text-fg-faint">
                    {agent.public_ip && `IP ${agent.public_ip}`}{agent.version && ` · v${agent.version}`}
                  </p>
                </div>
                <div className="flex flex-shrink-0 gap-2">
                  <Button size="sm" onClick={() => { setAdoptAgent(agent); setAdoptName(agent.fqdn); setAdoptZoneIds(new Set()); setAdoptDnsMode('static'); setAdoptDdnsInterval(60); setAdoptError(''); }}>Approve</Button>
                  <Button variant="secondary" size="sm" onClick={() => handleReject(agent.id)}>Reject</Button>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {otherAgents.length === 0 && pendingAgents.length === 0 ? (
        <EmptyState
          title="No agents registered"
          description="Install the NurProxy agent on a server and it will appear here for approval. See Setup for the install command."
        />
      ) : (
        <div className="space-y-3">
          {otherAgents.map((agent) => {
            const expanded = expandedId === agent.id;
            const agentServers = servers[agent.id] ?? [];
            const agentDomains = domains.filter((d) => agentServers.some((s) => s.id === d.server_id) && d.status !== 'deleting');

            return (
              <div key={agent.id} className="overflow-hidden rounded-xl border border-border bg-surface shadow-card">
                <button onClick={() => toggleExpand(agent.id)} className="flex w-full items-center justify-between gap-4 px-5 py-4 text-left transition-colors hover:bg-surface-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="truncate font-medium text-fg">{agent.name}</p>
                      <StatusBadge status={agent.status} />
                    </div>
                    <p className="mt-0.5 truncate text-sm text-fg-muted">{agent.fqdn}</p>
                  </div>
                  <div className="flex flex-shrink-0 items-center gap-5 text-xs text-fg-faint">
                    {agent.public_ip && <span className="hidden font-mono sm:inline">{agent.public_ip}</span>}
                    <span className="hidden sm:inline">Seen {seen(agent.last_seen)}</span>
                    <span>{agentServers.length} server{agentServers.length !== 1 ? 's' : ''}</span>
                    <svg className={`h-4 w-4 transition-transform ${expanded ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" /></svg>
                  </div>
                </button>

                {expanded && (
                  <div className="border-t border-border px-5 py-4">
                    <div className="grid gap-6 sm:grid-cols-2">
                      <div className="space-y-3">
                        <h3 className="text-xs font-semibold uppercase tracking-wide text-fg-faint">Details</h3>
                        <dl className="space-y-2 text-sm">
                          <Row label={<span className="flex items-center gap-1">DNS mode <HelpTip term="dns-mode" /></span>} value={agent.dns_mode || 'static'} />
                          {agent.dns_mode === 'ddns' && <Row label="DDNS interval" value={`${agent.ddns_interval}s`} />}
                          {agent.zones && agent.zones.length > 0 && <Row label="Zones" value={agent.zones.map((z) => z.name).join(', ')} />}
                          {agent.version && <Row label="Version" value={agent.version} />}
                          <Row label="ID" value={<span className="font-mono text-xs">{agent.id}</span>} />
                        </dl>
                        <Button variant="danger-ghost" size="sm" onClick={() => setDeleteAgent(agent)}>Delete agent</Button>
                      </div>

                      <div>
                        <div className="flex items-center justify-between">
                          <h3 className="flex items-center gap-1 text-xs font-semibold uppercase tracking-wide text-fg-faint">Servers <HelpTip term="server" /></h3>
                          <Link to="/servers" className="text-xs font-medium text-accent hover:underline">Manage in Servers →</Link>
                        </div>
                        {agentServers.length === 0 ? (
                          <p className="mt-2 text-sm text-fg-faint">No servers yet.</p>
                        ) : (
                          <div className="mt-2 space-y-2">
                            {agentServers.map((srv) => (
                              <div key={srv.id} className="rounded-lg bg-surface-2 px-3 py-2">
                                <p className="truncate text-sm font-medium text-fg">{srv.name}</p>
                                <p className="truncate font-mono text-xs text-fg-faint">{srv.address}</p>
                              </div>
                            ))}
                          </div>
                        )}

                        {agentDomains.length > 0 && (
                          <div className="mt-4">
                            <h4 className="text-xs font-semibold uppercase tracking-wide text-fg-faint">Domains</h4>
                            <div className="mt-2 space-y-1">
                              {agentDomains.map((d) => (
                                <div key={d.id} className="flex items-center justify-between text-sm">
                                  <span className="text-fg-muted">{d.subdomain}</span>
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

      {/* Adopt modal */}
      <Modal open={adoptAgent !== null} onClose={() => setAdoptAgent(null)} title="Approve agent" description={adoptAgent?.fqdn}>
        {adoptAgent && (
          <div className="space-y-4">
            {adoptError && <Callout tone="danger">{adoptError}</Callout>}
            <Field label="Display name">
              <Input value={adoptName} onChange={(e) => setAdoptName(e.target.value)} placeholder="e.g. Edge — Frankfurt" />
            </Field>
            <Field label="DNS zones" help="zone">
              <MultiSelect
                items={zones.map((z) => ({ id: z.id, label: z.name }))}
                selected={adoptZoneIds}
                onChange={setAdoptZoneIds}
                maxHeightClass="max-h-40"
                emptyHint="No zones available. Add a provider in Settings first."
              />
            </Field>
            <Field label="DNS mode" help="dns-mode">
              <div className="flex gap-4">
                <label className="flex cursor-pointer items-center gap-2 text-sm text-fg">
                  <input type="radio" name="adopt-dns-mode" checked={adoptDnsMode === 'static'} onChange={() => setAdoptDnsMode('static')} className="accent-[var(--accent)]" /> Static
                </label>
                <label className="flex cursor-pointer items-center gap-2 text-sm text-fg">
                  <input type="radio" name="adopt-dns-mode" checked={adoptDnsMode === 'ddns'} onChange={() => setAdoptDnsMode('ddns')} className="accent-[var(--accent)]" /> DDNS
                </label>
              </div>
            </Field>
            {adoptDnsMode === 'ddns' && (
              <Field label={`DDNS interval — ${adoptDdnsInterval}s`}>
                <input type="range" min={30} max={600} step={10} value={adoptDdnsInterval} onChange={(e) => setAdoptDdnsInterval(Number(e.target.value))} className="w-full accent-[var(--accent)]" />
                <div className="flex justify-between text-xs text-fg-faint"><span>30s</span><span>600s</span></div>
              </Field>
            )}
            <div className="flex justify-end gap-3 pt-1">
              <Button variant="secondary" onClick={() => setAdoptAgent(null)}>Cancel</Button>
              <Button onClick={handleAdopt} loading={adoptLoading}>Approve agent</Button>
            </div>
          </div>
        )}
      </Modal>

      <ConfirmDialog open={deleteAgent !== null} onClose={() => setDeleteAgent(null)} onConfirm={handleDelete} title="Delete agent" message={`Delete “${deleteAgent?.name}”? This removes all of its servers and domains too.`} confirmLabel="Delete" danger loading={deleteLoading} />
    </div>
  );
}

function Row({ label, value }: { label: React.ReactNode; value: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4">
      <dt className="text-fg-faint">{label}</dt>
      <dd className="min-w-0 truncate text-right text-fg">{value}</dd>
    </div>
  );
}

import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ChevronLeft } from 'lucide-react';
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

const seen = (d?: string) => (d ? formatRelativeTime(d) : 'Never');

export default function Agents() {
  const { t } = useTranslation();
  const toast = useToast();
  const [agents, setAgents] = useState<Agent[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const [domains, setDomains] = useState<Domain[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);
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
      toast.error(errMessage(err, t('agents.loadFailed')));
    } finally {
      setLoading(false);
    }
  }, [toast, t]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const loadServers = useCallback(async (agentId: string) => {
    try {
      const list = await api.listServers(agentId);
      setServers((prev) => ({ ...prev, [agentId]: list }));
    } catch (err) {
      toast.error(errMessage(err, t('agents.loadServersFailed')));
    }
  }, [toast, t]);

  function select(agent: Agent) {
    setSelectedId(agent.id);
    if ((agent.status === 'adopted' || agent.status === 'offline') && !servers[agent.id]) loadServers(agent.id);
  }

  function startAdopt(agent: Agent) {
    setAdoptAgent(agent); setAdoptName(agent.fqdn); setAdoptZoneIds(new Set());
    setAdoptDnsMode('static'); setAdoptDdnsInterval(60); setAdoptError('');
  }

  async function handleAdopt() {
    if (!adoptAgent) return;
    setAdoptLoading(true); setAdoptError('');
    try {
      await api.adoptAgent(adoptAgent.id, {
        name: adoptName || undefined,
        zone_ids: adoptZoneIds.size > 0 ? [...adoptZoneIds] : undefined,
        dns_mode: adoptDnsMode,
        ddns_interval: adoptDnsMode === 'ddns' ? adoptDdnsInterval : undefined,
      });
      toast.success(t('agents.adopted', { name: adoptName || adoptAgent.fqdn }));
      setAdoptAgent(null);
      fetchData();
    } catch (err) {
      setAdoptError(errMessage(err, t('setup.adoptFailed')));
    } finally {
      setAdoptLoading(false);
    }
  }

  async function handleReject(id: string) {
    try { await api.rejectAgent(id); toast.success(t('agents.rejected')); if (selectedId === id) setSelectedId(null); fetchData(); }
    catch (err) { toast.error(errMessage(err, t('agents.rejectFailed'))); }
  }

  async function handleDelete() {
    if (!deleteAgent) return;
    setDeleteLoading(true);
    try {
      await api.deleteAgent(deleteAgent.id);
      toast.success(t('agents.deleted'));
      if (selectedId === deleteAgent.id) setSelectedId(null);
      setDeleteAgent(null);
      fetchData();
    } catch (err) {
      toast.error(errMessage(err, t('agents.deleteFailed')));
    } finally {
      setDeleteLoading(false);
    }
  }

  const pendingAgents = agents.filter((a) => a.status === 'pending');
  const otherAgents = agents.filter((a) => a.status !== 'pending');
  const selected = agents.find((a) => a.id === selectedId) ?? null;

  if (loading) return <div className="py-12 text-center text-sm text-fg-muted">{t('common.loading')}</div>;

  const empty = agents.length === 0;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="flex items-center gap-2 font-display text-3xl font-bold tracking-tight text-fg">
          {t('agents.title')} <HelpTip term="agent" />
        </h1>
        <p className="mt-1 text-sm text-fg-muted">{t('agents.subtitle')}</p>
      </div>

      {empty ? (
        <EmptyState
          title={t('agents.none')}
          description={t('agents.noneBody')}
        />
      ) : (
        <div className="grid gap-6 md:grid-cols-[20rem_1fr]">
          {/* Master list */}
          <div className={selected ? 'hidden md:block' : 'block'}>
            <div className="space-y-4">
              {pendingAgents.length > 0 && (
                <div>
                  <h2 className="mb-2 px-1 text-xs font-semibold uppercase tracking-wide text-warning-fg">{t('agents.pendingApproval')}</h2>
                  <div className="space-y-2">
                    {pendingAgents.map((a) => (
                      <ListRow key={a.id} active={selectedId === a.id} tone="warning" onClick={() => select(a)} agent={a} />
                    ))}
                  </div>
                </div>
              )}
              <div>
                {otherAgents.length > 0 && <h2 className="mb-2 px-1 text-xs font-semibold uppercase tracking-wide text-fg-faint">{t('agents.title')}</h2>}
                <div className="space-y-2">
                  {otherAgents.map((a) => (
                    <ListRow key={a.id} active={selectedId === a.id} onClick={() => select(a)} agent={a} />
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Detail */}
          <div className={selected ? 'block' : 'hidden md:block'}>
            {!selected ? (
              <div className="flex h-full min-h-48 items-center justify-center rounded-xl border border-dashed border-border text-sm text-fg-faint">
                {t('agents.select')}
              </div>
            ) : (
              <div className="rounded-xl border border-border bg-surface p-6 shadow-card">
                <button onClick={() => setSelectedId(null)} className="mb-4 inline-flex items-center gap-1 text-sm text-fg-muted hover:text-fg md:hidden">
                  <ChevronLeft className="h-4 w-4" />
                  {t('common.back')}
                </button>

                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <h2 className="truncate font-display text-xl font-semibold text-fg">{selected.name}</h2>
                      <StatusBadge status={selected.status} />
                    </div>
                    <p className="truncate text-sm text-fg-muted">{selected.fqdn}</p>
                  </div>
                  {selected.status === 'pending' ? (
                    <div className="flex gap-2">
                      <Button size="sm" onClick={() => startAdopt(selected)}>{t('setup.approve')}</Button>
                      <Button variant="secondary" size="sm" onClick={() => handleReject(selected.id)}>{t('agents.reject')}</Button>
                    </div>
                  ) : (
                    <Button variant="danger-ghost" size="sm" onClick={() => setDeleteAgent(selected)}>{t('agents.deleteAgent')}</Button>
                  )}
                </div>

                {selected.status === 'pending' ? (
                  <Callout tone="warning" title={t('agents.awaitingApproval')}>
                    {t('agents.awaitingBody')}
                  </Callout>
                ) : (
                  <div className="mt-5 grid gap-6 sm:grid-cols-2">
                    <div className="space-y-3">
                      <h3 className="text-xs font-semibold uppercase tracking-wide text-fg-faint">{t('agents.details')}</h3>
                      <dl className="space-y-2 text-sm">
                        <Row label={<span className="flex items-center gap-1">{t('agents.dnsMode')} <HelpTip term="dns-mode" /></span>} value={selected.dns_mode || 'static'} />
                        {selected.dns_mode === 'ddns' && <Row label={t('agents.ddnsInterval')} value={`${selected.ddns_interval}s`} />}
                        {selected.zones && selected.zones.length > 0 && <Row label={t('agents.zones')} value={selected.zones.map((z) => z.name).join(', ')} />}
                        {selected.public_ip && <Row label={t('agents.ip')} value={selected.public_ip} />}
                        {selected.version && <Row label={t('agents.version')} value={selected.version} />}
                        <Row label={t('agents.lastSeen')} value={seen(selected.last_seen)} />
                        <Row label={t('agents.id')} value={<span className="font-mono text-xs">{selected.id}</span>} />
                      </dl>
                    </div>

                    <div>
                      <div className="flex items-center justify-between">
                        <h3 className="flex items-center gap-1 text-xs font-semibold uppercase tracking-wide text-fg-faint">{t('nav.servers')} <HelpTip term="server" /></h3>
                        <Link to="/servers" className="text-xs font-medium text-accent hover:underline">{t('agents.manageInServers')}</Link>
                      </div>
                      {(servers[selected.id] ?? []).length === 0 ? (
                        <p className="mt-2 text-sm text-fg-faint">{t('agents.noServers')}</p>
                      ) : (
                        <div className="mt-2 space-y-2">
                          {(servers[selected.id] ?? []).map((srv) => (
                            <div key={srv.id} className="rounded-lg bg-surface-2 px-3 py-2">
                              <p className="truncate text-sm font-medium text-fg">{srv.name}</p>
                              <p className="truncate font-mono text-xs text-fg-faint">{srv.address}</p>
                            </div>
                          ))}
                        </div>
                      )}

                      {(() => {
                        const agentServers = servers[selected.id] ?? [];
                        const agentDomains = domains.filter((d) => agentServers.some((s) => s.id === d.server_id) && d.status !== 'deleting');
                        if (agentDomains.length === 0) return null;
                        return (
                          <div className="mt-4">
                            <h4 className="text-xs font-semibold uppercase tracking-wide text-fg-faint">{t('nav.domains')}</h4>
                            <div className="mt-2 space-y-1">
                              {agentDomains.map((d) => (
                                <div key={d.id} className="flex items-center justify-between text-sm">
                                  <span className="text-fg-muted">{d.subdomain}</span>
                                  <StatusBadge status={d.status} />
                                </div>
                              ))}
                            </div>
                          </div>
                        );
                      })()}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Adopt modal */}
      <Modal open={adoptAgent !== null} onClose={() => setAdoptAgent(null)} title={t('setup.approveAgent')} description={adoptAgent?.fqdn}>
        {adoptAgent && (
          <div className="space-y-4">
            {adoptError && <Callout tone="danger">{adoptError}</Callout>}
            <Field label={t('setup.displayName')}>
              <Input value={adoptName} onChange={(e) => setAdoptName(e.target.value)} placeholder={t('setup.displayNamePh')} />
            </Field>
            <Field label={t('setup.dnsZones')} help="zone">
              <MultiSelect
                items={zones.map((z) => ({ id: z.id, label: z.name }))}
                selected={adoptZoneIds}
                onChange={setAdoptZoneIds}
                maxHeightClass="max-h-40"
                emptyHint={t('setup.noZonesYet')}
              />
            </Field>
            <Field label={t('setup.dnsMode')} help="dns-mode">
              <div className="flex gap-4">
                <label className="flex cursor-pointer items-center gap-2 text-sm text-fg">
                  <input type="radio" name="adopt-dns-mode" checked={adoptDnsMode === 'static'} onChange={() => setAdoptDnsMode('static')} className="accent-[var(--accent)]" /> {t('setup.static')}
                </label>
                <label className="flex cursor-pointer items-center gap-2 text-sm text-fg">
                  <input type="radio" name="adopt-dns-mode" checked={adoptDnsMode === 'ddns'} onChange={() => setAdoptDnsMode('ddns')} className="accent-[var(--accent)]" /> {t('setup.ddns')}
                </label>
              </div>
            </Field>
            {adoptDnsMode === 'ddns' && (
              <Field label={t('agents.ddnsIntervalLabel', { seconds: adoptDdnsInterval })}>
                <input type="range" min={30} max={600} step={10} value={adoptDdnsInterval} onChange={(e) => setAdoptDdnsInterval(Number(e.target.value))} className="w-full accent-[var(--accent)]" />
                <div className="flex justify-between text-xs text-fg-faint"><span>30s</span><span>600s</span></div>
              </Field>
            )}
            <div className="flex justify-end gap-3 pt-1">
              <Button variant="secondary" onClick={() => setAdoptAgent(null)}>{t('common.cancel')}</Button>
              <Button onClick={handleAdopt} loading={adoptLoading}>{t('setup.approveAgent')}</Button>
            </div>
          </div>
        )}
      </Modal>

      <ConfirmDialog
        open={deleteAgent !== null}
        onClose={() => setDeleteAgent(null)}
        onConfirm={handleDelete}
        title={t('agents.deleteAgent')}
        message={t('agents.deleteConfirm', { name: deleteAgent?.name })}
        confirmLabel={t('common.delete')}
        danger
        loading={deleteLoading}
        confirmText={deleteAgent?.name}
      />
    </div>
  );
}

function ListRow({ agent, active, tone, onClick }: { agent: Agent; active: boolean; tone?: 'warning'; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`flex w-full items-center justify-between gap-3 rounded-lg border px-4 py-3 text-left transition-colors ${
        active ? 'border-accent bg-accent-soft' : tone === 'warning' ? 'border-warning/40 bg-warning-soft/50 hover:border-warning/60' : 'border-border bg-surface hover:border-border-strong'
      }`}
    >
      <div className="min-w-0">
        <p className="truncate font-medium text-fg">{agent.name}</p>
        <p className="truncate text-xs text-fg-faint">{agent.fqdn}</p>
      </div>
      <StatusBadge status={agent.status} />
    </button>
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

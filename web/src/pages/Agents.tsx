import { useState, useCallback } from 'react';
import i18n from '../lib/i18n';
import { usePolling } from '../lib/usePolling';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ChevronLeft, Check, X } from 'lucide-react';
import { api } from '../lib/api';
import type { Agent, Zone, Server, Domain, ProxyPermissions } from '../lib/types';
import { CommandBlock } from '../components/CommandBlock';
import { formatRelativeTime } from '../lib/utils';
import { isDegraded } from '../lib/status';
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
import ExistingSetup from './ExistingSetup';
import LogTailViewer from '../components/LogTailViewer';

const seen = (d?: string) => (d ? formatRelativeTime(d) : i18n.t('time.never'));

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
  const [adoptFqdn, setAdoptFqdn] = useState('');
  const [adoptZoneIds, setAdoptZoneIds] = useState<Set<string>>(new Set());
  const [adoptDnsMode, setAdoptDnsMode] = useState<'static' | 'ddns'>('static');
  const [adoptDdnsInterval, setAdoptDdnsInterval] = useState(60);
  const [adoptLoading, setAdoptLoading] = useState(false);
  const [adoptError, setAdoptError] = useState('');

  const [editAgent, setEditAgent] = useState<Agent | null>(null);
  const [editName, setEditName] = useState('');
  const [editFqdn, setEditFqdn] = useState('');
  const [editZoneIds, setEditZoneIds] = useState<Set<string>>(new Set());
  const [editDnsMode, setEditDnsMode] = useState<'static' | 'ddns'>('static');
  const [editDdnsInterval, setEditDdnsInterval] = useState(60);
  const [editLoading, setEditLoading] = useState(false);
  const [editError, setEditError] = useState('');

  // Client-side check: does the hostname fall inside any of the selected zones?
  const fqdnInZones = useCallback((fqdn: string, ids: Set<string>) => {
    const names = zones.filter((z) => ids.has(z.id)).map((z) => z.name);
    return names.some((n) => fqdn === n || fqdn.endsWith('.' + n));
  }, [zones]);

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

  // Poll instead of fetching once: an agent's health, live proxy mode, and
  // detection change out-of-band (e.g. a §19 hot-switch flips it to existing,
  // or a permission grant clears an error). Polling makes the detail view
  // reflect those without a full page reload. Pauses while the tab is hidden.
  usePolling(fetchData, 5000);

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
    setAdoptAgent(agent); setAdoptName(agent.fqdn); setAdoptFqdn(agent.fqdn); setAdoptZoneIds(new Set());
    setAdoptDnsMode('static'); setAdoptDdnsInterval(60); setAdoptError('');
  }

  async function handleAdopt() {
    if (!adoptAgent) return;
    setAdoptLoading(true); setAdoptError('');
    try {
      await api.adoptAgent(adoptAgent.id, {
        name: adoptName || undefined,
        fqdn: adoptFqdn || undefined,
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

  function startEdit(agent: Agent) {
    setEditAgent(agent); setEditName(agent.name); setEditFqdn(agent.fqdn);
    setEditZoneIds(new Set((agent.zones ?? []).map((z) => z.id)));
    setEditDnsMode(agent.dns_mode || 'static'); setEditDdnsInterval(agent.ddns_interval || 60); setEditError('');
  }

  async function handleEdit() {
    if (!editAgent) return;
    setEditLoading(true); setEditError('');
    try {
      await api.updateAgent(editAgent.id, {
        name: editName || undefined,
        fqdn: editFqdn || undefined,
        zone_ids: [...editZoneIds],
        dns_mode: editDnsMode,
        ddns_interval: editDdnsInterval,
      });
      toast.success(t('agents.updated', { name: editName || editAgent.name }));
      setEditAgent(null);
      fetchData();
    } catch (err) {
      setEditError(errMessage(err, t('agents.updateFailed')));
    } finally {
      setEditLoading(false);
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
                      <StatusBadge status={selected.status} degraded={isDegraded(selected)} />
                    </div>
                    <p className="truncate text-sm text-fg-muted">{selected.fqdn}</p>
                  </div>
                  {selected.status === 'pending' ? (
                    <div className="flex gap-2">
                      <Button size="sm" onClick={() => startAdopt(selected)}>{t('setup.approve')}</Button>
                      <Button variant="secondary" size="sm" onClick={() => handleReject(selected.id)}>{t('agents.reject')}</Button>
                    </div>
                  ) : (
                    <div className="flex gap-2">
                      <Button variant="secondary" size="sm" onClick={() => startEdit(selected)}>{t('agents.edit')}</Button>
                      <Button variant="danger-ghost" size="sm" onClick={() => setDeleteAgent(selected)}>{t('agents.deleteAgent')}</Button>
                    </div>
                  )}
                </div>

                {/* Surface anything wrong the agent (or the orchestrator's DNS
                    management) is reporting, so problems are visible and fixable.
                    In existing mode a permission denial is shown granularly (with a
                    targeted fix) by the detected-proxy block below, so we suppress
                    the redundant raw-error blob here. */}
                {selected.status !== 'pending' && selected.last_error && selected.proxy_mode !== 'existing' && (
                  <Callout tone="danger" title={t('agents.agentError')}>{selected.last_error}</Callout>
                )}
                {selected.status !== 'pending' && selected.dns_error && (
                  <Callout tone="warning" title={t('agents.dnsProblem')}>{selected.dns_error}</Callout>
                )}

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
                        <Row
                          label={t('agents.proxyMode')}
                          value={
                            selected.proxy_mode === 'existing'
                              ? t('agents.proxyModeExisting', { kind: selected.proxy_detection?.kind || t('agents.proxyExternalGeneric') })
                              : t('agents.proxyModeBuiltIn')
                          }
                        />
                        {/* The bundled-Caddy running indicator only makes sense in built-in
                            mode. In existing mode the host proxy owns :80/:443 and the
                            bundled Caddy is intentionally stopped, so "not running" would be
                            a false alarm — show that the agent manages the existing proxy. */}
                        {selected.proxy_mode === 'existing' ? (
                          <Row
                            label={t('agents.proxyStatus')}
                            value={<span className="text-success-fg">{t('agents.managingExisting')}</span>}
                          />
                        ) : (
                          <Row
                            label={t('agents.caddyStatus')}
                            value={
                              <span className={selected.caddy_running === false ? 'text-danger-fg' : 'text-success-fg'}>
                                {selected.caddy_running === false ? t('agents.notRunning') : t('agents.running')}
                              </span>
                            }
                          />
                        )}
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

                {selected.status !== 'pending' && <DetectedProxy agent={selected} />}
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
            <Field label={t('agents.anchorFqdn')} hint={t('agents.anchorFqdnHelp')}>
              <Input value={adoptFqdn} onChange={(e) => setAdoptFqdn(e.target.value)} placeholder="edge1.example.com" />
            </Field>
            {adoptFqdn && adoptZoneIds.size > 0 && !fqdnInZones(adoptFqdn, adoptZoneIds) && (
              <Callout tone="warning">{t('agents.anchorFqdnWarn')}</Callout>
            )}
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

      {/* Edit modal — per-agent settings, incl. correcting the anchor FQDN. */}
      <Modal open={editAgent !== null} onClose={() => setEditAgent(null)} title={t('agents.editAgent')} description={editAgent?.fqdn}>
        {editAgent && (
          <div className="space-y-4">
            {editError && <Callout tone="danger">{editError}</Callout>}
            <Field label={t('setup.displayName')}>
              <Input value={editName} onChange={(e) => setEditName(e.target.value)} placeholder={t('setup.displayNamePh')} />
            </Field>
            <Field label={t('setup.dnsZones')} help="zone">
              <MultiSelect
                items={zones.map((z) => ({ id: z.id, label: z.name }))}
                selected={editZoneIds}
                onChange={setEditZoneIds}
                maxHeightClass="max-h-40"
                emptyHint={t('setup.noZonesYet')}
              />
            </Field>
            <Field label={t('agents.anchorFqdn')} hint={t('agents.anchorFqdnHelp')}>
              <Input value={editFqdn} onChange={(e) => setEditFqdn(e.target.value)} placeholder="edge1.example.com" />
            </Field>
            {editFqdn && editZoneIds.size > 0 && !fqdnInZones(editFqdn, editZoneIds) && (
              <Callout tone="warning">{t('agents.anchorFqdnWarn')}</Callout>
            )}
            <Field label={t('setup.dnsMode')} help="dns-mode">
              <div className="flex gap-4">
                <label className="flex cursor-pointer items-center gap-2 text-sm text-fg">
                  <input type="radio" name="edit-dns-mode" checked={editDnsMode === 'static'} onChange={() => setEditDnsMode('static')} className="accent-[var(--accent)]" /> {t('setup.static')}
                </label>
                <label className="flex cursor-pointer items-center gap-2 text-sm text-fg">
                  <input type="radio" name="edit-dns-mode" checked={editDnsMode === 'ddns'} onChange={() => setEditDnsMode('ddns')} className="accent-[var(--accent)]" /> {t('setup.ddns')}
                </label>
              </div>
            </Field>
            {editDnsMode === 'ddns' && (
              <Field label={t('agents.ddnsIntervalLabel', { seconds: editDdnsInterval })}>
                <input type="range" min={30} max={600} step={10} value={editDdnsInterval} onChange={(e) => setEditDdnsInterval(Number(e.target.value))} className="w-full accent-[var(--accent)]" />
                <div className="flex justify-between text-xs text-fg-faint"><span>30s</span><span>600s</span></div>
              </Field>
            )}
            <div className="flex justify-end gap-3 pt-1">
              <Button variant="secondary" onClick={() => setEditAgent(null)}>{t('common.cancel')}</Button>
              <Button onClick={handleEdit} loading={editLoading}>{t('agents.save')}</Button>
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
  // A degraded agent (connected but constrained, e.g. can't reload nginx) gets the
  // same dezent warning treatment as a pending one, so problems are visible in the
  // master list without opening the detail view.
  const degraded = isDegraded(agent);
  const warn = tone === 'warning' || degraded;
  return (
    <button
      onClick={onClick}
      className={`flex w-full items-center justify-between gap-3 rounded-lg border px-4 py-3 text-left transition-colors ${
        active ? 'border-accent bg-accent-soft' : warn ? 'border-warning/40 bg-warning-soft/50 hover:border-warning/60' : 'border-border bg-surface hover:border-border-strong'
      }`}
    >
      <div className="min-w-0">
        <p className="truncate font-medium text-fg">{agent.name}</p>
        <p className="truncate text-xs text-fg-faint">{agent.fqdn}</p>
      </div>
      <StatusBadge status={agent.status} degraded={degraded} />
    </button>
  );
}

// DetectedProxy renders the agent's read-only Phase-0 detection: which proxy is
// installed on the host, its version, the discovered paths, and any bind
// conflict on :80/:443. Phase 0 manages nothing — this is purely informational.
function DetectedProxy({ agent }: { agent: Agent }) {
  const { t } = useTranslation();
  const d = agent.proxy_detection;
  const [setupOpen, setSetupOpen] = useState(false);
  // Path of the log currently being tailed on-demand (§15); null = no viewer open.
  const [tailPath, setTailPath] = useState<string | null>(null);

  // Compose a one-line summary like "nginx 1.24 at /etc/nginx".
  const summary = () => {
    if (!d || !d.installed || !d.kind) return null;
    const name = d.version ? `${d.kind} ${d.version}` : d.kind;
    return d.config_dir ? t('agents.proxyAt', { name, dir: d.config_dir }) : name;
  };

  const conflicts = d?.port_conflicts ?? [];
  const detected = !!(d && d.installed && d.kind);
  // Once the agent has switched to existing mode (§19), it deliberately manages
  // the host proxy and the bundled Caddy is stopped — so a :80/:443 "bind
  // conflict" is the expected steady state, not an error, and the "switch to
  // existing" CTA is already done. Suppress both and confirm the active mode.
  const isExisting = agent.proxy_mode === 'existing';

  return (
    <div className="mt-6 border-t border-border pt-5">
      <div className="flex items-center justify-between">
        <h3 className="flex items-center gap-1 text-xs font-semibold uppercase tracking-wide text-fg-faint">
          {t('agents.detectedProxy')} <HelpTip term="proxy-detection" />
        </h3>
        {agent.proxy_detected_at && (
          <span className="text-xs text-fg-faint">{t('agents.detectedAt', { when: seen(agent.proxy_detected_at) })}</span>
        )}
      </div>

      {!d ? (
        <p className="mt-2 text-sm text-fg-faint">{t('agents.detectPending')}</p>
      ) : !d.installed || !d.kind ? (
        <p className="mt-2 text-sm text-fg-muted">{t('agents.noProxyDetected')}</p>
      ) : (
        <div className="mt-3 space-y-3">
          <p className="text-sm font-medium text-fg">{summary()}</p>
          <dl className="space-y-2 text-sm">
            <Row label={t('agents.proxyKind')} value={d.kind} />
            {d.version && <Row label={t('agents.proxyVersion')} value={d.version} />}
            {d.binary_path && <Row label={t('agents.proxyBinary')} value={<span className="font-mono text-xs">{d.binary_path}</span>} />}
            {d.config_dir && <Row label={t('agents.proxyConfigDir')} value={<span className="font-mono text-xs">{d.config_dir}</span>} />}
            {d.log_paths && d.log_paths.length > 0 && (
              <Row
                label={t('agents.proxyLogPaths')}
                value={
                  <span className="font-mono text-xs">
                    {d.log_paths.map((p) => (
                      <span key={p} className="flex items-center justify-end gap-2">
                        <span className="truncate">{p}</span>
                        <button
                          type="button"
                          onClick={() => setTailPath(p)}
                          className="shrink-0 font-sans font-medium text-accent underline underline-offset-2 hover:text-accent-hover"
                        >
                          {t('logtail.tailAction')}
                        </button>
                      </span>
                    ))}
                  </span>
                }
              />
            )}
          </dl>
        </div>
      )}

      {/* Already switched to existing mode: show the §12 permission self-test
          (granular: config writable? service reloadable?) with the targeted fix
          for whatever's missing — not a verbose blob. The button reopens setup. */}
      {isExisting && (
        <PermissionSelfTest
          kind={d?.kind || t('agents.proxyExternalGeneric')}
          perm={agent.proxy_permissions}
          onAdjust={() => setSetupOpen(true)}
        />
      )}

      {/* A detected proxy can be managed directly — this is the guided "Existing"
          setup entry point, pre-filled from detection (confirm-not-type, §2/§2.1).
          Hidden once already in existing mode (the confirm block above covers it). */}
      {detected && !isExisting && (
        <div className="mt-3">
          <Button variant="secondary" size="sm" onClick={() => setSetupOpen(true)}>
            {t('existing.manageThis', { kind: d?.kind })}
          </Button>
        </div>
      )}

      {conflicts.length > 0 && !isExisting && (
        <div className="mt-3">
          <Callout tone="warning" title={t('agents.bindConflict')}>
            <p>{t('agents.bindConflictBody')}</p>
            <ul className="mt-2 space-y-1">
              {conflicts.map((c) => (
                <li key={`${c.port}-${c.pid}`} className="font-mono text-xs">
                  {t('agents.bindConflictItem', {
                    port: c.port,
                    process: c.process || t('agents.unknownProcess'),
                    pid: c.pid ? ` (pid ${c.pid})` : '',
                  })}
                </li>
              ))}
            </ul>
            {/* The two real choices (§2.1), offered inline: keep only the agent
                (free the port) or switch this agent to manage the existing proxy. */}
            <div className="mt-3 space-y-2">
              <p className="font-medium">{t('agents.bindConflictChoices')}</p>
              <ol className="ml-4 list-decimal space-y-1">
                <li>{t('agents.bindConflictChoiceFree')}</li>
                <li>
                  {t('agents.bindConflictChoiceSwitch')}{' '}
                  <button
                    type="button"
                    onClick={() => setSetupOpen(true)}
                    className="font-medium text-accent underline underline-offset-2 hover:text-accent-hover"
                  >
                    {t('agents.bindConflictSwitchLink')}
                  </button>
                </li>
              </ol>
            </div>
          </Callout>
        </div>
      )}

      <ExistingSetup agent={agent} open={setupOpen} onClose={() => setSetupOpen(false)} />
      {tailPath && (
        <LogTailViewer agentId={agent.id} path={tailPath} open={!!tailPath} onClose={() => setTailPath(null)} />
      )}
    </div>
  );
}

// PermissionSelfTest renders the agent's §12 permission self-test for an
// existing-mode backend: a two-line checklist (config dir writable? service
// reloadable?) and, when a grant is missing, the exact least-privilege commands
// to fix just that — never the whole blob. It re-reads from the heartbeat-reported
// proxy_permissions, so once the operator runs the grant the warning clears on the
// next poll without a reload. perm is undefined for an older agent / first beat.
function PermissionSelfTest({
  kind,
  perm,
  onAdjust,
}: {
  kind: string;
  perm?: ProxyPermissions;
  onAdjust: () => void;
}) {
  const { t } = useTranslation();
  const ok = perm?.ok ?? true; // no report yet → don't cry wolf
  const steps = perm?.remediation?.steps ?? [];

  return (
    <div className="mt-3 space-y-3">
      <Callout
        tone={ok ? 'success' : 'warning'}
        title={
          ok
            ? t('agents.managingExistingTitle', { kind })
            : t('agents.permFixTitle', { kind })
        }
      >
        {/* The granular checklist replaces the verbose paragraph: each §12 grant
            with a clear ✓/✗ and, when missing, its actionable reason. */}
        {perm?.checked ? (
          <ul className="space-y-1.5">
            <PermCheckLine ok={perm.can_write} label={t('agents.permWriteCheck')} detail={perm.can_write ? '' : perm.write_error} />
            <PermCheckLine ok={perm.can_reload} label={t('agents.permReloadCheck')} detail={perm.can_reload ? '' : perm.reload_error} />
          </ul>
        ) : (
          <p>{t('agents.managingExistingShort', { kind })}</p>
        )}
      </Callout>

      {/* Targeted fix: only the steps for what's actually missing. */}
      {!ok && steps.length > 0 && (
        <div className="space-y-3 rounded-lg border border-border bg-surface-2/40 p-3">
          <p className="text-xs font-medium text-fg-muted">{t('agents.permFixHint')}</p>
          {steps.map((s, i) => (
            <div key={i} className="space-y-1.5">
              <p className="text-sm font-medium text-fg">{s.title}</p>
              <CommandBlock text={s.commands.join('\n')} label={t('agents.permStepLabel', { n: i + 1 })} />
            </div>
          ))}
        </div>
      )}

      <Button variant="secondary" size="sm" onClick={onAdjust}>
        {t('existing.adjustThis', { kind })}
      </Button>
    </div>
  );
}

// PermCheckLine is one ✓/✗ row of the permission self-test, with an optional
// actionable detail when the grant is missing.
function PermCheckLine({ ok, label, detail }: { ok: boolean; label: string; detail?: string }) {
  return (
    <li className="flex items-start gap-2 text-sm">
      {ok ? (
        <Check className="mt-0.5 h-4 w-4 shrink-0 text-success-fg" />
      ) : (
        <X className="mt-0.5 h-4 w-4 shrink-0 text-danger-fg" />
      )}
      <span>
        <span className={ok ? '' : 'font-medium'}>{label}</span>
        {!ok && detail && <span className="block text-xs text-fg-muted">{detail}</span>}
      </span>
    </li>
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

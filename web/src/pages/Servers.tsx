import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { api } from '../lib/api';
import type { Agent, Server, Domain, DiscoveredNetwork } from '../lib/types';
import StatusBadge from '../components/StatusBadge';
import Modal from '../components/Modal';
import ConfirmDialog from '../components/ConfirmDialog';
import EmptyState from '../components/EmptyState';
import Button from '../components/Button';
import Callout from '../components/Callout';
import HelpTip from '../components/HelpTip';
import { Field, Input, Select } from '../components/Field';
import { useToast, errMessage } from '../components/toast-context';

// prefillFromNetwork turns a detected subnet into a Server-address prefill (§38).
// For an IPv4 network on an octet boundary it drops the host octets so the
// operator types only the host part (192.168.178.0/24 → "192.168.178."); for
// other prefixes / IPv6 it returns the network base for hand-editing.
function prefillFromNetwork(n: DiscoveredNetwork): string {
  const [base, plenStr] = n.network.split('/');
  const plen = n.prefix_length ?? parseInt(plenStr || '0', 10);
  if (base.includes('.') && plen > 0 && plen < 32 && plen % 8 === 0) {
    return base.split('.').slice(0, plen / 8).join('.') + '.';
  }
  return base;
}

// canonAddr collapses addresses that point at the same backend so a server is
// suggested at most once and never when it already exists. Loopback names are
// unified (localhost = 127.0.0.1 = ::1) and the scheme's default port is filled
// in (http→80, https→443), so "localhost", "localhost:80" and "127.0.0.1:80" all
// produce the same key. Without this the dedup was a raw string compare, so
// localhost and 127.0.0.1 showed as two suggestions and an existing server in a
// different spelling never suppressed its suggestion.
function canonAddr(host: string, port?: number, scheme?: string): string {
  let h = host.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1') h = 'localhost';
  const p = port && port > 0 ? port : scheme === 'https' ? 443 : scheme === 'http' ? 80 : 0;
  return p ? `${h}:${p}` : h;
}

// parseAddr splits a stored Server address ("host", "host:port", "[::1]:port")
// into host + port so it can be canonicalized the same way as a discovered
// upstream.
function parseAddr(addr: string): { host: string; port?: number } {
  const a = addr.trim();
  const m6 = a.match(/^\[(.+)\]:(\d+)$/); // [ipv6]:port
  if (m6) return { host: m6[1], port: Number(m6[2]) };
  const i = a.lastIndexOf(':');
  if (i > 0 && /^\d+$/.test(a.slice(i + 1)) && !a.slice(0, i).includes(':')) {
    return { host: a.slice(0, i), port: Number(a.slice(i + 1)) };
  }
  return { host: a };
}

export default function Servers() {
  const { t } = useTranslation();
  const toast = useToast();
  const [agents, setAgents] = useState<Agent[]>([]);
  const [serversByAgent, setServersByAgent] = useState<Record<string, Server[]>>({});
  const [domains, setDomains] = useState<Domain[]>([]);
  const [loading, setLoading] = useState(true);

  // Add server form
  const [showAdd, setShowAdd] = useState(false);
  const [formAgent, setFormAgent] = useState('');
  const [name, setName] = useState('');
  const [address, setAddress] = useState('');
  const [notes, setNotes] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  const eligible = agents.filter((a) => a.status === 'adopted' || a.status === 'offline');

  const fetchData = useCallback(async () => {
    try {
      const [a, d] = await Promise.all([api.listAgents(), api.listDomains()]);
      setAgents(a); setDomains(d);
      const managed = a.filter((ag) => ag.status === 'adopted' || ag.status === 'offline');
      const entries = await Promise.all(managed.map(async (ag) => {
        try { return [ag.id, await api.listServers(ag.id)] as const; }
        catch { return [ag.id, [] as Server[]] as const; }
      }));
      setServersByAgent(Object.fromEntries(entries));
    } catch (err) {
      toast.error(errMessage(err, t('servers.loadFailed')));
    } finally {
      setLoading(false);
    }
  }, [toast, t]);

  useEffect(() => { fetchData(); }, [fetchData]);

  function openAdd(agentId?: string, prefill?: { name?: string; address?: string; notes?: string }) {
    setFormAgent(agentId ?? eligible[0]?.id ?? '');
    setName(prefill?.name ?? ''); setAddress(prefill?.address ?? ''); setNotes(prefill?.notes ?? ''); setError('');
    setShowAdd(true);
  }

  // suggestionsFor turns an agent's discovered nginx upstreams (§52) into Server
  // suggestions: collapse by address, merge the vhost names, and drop any address
  // that is already a Server. The operator confirms each with a name/notes — the
  // orchestrator never creates these on its own.
  const suggestionsFor = (agent: Agent, servers: Server[]) => {
    const existing = new Set(servers.map((s) => { const { host, port } = parseAddr(s.address); return canonAddr(host, port); }));
    const byKey = new Map<string, { addr: string; names: string[] }>();
    for (const u of agent.proxy_detection?.discovered_upstreams ?? []) {
      const key = canonAddr(u.host, u.port, u.scheme);
      if (existing.has(key)) continue;
      const entry = byKey.get(key);
      if (entry) entry.names.push(...(u.server_names ?? []));
      else byKey.set(key, { addr: u.port ? `${u.host}:${u.port}` : u.host, names: [...(u.server_names ?? [])] });
    }
    return [...byKey.values()].map(({ addr, names }) => ({ addr, names: [...new Set(names)] }));
  };

  async function handleCreate() {
    if (!formAgent || !name || !address) return;
    setSaving(true); setError('');
    try {
      await api.createServer(formAgent, { name, address, notes: notes || undefined });
      toast.success(t('servers.added'));
      setShowAdd(false);
      fetchData();
    } catch (err) {
      setError(errMessage(err, t('servers.addFailed')));
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    if (!deleteId) return;
    setDeleting(true);
    try { await api.deleteServer(deleteId); toast.success(t('servers.removed')); setDeleteId(null); fetchData(); }
    catch (err) { toast.error(errMessage(err, t('servers.removeFailed'))); }
    finally { setDeleting(false); }
  }

  const domainsForServer = (sid: string) => domains.filter((d) => d.server_id === sid && d.status !== 'deleting').length;
  const totalServers = Object.values(serversByAgent).reduce((n, s) => n + s.length, 0);
  const totalSuggestions = eligible.reduce((n, a) => n + suggestionsFor(a, serversByAgent[a.id] ?? []).length, 0);

  if (loading) return <div className="py-12 text-center text-sm text-fg-muted">{t('common.loading')}</div>;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 font-display text-3xl font-bold tracking-tight text-fg">
            {t('servers.title')} <HelpTip term="server" />
          </h1>
          <p className="mt-1 text-sm text-fg-muted">{t('servers.subtitle')}</p>
        </div>
        <Button onClick={() => openAdd()} disabled={eligible.length === 0}>{t('servers.addServer')}</Button>
      </div>

      {eligible.length === 0 ? (
        <EmptyState
          title={t('servers.approveFirst')}
          description={t('servers.approveFirstBody')}
          action={<Link to="/agents" className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-accent-fg hover:bg-accent-hover">{t('servers.goToAgents')}</Link>}
        />
      ) : totalServers === 0 && totalSuggestions === 0 ? (
        <EmptyState
          title={t('servers.noneYet')}
          description={t('servers.noneYetBody')}
          action={<Button onClick={() => openAdd()}>{t('servers.addServer')}</Button>}
        />
      ) : (
        <div className="space-y-5">
          {eligible.map((agent) => {
            const servers = serversByAgent[agent.id] ?? [];
            const suggestions = suggestionsFor(agent, servers);
            return (
              <section key={agent.id} className="overflow-hidden rounded-xl border border-border bg-surface shadow-card">
                <div className="flex items-center justify-between gap-3 border-b border-border px-5 py-3">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-fg">{agent.name}</span>
                    <StatusBadge status={agent.status} />
                    <span className="text-xs text-fg-faint">{t('counts.servers', { count: servers.length })}</span>
                  </div>
                  <button onClick={() => openAdd(agent.id)} className="text-sm font-medium text-accent hover:underline">{t('servers.addServer')}</button>
                </div>
                {servers.length === 0 ? (
                  <p className="px-5 py-4 text-sm text-fg-faint">{t('servers.onAgentNone')}</p>
                ) : (
                  <ul className="divide-y divide-border">
                    {servers.map((s) => {
                      const used = domainsForServer(s.id);
                      return (
                        <li key={s.id} className="flex items-center justify-between gap-4 px-5 py-3">
                          <div className="min-w-0">
                            <p className="truncate font-medium text-fg">{s.name}</p>
                            <p className="truncate font-mono text-xs text-fg-faint">{s.address}{s.notes && <span className="font-sans"> · {s.notes}</span>}</p>
                          </div>
                          <div className="flex flex-shrink-0 items-center gap-4">
                            <span className="text-xs text-fg-faint">{t('servers.usedBy', { count: used })}</span>
                            <button onClick={() => setDeleteId(s.id)} className="text-xs font-medium text-danger-fg hover:underline">{t('common.remove')}</button>
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                )}
                {suggestions.length > 0 && (
                  <div className="border-t border-border bg-surface-2/30 px-5 py-3">
                    <p className="mb-2 text-xs font-medium text-fg-muted">{t('servers.suggestedTitle')}</p>
                    <ul className="space-y-2">
                      {suggestions.map((s) => (
                        <li key={s.addr} className="flex items-center justify-between gap-4">
                          <div className="min-w-0">
                            <p className="truncate font-mono text-xs text-fg">{s.addr}</p>
                            {s.names.length > 0 && (
                              <p className="truncate text-xs text-fg-faint">{t('servers.suggestedUsedBy', { names: s.names.join(', ') })}</p>
                            )}
                          </div>
                          <button
                            onClick={() => openAdd(agent.id, {
                              name: s.names[0] ?? s.addr,
                              address: s.addr,
                              notes: s.names.length > 0 ? t('servers.suggestedNote', { names: s.names.join(', ') }) : '',
                            })}
                            className="flex-shrink-0 text-xs font-medium text-accent hover:underline"
                          >
                            {t('servers.addSuggestion')}
                          </button>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </section>
            );
          })}
        </div>
      )}

      <Modal open={showAdd} onClose={() => setShowAdd(false)} title={t('servers.addServer')} description={t('servers.addModalSub')}>
        <div className="space-y-4">
          {error && <Callout tone="danger">{error}</Callout>}
          <Field label={t('servers.agent')} hint={t('servers.agentHint')}>
            <Select value={formAgent} onChange={(e) => setFormAgent(e.target.value)}>
              {eligible.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
            </Select>
          </Field>
          <Field label={t('common.name')}><Input value={name} onChange={(e) => setName(e.target.value)} placeholder={t('servers.namePh')} /></Field>
          <Field
            label={t('common.address')}
            hint={t('servers.addressHint')}
          >
            <Input value={address} onChange={(e) => setAddress(e.target.value)} className="font-mono" placeholder={t('servers.addressPh')} />
            {/* Detected-subnet shortcuts (§38): prefill the network prefix so the
                operator only types the host part. Always still editable. */}
            {(() => {
              const nets = agents.find((a) => a.id === formAgent)?.proxy_detection?.networks ?? [];
              if (nets.length === 0) return null;
              const seen = new Set<string>();
              const unique = nets.filter((n) => !seen.has(n.network) && seen.add(n.network));
              return (
                <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                  <span className="text-xs text-fg-faint">{t('servers.detectedNets')}</span>
                  {unique.map((n) => (
                    <button
                      key={n.network}
                      type="button"
                      onClick={() => setAddress(prefillFromNetwork(n))}
                      className="rounded-md border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[11px] text-fg-muted hover:border-border-strong hover:text-fg"
                      title={n.interface}
                    >
                      {n.network}
                    </button>
                  ))}
                </div>
              );
            })()}
          </Field>
          <Field label={t('common.notesOptional')} hint={t('common.optional')}><Input value={notes} onChange={(e) => setNotes(e.target.value)} placeholder={t('servers.notesPh')} /></Field>
          <div className="flex justify-end gap-3 pt-1">
            <Button variant="secondary" onClick={() => setShowAdd(false)}>{t('common.cancel')}</Button>
            <Button onClick={handleCreate} loading={saving} disabled={!formAgent || !name || !address}>{t('servers.addServer')}</Button>
          </div>
        </div>
      </Modal>

      <ConfirmDialog
        open={deleteId !== null}
        onClose={() => setDeleteId(null)}
        onConfirm={handleDelete}
        title={t('common.remove')}
        message={t('servers.removeConfirm')}
        confirmLabel={t('common.remove')}
        danger
        loading={deleting}
      />
    </div>
  );
}

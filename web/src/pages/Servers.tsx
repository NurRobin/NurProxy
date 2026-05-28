import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { api } from '../lib/api';
import type { Agent, Server, Domain } from '../lib/types';
import StatusBadge from '../components/StatusBadge';
import Modal from '../components/Modal';
import ConfirmDialog from '../components/ConfirmDialog';
import EmptyState from '../components/EmptyState';
import Button from '../components/Button';
import Callout from '../components/Callout';
import HelpTip from '../components/HelpTip';
import { Field, Input, Select } from '../components/Field';
import { useToast, errMessage } from '../components/toast-context';

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

  function openAdd(agentId?: string) {
    setFormAgent(agentId ?? eligible[0]?.id ?? '');
    setName(''); setAddress(''); setNotes(''); setError('');
    setShowAdd(true);
  }

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
      ) : totalServers === 0 ? (
        <EmptyState
          title={t('servers.noneYet')}
          description={t('servers.noneYetBody')}
          action={<Button onClick={() => openAdd()}>{t('servers.addServer')}</Button>}
        />
      ) : (
        <div className="space-y-5">
          {eligible.map((agent) => {
            const servers = serversByAgent[agent.id] ?? [];
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

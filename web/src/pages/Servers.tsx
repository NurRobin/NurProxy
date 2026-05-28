import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
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
      toast.error(errMessage(err, 'Couldn’t load servers.'));
    } finally {
      setLoading(false);
    }
  }, [toast]);

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
      toast.success('Server added.');
      setShowAdd(false);
      fetchData();
    } catch (err) {
      setError(errMessage(err, 'Failed to add server.'));
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    if (!deleteId) return;
    try { await api.deleteServer(deleteId); toast.success('Server removed.'); setDeleteId(null); fetchData(); }
    catch (err) { toast.error(errMessage(err, 'Failed to remove server.')); }
  }

  const domainsForServer = (sid: string) => domains.filter((d) => d.server_id === sid && d.status !== 'deleting').length;
  const totalServers = Object.values(serversByAgent).reduce((n, s) => n + s.length, 0);

  if (loading) return <div className="py-12 text-center text-sm text-fg-muted">Loading servers…</div>;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 font-display text-3xl font-bold tracking-tight text-fg">
            Servers <HelpTip term="server" />
          </h1>
          <p className="mt-1 text-sm text-fg-muted">Backend addresses your agents proxy to. Each belongs to one agent.</p>
        </div>
        <Button onClick={() => openAdd()} disabled={eligible.length === 0}>Add server</Button>
      </div>

      {eligible.length === 0 ? (
        <EmptyState
          title="Approve an agent first"
          description="Servers live behind an agent. Connect and approve an agent, then register the servers it proxies to."
          action={<Link to="/agents" className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-accent-fg hover:bg-accent-hover">Go to Agents</Link>}
        />
      ) : totalServers === 0 ? (
        <EmptyState
          title="No servers yet"
          description="Register the first backend an agent should forward traffic to — e.g. a web app on your LAN."
          action={<Button onClick={() => openAdd()}>Add server</Button>}
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
                    <span className="text-xs text-fg-faint">{servers.length} server{servers.length !== 1 ? 's' : ''}</span>
                  </div>
                  <button onClick={() => openAdd(agent.id)} className="text-sm font-medium text-accent hover:underline">+ Add server</button>
                </div>
                {servers.length === 0 ? (
                  <p className="px-5 py-4 text-sm text-fg-faint">No servers on this agent yet.</p>
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
                            <span className="text-xs text-fg-faint">{used} domain{used !== 1 ? 's' : ''}</span>
                            <button onClick={() => setDeleteId(s.id)} className="text-xs font-medium text-danger-fg hover:underline">Remove</button>
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

      <Modal open={showAdd} onClose={() => setShowAdd(false)} title="Add server" description="A backend address one of your agents forwards traffic to.">
        <div className="space-y-4">
          {error && <Callout tone="danger">{error}</Callout>}
          <Field label="Agent" hint="The agent that will reach this server.">
            <Select value={formAgent} onChange={(e) => setFormAgent(e.target.value)}>
              {eligible.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
            </Select>
          </Field>
          <Field label="Name"><Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Web app" /></Field>
          <Field
            label="Address"
            hint="An IP or hostname reachable from this agent — i.e. how the agent reaches the server (LAN IP, container name, VPN address)."
          >
            <Input value={address} onChange={(e) => setAddress(e.target.value)} className="font-mono" placeholder="10.0.0.4  ·  app.internal" />
          </Field>
          <Field label="Notes" hint="Optional."><Input value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Description" /></Field>
          <div className="flex justify-end gap-3 pt-1">
            <Button variant="secondary" onClick={() => setShowAdd(false)}>Cancel</Button>
            <Button onClick={handleCreate} loading={saving} disabled={!formAgent || !name || !address}>Add server</Button>
          </div>
        </div>
      </Modal>

      <ConfirmDialog
        open={deleteId !== null}
        onClose={() => setDeleteId(null)}
        onConfirm={handleDelete}
        title="Remove server"
        message="Remove this server? Domains pointing at it will be affected until you repoint them."
        confirmLabel="Remove"
        danger
      />
    </div>
  );
}

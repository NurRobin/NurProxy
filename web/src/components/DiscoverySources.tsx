import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '../lib/api';
import type { DiscoverySource } from '../lib/types';
import { SYNC_INTERVALS } from '../lib/discovery';
import Modal from './Modal';
import ConfirmDialog from './ConfirmDialog';
import Button from './Button';
import Callout from './Callout';
import { Checkbox, Field, Input, PasswordInput, Select, Textarea } from './Field';
import { useToast, errMessage } from './toast-context';

interface Form {
  name: string;
  url: string;
  token_id: string;
  token_secret: string;
  verify_tls: boolean;
  fingerprint: string;
  ca_pem: string;
  sync_interval: number;
}

const EMPTY: Form = { name: '', url: '', token_id: '', token_secret: '', verify_tls: true, fingerprint: '', ca_pem: '', sync_interval: 0 };

function configOf(f: Form): Record<string, unknown> {
  return {
    url: f.url.trim(),
    token_id: f.token_id.trim(),
    // On edit an empty secret keeps the stored one.
    token_secret: f.token_secret.trim(),
    verify_tls: f.verify_tls,
    fingerprint: f.fingerprint.trim(),
    ca_pem: f.ca_pem.trim(),
  };
}

/**
 * Settings section for server discovery sources (#25): add, edit, test and
 * delete Proxmox VE sources, and run them on demand. The token secret is write
 * only; the API never returns it.
 */
export default function DiscoverySources() {
  const { t, i18n } = useTranslation();
  const toast = useToast();
  const [sources, setSources] = useState<DiscoverySource[]>([]);
  const [editing, setEditing] = useState<DiscoverySource | null>(null);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<Form>(EMPTY);
  const [error, setError] = useState('');
  const [testMsg, setTestMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [skipTest, setSkipTest] = useState(false);
  const [running, setRunning] = useState<string | null>(null);
  const [deleteId, setDeleteId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try { setSources(await api.listDiscoverySources()); }
    catch (err) { toast.error(errMessage(err, t('discovery.loadFailed'))); }
  }, [toast, t]);
  useEffect(() => { load(); }, [load]);

  function openAdd() {
    setEditing(null); setForm(EMPTY); setError(''); setTestMsg(null); setSkipTest(false); setOpen(true);
  }

  function openEdit(s: DiscoverySource) {
    // settings is the stored config minus the secret, which is never sent back.
    const str = (k: string) => (typeof s.settings[k] === 'string' ? (s.settings[k] as string) : '');
    setEditing(s);
    setForm({
      name: s.name, url: str('url'), token_id: str('token_id'), token_secret: '',
      verify_tls: s.settings.verify_tls === true, fingerprint: str('fingerprint'), ca_pem: str('ca_pem'),
      sync_interval: s.sync_interval,
    });
    setError(''); setTestMsg(null); setSkipTest(false); setOpen(true);
  }

  const set = <K extends keyof Form>(k: K, v: Form[K]) => { setForm((f) => ({ ...f, [k]: v })); setTestMsg(null); };

  async function handleTest() {
    setTesting(true); setTestMsg(null);
    try {
      const res = editing
        ? await api.testDiscoverySource({ source_id: editing.id, config: configOf(form) })
        : await api.testDiscoverySource({ type: 'proxmox', config: configOf(form) });
      setTestMsg({ ok: res.valid, text: res.valid ? t('discovery.testOk') : res.message });
    } catch (err) {
      setTestMsg({ ok: false, text: errMessage(err, t('discovery.testFailed')) });
    } finally { setTesting(false); }
  }

  async function handleSave() {
    setSaving(true); setError('');
    try {
      if (editing) {
        await api.updateDiscoverySource(editing.id, { name: form.name.trim(), config: configOf(form), sync_interval: form.sync_interval, skip_test: skipTest });
      } else {
        await api.createDiscoverySource({ type: 'proxmox', name: form.name.trim(), config: configOf(form), sync_interval: form.sync_interval, skip_test: skipTest });
      }
      toast.success(t('discovery.saved'));
      setOpen(false);
      load();
    } catch (err) {
      setError(errMessage(err, t('discovery.saveFailed')));
    } finally { setSaving(false); }
  }

  async function handleRun(id: string) {
    setRunning(id);
    try {
      const v = await api.runDiscovery(id);
      toast.success(t('discovery.runDone', { count: v.candidates.length }));
    } catch (err) {
      toast.error(errMessage(err, t('discovery.runFailed')));
    } finally { setRunning(null); load(); }
  }

  async function handleDelete() {
    if (!deleteId) return;
    try { await api.deleteDiscoverySource(deleteId); toast.success(t('discovery.deleted')); setDeleteId(null); load(); }
    catch (err) { toast.error(errMessage(err, t('discovery.deleteFailed'))); }
  }

  const fmtTime = (iso?: string) => (iso ? new Date(iso).toLocaleString(i18n.resolvedLanguage) : '');
  const intervalLabel = (s: number) =>
    s === 0 ? t('discovery.syncManual')
      : s < 3600 ? t('discovery.syncEveryMinutes', { count: s / 60 })
        : t('discovery.syncEveryHours', { count: s / 3600 });
  const canSave = form.name.trim() && form.url.trim() && form.token_id.trim() && (editing || form.token_secret.trim());

  return (
    <section className="rounded-xl border border-border bg-surface p-6 shadow-card">
      <div className="flex items-center justify-between gap-4">
        <h2 className="text-lg font-semibold text-fg">{t('discovery.sectionTitle')}</h2>
        <Button size="sm" onClick={openAdd}>{t('discovery.addSource')}</Button>
      </div>
      <p className="mb-4 mt-1 text-sm text-fg-muted">{t('discovery.sectionSub')}</p>
      {sources.length === 0 ? (
        <p className="text-sm text-fg-faint">{t('discovery.none')}</p>
      ) : (
        <div className="space-y-3">
          {sources.map((s) => (
            <div key={s.id} className="rounded-lg border border-border bg-surface-2 px-4 py-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex min-w-0 items-center gap-2">
                  <span className="font-medium text-fg">{s.name}</span>
                  <span className="rounded bg-surface-3 px-1.5 py-0.5 text-xs text-fg-faint">{s.type_name}</span>
                  <span className="truncate font-mono text-xs text-fg-faint">{s.summary}</span>
                </div>
                <div className="flex items-center gap-3">
                  <button onClick={() => handleRun(s.id)} disabled={running === s.id} className="text-xs font-medium text-accent hover:underline disabled:opacity-50">
                    {running === s.id ? t('discovery.running') : t('discovery.runNow')}
                  </button>
                  <button onClick={() => openEdit(s)} className="text-xs font-medium text-accent hover:underline">{t('discovery.edit')}</button>
                  <button onClick={() => setDeleteId(s.id)} className="text-xs font-medium text-danger-fg hover:underline">{t('common.delete')}</button>
                </div>
              </div>
              <p className="mt-1 text-xs text-fg-faint">
                {s.last_run_at ? t('discovery.lastRun', { when: fmtTime(s.last_run_at), count: s.candidates, imported: s.imported }) : t('discovery.neverRun')}
                {' · '}{intervalLabel(s.sync_interval)}
                {s.missing > 0 && <span className="text-warning-fg">{' · '}{t('discovery.missingCount', { count: s.missing })}</span>}
              </p>
              {s.last_error && <p className="mt-1 break-words text-xs text-danger-fg">{t('discovery.lastError', { error: s.last_error })}</p>}
            </div>
          ))}
        </div>
      )}

      <Modal open={open} onClose={() => setOpen(false)} title={editing ? t('discovery.editTitle') : t('discovery.addTitle')} description={t('discovery.modalSub')} wide>
        <div className="space-y-4">
          {error && <Callout tone="danger">{error}</Callout>}
          <Field label={t('common.name')}><Input value={form.name} onChange={(e) => set('name', e.target.value)} placeholder={t('discovery.namePh')} /></Field>
          <Field label={t('discovery.url')} hint={t('discovery.urlHint')}>
            <Input value={form.url} onChange={(e) => set('url', e.target.value)} className="font-mono" placeholder="https://pve.lan:8006" />
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t('discovery.tokenId')} hint={t('discovery.tokenIdHint')}>
              <Input value={form.token_id} onChange={(e) => set('token_id', e.target.value)} className="font-mono" placeholder="nurproxy@pve!discovery" />
            </Field>
            <Field label={t('discovery.tokenSecret')} hint={editing ? t('discovery.tokenSecretKeep') : undefined}>
              <PasswordInput value={form.token_secret} onChange={(e) => set('token_secret', e.target.value)} className="font-mono" autoComplete="off" />
            </Field>
          </div>
          <Callout tone="info">{t('discovery.permissionsHint')}</Callout>
          <Checkbox label={t('discovery.verifyTls')} checked={form.verify_tls} onChange={(e) => set('verify_tls', e.target.checked)} />
          <Field label={t('discovery.fingerprint')} hint={t('discovery.fingerprintHint')}>
            <Input value={form.fingerprint} onChange={(e) => set('fingerprint', e.target.value)} className="font-mono" placeholder="AB:CD:…" />
          </Field>
          <Field label={t('discovery.caPem')} hint={t('discovery.caPemHint')}>
            <Textarea value={form.ca_pem} onChange={(e) => set('ca_pem', e.target.value)} rows={3} className="font-mono text-xs" placeholder="-----BEGIN CERTIFICATE-----" />
          </Field>
          {!form.verify_tls && !form.fingerprint.trim() && <Callout tone="warning">{t('discovery.insecureWarning')}</Callout>}
          <Field label={t('discovery.syncInterval')} hint={t('discovery.syncIntervalHint')} className="max-w-xs">
            <Select value={String(form.sync_interval)} onChange={(e) => set('sync_interval', Number(e.target.value))}>
              {SYNC_INTERVALS.map((s) => <option key={s} value={s}>{intervalLabel(s)}</option>)}
            </Select>
          </Field>
          <Checkbox label={t('discovery.skipTest')} checked={skipTest} onChange={(e) => setSkipTest(e.target.checked)} />
          {testMsg && <Callout tone={testMsg.ok ? 'success' : 'danger'}>{testMsg.text}</Callout>}
          <div className="flex flex-wrap justify-between gap-3 pt-1">
            <Button variant="secondary" onClick={() => setOpen(false)}>{t('common.cancel')}</Button>
            <div className="flex gap-3">
              <Button variant="secondary" onClick={handleTest} loading={testing} disabled={!form.url.trim() || !form.token_id.trim() || (!editing && !form.token_secret.trim())}>{t('discovery.test')}</Button>
              <Button onClick={handleSave} loading={saving} disabled={!canSave}>{t('common.save')}</Button>
            </div>
          </div>
        </div>
      </Modal>

      <ConfirmDialog
        open={deleteId !== null}
        onClose={() => setDeleteId(null)}
        onConfirm={handleDelete}
        title={t('discovery.deleteTitle')}
        message={t('discovery.deleteMsg')}
        confirmLabel={t('common.delete')}
        danger
      />
    </section>
  );
}

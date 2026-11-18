import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '../lib/api';
import type { Agent, DiscoverySource, DiscoveryView } from '../lib/types';
import { importItems, initialRows, isUsableAddress, rowsMissingAddress, type ImportRow } from '../lib/discovery';
import Modal from './Modal';
import Button from './Button';
import Callout from './Callout';
import { Field, Input, Select } from './Field';
import { useToast, errMessage } from './toast-context';

interface Props {
  open: boolean;
  onClose: () => void;
  agent: Agent | null;
  agents: Agent[];
  sources: DiscoverySource[];
  onImported: () => void;
}

/**
 * Lists the machines a discovery source reported and imports the selected ones
 * as servers under one agent (#25). Machines already imported (under any
 * agent) are shown but cannot be selected; names and addresses stay editable
 * before and after the import.
 */
export default function DiscoverImportModal({ open, onClose, agent, agents, sources, onImported }: Props) {
  const { t, i18n } = useTranslation();
  const toast = useToast();
  // The parent mounts the modal only while it is open, so state starts fresh.
  const [sourceId, setSourceId] = useState(() => sources[0]?.id ?? '');
  const [view, setView] = useState<DiscoveryView | null>(null);
  const [rows, setRows] = useState<ImportRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState('');

  const show = useCallback((v: DiscoveryView) => { setView(v); setRows(initialRows(v.candidates)); }, []);

  useEffect(() => {
    if (!open || !sourceId) return;
    let cancelled = false;
    setLoading(true); setError('');
    api.getDiscoveryCandidates(sourceId)
      .then((v) => { if (!cancelled) show(v); })
      .catch((err) => { if (!cancelled) setError(errMessage(err, t('discovery.loadFailed'))); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [open, sourceId, show, t]);

  async function handleRun() {
    setRunning(true); setError('');
    try { show(await api.runDiscovery(sourceId)); }
    catch (err) { setError(errMessage(err, t('discovery.runFailed'))); }
    finally { setRunning(false); }
  }

  async function handleImport() {
    if (!agent || !view) return;
    setImporting(true); setError('');
    try {
      const res = await api.importServers(agent.id, { source_id: sourceId, items: importItems(rows, view.candidates) });
      toast.success(t('discovery.imported', { count: res.created.length }));
      if (res.skipped.length > 0) toast.push(t('discovery.skipped', { count: res.skipped.length }), 'info');
      onImported();
      onClose();
    } catch (err) {
      setError(errMessage(err, t('discovery.importFailed')));
    } finally { setImporting(false); }
  }

  const update = (id: string, patch: Partial<ImportRow>) =>
    setRows((rs) => rs.map((r) => (r.external_id === id ? { ...r, ...patch } : r)));
  const agentName = (id?: string) => agents.find((a) => a.id === id)?.name ?? id ?? '';
  const selectable = view?.candidates.filter((c) => !c.server_id) ?? [];
  const selected = rows.filter((r) => r.selected && selectable.some((c) => c.external_id === r.external_id));
  const missingAddr = rowsMissingAddress(selected);
  const allSelected = selectable.length > 0 && selected.length === selectable.length;

  return (
    <Modal open={open} onClose={onClose} title={t('discovery.importTitle', { agent: agent?.name ?? '' })} description={t('discovery.importSub')} wide>
      <div className="space-y-4">
        {error && <Callout tone="danger">{error}</Callout>}
        <div className="flex flex-wrap items-end justify-between gap-3">
          {sources.length > 1 ? (
            <Field label={t('discovery.source')} className="min-w-48">
              <Select value={sourceId} onChange={(e) => setSourceId(e.target.value)}>
                {sources.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
              </Select>
            </Field>
          ) : (
            <p className="text-sm text-fg-muted">{sources[0]?.name} <span className="font-mono text-xs text-fg-faint">{sources[0]?.summary}</span></p>
          )}
          <div className="flex items-center gap-3">
            {view?.last_run_at && <span className="text-xs text-fg-faint">{t('discovery.lastRunShort', { when: new Date(view.last_run_at).toLocaleString(i18n.resolvedLanguage) })}</span>}
            <Button size="sm" variant="secondary" onClick={handleRun} loading={running} disabled={!sourceId}>{t('discovery.runNow')}</Button>
          </div>
        </div>

        {view?.last_error && <Callout tone="danger">{t('discovery.lastError', { error: view.last_error })}</Callout>}
        {(view?.warnings ?? []).map((w) => <Callout key={w} tone="warning">{w}</Callout>)}
        {(view?.missing.length ?? 0) > 0 && (
          <Callout tone="warning">{t('discovery.missingList', { names: view!.missing.map((s) => s.name).join(', ') })}</Callout>
        )}

        {loading ? (
          <p className="py-6 text-center text-sm text-fg-muted">{t('common.loading')}</p>
        ) : !view?.has_result ? (
          <p className="py-6 text-center text-sm text-fg-faint">{t('discovery.noResult')}</p>
        ) : view.candidates.length === 0 ? (
          <p className="py-6 text-center text-sm text-fg-faint">{t('discovery.noMachines')}</p>
        ) : (
          <div className="overflow-hidden rounded-lg border border-border">
            <div className="flex items-center gap-3 border-b border-border bg-surface-2 px-3 py-2 text-xs text-fg-muted">
              <input
                type="checkbox"
                aria-label={t('discovery.selectAll')}
                checked={allSelected}
                disabled={selectable.length === 0}
                onChange={(e) => setRows((rs) => rs.map((r) => (selectable.some((c) => c.external_id === r.external_id) ? { ...r, selected: e.target.checked } : r)))}
              />
              <span>{t('discovery.selectedCount', { count: selected.length, total: selectable.length })}</span>
            </div>
            <ul className="max-h-[50vh] divide-y divide-border overflow-y-auto">
              {view.candidates.map((c) => {
                const row = rows.find((r) => r.external_id === c.external_id);
                if (!row) return null;
                const imported = !!c.server_id;
                const listId = `addrs-${c.external_id.replace(/[^a-zA-Z0-9]/g, '-')}`;
                return (
                  <li key={c.external_id} className={`flex gap-3 px-3 py-2.5 ${imported ? 'opacity-60' : ''}`}>
                    <input
                      type="checkbox"
                      className="mt-2"
                      aria-label={c.name}
                      checked={row.selected && !imported}
                      disabled={imported}
                      onChange={(e) => update(c.external_id, { selected: e.target.checked })}
                    />
                    <div className="min-w-0 flex-1 space-y-1.5">
                      <div className="flex flex-wrap items-center gap-2 text-xs text-fg-faint">
                        <span className="rounded bg-surface-3 px-1.5 py-0.5 uppercase">{c.kind}</span>
                        <span className="font-mono">{c.external_id}</span>
                        {c.status && <span>{c.status}</span>}
                        {c.address_source && <span>· {t(`discovery.addrSource.${c.address_source}`, { defaultValue: c.address_source })}</span>}
                        {imported && <span className="font-medium text-fg-muted">· {t('discovery.alreadyImported', { name: c.server_name, agent: agentName(c.agent_id) })}</span>}
                      </div>
                      {!imported && (
                        <div className="grid gap-2 sm:grid-cols-2">
                          <Input value={row.name} aria-label={t('common.name')} onChange={(e) => update(c.external_id, { name: e.target.value })} />
                          <Input
                            value={row.address}
                            aria-label={t('common.address')}
                            list={listId}
                            className="font-mono"
                            placeholder={t('discovery.addressNeeded')}
                            onChange={(e) => update(c.external_id, { address: e.target.value, selected: row.selected || e.target.value.trim() !== '' })}
                          />
                          <datalist id={listId}>
                            {c.addresses.filter((a) => isUsableAddress(a.kind)).map((a) => <option key={a.ip} value={a.ip} />)}
                          </datalist>
                        </div>
                      )}
                      {c.addresses.length > 0 && (
                        <div className="flex flex-wrap gap-1.5">
                          {c.addresses.map((a) => (
                            <span
                              key={a.ip}
                              title={a.interface}
                              className={`rounded-md border px-1.5 py-0.5 font-mono text-[11px] ${isUsableAddress(a.kind) ? 'border-border bg-surface-2 text-fg-muted' : 'border-dashed border-border text-fg-faint line-through decoration-fg-faint/50'}`}
                            >
                              {a.ip}{a.interface ? ` · ${a.interface}` : ''}{isUsableAddress(a.kind) ? '' : ` · ${t(`discovery.addrKind.${a.kind}`)}`}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>
          </div>
        )}

        {missingAddr.length > 0 && <Callout tone="warning">{t('discovery.needAddress', { count: missingAddr.length })}</Callout>}
        <div className="flex justify-between gap-3 pt-1">
          <Button variant="secondary" onClick={onClose}>{t('common.cancel')}</Button>
          <Button onClick={handleImport} loading={importing} disabled={!view?.has_result || selected.length === 0 || missingAddr.length > 0}>
            {t('discovery.importButton', { count: selected.length })}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

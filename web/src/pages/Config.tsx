import { useState, useEffect, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { ChevronLeft, FileCode, RotateCcw, History } from 'lucide-react';
import { api } from '../lib/api';
import type { Agent, ConfigArtifact, ConfigArtifactVersion } from '../lib/types';
import { formatRelativeTime } from '../lib/utils';
import { usePolling } from '../lib/usePolling';
import ArtifactStatusBadge from '../components/ArtifactStatusBadge';
import DiffView from '../components/DiffView';
import Modal from '../components/Modal';
import EmptyState from '../components/EmptyState';
import Button from '../components/Button';
import Callout from '../components/Callout';
import HelpTip from '../components/HelpTip';
import { useToast, errMessage } from '../components/toast-context';

// Config (Phase 3): the central versioned config store surfaced for operators.
// Per-artifact view (content + status + last_error), version history with a diff
// between any two versions, rollback-to-version, and the drift-review flow
// (diff + Accept/Reject). When more than three artifacts drift at once a bulk
// review banner offers accept-all / reject-all (§11). Every action routes through
// the audited orchestrator endpoints; the dashboard never touches a host directly.

const BULK_THRESHOLD = 3;

export default function Config() {
  const { t } = useTranslation();
  const toast = useToast();
  const [artifacts, setArtifacts] = useState<ConfigArtifact[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [bulkOpen, setBulkOpen] = useState(false);
  const [bulkBusy, setBulkBusy] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const [arts, ags] = await Promise.all([api.listArtifacts(), api.listAgents()]);
      setArtifacts(arts);
      setAgents(ags);
    } catch (err) {
      toast.error(errMessage(err, t('config.loadFailed')));
    } finally {
      setLoading(false);
    }
  }, [toast, t]);

  // Poll so drift flagged on the next agent heartbeat surfaces without a reload.
  usePolling(fetchData, 15000);

  const agentName = useCallback(
    (id: string) => agents.find((a) => a.id === id)?.name ?? id,
    [agents],
  );

  const drifted = useMemo(() => artifacts.filter((a) => a.drifted), [artifacts]);
  const selected = artifacts.find((a) => a.id === selectedId) ?? null;

  // Group artifacts by agent for the master list.
  const groups = useMemo(() => {
    const byAgent = new Map<string, ConfigArtifact[]>();
    for (const a of artifacts) {
      const list = byAgent.get(a.agent_id) ?? [];
      list.push(a);
      byAgent.set(a.agent_id, list);
    }
    return [...byAgent.entries()].sort((x, y) => agentName(x[0]).localeCompare(agentName(y[0])));
  }, [artifacts, agentName]);

  async function handleBulk(action: 'accept' | 'reject') {
    setBulkBusy(true);
    try {
      const res = await api.bulkArtifacts(action);
      toast.success(t('config.bulkDone', { resolved: res.resolved, total: res.total }));
      setBulkOpen(false);
      fetchData();
    } catch (err) {
      toast.error(errMessage(err, t('config.bulkFailed')));
    } finally {
      setBulkBusy(false);
    }
  }

  if (loading) return <div className="py-12 text-center text-sm text-fg-muted">{t('common.loading')}</div>;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="flex items-center gap-2 font-display text-3xl font-bold tracking-tight text-fg">
          {t('config.title')} <HelpTip term="config-artifact" />
        </h1>
        <p className="mt-1 text-sm text-fg-muted">{t('config.subtitle')}</p>
      </div>

      {/* Bulk-review banner: >3 drift at once (e.g. after an OS package update). */}
      {drifted.length > BULK_THRESHOLD && (
        <Callout tone="warning" title={t('config.bulkBannerTitle', { count: drifted.length })}>
          <p>{t('config.bulkBannerBody')}</p>
          <div className="mt-2">
            <Button size="sm" variant="secondary" onClick={() => setBulkOpen(true)}>
              {t('config.bulkReview')}
            </Button>
          </div>
        </Callout>
      )}

      {artifacts.length === 0 ? (
        <EmptyState
          icon={<FileCode className="h-6 w-6" />}
          title={t('config.none')}
          description={t('config.noneBody')}
        />
      ) : (
        <div className="grid gap-6 md:grid-cols-[22rem_1fr]">
          {/* Master list, grouped by agent */}
          <div className={selected ? 'hidden md:block' : 'block'}>
            <div className="space-y-5">
              {groups.map(([agentID, list]) => (
                <div key={agentID}>
                  <h2 className="mb-2 px-1 text-xs font-semibold uppercase tracking-wide text-fg-faint">
                    {agentName(agentID)}
                  </h2>
                  <div className="space-y-2">
                    {list.map((a) => (
                      <ArtifactRow key={a.id} active={selectedId === a.id} artifact={a} onClick={() => setSelectedId(a.id)} />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Detail */}
          <div className={selected ? 'block' : 'hidden md:block'}>
            {!selected ? (
              <div className="flex h-full min-h-48 items-center justify-center rounded-xl border border-dashed border-border text-sm text-fg-faint">
                {t('config.select')}
              </div>
            ) : (
              <ArtifactDetail
                artifact={selected}
                agentName={agentName(selected.agent_id)}
                onBack={() => setSelectedId(null)}
                onChanged={fetchData}
              />
            )}
          </div>
        </div>
      )}

      {/* Bulk review modal: combined accept-all / reject-all over all drifted. */}
      <Modal open={bulkOpen} onClose={() => setBulkOpen(false)} title={t('config.bulkReview')} description={t('config.bulkModalDesc', { count: drifted.length })} wide>
        <div className="space-y-4">
          <Callout tone="warning">{t('config.bulkModalWarn')}</Callout>
          <div className="max-h-[24rem] space-y-3 overflow-auto">
            {drifted.map((a) => (
              <div key={a.id} className="rounded-lg border border-border">
                <div className="flex items-center justify-between gap-2 border-b border-border bg-surface-2 px-3 py-1.5 text-xs">
                  <span className="truncate font-mono text-fg-muted">{a.target.path}</span>
                  <span className="shrink-0 text-fg-faint">{agentName(a.agent_id)}</span>
                </div>
                <div className="p-2">
                  <pre className="max-h-40 overflow-auto rounded bg-surface-2 p-2 font-mono text-xs leading-relaxed text-fg-muted">
                    {a.content || t('config.empty')}
                  </pre>
                  <p className="mt-1 px-1 text-xs text-fg-faint">{t('config.bulkRowNote')}</p>
                </div>
              </div>
            ))}
          </div>
          <div className="flex flex-wrap justify-end gap-3 pt-1">
            <Button variant="secondary" onClick={() => setBulkOpen(false)}>{t('common.cancel')}</Button>
            <Button variant="danger-ghost" onClick={() => handleBulk('reject')} loading={bulkBusy}>{t('config.rejectAll')}</Button>
            <Button onClick={() => handleBulk('accept')} loading={bulkBusy}>{t('config.acceptAll')}</Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

function ArtifactRow({ artifact, active, onClick }: { artifact: ConfigArtifact; active: boolean; onClick: () => void }) {
  const { t } = useTranslation();
  return (
    <button
      onClick={onClick}
      className={`flex w-full items-center justify-between gap-3 rounded-lg border px-4 py-3 text-left transition-colors ${
        active
          ? 'border-accent bg-accent-soft'
          : artifact.drifted
            ? 'border-warning/40 bg-warning-soft/40 hover:border-warning/60'
            : 'border-border bg-surface hover:border-border-strong'
      }`}
    >
      <div className="min-w-0">
        <p className="truncate font-mono text-sm font-medium text-fg">{shortPath(artifact.target.path)}</p>
        <p className="truncate text-xs text-fg-faint">
          {artifact.backend} · {t(`config.source.${artifact.source}`)}
        </p>
      </div>
      <ArtifactStatusBadge state={artifact.apply_state} />
    </button>
  );
}

function ArtifactDetail({
  artifact,
  agentName,
  onBack,
  onChanged,
}: {
  artifact: ConfigArtifact;
  agentName: string;
  onBack: () => void;
  onChanged: () => void;
}) {
  const { t } = useTranslation();
  const toast = useToast();
  const [versions, setVersions] = useState<ConfigArtifactVersion[]>([]);
  const [loadingVersions, setLoadingVersions] = useState(true);
  const [busy, setBusy] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);

  const loadVersions = useCallback(async () => {
    setLoadingVersions(true);
    try {
      setVersions(await api.listArtifactVersions(artifact.id));
    } catch (err) {
      toast.error(errMessage(err, t('config.versionsFailed')));
    } finally {
      setLoadingVersions(false);
    }
  }, [artifact.id, toast, t]);

  useEffect(() => { loadVersions(); }, [loadVersions]);

  async function handleAccept() {
    setBusy(true);
    try {
      await api.acceptArtifact(artifact.id);
      toast.success(t('config.accepted'));
      onChanged();
      loadVersions();
    } catch (err) {
      toast.error(errMessage(err, t('config.acceptFailed')));
    } finally {
      setBusy(false);
    }
  }

  async function handleReject() {
    setBusy(true);
    try {
      await api.rejectArtifact(artifact.id);
      toast.success(t('config.rejected'));
      onChanged();
      loadVersions();
    } catch (err) {
      toast.error(errMessage(err, t('config.rejectFailed')));
    } finally {
      setBusy(false);
    }
  }

  async function handleRollback(version: number) {
    setBusy(true);
    try {
      await api.rollbackArtifact(artifact.id, version);
      toast.success(t('config.rolledBack', { version }));
      setHistoryOpen(false);
      onChanged();
      loadVersions();
    } catch (err) {
      toast.error(errMessage(err, t('config.rollbackFailed')));
    } finally {
      setBusy(false);
    }
  }

  // The accepted (live) version's content, for the drift diff baseline.
  const liveVersion = versions.find((v) => v.version === artifact.live_version);
  const liveContent = liveVersion?.content ?? artifact.content;
  // The orchestrator preserves the accepted content while an artifact is drifted
  // and learns the on-disk bytes only on the next apply-ACK (the heartbeat carries
  // just a checksum). So when the stored content still equals the accepted state
  // we have a checksum mismatch but no on-disk bytes to diff yet.
  const onDiskCaptured = artifact.content !== liveContent;

  return (
    <div className="rounded-xl border border-border bg-surface p-6 shadow-card">
      <button onClick={onBack} className="mb-4 inline-flex items-center gap-1 text-sm text-fg-muted hover:text-fg md:hidden">
        <ChevronLeft className="h-4 w-4" />
        {t('common.back')}
      </button>

      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h2 className="truncate font-mono text-lg font-semibold text-fg">{artifact.target.path}</h2>
            <ArtifactStatusBadge state={artifact.apply_state} />
          </div>
          <p className="text-sm text-fg-muted">
            {agentName} · {artifact.backend} · {t(`config.source.${artifact.source}`)} · {t('config.versionN', { n: artifact.live_version })}
          </p>
        </div>
        <Button variant="secondary" size="sm" onClick={() => setHistoryOpen(true)}>
          <History className="h-4 w-4" />
          {t('config.history')}
        </Button>
      </div>

      {/* apply_failed → surface the last error prominently (§15 cross-cutting). */}
      {artifact.apply_state === 'apply_failed' && artifact.last_error && (
        <div className="mt-4">
          <Callout tone="danger" title={t('config.applyFailed')}>{artifact.last_error}</Callout>
        </div>
      )}

      {/* Drift-review flow: on-disk ≠ accepted ⇒ diff + Accept / Reject (§11). */}
      {artifact.drifted ? (
        <div className="mt-5 space-y-3">
          <Callout tone="warning" title={t('config.driftedTitle')}>{t('config.driftedBody')}</Callout>
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-faint">{t('config.driftDiff')}</h3>
            {onDiskCaptured ? (
              <DiffView
                before={liveContent}
                after={artifact.content}
                beforeLabel={t('config.accepted')}
                afterLabel={t('config.onDisk')}
              />
            ) : (
              <Callout tone="neutral">{t('config.driftChecksumOnly')}</Callout>
            )}
          </div>
          <div className="flex flex-wrap justify-end gap-3">
            <Button variant="danger-ghost" onClick={handleReject} loading={busy}>{t('config.reject')}</Button>
            <Button onClick={handleAccept} loading={busy}>{t('config.accept')}</Button>
          </div>
        </div>
      ) : (
        <div className="mt-5">
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-faint">{t('config.content')}</h3>
          <pre className="max-h-[28rem] overflow-auto rounded-lg border border-border bg-surface-2 p-3 font-mono text-xs leading-relaxed text-fg-muted">
            {artifact.content || t('config.empty')}
          </pre>
        </div>
      )}

      <dl className="mt-5 space-y-2 border-t border-border pt-4 text-sm">
        <Row label={t('config.target')} value={<span className="font-mono text-xs">{artifact.target.kind}</span>} />
        <Row label={t('config.enabled')} value={artifact.enabled ? t('config.yes') : t('config.no')} />
        <Row label={t('config.checksum')} value={<span className="font-mono text-xs">{artifact.checksum.slice(0, 16)}</span>} />
        <Row label={t('config.updated')} value={formatRelativeTime(artifact.updated_at)} />
      </dl>

      <Modal open={historyOpen} onClose={() => setHistoryOpen(false)} title={t('config.history')} description={artifact.target.path} wide>
        <VersionHistory
          versions={versions}
          loading={loadingVersions}
          liveVersion={artifact.live_version}
          busy={busy}
          onRollback={handleRollback}
        />
      </Modal>
    </div>
  );
}

// VersionHistory lists the append-only history newest-first, lets the operator
// pick any two versions to diff, and rolls back to any prior version (§11).
function VersionHistory({
  versions,
  loading,
  liveVersion,
  busy,
  onRollback,
}: {
  versions: ConfigArtifactVersion[];
  loading: boolean;
  liveVersion: number;
  busy: boolean;
  onRollback: (version: number) => void;
}) {
  const { t } = useTranslation();
  // Default the diff to the two most recent versions.
  const [base, setBase] = useState<number | null>(null);
  const [compare, setCompare] = useState<number | null>(null);

  useEffect(() => {
    if (versions.length >= 2) {
      setCompare(versions[0].version);
      setBase(versions[1].version);
    } else if (versions.length === 1) {
      setCompare(versions[0].version);
      setBase(versions[0].version);
    }
  }, [versions]);

  if (loading) return <p className="py-8 text-center text-sm text-fg-muted">{t('common.loading')}</p>;
  if (versions.length === 0) return <p className="py-8 text-center text-sm text-fg-faint">{t('config.noVersions')}</p>;

  const baseVer = versions.find((v) => v.version === base);
  const compareVer = versions.find((v) => v.version === compare);

  return (
    <div className="space-y-4">
      <div className="max-h-56 space-y-2 overflow-auto">
        {versions.map((v) => (
          <div key={v.id} className="flex items-center justify-between gap-3 rounded-lg border border-border px-3 py-2">
            <div className="min-w-0">
              <p className="flex items-center gap-2 text-sm font-medium text-fg">
                {t('config.versionN', { n: v.version })}
                {v.version === liveVersion && (
                  <span className="rounded-full bg-success-soft px-2 py-0.5 text-xs font-medium text-success-fg">{t('config.live')}</span>
                )}
              </p>
              <p className="truncate text-xs text-fg-faint">
                {v.actor ?? t('config.unknownActor')} · {v.note || t(`config.source.${v.source}`)} · {formatRelativeTime(v.created_at)}
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-1">
              <button
                onClick={() => setBase(v.version)}
                className={`rounded px-2 py-0.5 text-xs ${base === v.version ? 'bg-danger-soft text-danger-fg' : 'text-fg-faint hover:text-fg'}`}
              >
                {t('config.diffBase')}
              </button>
              <button
                onClick={() => setCompare(v.version)}
                className={`rounded px-2 py-0.5 text-xs ${compare === v.version ? 'bg-success-soft text-success-fg' : 'text-fg-faint hover:text-fg'}`}
              >
                {t('config.diffCompare')}
              </button>
              {v.version !== liveVersion && (
                <Button variant="secondary" size="sm" onClick={() => onRollback(v.version)} loading={busy}>
                  <RotateCcw className="h-3.5 w-3.5" />
                  {t('config.rollback')}
                </Button>
              )}
            </div>
          </div>
        ))}
      </div>

      {baseVer && compareVer && (
        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-faint">{t('config.versionDiff')}</h3>
          <DiffView
            before={baseVer.content}
            after={compareVer.content}
            beforeLabel={t('config.versionN', { n: baseVer.version })}
            afterLabel={t('config.versionN', { n: compareVer.version })}
          />
        </div>
      )}
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

// shortPath trims a long path to its tail for the compact list row.
function shortPath(p: string): string {
  if (p.length <= 32) return p;
  const parts = p.split('/');
  return '…/' + parts.slice(-2).join('/');
}

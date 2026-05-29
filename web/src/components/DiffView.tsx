import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { diffLines, diffStats } from '../lib/diff';

interface DiffViewProps {
  before: string;
  after: string;
  /** Optional labels for the two sides, shown in the header. */
  beforeLabel?: string;
  afterLabel?: string;
}

// DiffView renders a unified, line-numbered diff between two config texts.
// Added lines are tinted success, removed lines danger; equal lines are muted.
// Color is paired with a +/- gutter sign so meaning never relies on color alone.
export default function DiffView({ before, after, beforeLabel, afterLabel }: DiffViewProps) {
  const { t } = useTranslation();
  const lines = useMemo(() => diffLines(before, after), [before, after]);
  const stats = useMemo(() => diffStats(lines), [lines]);

  if (before === after) {
    return (
      <div className="rounded-lg border border-border bg-surface-2 px-3 py-4 text-center text-sm text-fg-faint">
        {t('config.noChanges')}
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-lg border border-border">
      <div className="flex items-center justify-between gap-3 border-b border-border bg-surface-2 px-3 py-1.5 text-xs">
        <span className="truncate text-fg-muted">
          {beforeLabel && afterLabel ? `${beforeLabel} → ${afterLabel}` : t('config.diff')}
        </span>
        <span className="flex shrink-0 items-center gap-2 font-mono">
          <span className="text-success-fg">+{stats.added}</span>
          <span className="text-danger-fg">-{stats.removed}</span>
        </span>
      </div>
      <div className="max-h-[28rem] overflow-auto bg-surface font-mono text-xs leading-relaxed">
        {lines.map((l, idx) => {
          const tone =
            l.op === 'add'
              ? 'bg-success-soft/60 text-success-fg'
              : l.op === 'remove'
                ? 'bg-danger-soft/60 text-danger-fg'
                : 'text-fg-muted';
          const sign = l.op === 'add' ? '+' : l.op === 'remove' ? '-' : ' ';
          return (
            <div key={idx} className={`flex ${tone}`}>
              <span className="w-10 shrink-0 select-none px-1 text-right text-fg-faint/70">{l.oldNo ?? ''}</span>
              <span className="w-10 shrink-0 select-none px-1 text-right text-fg-faint/70">{l.newNo ?? ''}</span>
              <span className="w-4 shrink-0 select-none text-center">{sign}</span>
              <span className="whitespace-pre-wrap break-all pr-3">{l.text || ' '}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

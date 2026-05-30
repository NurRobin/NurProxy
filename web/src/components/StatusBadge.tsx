import { useTranslation } from 'react-i18next';
import { statusMeta } from '../lib/status';

const KNOWN = ['active', 'adopted', 'pending', 'error', 'offline', 'deleting'];

export default function StatusBadge({ status, degraded = false }: { status: string; degraded?: boolean }) {
  const { t } = useTranslation();
  const m = statusMeta(status);
  const key = KNOWN.includes(status) ? status : 'offline';
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${m.badge}`}>
        <span className={`h-1.5 w-1.5 rounded-full ${m.dot} ${m.pulse ? 'animate-pulse' : ''}`} />
        {t(`status.${key}`)}
      </span>
      {/* Degraded is orthogonal to status: the agent is connected (e.g. adopted)
          but constrained — shown as a separate warning chip, never overriding the
          status itself. */}
      {degraded && (
        <span className="inline-flex items-center gap-1.5 rounded-full bg-warning-soft px-2.5 py-0.5 text-xs font-medium text-warning-fg">
          <span className="h-1.5 w-1.5 rounded-full bg-warning" />
          {t('status.degraded')}
        </span>
      )}
    </span>
  );
}

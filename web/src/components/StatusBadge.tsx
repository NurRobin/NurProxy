import { statusMeta } from '../lib/status';

export default function StatusBadge({ status }: { status: string }) {
  const m = statusMeta(status);
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${m.badge}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${m.dot} ${m.pulse ? 'animate-pulse' : ''}`} />
      {m.label}
    </span>
  );
}

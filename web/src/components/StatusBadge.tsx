type Status = 'active' | 'adopted' | 'pending' | 'error' | 'offline' | 'deleting';

const statusConfig: Record<Status, { cls: string; dot: string; label: string }> = {
  active:   { cls: 'bg-success-soft text-success-fg', dot: 'bg-success',  label: 'Active' },
  adopted:  { cls: 'bg-success-soft text-success-fg', dot: 'bg-success',  label: 'Adopted' },
  pending:  { cls: 'bg-warning-soft text-warning-fg', dot: 'bg-warning',  label: 'Pending' },
  error:    { cls: 'bg-danger-soft text-danger-fg',   dot: 'bg-danger',   label: 'Error' },
  offline:  { cls: 'bg-surface-2 text-fg-muted',      dot: 'bg-fg-faint', label: 'Offline' },
  deleting: { cls: 'bg-info-soft text-info-fg',       dot: 'bg-info',     label: 'Deleting' },
};

export default function StatusBadge({ status }: { status: string }) {
  const config = statusConfig[status as Status] ?? statusConfig.offline;
  const pulse = status === 'pending' || status === 'deleting';
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${config.cls}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${config.dot} ${pulse ? 'animate-pulse' : ''}`} />
      {config.label}
    </span>
  );
}

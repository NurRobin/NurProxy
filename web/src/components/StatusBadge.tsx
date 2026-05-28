type Status = 'active' | 'adopted' | 'pending' | 'error' | 'offline' | 'deleting';

const statusConfig: Record<Status, { bg: string; text: string; dot: string; label: string }> = {
  active:   { bg: 'bg-green-900/40',  text: 'text-green-400',  dot: 'bg-green-400',  label: 'Active' },
  adopted:  { bg: 'bg-green-900/40',  text: 'text-green-400',  dot: 'bg-green-400',  label: 'Adopted' },
  pending:  { bg: 'bg-yellow-900/40', text: 'text-yellow-400', dot: 'bg-yellow-400', label: 'Pending' },
  error:    { bg: 'bg-red-900/40',    text: 'text-red-400',    dot: 'bg-red-400',    label: 'Error' },
  offline:  { bg: 'bg-gray-800',      text: 'text-gray-400',   dot: 'bg-gray-500',   label: 'Offline' },
  deleting: { bg: 'bg-orange-900/40', text: 'text-orange-400', dot: 'bg-orange-400', label: 'Deleting' },
};

export default function StatusBadge({ status }: { status: string }) {
  const config = statusConfig[status as Status] ?? statusConfig.offline;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${config.bg} ${config.text}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${config.dot}`} />
      {config.label}
    </span>
  );
}

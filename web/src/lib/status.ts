/**
 * Single source of truth for entity status presentation (badge + topology dot).
 * Keeps StatusBadge and the topology node dots from drifting apart.
 */
export type Status = 'active' | 'adopted' | 'pending' | 'error' | 'offline' | 'deleting';

export interface StatusMeta {
  label: string;
  /** badge background + foreground classes */
  badge: string;
  /** solid dot background class */
  dot: string;
  /** whether the dot should pulse (transient states) */
  pulse: boolean;
}

const META: Record<Status, StatusMeta> = {
  active:   { label: 'Active',   badge: 'bg-success-soft text-success-fg', dot: 'bg-success',  pulse: false },
  adopted:  { label: 'Adopted',  badge: 'bg-success-soft text-success-fg', dot: 'bg-success',  pulse: false },
  pending:  { label: 'Pending',  badge: 'bg-warning-soft text-warning-fg', dot: 'bg-warning',  pulse: true },
  error:    { label: 'Error',    badge: 'bg-danger-soft text-danger-fg',   dot: 'bg-danger',   pulse: false },
  offline:  { label: 'Offline',  badge: 'bg-surface-2 text-fg-muted',      dot: 'bg-fg-faint', pulse: false },
  deleting: { label: 'Deleting', badge: 'bg-info-soft text-info-fg',       dot: 'bg-info',     pulse: true },
};

export function statusMeta(status: string): StatusMeta {
  return META[status as Status] ?? META.offline;
}

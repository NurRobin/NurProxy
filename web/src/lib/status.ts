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

/**
 * isDegraded reports whether an agent is connected but not fully healthy: it has
 * an operational error, or its §12 permission self-test failed (e.g. existing-mode
 * nginx it can read+write but cannot reload). This is orthogonal to status —
 * a degraded agent is still 'adopted' — so the UI shows it alongside the status
 * badge rather than overriding it. Reading/serving keeps working; only pushing
 * changes live is constrained.
 */
export function isDegraded(agent: {
  status?: string;
  last_error?: string;
  proxy_permissions?: { checked?: boolean; ok?: boolean };
}): boolean {
  if (agent.status === 'offline' || agent.status === 'error') return false; // own state
  if (agent.last_error) return true;
  const p = agent.proxy_permissions;
  return !!(p?.checked && !p.ok);
}

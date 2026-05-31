import { useTranslation } from 'react-i18next';
import type { ArtifactApplyState } from '../lib/types';

// Maps a config artifact's apply_state to a badge. Separate from the entity
// StatusBadge because these are config-lifecycle states (live | drifted |
// apply_failed), not entity-lifecycle states. Each pairs a colored dot with a
// label so meaning never relies on color alone (§15 cross-cutting UX).
const META: Record<ArtifactApplyState, { badge: string; dot: string; pulse: boolean }> = {
  live: { badge: 'bg-success-soft text-success-fg', dot: 'bg-success', pulse: false },
  drifted: { badge: 'bg-warning-soft text-warning-fg', dot: 'bg-warning', pulse: true },
  apply_failed: { badge: 'bg-danger-soft text-danger-fg', dot: 'bg-danger', pulse: false },
};

export default function ArtifactStatusBadge({ state }: { state: ArtifactApplyState }) {
  const { t } = useTranslation();
  const m = META[state] ?? META.live;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${m.badge}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${m.dot} ${m.pulse ? 'animate-pulse' : ''}`} />
      {t(`config.state.${state}`)}
    </span>
  );
}

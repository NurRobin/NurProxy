import type { ReactNode } from 'react';
import { Info, TriangleAlert, CircleCheck, CircleX, AlignLeft, type LucideIcon } from 'lucide-react';

type Tone = 'info' | 'warning' | 'success' | 'danger' | 'neutral';

const tones: Record<Tone, string> = {
  info: 'border-info/35 bg-info-soft text-info-fg',
  warning: 'border-warning/40 bg-warning-soft text-warning-fg',
  success: 'border-success/35 bg-success-soft text-success-fg',
  danger: 'border-danger/40 bg-danger-soft text-danger-fg',
  neutral: 'border-border bg-surface-2 text-fg-muted',
};

// Distinct icon shape per tone so meaning doesn't rely on color alone.
const icons: Record<Tone, LucideIcon> = {
  info: Info,
  warning: TriangleAlert,
  success: CircleCheck,
  danger: CircleX,
  neutral: AlignLeft,
};

export default function Callout({ tone = 'info', title, children }: { tone?: Tone; title?: ReactNode; children?: ReactNode }) {
  const Icon = icons[tone];
  return (
    <div className={`flex gap-3 rounded-lg border px-3.5 py-3 text-sm ${tones[tone]}`}>
      <Icon className="mt-0.5 h-4 w-4 flex-shrink-0" aria-hidden="true" />
      <div className="min-w-0 leading-relaxed">
        {title && <p className="font-medium">{title}</p>}
        {children && <div className={title ? 'mt-0.5' : ''}>{children}</div>}
      </div>
    </div>
  );
}

import type { ReactNode } from 'react';

type Tone = 'info' | 'warning' | 'success' | 'danger' | 'neutral';

const tones: Record<Tone, string> = {
  info: 'border-info/35 bg-info-soft text-info-fg',
  warning: 'border-warning/40 bg-warning-soft text-warning-fg',
  success: 'border-success/35 bg-success-soft text-success-fg',
  danger: 'border-danger/40 bg-danger-soft text-danger-fg',
  neutral: 'border-border bg-surface-2 text-fg-muted',
};

const icons: Record<Tone, ReactNode> = {
  info: <path strokeLinecap="round" strokeLinejoin="round" d="M11.25 11.25h1.5v5.25M12 7.5h.007M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z" />,
  warning: <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m0 3.75h.007M12 3l9 16H3l9-16z" />,
  success: <path strokeLinecap="round" strokeLinejoin="round" d="m9 12.75 2.25 2.25L15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z" />,
  danger: <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m0 3.75h.007M12 3l9 16H3l9-16z" />,
  neutral: <path strokeLinecap="round" strokeLinejoin="round" d="M11.25 11.25h1.5v5.25M12 7.5h.007M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z" />,
};

export default function Callout({ tone = 'info', title, children }: { tone?: Tone; title?: ReactNode; children?: ReactNode }) {
  return (
    <div className={`flex gap-3 rounded-lg border px-3.5 py-3 text-sm ${tones[tone]}`}>
      <svg className="mt-0.5 h-4 w-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8} aria-hidden="true">
        {icons[tone]}
      </svg>
      <div className="min-w-0 leading-relaxed">
        {title && <p className="font-medium">{title}</p>}
        {children && <div className={title ? 'mt-0.5' : ''}>{children}</div>}
      </div>
    </div>
  );
}

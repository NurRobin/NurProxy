import { createContext, useContext } from 'react';

/** A UI variant is a whole different shell/experience, not just a color theme. */
export type UIVariant = 'workbench' | 'classic' | 'wallboard' | 'spreadsheet';

export const UI_VARIANTS: { id: UIVariant; name: string; description: string }[] = [
  { id: 'classic', name: 'Classic', description: 'A compact top-nav dashboard with a health panel, cards, and tables.' },
  { id: 'workbench', name: 'Workbench', description: 'A live topology map of your infrastructure with a sidebar and click-to-inspect panels.' },
  { id: 'wallboard', name: 'Wallboard', description: 'A read-only status grid for a spare monitor. Big, glanceable, auto-refreshing.' },
  { id: 'spreadsheet', name: 'Spreadsheet', description: 'A dense, table-first view with multi-select and bulk actions for power users.' },
];

export interface UIVariantContextValue {
  variant: UIVariant;
  setVariant: (v: UIVariant) => void;
}

export const UIVariantContext = createContext<UIVariantContextValue | null>(null);

export function useUIVariant(): UIVariantContextValue {
  const ctx = useContext(UIVariantContext);
  if (!ctx) throw new Error('useUIVariant must be used within UIVariantProvider');
  return ctx;
}

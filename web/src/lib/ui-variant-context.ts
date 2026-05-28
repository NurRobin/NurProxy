import { createContext, useContext } from 'react';

/** A UI variant is a whole different shell/experience, not just a color theme. */
export type UIVariant = 'workbench' | 'classic';

export const UI_VARIANTS: { id: UIVariant; name: string; description: string }[] = [
  { id: 'workbench', name: 'Workbench', description: 'A live topology map of your infrastructure with a sidebar and click-to-inspect panels.' },
  { id: 'classic', name: 'Classic', description: 'A compact top-nav dashboard with cards and tables.' },
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

import { createContext, useContext } from 'react';

export interface HelpContextValue {
  open: boolean;
  slug: string | null;
  openHelp: (slug?: string) => void;
  closeHelp: () => void;
}

export const HelpContext = createContext<HelpContextValue | null>(null);

export function useHelp(): HelpContextValue {
  const ctx = useContext(HelpContext);
  if (!ctx) throw new Error('useHelp must be used within HelpProvider');
  return ctx;
}

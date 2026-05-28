import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { UIVariantContext, type UIVariant } from './ui-variant-context';

const STORAGE_KEY = 'nurproxy-ui';

function readInitial(): UIVariant {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === 'classic' || v === 'workbench') return v;
  } catch { /* ignore */ }
  return 'workbench';
}

export function UIVariantProvider({ children }: { children: ReactNode }) {
  const [variant, setVariantState] = useState<UIVariant>(readInitial);

  useEffect(() => {
    try { localStorage.setItem(STORAGE_KEY, variant); } catch { /* ignore */ }
  }, [variant]);

  const setVariant = useCallback((v: UIVariant) => setVariantState(v), []);

  return (
    <UIVariantContext.Provider value={{ variant, setVariant }}>
      {children}
    </UIVariantContext.Provider>
  );
}

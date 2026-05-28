import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { UIVariantContext, type UIVariant } from './ui-variant-context';

const STORAGE_KEY = 'nurproxy-ui';

const VALID: UIVariant[] = ['classic', 'workbench', 'terminal', 'wallboard', 'spreadsheet'];

function readInitial(): UIVariant {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v && (VALID as string[]).includes(v)) return v as UIVariant;
  } catch { /* ignore */ }
  return 'classic';
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

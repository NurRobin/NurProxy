import { useEffect } from 'react';

/**
 * Runs `fn` immediately, then on an interval — but only while the tab is
 * visible. When the tab is hidden the interval pauses (kinder to a homelab's
 * resources); becoming visible again refetches immediately and resumes.
 * `fn` should be a stable reference (wrap in useCallback).
 */
export function usePolling(fn: () => void, intervalMs: number) {
  useEffect(() => {
    let id: ReturnType<typeof setInterval> | null = null;
    const start = () => { if (id == null) id = setInterval(fn, intervalMs); };
    const stop = () => { if (id != null) { clearInterval(id); id = null; } };

    fn(); // initial load
    if (document.visibilityState === 'visible') start();

    const onVisibility = () => {
      if (document.visibilityState === 'visible') { fn(); start(); }
      else stop();
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => { stop(); document.removeEventListener('visibilitychange', onVisibility); };
  }, [fn, intervalMs]);
}

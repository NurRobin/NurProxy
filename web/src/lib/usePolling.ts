import { useEffect } from 'react';

export function pollingActive(visibility: DocumentVisibilityState, keepAliveWhenHidden = false): boolean {
  return visibility === 'visible' || keepAliveWhenHidden;
}

/**
 * Runs `fn` immediately, then on an interval while the tab is visible.
 * Callers with an active operation may keep polling while hidden;
 * once it becomes terminal, the hidden interval stops on the next render.
 * `fn` should be a stable reference (wrap in useCallback).
 */
export function usePolling(fn: () => void, intervalMs: number, options?: { keepAliveWhenHidden?: boolean }) {
  const keepAliveWhenHidden = options?.keepAliveWhenHidden ?? false;
  useEffect(() => {
    let id: ReturnType<typeof setInterval> | null = null;
    const start = () => { if (id == null) id = setInterval(fn, intervalMs); };
    const stop = () => { if (id != null) { clearInterval(id); id = null; } };

    fn(); // initial load
    if (pollingActive(document.visibilityState, keepAliveWhenHidden)) start();

    const onVisibility = () => {
      if (pollingActive(document.visibilityState, keepAliveWhenHidden)) { fn(); start(); }
      else stop();
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => { stop(); document.removeEventListener('visibilitychange', onVisibility); };
  }, [fn, intervalMs, keepAliveWhenHidden]);
}

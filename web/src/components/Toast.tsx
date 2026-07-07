import { useCallback, useRef, useState, type ReactNode } from 'react';
import { TriangleAlert, CircleCheck, Info, X, type LucideIcon } from 'lucide-react';
import { ToastContext, type ToastVariant, type ToastRecord, type ToastAction, type ToastOptions } from './toast-context';

interface Toast {
  id: number;
  message: string;
  variant: ToastVariant;
  action?: ToastAction;
}

const HISTORY_CAP = 50;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [history, setHistory] = useState<ToastRecord[]>([]);
  const [unseen, setUnseen] = useState(0);
  const counter = useRef(0);
  // Currently visible toasts keyed by variant+message, so repeated identical
  // failures (e.g. the same poll erroring every cycle) don't stack up.
  const activeKeys = useRef(new Map<string, number>());

  const remove = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
    for (const [key, toastId] of activeKeys.current) {
      if (toastId === id) activeKeys.current.delete(key);
    }
  }, []);

  const push = useCallback((message: string, variant: ToastVariant = 'info', opts?: ToastOptions) => {
    // Empty messages mark errors handled elsewhere (see errMessage) — drop them.
    if (!message) return;
    const key = `${variant}:${message}`;
    if (activeKeys.current.has(key)) return;
    const id = ++counter.current;
    activeKeys.current.set(key, id);
    setToasts((prev) => [...prev, { id, message, variant, action: opts?.action }]);
    setHistory((prev) => [{ id, message, variant, at: new Date().toISOString() }, ...prev].slice(0, HISTORY_CAP));
    if (variant === 'error') setUnseen((n) => n + 1);
    const duration = opts?.duration ?? (variant === 'error' ? 7000 : 4000);
    window.setTimeout(() => remove(id), duration);
  }, [remove]);

  const error = useCallback((message: string) => push(message, 'error'), [push]);
  const success = useCallback((message: string) => push(message, 'success'), [push]);
  const markSeen = useCallback(() => setUnseen(0), []);
  const clearHistory = useCallback(() => { setHistory([]); setUnseen(0); }, []);

  return (
    <ToastContext.Provider value={{ push, error, success, history, unseen, markSeen, clearHistory }}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-full max-w-sm flex-col gap-2">
        {toasts.map((t) => (
          <ToastItem key={t.id} toast={t} onClose={() => remove(t.id)} />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

const styles: Record<ToastVariant, { box: string; Icon: LucideIcon }> = {
  error: { box: 'border-danger/40 bg-danger-soft text-danger-fg', Icon: TriangleAlert },
  success: { box: 'border-success/40 bg-success-soft text-success-fg', Icon: CircleCheck },
  info: { box: 'border-info/40 bg-info-soft text-info-fg', Icon: Info },
};

function ToastItem({ toast, onClose }: { toast: Toast; onClose: () => void }) {
  const s = styles[toast.variant];
  return (
    <div
      role={toast.variant === 'error' ? 'alert' : 'status'}
      className={`animate-toast-in pointer-events-auto flex items-start gap-3 rounded-lg border px-4 py-3 shadow-pop ${s.box}`}
    >
      <s.Icon className="mt-0.5 h-5 w-5 flex-shrink-0" aria-hidden="true" />
      <p className="flex-1 break-words text-sm">{toast.message}</p>
      {toast.action && (
        <button
          onClick={() => { toast.action!.onClick(); onClose(); }}
          className="-my-0.5 flex-shrink-0 rounded-md border border-current/30 px-2 py-1 text-xs font-semibold hover:bg-current/10"
        >
          {toast.action.label}
        </button>
      )}
      <button onClick={onClose} aria-label="Dismiss" className="-mr-1 -mt-0.5 rounded p-1 opacity-70 hover:opacity-100">
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}

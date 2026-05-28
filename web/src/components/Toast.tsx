import { useCallback, useRef, useState, type ReactNode } from 'react';
import { ToastContext, type ToastVariant } from './toast-context';

interface Toast {
  id: number;
  message: string;
  variant: ToastVariant;
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const counter = useRef(0);

  const remove = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const push = useCallback((message: string, variant: ToastVariant = 'info') => {
    const id = ++counter.current;
    setToasts((prev) => [...prev, { id, message, variant }]);
    window.setTimeout(() => remove(id), variant === 'error' ? 7000 : 4000);
  }, [remove]);

  const error = useCallback((message: string) => push(message, 'error'), [push]);
  const success = useCallback((message: string) => push(message, 'success'), [push]);

  return (
    <ToastContext.Provider value={{ push, error, success }}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-full max-w-sm flex-col gap-2">
        {toasts.map((t) => (
          <ToastItem key={t.id} toast={t} onClose={() => remove(t.id)} />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

const styles: Record<ToastVariant, { box: string; icon: ReactNode }> = {
  error: {
    box: 'border-danger/40 bg-danger-soft text-danger-fg',
    icon: <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m0 3.75h.007M12 3l9 16H3l9-16z" />,
  },
  success: {
    box: 'border-success/40 bg-success-soft text-success-fg',
    icon: <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z" />,
  },
  info: {
    box: 'border-info/40 bg-info-soft text-info-fg',
    icon: <path strokeLinecap="round" strokeLinejoin="round" d="M11.25 11.25h1.5v5.25M12 7.5h.007M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z" />,
  },
};

function ToastItem({ toast, onClose }: { toast: Toast; onClose: () => void }) {
  const s = styles[toast.variant];
  return (
    <div
      role="status"
      className={`animate-toast-in pointer-events-auto flex items-start gap-3 rounded-lg border px-4 py-3 shadow-pop ${s.box}`}
    >
      <svg className="mt-0.5 h-5 w-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        {s.icon}
      </svg>
      <p className="flex-1 break-words text-sm">{toast.message}</p>
      <button onClick={onClose} aria-label="Dismiss" className="-mr-1 -mt-0.5 rounded p-1 opacity-70 hover:opacity-100">
        <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" />
        </svg>
      </button>
    </div>
  );
}

import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useToast } from './toast-context';
import { formatRelativeTime } from '../lib/utils';

const dotColor = { error: 'bg-danger', success: 'bg-success', info: 'bg-info' } as const;

export default function NotificationBell() {
  const { history, unseen, markSeen, clearHistory } = useToast();
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState({ top: 0, right: 0 });
  const btnRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);

  function toggle() {
    if (open) { setOpen(false); return; }
    const r = btnRef.current?.getBoundingClientRect();
    if (r) setPos({ top: r.bottom + 8, right: Math.max(8, window.innerWidth - r.right) });
    markSeen();
    setOpen(true);
  }

  useEffect(() => {
    if (!open) return;
    const onDown = (e: PointerEvent) => {
      const t = e.target as Node;
      if (panelRef.current?.contains(t) || btnRef.current?.contains(t)) return;
      setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    const close = () => setOpen(false);
    window.addEventListener('pointerdown', onDown);
    window.addEventListener('keydown', onKey);
    window.addEventListener('resize', close);
    return () => { window.removeEventListener('pointerdown', onDown); window.removeEventListener('keydown', onKey); window.removeEventListener('resize', close); };
  }, [open]);

  return (
    <>
      <button
        ref={btnRef}
        type="button"
        onClick={toggle}
        aria-label={`Notifications${unseen > 0 ? ` (${unseen} unseen)` : ''}`}
        className="relative inline-flex h-9 w-9 items-center justify-center rounded-lg text-fg-muted transition-colors hover:bg-surface-2 hover:text-fg"
      >
        <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round">
          <path d="M14.857 17.082a23.85 23.85 0 0 0 5.454-1.31A8.97 8.97 0 0 1 18 9.75V9A6 6 0 0 0 6 9v.75a8.97 8.97 0 0 1-2.312 6.022 23.85 23.85 0 0 0 5.455 1.31m5.714 0a24.26 24.26 0 0 1-5.714 0m5.714 0a3 3 0 1 1-5.714 0" />
        </svg>
        {unseen > 0 && (
          <span className="absolute right-1 top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-danger px-1 text-[10px] font-bold leading-none text-white">
            {unseen > 9 ? '9+' : unseen}
          </span>
        )}
      </button>
      {open && createPortal(
        <div
          ref={panelRef}
          style={{ top: pos.top, right: pos.right }}
          className="animate-pop-in fixed z-[90] w-80 max-w-[calc(100vw-1rem)] overflow-hidden rounded-xl border border-border bg-surface shadow-pop"
        >
          <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
            <span className="text-sm font-semibold text-fg">Notifications</span>
            {history.length > 0 && (
              <button onClick={clearHistory} className="text-xs font-medium text-fg-faint hover:text-fg">Clear</button>
            )}
          </div>
          {history.length === 0 ? (
            <p className="px-4 py-6 text-center text-sm text-fg-faint">No recent activity.</p>
          ) : (
            <ul className="max-h-80 divide-y divide-border overflow-y-auto">
              {history.map((r) => (
                <li key={r.id} className="flex items-start gap-3 px-4 py-2.5">
                  <span className={`mt-1.5 h-2 w-2 flex-shrink-0 rounded-full ${dotColor[r.variant]}`} />
                  <div className="min-w-0 flex-1">
                    <p className="break-words text-sm text-fg">{r.message}</p>
                    <p className="mt-0.5 text-xs text-fg-faint">{formatRelativeTime(r.at)}</p>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>,
        document.body,
      )}
    </>
  );
}

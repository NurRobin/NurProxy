import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { glossary } from '../lib/glossary';
import { useHelp } from './help-context';

/**
 * A small "?" affordance that reveals a one-line definition and a link into the
 * wiki side-panel. The popover is rendered in a portal with fixed positioning so
 * it's never clipped by an ancestor's overflow (modals, scroll containers, the
 * agent accordion). Hover uses a short close delay so moving the cursor onto the
 * popover doesn't dismiss it.
 */
export default function HelpTip({ term, label }: { term: string; label?: string }) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number }>({ top: 0, left: 0 });
  const btnRef = useRef<HTMLButtonElement>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const id = useId();
  const { openHelp } = useHelp();
  const entry = glossary[term];

  const place = useCallback(() => {
    const r = btnRef.current?.getBoundingClientRect();
    if (!r) return;
    const half = 128; // half of the 256px popover
    const left = Math.min(Math.max(r.left + r.width / 2, half + 8), window.innerWidth - half - 8);
    setPos({ top: r.bottom + 8, left });
  }, []);

  const show = useCallback(() => {
    if (timer.current) clearTimeout(timer.current);
    place();
    setOpen(true);
  }, [place]);

  const hideSoon = useCallback(() => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setOpen(false), 140);
  }, []);

  // Close on scroll/resize so the fixed popover never drifts from its anchor.
  useEffect(() => {
    if (!open) return;
    const close = () => setOpen(false);
    window.addEventListener('scroll', close, true);
    window.addEventListener('resize', close);
    return () => {
      window.removeEventListener('scroll', close, true);
      window.removeEventListener('resize', close);
    };
  }, [open]);

  if (!entry) return null;

  return (
    <>
      <button
        ref={btnRef}
        type="button"
        aria-label={`What is ${label ?? entry.term}?`}
        aria-expanded={open}
        aria-describedby={open ? id : undefined}
        onClick={() => (open ? setOpen(false) : show())}
        onMouseEnter={show}
        onMouseLeave={hideSoon}
        className="inline-flex h-4 w-4 items-center justify-center rounded-full border border-border text-[10px] font-semibold leading-none text-fg-faint transition-colors hover:border-accent hover:text-accent"
      >
        ?
      </button>
      {open && createPortal(
        <span
          role="tooltip"
          id={id}
          onMouseEnter={show}
          onMouseLeave={hideSoon}
          style={{ top: pos.top, left: pos.left }}
          className="animate-pop-in fixed z-[90] w-64 -translate-x-1/2 rounded-lg border border-border bg-surface p-3 text-left shadow-pop"
        >
          <span className="block text-xs font-semibold text-fg">{entry.term}</span>
          <span className="mt-1 block text-xs leading-relaxed text-fg-muted">{entry.short}</span>
          {entry.doc && (
            <button
              type="button"
              onClick={() => { openHelp(entry.doc); setOpen(false); }}
              className="mt-2 inline-block text-xs font-medium text-accent hover:underline"
            >
              Learn more →
            </button>
          )}
        </span>,
        document.body,
      )}
    </>
  );
}

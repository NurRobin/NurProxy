import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { glossary } from '../lib/glossary';
import { useHelp } from './help-context';

/**
 * A small "?" affordance that reveals a definition + a link into the wiki
 * side-panel. The popover is portalled with fixed positioning so it's never
 * clipped by an ancestor's overflow. It's a non-modal dialog: hover opens it
 * (with a close delay so the cursor can reach it); keyboard activation moves
 * focus into it so "Learn more" is reachable; Escape closes and restores focus.
 */
export default function HelpTip({ term, label }: { term: string; label?: string }) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number }>({ top: 0, left: 0 });
  const btnRef = useRef<HTMLButtonElement>(null);
  const learnRef = useRef<HTMLButtonElement>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const wantFocus = useRef(false);
  const id = useId();
  const { openHelp } = useHelp();
  const entry = glossary[term];

  const place = useCallback(() => {
    const r = btnRef.current?.getBoundingClientRect();
    if (!r) return;
    const half = 128;
    const left = Math.min(Math.max(r.left + r.width / 2, half + 8), window.innerWidth - half - 8);
    setPos({ top: r.bottom + 8, left });
  }, []);

  const show = useCallback(() => { if (timer.current) clearTimeout(timer.current); place(); setOpen(true); }, [place]);
  const hideSoon = useCallback(() => { if (timer.current) clearTimeout(timer.current); timer.current = setTimeout(() => setOpen(false), 140); }, []);

  useEffect(() => {
    if (open && wantFocus.current) { wantFocus.current = false; learnRef.current?.focus(); }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const close = () => setOpen(false);
    window.addEventListener('scroll', close, true);
    window.addEventListener('resize', close);
    return () => { window.removeEventListener('scroll', close, true); window.removeEventListener('resize', close); };
  }, [open]);

  if (!entry) return null;

  return (
    <>
      <button
        ref={btnRef}
        type="button"
        aria-label={`What is ${label ?? entry.term}?`}
        aria-expanded={open}
        aria-haspopup="dialog"
        onClick={(e) => {
          if (open) { setOpen(false); return; }
          if (e.detail === 0) wantFocus.current = true; // keyboard activation
          show();
        }}
        onMouseEnter={show}
        onMouseLeave={hideSoon}
        className="inline-flex h-4 w-4 items-center justify-center rounded-full border border-border text-[10px] font-semibold leading-none text-fg-faint transition-colors hover:border-accent hover:text-accent"
      >
        ?
      </button>
      {open && createPortal(
        <div
          role="dialog"
          aria-label={entry.term}
          id={id}
          onMouseEnter={show}
          onMouseLeave={hideSoon}
          onKeyDown={(e) => { if (e.key === 'Escape') { setOpen(false); btnRef.current?.focus(); } }}
          style={{ top: pos.top, left: pos.left }}
          className="animate-pop-in fixed z-[90] w-64 -translate-x-1/2 rounded-lg border border-border bg-surface p-3 text-left shadow-pop"
        >
          <span className="block text-xs font-semibold text-fg">{entry.term}</span>
          <span className="mt-1 block text-xs leading-relaxed text-fg-muted">{entry.short}</span>
          {entry.doc && (
            <button
              ref={learnRef}
              type="button"
              onClick={() => { openHelp(entry.doc); setOpen(false); }}
              className="mt-2 inline-block rounded text-xs font-medium text-accent hover:underline"
            >
              Learn more →
            </button>
          )}
        </div>,
        document.body,
      )}
    </>
  );
}

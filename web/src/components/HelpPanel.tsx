import { useCallback, useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react';
import { HelpContext } from './help-context';
import { TOPICS, getTopic, DEFAULT_SLUG } from '../lib/wiki';
import Markdown from './Markdown';

const WIDTH_KEY = 'nurproxy-help-width';
const MIN_W = 300;
const MAX_W = 680;

function readWidth(): number {
  try {
    const v = Number(localStorage.getItem(WIDTH_KEY));
    if (v >= MIN_W && v <= MAX_W) return v;
  } catch { /* ignore */ }
  return 400;
}

/**
 * Wraps the app in a horizontal split: main content on the left, an optional
 * resizable wiki panel on the right. Opening help never navigates the router,
 * so in-progress forms keep their state. On small screens the panel is a
 * full-screen overlay instead of a split.
 */
export function HelpProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const [slug, setSlug] = useState<string | null>(null);
  const [width, setWidth] = useState(readWidth);
  const [dragging, setDragging] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const widthRef = useRef(width);
  useEffect(() => { widthRef.current = width; }, [width]);

  // Close the topic menu on an outside click.
  useEffect(() => {
    if (!menuOpen) return;
    const onClick = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false);
    };
    window.addEventListener('mousedown', onClick);
    return () => window.removeEventListener('mousedown', onClick);
  }, [menuOpen]);

  const openHelp = useCallback((s?: string) => { setSlug(s ?? DEFAULT_SLUG); setOpen(true); }, []);
  const closeHelp = useCallback(() => setOpen(false), []);

  // Escape closes the panel.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open]);

  // Drag-to-resize.
  useEffect(() => {
    if (!dragging) return;
    const onMove = (e: PointerEvent) => {
      const w = Math.min(Math.min(MAX_W, window.innerWidth - 320), Math.max(MIN_W, window.innerWidth - e.clientX));
      setWidth(w);
    };
    const onUp = () => {
      setDragging(false);
      try { localStorage.setItem(WIDTH_KEY, String(widthRef.current)); } catch { /* ignore */ }
    };
    document.body.style.userSelect = 'none';
    document.body.style.cursor = 'col-resize';
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    return () => {
      document.body.style.userSelect = '';
      document.body.style.cursor = '';
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
    };
  }, [dragging]);

  const topic = open ? getTopic(slug ?? undefined) : null;

  return (
    <HelpContext.Provider value={{ open, slug, openHelp, closeHelp }}>
      <div className="flex min-h-screen w-full">
        <div className="min-w-0 flex-1">{children}</div>

        {open && topic && (
          <>
            <div
              role="separator"
              aria-orientation="vertical"
              aria-label="Resize help panel"
              onPointerDown={(e) => { e.preventDefault(); setDragging(true); }}
              className={`hidden w-1.5 shrink-0 cursor-col-resize transition-colors sm:block ${dragging ? 'bg-accent' : 'bg-border hover:bg-accent'}`}
            />
            <aside
              style={{ '--help-w': `${width}px` } as CSSProperties}
              className="fixed inset-0 z-40 flex flex-col border-border bg-surface shadow-pop sm:static sm:inset-auto sm:z-auto sm:h-screen sm:w-[var(--help-w)] sm:shrink-0 sm:border-l sm:shadow-none sm:sticky sm:top-0"
            >
              <header className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
                <div ref={menuRef} className="relative flex items-center gap-2">
                  <svg className="h-4 w-4 flex-shrink-0 text-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}><path strokeLinecap="round" strokeLinejoin="round" d="M9.879 7.519a3 3 0 1 1 4.04 2.829c-.68.252-1.171.836-1.33 1.546l-.149.66M12 17h.007M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z" /></svg>
                  <button
                    type="button"
                    onClick={() => setMenuOpen((v) => !v)}
                    aria-haspopup="listbox"
                    aria-expanded={menuOpen}
                    aria-label="Help topic"
                    className="flex items-center gap-1 rounded-md px-2 py-1 text-sm font-semibold text-fg transition-colors hover:bg-surface-2"
                  >
                    {topic.title}
                    <svg className={`h-4 w-4 text-fg-faint transition-transform ${menuOpen ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="m6 9 6 6 6-6" /></svg>
                  </button>
                  {menuOpen && (
                    <div role="listbox" className="absolute left-6 top-full z-10 mt-1 max-h-80 w-60 overflow-y-auto rounded-lg border border-border bg-surface p-1 shadow-pop">
                      {TOPICS.map((t) => (
                        <button
                          key={t.slug}
                          type="button"
                          role="option"
                          aria-selected={t.slug === topic.slug}
                          onClick={() => { setSlug(t.slug); setMenuOpen(false); }}
                          className={`block w-full rounded-md px-3 py-2 text-left text-sm transition-colors ${
                            t.slug === topic.slug ? 'bg-accent-soft font-medium text-accent' : 'text-fg-muted hover:bg-surface-2 hover:text-fg'
                          }`}
                        >
                          {t.title}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
                <button onClick={closeHelp} aria-label="Close help" className="rounded-lg p-1.5 text-fg-faint transition-colors hover:bg-surface-2 hover:text-fg">
                  <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" /></svg>
                </button>
              </header>
              <div className="min-h-0 flex-1 overflow-y-auto px-5 py-5">
                <Markdown source={topic.content} onLink={(s) => setSlug(s)} />
              </div>
            </aside>
          </>
        )}
      </div>
    </HelpContext.Provider>
  );
}

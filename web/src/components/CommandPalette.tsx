import { useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useNavigate } from 'react-router-dom';
import { useTheme } from '../lib/theme-context';
import { useUIVariant, UI_VARIANTS } from '../lib/ui-variant-context';

interface Cmd { id: string; label: string; hint?: string; run: () => void }

/**
 * Global ⌘K / Ctrl+K command palette. Mounted inside every shell (within the
 * router), so navigation + quick actions are keyboard-reachable everywhere.
 */
export default function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const [active, setActive] = useState(0);
  const navigate = useNavigate();
  const { toggle: toggleTheme } = useTheme();
  const { variant, setVariant } = useUIVariant();
  const inputRef = useRef<HTMLInputElement>(null);

  const commands = useMemo<Cmd[]>(() => {
    const go = (to: string, label: string): Cmd => ({ id: `go:${to}`, label, hint: 'Go', run: () => navigate(to) });
    return [
      go('/', 'Overview'),
      go('/agents', 'Agents'),
      go('/servers', 'Servers'),
      go('/domains', 'Domains'),
      go('/settings', 'Settings'),
      go('/help', 'Docs'),
      { id: 'new-domain', label: 'New domain', hint: 'Create', run: () => navigate('/domains') },
      { id: 'theme', label: 'Toggle light / dark', hint: 'Theme', run: toggleTheme },
      ...UI_VARIANTS.filter((v) => v.id !== variant).map((v): Cmd => ({
        id: `variant:${v.id}`, label: `Switch to ${v.name} appearance`, hint: 'Appearance', run: () => setVariant(v.id),
      })),
    ];
  }, [navigate, toggleTheme, setVariant, variant]);

  const filtered = q ? commands.filter((c) => c.label.toLowerCase().includes(q.toLowerCase())) : commands;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setOpen((o) => !o); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => { if (open) { setQ(''); setActive(0); const t = setTimeout(() => inputRef.current?.focus(), 0); return () => clearTimeout(t); } }, [open]);
  useEffect(() => { setActive(0); }, [q]);

  if (!open) return null;

  const run = (c: Cmd) => { setOpen(false); c.run(); };

  return createPortal(
    <div
      className="animate-fade-in fixed inset-0 z-[80] flex items-start justify-center bg-[oklch(0.15_0.01_60_/_0.5)] p-4 pt-[12vh] backdrop-blur-[2px]"
      onClick={(e) => { if (e.target === e.currentTarget) setOpen(false); }}
    >
      <div className="animate-pop-in w-full max-w-lg overflow-hidden rounded-xl border border-border bg-surface shadow-pop" role="dialog" aria-label="Command palette">
        <input
          ref={inputRef}
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') setOpen(false);
            else if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => Math.min(a + 1, filtered.length - 1)); }
            else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
            else if (e.key === 'Enter') { const c = filtered[active]; if (c) run(c); }
          }}
          placeholder="Type a command…"
          className="w-full border-b border-border bg-transparent px-4 py-3 text-sm text-fg placeholder:text-fg-faint focus:outline-none"
        />
        <ul className="max-h-80 overflow-y-auto p-1">
          {filtered.length === 0 ? (
            <li className="px-3 py-2 text-sm text-fg-faint">No commands.</li>
          ) : filtered.map((c, i) => (
            <li key={c.id}>
              <button
                onMouseEnter={() => setActive(i)}
                onClick={() => run(c)}
                className={`flex w-full items-center justify-between gap-3 rounded-md px-3 py-2 text-left text-sm transition-colors ${i === active ? 'bg-accent-soft text-accent' : 'text-fg hover:bg-surface-2'}`}
              >
                <span>{c.label}</span>
                {c.hint && <span className="text-xs text-fg-faint">{c.hint}</span>}
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>,
    document.body,
  );
}

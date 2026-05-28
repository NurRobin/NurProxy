import { useEffect, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';

export interface MenuItem {
  label: string;
  onSelect: () => void;
  icon?: ReactNode;
  danger?: boolean;
  disabled?: boolean;
}

export interface MenuState {
  x: number;
  y: number;
  title?: string;
  items: MenuItem[];
}

/**
 * A custom right-click menu rendered in a portal at the cursor, clamped to the
 * viewport. Token-styled so it matches the rest of the UI (native menus can't be).
 */
export default function ContextMenu({ menu, onClose }: { menu: MenuState | null; onClose: () => void }) {
  const [el, setEl] = useState<HTMLDivElement | null>(null);
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null);

  // Clamp once the menu is measured so it never overflows the viewport.
  useEffect(() => {
    if (!menu || !el) { setPos(menu ? { x: menu.x, y: menu.y } : null); return; }
    const r = el.getBoundingClientRect();
    const x = Math.min(menu.x, window.innerWidth - r.width - 8);
    const y = Math.min(menu.y, window.innerHeight - r.height - 8);
    setPos({ x: Math.max(8, x), y: Math.max(8, y) });
  }, [menu, el]);

  useEffect(() => {
    if (!menu) return;
    const close = () => onClose();
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    window.addEventListener('resize', close);
    window.addEventListener('scroll', close, true);
    window.addEventListener('pointerdown', close);
    window.addEventListener('contextmenu', close);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('resize', close);
      window.removeEventListener('scroll', close, true);
      window.removeEventListener('pointerdown', close);
      window.removeEventListener('contextmenu', close);
    };
  }, [menu, onClose]);

  if (!menu) return null;

  return createPortal(
    <div
      ref={setEl}
      // Stop the menu's own pointerdown from triggering the outside-close listener.
      onPointerDown={(e) => e.stopPropagation()}
      onContextMenu={(e) => e.preventDefault()}
      style={{ left: (pos ?? menu).x, top: (pos ?? menu).y, visibility: pos ? 'visible' : 'hidden' }}
      className="animate-pop-in fixed z-[95] min-w-44 max-w-64 rounded-lg border border-border bg-surface p-1 shadow-pop"
    >
      {menu.title && (
        <div className="truncate px-3 py-1.5 text-xs font-medium text-fg-faint">{menu.title}</div>
      )}
      {menu.items.map((item, i) => (
        <button
          key={i}
          type="button"
          disabled={item.disabled}
          onClick={() => { onClose(); item.onSelect(); }}
          className={`flex w-full items-center gap-2.5 rounded-md px-3 py-1.5 text-left text-sm transition-colors disabled:opacity-40 disabled:pointer-events-none ${
            item.danger ? 'text-danger-fg hover:bg-danger-soft' : 'text-fg hover:bg-surface-2'
          }`}
        >
          {item.icon && <span className="flex h-4 w-4 items-center justify-center text-fg-faint">{item.icon}</span>}
          {item.label}
        </button>
      ))}
    </div>,
    document.body,
  );
}

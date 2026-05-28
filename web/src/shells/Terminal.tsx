import { BrowserRouter } from 'react-router-dom';
import { ThemeToggle } from '../lib/theme';
import BrandMark from '../components/BrandMark';
import NotificationBell from '../components/NotificationBell';
import CommandPalette from '../components/CommandPalette';
import TerminalOverview from '../pages/TerminalOverview';
import { AppRoutes } from './appRoutes';

/** Keyboard-first shell: minimal chrome, the ⌘K palette is the primary nav. */
export default function TerminalShell({ onLogout }: { onLogout: () => void }) {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-bg text-fg">
        <header className="sticky top-0 z-30 flex h-11 items-center justify-between border-b border-border bg-bg/85 px-4 backdrop-blur">
          <span className="flex items-center gap-2">
            <BrandMark size={20} />
            <span className="font-display text-sm font-bold tracking-tight">NurProxy</span>
          </span>
          <div className="flex items-center gap-1">
            <kbd className="mr-1 hidden rounded-md border border-border px-2 py-0.5 font-mono text-xs text-fg-faint sm:inline">⌘K</kbd>
            <NotificationBell />
            <ThemeToggle />
            <button onClick={onLogout} className="rounded-lg px-2 py-1.5 font-mono text-sm text-fg-muted transition-colors hover:text-fg">exit</button>
          </div>
        </header>
        <main className="mx-auto max-w-5xl px-4 py-8 sm:px-6">
          <AppRoutes overview={<TerminalOverview />} />
        </main>
      </div>
      <CommandPalette />
    </BrowserRouter>
  );
}

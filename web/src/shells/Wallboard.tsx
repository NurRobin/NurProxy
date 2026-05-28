import { BrowserRouter, Link } from 'react-router-dom';
import { ThemeToggle } from '../lib/theme';
import NotificationBell from '../components/NotificationBell';
import CommandPalette from '../components/CommandPalette';
import Wallboard from '../pages/Wallboard';
import { AppRoutes } from './appRoutes';

/** Read-only, glanceable status board for a spare monitor. Nav lives in ⌘K. */
export default function WallboardShell({ onLogout }: { onLogout: () => void }) {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-bg text-fg">
        <main className="px-4 py-5 sm:px-6">
          <AppRoutes overview={<Wallboard />} />
        </main>
        <div className="fixed right-3 top-3 z-30 flex items-center gap-1 rounded-lg border border-border bg-surface/80 px-1 py-0.5 backdrop-blur">
          <NotificationBell />
          <ThemeToggle />
          <Link to="/settings" aria-label="Settings" title="Settings" className="inline-flex h-9 w-9 items-center justify-center rounded-lg text-fg-muted hover:bg-surface-2 hover:text-fg">
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.7}><path strokeLinecap="round" strokeLinejoin="round" d="M10.5 6a1.65 1.65 0 0 1 3 0l.2 1a1.65 1.65 0 0 0 2.3 1.1l.9-.4a1.65 1.65 0 0 1 2 2.4l-.6.8a1.65 1.65 0 0 0 0 2l.6.8a1.65 1.65 0 0 1-2 2.4l-.9-.4a1.65 1.65 0 0 0-2.3 1.1l-.2 1a1.65 1.65 0 0 1-3 0l-.2-1a1.65 1.65 0 0 0-2.3-1.1l-.9.4a1.65 1.65 0 0 1-2-2.4l.6-.8a1.65 1.65 0 0 0 0-2l-.6-.8a1.65 1.65 0 0 1 2-2.4l.9.4a1.65 1.65 0 0 0 2.3-1.1l.2-1z" /><circle cx="12" cy="12" r="2.5" /></svg>
          </Link>
          <button onClick={onLogout} aria-label="Logout" title="Logout" className="inline-flex h-9 w-9 items-center justify-center rounded-lg text-fg-muted hover:bg-surface-2 hover:text-fg">
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.7}><path strokeLinecap="round" strokeLinejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0 0 13.5 3h-6A2.25 2.25 0 0 0 5.25 5.25v13.5A2.25 2.25 0 0 0 7.5 21h6a2.25 2.25 0 0 0 2.25-2.25V15M18 12H9m9 0-3-3m3 3-3 3" /></svg>
          </button>
        </div>
      </div>
      <CommandPalette />
    </BrowserRouter>
  );
}

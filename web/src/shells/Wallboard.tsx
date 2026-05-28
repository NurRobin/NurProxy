import { BrowserRouter, NavLink } from 'react-router-dom';
import { LayoutDashboard, Settings as SettingsIcon, LogOut } from 'lucide-react';
import { ThemeToggle } from '../lib/theme';
import NotificationBell from '../components/NotificationBell';
import CommandPalette from '../components/CommandPalette';
import Wallboard from '../pages/Wallboard';
import { AppRoutes } from './appRoutes';

function ctrlClass({ isActive }: { isActive: boolean }) {
  return `inline-flex h-9 w-9 items-center justify-center rounded-lg transition-colors ${
    isActive ? 'bg-accent-soft text-accent' : 'text-fg-muted hover:bg-surface-2 hover:text-fg'
  }`;
}

/** Read-only, glanceable status board for a spare monitor. Nav lives in ⌘K. */
export default function WallboardShell({ onLogout }: { onLogout: () => void }) {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-bg text-fg">
        <main className="px-4 py-5 sm:px-6">
          <AppRoutes overview={<Wallboard />} />
        </main>
        <div className="fixed right-3 top-3 z-30 flex items-center gap-1 rounded-lg border border-border bg-surface/80 px-1 py-0.5 backdrop-blur">
          <NavLink to="/" end className={ctrlClass} aria-label="Board" title="Board"><LayoutDashboard className="h-5 w-5" /></NavLink>
          <NavLink to="/settings" className={ctrlClass} aria-label="Settings" title="Settings"><SettingsIcon className="h-5 w-5" /></NavLink>
          <NotificationBell />
          <ThemeToggle />
          <button onClick={onLogout} aria-label="Logout" title="Logout" className="inline-flex h-9 w-9 items-center justify-center rounded-lg text-fg-muted transition-colors hover:bg-surface-2 hover:text-fg"><LogOut className="h-5 w-5" /></button>
        </div>
      </div>
      <CommandPalette />
    </BrowserRouter>
  );
}

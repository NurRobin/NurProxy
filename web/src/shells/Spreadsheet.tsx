import { BrowserRouter, NavLink } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ThemeToggle } from '../lib/theme';
import BrandMark from '../components/BrandMark';
import NotificationBell from '../components/NotificationBell';
import CommandPalette from '../components/CommandPalette';
import SpreadsheetOverview from '../pages/SpreadsheetOverview';
import { AppRoutes } from './appRoutes';
import { NAV } from './nav';

function navLinkClass({ isActive }: { isActive: boolean }) {
  return `rounded-md px-2.5 py-1.5 text-sm font-medium transition-colors ${
    isActive ? 'bg-accent-soft text-accent' : 'text-fg-muted hover:bg-surface-2 hover:text-fg'
  }`;
}

/** Dense, table-first shell for power users. Overview is a sortable grid. */
export default function SpreadsheetShell({ onLogout }: { onLogout: () => void }) {
  const { t } = useTranslation();
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-bg text-fg">
        <header className="sticky top-0 z-30 border-b border-border bg-bg/85 backdrop-blur">
          <div className="mx-auto flex h-12 max-w-7xl items-center justify-between gap-4 px-4 sm:px-6">
            <div className="flex min-w-0 items-center gap-4">
              <span className="flex items-center gap-2"><BrandMark size={22} /><span className="font-display text-base font-bold tracking-tight">NurProxy</span></span>
              <nav className="hidden items-center gap-0.5 sm:flex">
                {NAV.map(({ to, label }) => <NavLink key={to} to={to} end={to === '/'} className={navLinkClass}>{t(label)}</NavLink>)}
              </nav>
            </div>
            <div className="flex items-center gap-1">
              <NavLink to="/help" className={navLinkClass}>{t('common.docs')}</NavLink>
              <NotificationBell />
              <ThemeToggle />
              <button onClick={onLogout} className="rounded-md px-2.5 py-1.5 text-sm font-medium text-fg-muted hover:bg-surface-2 hover:text-fg">{t('common.logout')}</button>
            </div>
          </div>
        </header>
        <main className="mx-auto max-w-7xl px-4 py-6 sm:px-6">
          <AppRoutes overview={<SpreadsheetOverview />} />
        </main>
      </div>
      <CommandPalette />
    </BrowserRouter>
  );
}

import { BrowserRouter, NavLink } from 'react-router-dom';
import { ThemeToggle } from '../lib/theme';
import BrandMark from '../components/BrandMark';
import Overview from '../pages/Overview';
import { AppRoutes } from './appRoutes';
import { NAV } from './nav';

function navLinkClass({ isActive }: { isActive: boolean }) {
  return `rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
    isActive ? 'bg-accent-soft text-accent' : 'text-fg-muted hover:bg-surface-2 hover:text-fg'
  }`;
}

export default function ClassicShell({ onLogout }: { onLogout: () => void }) {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-bg text-fg">
        <header className="sticky top-0 z-30 border-b border-border bg-bg/85 backdrop-blur">
          <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
            <div className="flex h-14 items-center justify-between gap-4">
              <div className="flex min-w-0 items-center gap-6">
                <span className="flex items-center gap-2">
                  <BrandMark />
                  <span className="font-display text-lg font-bold tracking-tight text-fg">NurProxy</span>
                </span>
                <nav className="hidden items-center gap-1 sm:flex">
                  {NAV.map(({ to, label }) => (
                    <NavLink key={to} to={to} end={to === '/'} className={navLinkClass}>{label}</NavLink>
                  ))}
                </nav>
              </div>
              <div className="flex items-center gap-1">
                <NavLink to="/help" className={navLinkClass}>Docs</NavLink>
                <ThemeToggle />
                <button onClick={onLogout} className="rounded-lg px-3 py-2 text-sm font-medium text-fg-muted transition-colors hover:bg-surface-2 hover:text-fg">Logout</button>
              </div>
            </div>
            <nav className="-mx-1 flex gap-1 overflow-x-auto pb-2 sm:hidden">
              {NAV.map(({ to, label }) => (
                <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) =>
                  `whitespace-nowrap rounded-lg px-3 py-1.5 text-sm font-medium transition-colors ${isActive ? 'bg-accent-soft text-accent' : 'text-fg-muted hover:bg-surface-2 hover:text-fg'}`
                }>{label}</NavLink>
              ))}
            </nav>
          </div>
        </header>
        <main className="mx-auto max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
          <AppRoutes overview={<Overview />} />
        </main>
      </div>
    </BrowserRouter>
  );
}

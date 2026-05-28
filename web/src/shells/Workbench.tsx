import { useEffect, useState } from 'react';
import { BrowserRouter, NavLink } from 'react-router-dom';
import { api } from '../lib/api';
import { ThemeToggle } from '../lib/theme';
import BrandMark from '../components/BrandMark';
import NotificationBell from '../components/NotificationBell';
import Topology from '../pages/Topology';
import { AppRoutes } from './appRoutes';
import { NAV } from './nav';

function useCounts() {
  const [counts, setCounts] = useState<Record<string, number>>({});
  useEffect(() => {
    let live = true;
    const load = async () => {
      try {
        const [a, d] = await Promise.all([api.listAgents(), api.listDomains()]);
        if (live) setCounts({ '/agents': a.length, '/domains': d.length });
      } catch (e) {
        // Non-critical (nav badges); don't toast every 30s, but don't swallow silently.
        console.warn('nav counts refresh failed', e);
      }
    };
    load();
    const t = setInterval(load, 30000);
    return () => { live = false; clearInterval(t); };
  }, []);
  return counts;
}

function railClass({ isActive }: { isActive: boolean }) {
  return `flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
    isActive ? 'bg-accent-soft text-accent' : 'text-fg-muted hover:bg-surface-2 hover:text-fg'
  }`;
}

export default function WorkbenchShell({ onLogout }: { onLogout: () => void }) {
  const counts = useCounts();

  return (
    <BrowserRouter>
      <div className="flex min-h-screen bg-bg text-fg">
        {/* Desktop sidebar rail */}
        <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-border bg-surface md:flex">
          <div className="flex items-center gap-2 px-4 py-4">
            <BrandMark />
            <span className="font-display text-lg font-bold tracking-tight text-fg">NurProxy</span>
          </div>
          <nav className="flex-1 space-y-0.5 px-3 py-2">
            {NAV.map(({ to, label, icon }) => (
              <NavLink key={to} to={to} end={to === '/'} className={railClass}>
                {icon}
                <span className="flex-1">{label}</span>
                {counts[to] !== undefined && (
                  <span className="rounded-full bg-surface-2 px-2 py-0.5 text-xs font-semibold text-fg-faint">{counts[to]}</span>
                )}
              </NavLink>
            ))}
          </nav>
          <div className="space-y-0.5 border-t border-border px-3 py-3">
            <NavLink to="/help" className={railClass}>
              <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.7}><path strokeLinecap="round" strokeLinejoin="round" d="M9.879 7.519a3 3 0 1 1 4.04 2.829c-.68.252-1.171.836-1.33 1.546l-.149.66M12 17h.007M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z" /></svg>
              <span className="flex-1">Docs</span>
            </NavLink>
            <div className="flex items-center justify-between px-3 pt-1">
              <button onClick={onLogout} className="text-sm font-medium text-fg-muted transition-colors hover:text-fg">Logout</button>
              <div className="flex items-center gap-1"><NotificationBell /><ThemeToggle /></div>
            </div>
          </div>
        </aside>

        {/* Mobile top bar */}
        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-30 border-b border-border bg-bg/85 backdrop-blur md:hidden">
            <div className="flex h-14 items-center justify-between px-4">
              <span className="flex items-center gap-2"><BrandMark /><span className="font-display text-lg font-bold text-fg">NurProxy</span></span>
              <div className="flex items-center gap-1"><NotificationBell /><ThemeToggle /><button onClick={onLogout} className="rounded-lg px-2 py-2 text-sm font-medium text-fg-muted hover:text-fg">Logout</button></div>
            </div>
            <nav className="-mx-1 flex gap-1 overflow-x-auto px-3 pb-2">
              {[...NAV, { to: '/help', label: 'Docs', icon: null }].map(({ to, label }) => (
                <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) =>
                  `whitespace-nowrap rounded-lg px-3 py-1.5 text-sm font-medium transition-colors ${isActive ? 'bg-accent-soft text-accent' : 'text-fg-muted hover:bg-surface-2 hover:text-fg'}`
                }>{label}</NavLink>
              ))}
            </nav>
          </header>
          <main className="min-w-0 flex-1 px-4 py-6 sm:px-6 lg:px-8">
            <div className="mx-auto w-full max-w-6xl">
              <AppRoutes overview={<Topology />} />
            </div>
          </main>
        </div>
      </div>
    </BrowserRouter>
  );
}

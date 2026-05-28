import { useState, useEffect, useCallback } from 'react';
import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom';
import { api } from './lib/api';
import Overview from './pages/Overview';
import Agents from './pages/Agents';
import Domains from './pages/Domains';
import Settings from './pages/Settings';
import Login from './pages/Login';
import SetupWizard from './pages/SetupWizard';

type AuthState = 'loading' | 'setup_required' | 'unauthenticated' | 'needs_setup_wizard' | 'authenticated';

function App() {
  const [authState, setAuthState] = useState<AuthState>('loading');

  const checkSetupWizard = useCallback(async () => {
    try {
      const settings = await api.getSettings();
      const setupComplete = settings.find((s) => s.key === 'setup_complete');
      if (setupComplete?.value === 'true') {
        setAuthState('authenticated');
      } else {
        setAuthState('needs_setup_wizard');
      }
    } catch {
      setAuthState('authenticated');
    }
  }, []);

  const checkAuth = useCallback(async () => {
    try {
      const status = await api.authStatus();
      if (status.setup_required) {
        setAuthState('setup_required');
      } else if (status.authenticated) {
        // Authenticated - check if wizard is needed
        await checkSetupWizard();
      } else {
        setAuthState('unauthenticated');
      }
    } catch {
      setAuthState('unauthenticated');
    }
  }, [checkSetupWizard]);

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  async function handleLogout() {
    try {
      await api.logout();
    } catch {
      // ignore
    }
    setAuthState('unauthenticated');
  }

  if (authState === 'loading') {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-950">
        <div className="text-gray-400">Loading...</div>
      </div>
    );
  }

  if (authState === 'setup_required' || authState === 'unauthenticated') {
    return (
      <BrowserRouter>
        <Routes>
          <Route path="*" element={<Login onAuth={() => checkSetupWizard()} />} />
        </Routes>
      </BrowserRouter>
    );
  }

  if (authState === 'needs_setup_wizard') {
    return (
      <BrowserRouter>
        <Routes>
          <Route path="*" element={<SetupWizard onComplete={() => setAuthState('authenticated')} />} />
        </Routes>
      </BrowserRouter>
    );
  }

  return (
    <BrowserRouter>
      <div className="min-h-screen bg-gray-950 text-gray-100">
        <nav className="border-b border-gray-800 bg-gray-900">
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="flex h-14 items-center justify-between">
              <div className="flex items-center gap-6">
                <span className="text-lg font-bold text-white">NurProxy</span>
                <div className="hidden sm:flex sm:gap-1">
                  {[
                    { to: '/', label: 'Overview' },
                    { to: '/agents', label: 'Agents' },
                    { to: '/domains', label: 'Domains' },
                    { to: '/settings', label: 'Settings' },
                  ].map(({ to, label }) => (
                    <NavLink
                      key={to}
                      to={to}
                      end={to === '/'}
                      className={({ isActive }) =>
                        `rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                          isActive
                            ? 'bg-gray-800 text-white'
                            : 'text-gray-400 hover:bg-gray-800 hover:text-white'
                        }`
                      }
                    >
                      {label}
                    </NavLink>
                  ))}
                </div>
              </div>
              <button
                onClick={handleLogout}
                className="rounded-md px-3 py-2 text-sm font-medium text-gray-400 transition-colors hover:bg-gray-800 hover:text-white"
              >
                Logout
              </button>
            </div>
            {/* Mobile nav */}
            <div className="flex gap-1 overflow-x-auto pb-2 sm:hidden">
              {[
                { to: '/', label: 'Overview' },
                { to: '/agents', label: 'Agents' },
                { to: '/domains', label: 'Domains' },
                { to: '/settings', label: 'Settings' },
              ].map(({ to, label }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={to === '/'}
                  className={({ isActive }) =>
                    `whitespace-nowrap rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                      isActive
                        ? 'bg-gray-800 text-white'
                        : 'text-gray-400 hover:bg-gray-800 hover:text-white'
                    }`
                  }
                >
                  {label}
                </NavLink>
              ))}
            </div>
          </div>
        </nav>
        <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/agents" element={<Agents />} />
            <Route path="/domains" element={<Domains />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/login" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;

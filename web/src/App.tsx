import { useState, useEffect, useCallback } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { api } from './lib/api';
import { useUIVariant } from './lib/ui-variant-context';
import { Spinner } from './components/Button';
import Login from './pages/Login';
import SetupWizard from './pages/SetupWizard';
import ClassicShell from './shells/Classic';
import WorkbenchShell from './shells/Workbench';
import WallboardShell from './shells/Wallboard';
import SpreadsheetShell from './shells/Spreadsheet';

const SHELLS = {
  classic: ClassicShell,
  workbench: WorkbenchShell,
  wallboard: WallboardShell,
  spreadsheet: SpreadsheetShell,
} as const;

type AuthState = 'loading' | 'error' | 'setup_required' | 'unauthenticated' | 'needs_setup_wizard' | 'authenticated';

function App() {
  const [authState, setAuthState] = useState<AuthState>('loading');
  const { variant } = useUIVariant();

  const checkSetupWizard = useCallback(async () => {
    try {
      const settings = await api.getSettings();
      const setupComplete = settings.find((s) => s.key === 'setup_complete');
      setAuthState(setupComplete?.value === 'true' ? 'authenticated' : 'needs_setup_wizard');
    } catch {
      // Don't fail open into the dashboard — surface the outage and let the user retry.
      setAuthState('error');
    }
  }, []);

  const checkAuth = useCallback(async () => {
    try {
      const status = await api.authStatus();
      if (status.setup_required) setAuthState('setup_required');
      else if (status.authenticated) await checkSetupWizard();
      else setAuthState('unauthenticated');
    } catch {
      setAuthState('unauthenticated');
    }
  }, [checkSetupWizard]);

  useEffect(() => { checkAuth(); }, [checkAuth]);

  async function handleLogout() {
    try { await api.logout(); } catch { /* ignore */ }
    setAuthState('unauthenticated');
  }

  if (authState === 'loading') {
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg text-fg-muted">
        <Spinner className="h-6 w-6" />
      </div>
    );
  }

  if (authState === 'error') {
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg px-4">
        <div className="w-full max-w-sm rounded-xl border border-border bg-surface p-6 text-center shadow-card">
          <h1 className="font-display text-lg font-semibold text-fg">Can’t reach the orchestrator</h1>
          <p className="mt-1 text-sm text-fg-muted">We couldn’t verify the dashboard state. Check that the orchestrator is running, then try again.</p>
          <button
            onClick={() => { setAuthState('loading'); checkAuth(); }}
            className="mt-5 rounded-lg bg-accent px-4 py-2 text-sm font-medium text-accent-fg hover:bg-accent-hover"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (authState === 'setup_required' || authState === 'unauthenticated') {
    return (
      <BrowserRouter>
        <Routes><Route path="*" element={<Login onAuth={() => checkSetupWizard()} />} /></Routes>
      </BrowserRouter>
    );
  }

  if (authState === 'needs_setup_wizard') {
    return (
      <BrowserRouter>
        <Routes><Route path="*" element={<SetupWizard onComplete={() => setAuthState('authenticated')} />} /></Routes>
      </BrowserRouter>
    );
  }

  const Shell = SHELLS[variant] ?? ClassicShell;
  return <Shell onLogout={handleLogout} />;
}

export default App;

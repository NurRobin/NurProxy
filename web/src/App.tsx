import { useState, useEffect, useCallback } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { api } from './lib/api';
import { useUIVariant } from './lib/ui-variant-context';
import { Spinner } from './components/Button';
import Login from './pages/Login';
import SetupWizard from './pages/SetupWizard';
import ClassicShell from './shells/Classic';
import WorkbenchShell from './shells/Workbench';

type AuthState = 'loading' | 'setup_required' | 'unauthenticated' | 'needs_setup_wizard' | 'authenticated';

function App() {
  const [authState, setAuthState] = useState<AuthState>('loading');
  const { variant } = useUIVariant();

  const checkSetupWizard = useCallback(async () => {
    try {
      const settings = await api.getSettings();
      const setupComplete = settings.find((s) => s.key === 'setup_complete');
      setAuthState(setupComplete?.value === 'true' ? 'authenticated' : 'needs_setup_wizard');
    } catch {
      setAuthState('authenticated');
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

  return variant === 'classic'
    ? <ClassicShell onLogout={handleLogout} />
    : <WorkbenchShell onLogout={handleLogout} />;
}

export default App;

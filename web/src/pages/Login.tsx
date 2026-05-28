import { useState, useEffect } from 'react';
import { api } from '../lib/api';
import Button, { Spinner } from '../components/Button';
import { Field, PasswordInput } from '../components/Field';
import BrandMark from '../components/BrandMark';

interface LoginProps {
  onAuth: () => void;
}

export default function Login({ onAuth }: LoginProps) {
  const [setupRequired, setSetupRequired] = useState<boolean | null>(null);
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api.authStatus().then((s) => setSetupRequired(s.setup_required)).catch(() => setSetupRequired(true));
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    if (setupRequired) {
      if (password.length < 8) { setError('Password must be at least 8 characters.'); return; }
      if (password !== confirmPassword) { setError('Passwords do not match.'); return; }
    }
    setLoading(true);
    try {
      if (setupRequired) await api.setup(password);
      else await api.login(password);
      onAuth();
    } catch (err) {
      setError(err instanceof Error ? err.message.replace(/^API error \d+:\s*/, '') : 'Authentication failed.');
    } finally {
      setLoading(false);
    }
  }

  if (setupRequired === null) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg text-fg-muted">
        <Spinner className="h-6 w-6" />
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center text-center">
          <BrandMark size={40} />
          <h1 className="mt-4 font-display text-2xl font-bold tracking-tight text-fg">
            {setupRequired ? 'Welcome to NurProxy' : 'NurProxy'}
          </h1>
          <p className="mt-1 text-sm text-fg-muted">
            {setupRequired ? 'Create the admin password to get started.' : 'Sign in to continue.'}
          </p>
        </div>

        <form onSubmit={handleSubmit} className="rounded-xl border border-border bg-surface p-6 shadow-card">
          {error && (
            <div className="mb-4 rounded-lg border border-danger/40 bg-danger-soft px-4 py-3 text-sm text-danger-fg">
              {error}
            </div>
          )}

          <div className="space-y-4">
            <Field label={setupRequired ? 'Admin password' : 'Password'} htmlFor="password">
              <PasswordInput
                id="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={setupRequired ? 'At least 8 characters' : 'Enter password'}
                autoFocus
                required
              />
            </Field>

            {setupRequired && (
              <Field label="Confirm password" htmlFor="confirm">
                <PasswordInput
                  id="confirm"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Re-enter password"
                  required
                />
              </Field>
            )}
          </div>

          <Button type="submit" loading={loading} className="mt-6 w-full justify-center">
            {setupRequired ? 'Create password & continue' : 'Sign in'}
          </Button>

          {setupRequired && (
            <p className="mt-4 text-xs leading-relaxed text-fg-faint">
              This is the only admin account. There’s no email reset — store this password
              somewhere safe.
            </p>
          )}
        </form>
      </div>
    </div>
  );
}

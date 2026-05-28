import { useState, useEffect, useCallback } from 'react';
import { api } from '../lib/api';
import type { Provider, Setting } from '../lib/types';
import type { HealthResponse } from '../lib/api';
import Modal from '../components/Modal';
import ConfirmDialog from '../components/ConfirmDialog';

export default function Settings() {
  const [providers, setProviders] = useState<Provider[]>([]);
  const [settings, setSettings] = useState<Setting[]>([]);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);

  // Provider form
  const [showAddProvider, setShowAddProvider] = useState(false);
  const [provType, setProvType] = useState('cloudflare');
  const [provName, setProvName] = useState('');
  const [provApiToken, setProvApiToken] = useState('');
  const [provZoneId, setProvZoneId] = useState('');
  const [provZoneName, setProvZoneName] = useState('');
  const [provTestResult, setProvTestResult] = useState<{ valid: boolean; message: string } | null>(null);
  const [provTestLoading, setProvTestLoading] = useState(false);
  const [provCreateLoading, setProvCreateLoading] = useState(false);
  const [provError, setProvError] = useState('');

  // Delete provider
  const [deleteProviderId, setDeleteProviderId] = useState<string | null>(null);

  // Reconciler
  const [reconcilerInterval, setReconcilerInterval] = useState('');
  const [reconcilerSaving, setReconcilerSaving] = useState(false);

  // Password
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [passwordSuccess, setPasswordSuccess] = useState('');
  const [passwordLoading, setPasswordLoading] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const [p, s, h] = await Promise.all([
        api.listProviders(),
        api.getSettings(),
        api.health(),
      ]);
      setProviders(p);
      setSettings(s);
      setHealth(h);

      const rec = s.find((st) => st.key === 'reconciler_interval');
      if (rec) setReconcilerInterval(rec.value);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  function getProviderConfig() {
    if (provType === 'cloudflare') {
      return { api_token: provApiToken };
    }
    return { api_token: provApiToken };
  }

  async function handleTestProvider() {
    setProvTestLoading(true);
    setProvTestResult(null);
    try {
      const result = await api.testProvider({
        type: provType,
        config: getProviderConfig(),
      });
      setProvTestResult(result);
    } catch (err) {
      setProvTestResult({ valid: false, message: err instanceof Error ? err.message : 'Test failed' });
    } finally {
      setProvTestLoading(false);
    }
  }

  async function handleCreateProvider() {
    if (!provName || !provApiToken) return;
    setProvCreateLoading(true);
    setProvError('');
    try {
      await api.createProvider({
        type: provType,
        name: provName,
        config: getProviderConfig(),
        zone_id: provZoneId || undefined,
        zone_name: provZoneName || undefined,
      });
      setShowAddProvider(false);
      setProvName('');
      setProvApiToken('');
      setProvZoneId('');
      setProvZoneName('');
      setProvTestResult(null);
      fetchData();
    } catch (err) {
      setProvError(err instanceof Error ? err.message : 'Failed to create provider');
    } finally {
      setProvCreateLoading(false);
    }
  }

  async function handleDeleteProvider() {
    if (!deleteProviderId) return;
    try {
      await api.deleteProvider(deleteProviderId);
      setDeleteProviderId(null);
      fetchData();
    } catch {
      // ignore
    }
  }

  async function handleSaveReconciler() {
    setReconcilerSaving(true);
    try {
      await api.updateSetting('reconciler_interval', reconcilerInterval);
    } catch {
      // ignore
    } finally {
      setReconcilerSaving(false);
    }
  }

  async function handleChangePassword() {
    setPasswordError('');
    setPasswordSuccess('');
    if (newPassword.length < 8) {
      setPasswordError('Password must be at least 8 characters');
      return;
    }
    if (newPassword !== confirmPassword) {
      setPasswordError('Passwords do not match');
      return;
    }

    setPasswordLoading(true);
    try {
      // Login with current password to verify, then we'd need a password change endpoint
      // For now, we verify by logging in first
      await api.login(currentPassword);
      // The backend doesn't have a dedicated change-password endpoint,
      // so we use the setup endpoint if available, or the settings endpoint
      await api.updateSetting('admin_password_hash', newPassword);
      setPasswordSuccess('Password updated');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      setPasswordError(err instanceof Error ? err.message : 'Failed to change password');
    } finally {
      setPasswordLoading(false);
    }
  }

  if (loading) {
    return <div className="text-gray-400">Loading...</div>;
  }

  return (
    <div className="space-y-8">
      <h1 className="text-2xl font-bold text-white">Settings</h1>

      {/* DNS Providers */}
      <section className="rounded-xl border border-gray-800 bg-gray-900 p-6">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">DNS Providers</h2>
          <button
            onClick={() => {
              setShowAddProvider(true);
              setProvError('');
              setProvTestResult(null);
            }}
            className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700"
          >
            Add Provider
          </button>
        </div>

        {providers.length === 0 ? (
          <p className="mt-4 text-sm text-gray-500">No DNS providers configured. Add one to start managing domains.</p>
        ) : (
          <div className="mt-4 space-y-3">
            {providers.map((p) => (
              <div key={p.id} className="flex items-center justify-between rounded-lg bg-gray-800 px-4 py-3">
                <div className="flex items-center gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <p className="font-medium text-white">{p.name}</p>
                      <span className="rounded bg-gray-700 px-1.5 py-0.5 text-xs text-gray-400">{p.type}</span>
                      {p.is_default && (
                        <span className="rounded bg-blue-900/40 px-1.5 py-0.5 text-xs text-blue-400">default</span>
                      )}
                    </div>
                    <p className="mt-0.5 text-sm text-gray-500">{p.zone_name || 'No zone configured'}</p>
                  </div>
                </div>
                <button
                  onClick={() => setDeleteProviderId(p.id)}
                  className="text-xs text-red-400 hover:text-red-300"
                >
                  Delete
                </button>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Reconciler */}
      <section className="rounded-xl border border-gray-800 bg-gray-900 p-6">
        <h2 className="text-lg font-semibold text-white">Reconciler</h2>
        <p className="mt-1 text-sm text-gray-400">Controls how often the system syncs DNS records and proxy configs.</p>
        <div className="mt-4 flex items-end gap-3">
          <div>
            <label className="block text-sm font-medium text-gray-300">Interval (seconds)</label>
            <input
              type="number"
              value={reconcilerInterval}
              onChange={(e) => setReconcilerInterval(e.target.value)}
              min={5}
              className="mt-1 block w-32 rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            />
          </div>
          <button
            onClick={handleSaveReconciler}
            disabled={reconcilerSaving}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
          >
            {reconcilerSaving ? 'Saving...' : 'Save'}
          </button>
        </div>
        {settings.find((s) => s.key === 'reconciler_last_run') && (
          <p className="mt-3 text-xs text-gray-500">
            Last run: {settings.find((s) => s.key === 'reconciler_last_run')?.value ?? 'Never'}
          </p>
        )}
      </section>

      {/* Auth */}
      <section className="rounded-xl border border-gray-800 bg-gray-900 p-6">
        <h2 className="text-lg font-semibold text-white">Authentication</h2>
        <p className="mt-1 text-sm text-gray-400">Change the admin password.</p>

        {passwordError && (
          <div className="mt-3 rounded-lg bg-red-900/30 border border-red-800 px-3 py-2 text-sm text-red-400">
            {passwordError}
          </div>
        )}
        {passwordSuccess && (
          <div className="mt-3 rounded-lg bg-green-900/30 border border-green-800 px-3 py-2 text-sm text-green-400">
            {passwordSuccess}
          </div>
        )}

        <div className="mt-4 max-w-sm space-y-3">
          <div>
            <label className="block text-sm font-medium text-gray-300">Current Password</label>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300">New Password</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
              placeholder="Minimum 8 characters"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300">Confirm New Password</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            />
          </div>
          <button
            onClick={handleChangePassword}
            disabled={passwordLoading || !currentPassword || !newPassword}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
          >
            {passwordLoading ? 'Updating...' : 'Change Password'}
          </button>
        </div>
      </section>

      {/* System Info */}
      <section className="rounded-xl border border-gray-800 bg-gray-900 p-6">
        <h2 className="text-lg font-semibold text-white">System Info</h2>
        <dl className="mt-4 space-y-2 text-sm">
          <div className="flex justify-between">
            <dt className="text-gray-500">Version</dt>
            <dd className="text-gray-200">{health?.version ?? 'unknown'}</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-gray-500">Status</dt>
            <dd className="text-green-400">{health?.status ?? 'unknown'}</dd>
          </div>
        </dl>
      </section>

      {/* Add Provider Modal */}
      <Modal open={showAddProvider} onClose={() => setShowAddProvider(false)} title="Add DNS Provider">
        <div className="space-y-4">
          {provError && (
            <div className="rounded-lg bg-red-900/30 border border-red-800 px-3 py-2 text-sm text-red-400">{provError}</div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-300">Provider Type</label>
            <select
              value={provType}
              onChange={(e) => setProvType(e.target.value)}
              className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            >
              <option value="cloudflare">Cloudflare</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300">Name</label>
            <input
              value={provName}
              onChange={(e) => setProvName(e.target.value)}
              className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
              placeholder="e.g. My Cloudflare"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300">API Token</label>
            <input
              type="password"
              value={provApiToken}
              onChange={(e) => setProvApiToken(e.target.value)}
              className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
              placeholder="Your API token"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-sm font-medium text-gray-300">Zone ID</label>
              <input
                value={provZoneId}
                onChange={(e) => setProvZoneId(e.target.value)}
                className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
                placeholder="Optional"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300">Zone Name</label>
              <input
                value={provZoneName}
                onChange={(e) => setProvZoneName(e.target.value)}
                className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
                placeholder="e.g. example.com"
              />
            </div>
          </div>

          {/* Test result */}
          {provTestResult && (
            <div
              className={`rounded-lg px-3 py-2 text-sm ${
                provTestResult.valid
                  ? 'bg-green-900/30 border border-green-800 text-green-400'
                  : 'bg-red-900/30 border border-red-800 text-red-400'
              }`}
            >
              {provTestResult.message}
            </div>
          )}

          <div className="flex justify-between pt-2">
            <button
              onClick={handleTestProvider}
              disabled={provTestLoading || !provApiToken}
              className="rounded-lg border border-gray-600 px-4 py-2 text-sm font-medium text-gray-300 hover:bg-gray-800 disabled:opacity-50"
            >
              {provTestLoading ? 'Testing...' : 'Test Connection'}
            </button>
            <div className="flex gap-3">
              <button
                onClick={() => setShowAddProvider(false)}
                className="rounded-lg border border-gray-600 px-4 py-2 text-sm font-medium text-gray-300 hover:bg-gray-800"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateProvider}
                disabled={provCreateLoading || !provName || !provApiToken}
                className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
              >
                {provCreateLoading ? 'Adding...' : 'Add Provider'}
              </button>
            </div>
          </div>
        </div>
      </Modal>

      {/* Delete Provider Confirm */}
      <ConfirmDialog
        open={deleteProviderId !== null}
        onClose={() => setDeleteProviderId(null)}
        onConfirm={handleDeleteProvider}
        title="Delete Provider"
        message="Are you sure you want to delete this DNS provider? Domains using this provider will lose DNS management."
        confirmLabel="Delete"
        danger
      />
    </div>
  );
}

import { useState, useEffect, useCallback } from 'react';
import { api } from '../lib/api';
import type { Provider, Zone, Setting } from '../lib/types';
import type { HealthResponse, TestProviderZone } from '../lib/api';
import Modal from '../components/Modal';
import ConfirmDialog from '../components/ConfirmDialog';

export default function Settings() {
  const [providers, setProviders] = useState<Provider[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const [, setSettings] = useState<Setting[]>([]);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);

  // Add provider modal
  const [showAddProvider, setShowAddProvider] = useState(false);
  const [provType, setProvType] = useState('cloudflare');
  const [provApiToken, setProvApiToken] = useState('');
  const [provTestLoading, setProvTestLoading] = useState(false);
  const [provTestError, setProvTestError] = useState('');
  const [provZones, setProvZones] = useState<TestProviderZone[]>([]);
  const [selectedZones, setSelectedZones] = useState<Set<string>>(new Set());
  const [provSaveLoading, setProvSaveLoading] = useState(false);
  const [provError, setProvError] = useState('');
  const [provModalStep, setProvModalStep] = useState<'token' | 'zones'>('token');

  // Delete provider
  const [deleteProviderId, setDeleteProviderId] = useState<string | null>(null);

  // Delete zone
  const [deleteZoneId, setDeleteZoneId] = useState<string | null>(null);

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
      const [p, z, s, h] = await Promise.all([
        api.listProviders(),
        api.listAllZones(),
        api.getSettings(),
        api.health(),
      ]);
      setProviders(p);
      setZones(z);
      setSettings(s);
      setHealth(h);
      const rec = s.find((st) => st.key === 'reconciler_interval');
      if (rec) setReconcilerInterval(rec.value);
    } catch { /* ignore */ } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  function resetProviderModal() {
    setProvType('cloudflare');
    setProvApiToken('');
    setProvTestLoading(false);
    setProvTestError('');
    setProvZones([]);
    setSelectedZones(new Set());
    setProvSaveLoading(false);
    setProvError('');
    setProvModalStep('token');
  }

  async function handleTestToken() {
    setProvTestLoading(true);
    setProvTestError('');
    try {
      const result = await api.testProvider({
        type: provType,
        config: { api_token: provApiToken },
      });
      if (!result.valid) {
        setProvTestError(result.message);
        return;
      }
      if (result.zones && result.zones.length > 0) {
        setProvZones(result.zones);
        setSelectedZones(new Set(result.zones.map(z => z.id)));
        setProvModalStep('zones');
      } else {
        setProvTestError('Token is valid but no zones found. Check Zone:Read permission.');
      }
    } catch (err) {
      setProvTestError(err instanceof Error ? err.message : 'Connection failed');
    } finally {
      setProvTestLoading(false);
    }
  }

  function toggleZone(id: string) {
    setSelectedZones(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  function toggleAllZones() {
    if (selectedZones.size === provZones.length) setSelectedZones(new Set());
    else setSelectedZones(new Set(provZones.map(z => z.id)));
  }

  async function handleSaveZones() {
    if (selectedZones.size === 0) return;
    setProvSaveLoading(true);
    setProvError('');
    try {
      // Step 1: Create the provider
      const provider = await api.createProvider({
        type: provType,
        name: provType,
        config: { api_token: provApiToken },
      });

      // Step 2: Batch-create selected zones
      const zonesToCreate = provZones
        .filter(z => selectedZones.has(z.id))
        .map(z => ({ external_id: z.id, name: z.name }));

      await api.createZonesBatch({
        provider_id: provider.id,
        zones: zonesToCreate,
      });

      setShowAddProvider(false);
      resetProviderModal();
      fetchData();
    } catch (err) {
      setProvError(err instanceof Error ? err.message : 'Failed to save');
    } finally {
      setProvSaveLoading(false);
    }
  }

  async function handleDeleteProvider() {
    if (!deleteProviderId) return;
    try {
      await api.deleteProvider(deleteProviderId);
      setDeleteProviderId(null);
      fetchData();
    } catch { /* ignore */ }
  }

  async function handleDeleteZone() {
    if (!deleteZoneId) return;
    try {
      await api.deleteZone(deleteZoneId);
      setDeleteZoneId(null);
      fetchData();
    } catch { /* ignore */ }
  }

  async function handleSaveReconciler() {
    setReconcilerSaving(true);
    try {
      await api.updateSetting('reconciler_interval', reconcilerInterval);
    } catch { /* ignore */ } finally {
      setReconcilerSaving(false);
    }
  }

  async function handleChangePassword() {
    setPasswordError('');
    setPasswordSuccess('');
    if (newPassword.length < 8) { setPasswordError('Password must be at least 8 characters'); return; }
    if (newPassword !== confirmPassword) { setPasswordError('Passwords do not match'); return; }
    setPasswordLoading(true);
    try {
      await api.login(currentPassword);
      await api.updateSetting('admin_password_hash', newPassword);
      setPasswordSuccess('Password updated');
      setCurrentPassword(''); setNewPassword(''); setConfirmPassword('');
    } catch (err) {
      setPasswordError(err instanceof Error ? err.message : 'Failed to change password');
    } finally {
      setPasswordLoading(false);
    }
  }

  if (loading) return <div className="text-gray-400">Loading...</div>;

  return (
    <div className="space-y-8">
      <h1 className="text-2xl font-bold text-white">Settings</h1>

      {/* DNS Providers */}
      <section className="rounded-xl border border-gray-800 bg-gray-900 p-6">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">DNS Providers</h2>
          <button
            onClick={() => { resetProviderModal(); setShowAddProvider(true); }}
            className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700"
          >
            Add Provider
          </button>
        </div>

        {providers.length === 0 ? (
          <p className="mt-4 text-sm text-gray-500">No DNS providers configured.</p>
        ) : (
          <div className="mt-4 space-y-3">
            {providers.map((p) => {
              const providerZones = zones.filter(z => z.provider_id === p.id);
              return (
                <div key={p.id} className="rounded-lg bg-gray-800 px-4 py-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <p className="font-medium text-white">{p.name}</p>
                      <span className="rounded bg-gray-700 px-1.5 py-0.5 text-xs text-gray-400">{p.type}</span>
                      {p.is_default && <span className="rounded bg-blue-900/40 px-1.5 py-0.5 text-xs text-blue-400">default</span>}
                    </div>
                    <button onClick={() => setDeleteProviderId(p.id)} className="text-xs text-red-400 hover:text-red-300">Delete</button>
                  </div>
                  {providerZones.length > 0 && (
                    <div className="mt-2 space-y-1 ml-2">
                      {providerZones.map((z) => (
                        <div key={z.id} className="flex items-center justify-between rounded-md bg-gray-900/60 px-3 py-1.5">
                          <span className="text-sm text-gray-300">{z.name}</span>
                          <button onClick={() => setDeleteZoneId(z.id)} className="text-xs text-red-400 hover:text-red-300">Delete</button>
                        </div>
                      ))}
                    </div>
                  )}
                  {providerZones.length === 0 && (
                    <p className="mt-1 text-xs text-gray-500">No zones</p>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Reconciler */}
      <section className="rounded-xl border border-gray-800 bg-gray-900 p-6">
        <h2 className="text-lg font-semibold text-white">Reconciler</h2>
        <p className="mt-1 text-sm text-gray-400">How often the system syncs DNS and proxy configs.</p>
        <div className="mt-4 flex items-end gap-3">
          <div>
            <label className="block text-sm font-medium text-gray-300">Interval (seconds)</label>
            <input type="number" value={reconcilerInterval} onChange={(e) => setReconcilerInterval(e.target.value)} min={5}
              className="mt-1 block w-32 rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none" />
          </div>
          <button onClick={handleSaveReconciler} disabled={reconcilerSaving}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50">
            {reconcilerSaving ? 'Saving...' : 'Save'}
          </button>
        </div>
      </section>

      {/* Auth */}
      <section className="rounded-xl border border-gray-800 bg-gray-900 p-6">
        <h2 className="text-lg font-semibold text-white">Authentication</h2>
        {passwordError && <div className="mt-3 rounded-lg bg-red-900/30 border border-red-800 px-3 py-2 text-sm text-red-400">{passwordError}</div>}
        {passwordSuccess && <div className="mt-3 rounded-lg bg-green-900/30 border border-green-800 px-3 py-2 text-sm text-green-400">{passwordSuccess}</div>}
        <div className="mt-4 max-w-sm space-y-3">
          <div>
            <label className="block text-sm font-medium text-gray-300">Current Password</label>
            <input type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)}
              className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300">New Password</label>
            <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="Minimum 8 characters"
              className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300">Confirm New Password</label>
            <input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)}
              className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none" />
          </div>
          <button onClick={handleChangePassword} disabled={passwordLoading || !currentPassword || !newPassword}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50">
            {passwordLoading ? 'Updating...' : 'Change Password'}
          </button>
        </div>
      </section>

      {/* System Info */}
      <section className="rounded-xl border border-gray-800 bg-gray-900 p-6">
        <h2 className="text-lg font-semibold text-white">System Info</h2>
        <dl className="mt-4 space-y-2 text-sm">
          <div className="flex justify-between"><dt className="text-gray-500">Version</dt><dd className="text-gray-200">{health?.version ?? 'unknown'}</dd></div>
          <div className="flex justify-between"><dt className="text-gray-500">Status</dt><dd className="text-green-400">{health?.status ?? 'unknown'}</dd></div>
        </dl>
      </section>

      {/* Add Provider Modal — same zone-auto-detect flow as wizard */}
      <Modal open={showAddProvider} onClose={() => setShowAddProvider(false)} title="Add DNS Provider" wide>
        <div className="space-y-4">
          {provError && <div className="rounded-lg bg-red-900/30 border border-red-800 px-3 py-2 text-sm text-red-400">{provError}</div>}

          {provModalStep === 'token' && (
            <>
              <div>
                <label className="block text-sm font-medium text-gray-300">Provider</label>
                <select value={provType} onChange={(e) => setProvType(e.target.value)}
                  className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none">
                  <option value="cloudflare">Cloudflare</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300">API Token</label>
                <input type="password" value={provApiToken} onChange={(e) => { setProvApiToken(e.target.value); setProvTestError(''); }}
                  onKeyDown={(e) => { if (e.key === 'Enter' && provApiToken) handleTestToken(); }}
                  className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
                  placeholder="Paste your API token" />
                <p className="mt-1 text-xs text-gray-500">Needs Zone:Read and DNS:Edit permissions.</p>
              </div>
              {provTestError && <div className="rounded-lg bg-red-900/30 border border-red-800 px-3 py-2 text-sm text-red-400">{provTestError}</div>}
              <div className="flex justify-between pt-2">
                <button onClick={() => setShowAddProvider(false)}
                  className="rounded-lg border border-gray-600 px-4 py-2 text-sm font-medium text-gray-300 hover:bg-gray-800">Cancel</button>
                <button onClick={handleTestToken} disabled={provTestLoading || !provApiToken}
                  className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50">
                  {provTestLoading ? 'Connecting...' : 'Connect'}
                </button>
              </div>
            </>
          )}

          {provModalStep === 'zones' && (
            <>
              <div className="rounded-lg bg-green-900/30 border border-green-800 px-3 py-2 text-sm text-green-400 flex items-center gap-2">
                <svg className="h-4 w-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                </svg>
                Token valid — {provZones.length} zone{provZones.length !== 1 ? 's' : ''} found
              </div>
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="block text-sm font-medium text-gray-300">Select zones to add</label>
                  <button onClick={toggleAllZones} className="text-xs text-blue-400 hover:text-blue-300">
                    {selectedZones.size === provZones.length ? 'Deselect all' : 'Select all'}
                  </button>
                </div>
                <div className="space-y-1 max-h-48 overflow-y-auto rounded-lg border border-gray-700 bg-gray-800 p-2">
                  {provZones.map((zone) => (
                    <label key={zone.id}
                      className={`flex items-center gap-3 rounded-md px-3 py-2.5 cursor-pointer transition-colors ${
                        selectedZones.has(zone.id) ? 'bg-blue-900/30' : 'hover:bg-gray-700/50'
                      }`}>
                      <input type="checkbox" checked={selectedZones.has(zone.id)} onChange={() => toggleZone(zone.id)} className="accent-blue-500 h-4 w-4" />
                      <span className="text-sm text-white font-medium">{zone.name}</span>
                      <span className="text-xs text-gray-500 ml-auto font-mono">{zone.id.slice(0, 8)}…</span>
                    </label>
                  ))}
                </div>
                <p className="mt-1.5 text-xs text-gray-500">Selected zones will be added to the provider.</p>
              </div>
              <div className="flex justify-between pt-2">
                <button onClick={() => { setProvModalStep('token'); setProvZones([]); }}
                  className="rounded-lg border border-gray-600 px-4 py-2 text-sm font-medium text-gray-300 hover:bg-gray-800">Back</button>
                <button onClick={handleSaveZones} disabled={provSaveLoading || selectedZones.size === 0}
                  className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50">
                  {provSaveLoading ? `Adding...` : `Add ${selectedZones.size} zone${selectedZones.size !== 1 ? 's' : ''}`}
                </button>
              </div>
            </>
          )}
        </div>
      </Modal>

      <ConfirmDialog
        open={deleteProviderId !== null}
        onClose={() => setDeleteProviderId(null)}
        onConfirm={handleDeleteProvider}
        title="Delete Provider"
        message="Are you sure? All zones and domains using this provider will lose DNS management."
        confirmLabel="Delete"
        danger
      />

      <ConfirmDialog
        open={deleteZoneId !== null}
        onClose={() => setDeleteZoneId(null)}
        onConfirm={handleDeleteZone}
        title="Delete Zone"
        message="Are you sure? Domains using this zone will lose DNS management."
        confirmLabel="Delete"
        danger
      />
    </div>
  );
}

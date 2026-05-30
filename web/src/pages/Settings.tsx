import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation, Trans } from 'react-i18next';
import { api } from '../lib/api';
import { LANGUAGES } from '../lib/i18n';
import type { Provider, Zone, Setting } from '../lib/types';
import type { HealthResponse, TestProviderZone } from '../lib/api';
import Modal from '../components/Modal';
import ConfirmDialog from '../components/ConfirmDialog';
import Button from '../components/Button';
import Callout from '../components/Callout';
import HelpTip from '../components/HelpTip';
import { Field, Input, PasswordInput, Select } from '../components/Field';
import MultiSelect from '../components/MultiSelect';
import { useToast, errMessage } from '../components/toast-context';
import { useUIVariant, UI_VARIANTS } from '../lib/ui-variant-context';

const CF_TOKEN_URL = 'https://dash.cloudflare.com/?to=/:account/api-tokens';

function Section({ title, help, action, children }: { title: string; help?: string; action?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="rounded-xl border border-border bg-surface p-6 shadow-card">
      <div className="flex items-center justify-between gap-4">
        <h2 className="flex items-center gap-1.5 text-lg font-semibold text-fg">{title}{help && <HelpTip term={help} />}</h2>
        {action}
      </div>
      <div className="mt-4">{children}</div>
    </section>
  );
}

export default function Settings() {
  const toast = useToast();
  const { t, i18n } = useTranslation();
  const { variant, setVariant } = useUIVariant();
  const [providers, setProviders] = useState<Provider[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const [, setSettings] = useState<Setting[]>([]);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);

  // Add provider modal
  const [showAddProvider, setShowAddProvider] = useState(false);
  const [provApiToken, setProvApiToken] = useState('');
  const [provTestLoading, setProvTestLoading] = useState(false);
  const [provTestError, setProvTestError] = useState('');
  const [provZones, setProvZones] = useState<TestProviderZone[]>([]);
  const [selectedZones, setSelectedZones] = useState<Set<string>>(new Set());
  const [provSaveLoading, setProvSaveLoading] = useState(false);
  const [provModalStep, setProvModalStep] = useState<'token' | 'zones'>('token');
  const provType = 'cloudflare';

  const [deleteProviderId, setDeleteProviderId] = useState<string | null>(null);
  const [deleteZoneId, setDeleteZoneId] = useState<string | null>(null);

  const [reconcilerInterval, setReconcilerInterval] = useState('');
  const [reconcilerSaving, setReconcilerSaving] = useState(false);

  const [acmeEmail, setAcmeEmail] = useState('');
  const [acmeSaving, setAcmeSaving] = useState(false);

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [passwordLoading, setPasswordLoading] = useState(false);

  const [apiKeyInfo, setApiKeyInfo] = useState<{ exists: boolean; masked?: string }>({ exists: false });
  const [apiKeyPlaintext, setApiKeyPlaintext] = useState('');

  const fetchData = useCallback(async () => {
    try {
      const [p, z, s, h, k] = await Promise.all([
        api.listProviders(), api.listAllZones(), api.getSettings(), api.health(), api.getAPIKey(),
      ]);
      setProviders(p); setZones(z); setSettings(s); setHealth(h); setApiKeyInfo(k);
      const rec = s.find((st) => st.key === 'reconciler_interval');
      if (rec) setReconcilerInterval(rec.value);
      const email = s.find((st) => st.key === 'acme_email');
      if (email) setAcmeEmail(email.value);
    } catch (err) {
      toast.error(errMessage(err, t('settings.loadFailed')));
    } finally {
      setLoading(false);
    }
  }, [toast, t]);

  useEffect(() => { fetchData(); }, [fetchData]);

  function resetProviderModal() {
    setProvApiToken(''); setProvTestLoading(false); setProvTestError('');
    setProvZones([]); setSelectedZones(new Set()); setProvSaveLoading(false); setProvModalStep('token');
  }

  async function handleTestToken() {
    setProvTestLoading(true);
    setProvTestError('');
    try {
      const result = await api.testProvider({ type: provType, config: { api_token: provApiToken } });
      if (!result.valid) { setProvTestError(result.message); return; }
      if (result.zones && result.zones.length > 0) {
        setProvZones(result.zones);
        setSelectedZones(new Set(result.zones.map((z) => z.id)));
        setProvModalStep('zones');
      } else {
        setProvTestError(t('settings.tokenNoZones'));
      }
    } catch (err) {
      setProvTestError(errMessage(err, t('setup.connFailed')));
    } finally {
      setProvTestLoading(false);
    }
  }

  async function handleSaveZones() {
    if (selectedZones.size === 0) return;
    setProvSaveLoading(true);
    try {
      const provider = await api.createProvider({ type: provType, name: provType, config: { api_token: provApiToken } });
      const zonesToCreate = provZones.filter((z) => selectedZones.has(z.id)).map((z) => ({ external_id: z.id, name: z.name }));
      await api.createZonesBatch({ provider_id: provider.id, zones: zonesToCreate });
      toast.success(t('setup.zonesAdded', { count: zonesToCreate.length }));
      setShowAddProvider(false);
      resetProviderModal();
      fetchData();
    } catch (err) {
      setProvTestError(errMessage(err, t('setup.saveFailed')));
    } finally {
      setProvSaveLoading(false);
    }
  }

  async function handleDeleteProvider() {
    if (!deleteProviderId) return;
    try { await api.deleteProvider(deleteProviderId); toast.success(t('settings.providerDeleted')); setDeleteProviderId(null); fetchData(); }
    catch (err) { toast.error(errMessage(err, t('settings.providerDeleteFailed'))); }
  }
  async function handleDeleteZone() {
    if (!deleteZoneId) return;
    try { await api.deleteZone(deleteZoneId); toast.success(t('settings.zoneRemoved')); setDeleteZoneId(null); fetchData(); }
    catch (err) { toast.error(errMessage(err, t('settings.zoneRemoveFailed'))); }
  }

  async function handleSaveReconciler() {
    setReconcilerSaving(true);
    try { await api.updateSetting('reconciler_interval', reconcilerInterval); toast.success(t('settings.intervalSaved')); }
    catch (err) { toast.error(errMessage(err, t('settings.saveFailedGeneric'))); }
    finally { setReconcilerSaving(false); }
  }

  async function handleSaveAcmeEmail() {
    setAcmeSaving(true);
    try {
      await api.updateSetting('acme_email', acmeEmail.trim());
      setSettings((prev) => {
        const next = prev.filter((s) => s.key !== 'acme_email');
        next.push({ key: 'acme_email', value: acmeEmail.trim(), updated_at: new Date().toISOString() });
        return next;
      });
      toast.success(t('settings.acmeSaved'));
    } catch (err) { toast.error(errMessage(err, t('settings.saveFailedGeneric'))); }
    finally { setAcmeSaving(false); }
  }

  async function handleChangePassword() {
    setPasswordError('');
    if (newPassword.length < 8) { setPasswordError(t('settings.pwTooShort')); return; }
    if (newPassword !== confirmPassword) { setPasswordError(t('settings.pwMismatch')); return; }
    setPasswordLoading(true);
    try {
      await api.changePassword(currentPassword, newPassword);
      toast.success(t('settings.pwUpdated'));
      setCurrentPassword(''); setNewPassword(''); setConfirmPassword('');
    } catch (err) {
      setPasswordError(errMessage(err, t('settings.pwFailed')));
    } finally {
      setPasswordLoading(false);
    }
  }

  async function handleGenerateAPIKey() {
    setApiKeyPlaintext('');
    try {
      const res = await api.generateAPIKey();
      setApiKeyPlaintext(res.api_key);
      setApiKeyInfo(await api.getAPIKey());
    } catch (err) {
      toast.error(errMessage(err, t('settings.keyGenFailed')));
    }
  }
  async function handleRevokeAPIKey() {
    setApiKeyPlaintext('');
    try { await api.revokeAPIKey(); toast.success(t('settings.keyRevoked')); setApiKeyInfo({ exists: false }); }
    catch (err) { toast.error(errMessage(err, t('settings.keyRevokeFailed'))); }
  }

  if (loading) return <div className="py-12 text-center text-sm text-fg-muted">{t('common.loading')}</div>;

  return (
    <div className="space-y-6">
      <h1 className="font-display text-3xl font-bold tracking-tight text-fg">{t('settings.title')}</h1>

      <Section title={t('settings.appearance')}>
        <p className="-mt-1 text-sm text-fg-muted">{t('settings.appearanceSub')}</p>
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          {UI_VARIANTS.map((v) => {
            const active = v.id === variant;
            return (
              <button
                key={v.id}
                onClick={() => setVariant(v.id)}
                className={`rounded-xl border p-4 text-left transition-colors ${active ? 'border-accent bg-accent-soft' : 'border-border bg-surface-2 hover:border-border-strong'}`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-medium text-fg">{t(`appearanceVariants.${v.id}.name`)}</span>
                  {active && <span className="rounded-full bg-accent px-2 py-0.5 text-xs font-semibold text-accent-fg">{t('settings.active')}</span>}
                </div>
                <p className="mt-1 text-sm text-fg-muted">{t(`appearanceVariants.${v.id}.description`)}</p>
              </button>
            );
          })}
        </div>
        <div className="mt-4 max-w-xs">
          <Field label={t('settings.language')}>
            <Select value={i18n.resolvedLanguage} onChange={(e) => i18n.changeLanguage(e.target.value)}>
              {LANGUAGES.map((l) => <option key={l.code} value={l.code}>{l.label}</option>)}
            </Select>
          </Field>
        </div>
      </Section>

      <Section title={t('settings.dnsProviders')} action={<Button size="sm" onClick={() => { resetProviderModal(); setShowAddProvider(true); }}>{t('settings.addProvider')}</Button>}>
        {providers.length === 0 ? (
          <p className="text-sm text-fg-faint">{t('settings.noProviders')}</p>
        ) : (
          <div className="space-y-3">
            {providers.map((p) => {
              const providerZones = zones.filter((z) => z.provider_id === p.id);
              return (
                <div key={p.id} className="rounded-lg border border-border bg-surface-2 px-4 py-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-fg">{p.name}</span>
                      <span className="rounded bg-surface-3 px-1.5 py-0.5 text-xs text-fg-faint">{p.type}</span>
                      {p.is_default && <span className="rounded bg-accent-soft px-1.5 py-0.5 text-xs text-accent">default</span>}
                    </div>
                    <button onClick={() => setDeleteProviderId(p.id)} className="text-xs font-medium text-danger-fg hover:underline">{t('common.delete')}</button>
                  </div>
                  {providerZones.length > 0 ? (
                    <div className="mt-2 space-y-1">
                      {providerZones.map((z) => (
                        <div key={z.id} className="flex items-center justify-between rounded-md bg-surface px-3 py-1.5">
                          <span className="text-sm text-fg-muted">{z.name}</span>
                          <button onClick={() => setDeleteZoneId(z.id)} className="text-xs font-medium text-danger-fg hover:underline">{t('common.remove')}</button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="mt-1 text-xs text-fg-faint">{t('settings.noZones')}</p>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </Section>

      <Section title={t('settings.reconciler')} help="reconciler">
        <p className="-mt-1 text-sm text-fg-muted">{t('settings.reconcilerSub')}</p>
        <div className="mt-4 flex items-end gap-3">
          <Field label={t('settings.intervalSeconds')} className="w-40">
            <Input type="number" value={reconcilerInterval} onChange={(e) => setReconcilerInterval(e.target.value)} min={5} />
          </Field>
          <Button onClick={handleSaveReconciler} loading={reconcilerSaving} className="mb-0.5">{t('common.save')}</Button>
        </div>
      </Section>

      <Section title={t('settings.tls')}>
        <p className="-mt-1 text-sm text-fg-muted">{t('settings.tlsSub')}</p>
        <Callout tone="info" title={t('settings.tlsPrivacyTitle')}>{t('settings.tlsPrivacyBody')}</Callout>
        <div className="mt-4 flex items-end gap-3">
          <Field label={t('settings.acmeEmail')} className="w-80">
            <Input type="email" value={acmeEmail} onChange={(e) => setAcmeEmail(e.target.value)} placeholder="you@example.com" autoComplete="email" />
          </Field>
          <Button onClick={handleSaveAcmeEmail} loading={acmeSaving} className="mb-0.5">{t('common.save')}</Button>
        </div>
        <p className="mt-2 text-xs text-fg-faint">{t('settings.acmeEmailHelp')}</p>
      </Section>

      <Section title={t('settings.authentication')}>
        {passwordError && <Callout tone="danger">{passwordError}</Callout>}
        <div className="mt-3 max-w-sm space-y-3">
          <Field label={t('settings.currentPassword')}><PasswordInput value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} /></Field>
          <Field label={t('settings.newPassword')}><PasswordInput value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder={t('login.phMin')} /></Field>
          <Field label={t('settings.confirmNewPassword')}><PasswordInput value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} /></Field>
          <Button onClick={handleChangePassword} loading={passwordLoading} disabled={!currentPassword || !newPassword}>{t('settings.changePassword')}</Button>
        </div>
      </Section>

      <Section title={t('settings.adminApiKey')} help="admin-api-key">
        <p className="-mt-1 text-sm text-fg-muted"><Trans i18nKey="settings.adminApiKeySub" components={[<code className="rounded bg-surface-2 px-1 text-fg" />]} /></p>
        {apiKeyPlaintext && (
          <Callout tone="success" title={t('settings.copyNow')}>
            <code className="mt-1 block break-all font-mono text-xs">{apiKeyPlaintext}</code>
          </Callout>
        )}
        <div className="mt-4 flex flex-wrap items-center gap-3">
          {apiKeyInfo.exists ? (
            <>
              <span className="text-sm text-fg-muted">{t('settings.activeKey')} <code className="font-mono text-fg">{apiKeyInfo.masked ?? '••••'}</code></span>
              <Button size="sm" onClick={handleGenerateAPIKey}>{t('settings.regenerate')}</Button>
              <Button variant="danger-ghost" size="sm" onClick={handleRevokeAPIKey}>{t('settings.revoke')}</Button>
            </>
          ) : (
            <Button onClick={handleGenerateAPIKey}>{t('settings.generateKey')}</Button>
          )}
        </div>
      </Section>

      <Section title={t('settings.system')}>
        <dl className="-mt-1 space-y-2 text-sm">
          <div className="flex justify-between"><dt className="text-fg-faint">{t('settings.versionLabel')}</dt><dd className="text-fg">{health?.version ?? 'unknown'}</dd></div>
          <div className="flex justify-between"><dt className="text-fg-faint">{t('settings.statusLabel')}</dt><dd className="capitalize text-success-fg">{health?.status ?? 'unknown'}</dd></div>
        </dl>
      </Section>

      {/* Add provider modal */}
      <Modal open={showAddProvider} onClose={() => setShowAddProvider(false)} title={t('settings.addProviderTitle')} wide>
        <div className="space-y-4">
          {provModalStep === 'token' && (
            <>
              <Field label={t('setup.provider')}>
                <div className="flex items-center gap-2 rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm text-fg">
                  <span className="font-medium">Cloudflare</span>
                  <span className="rounded bg-surface-3 px-1.5 py-0.5 text-xs text-fg-faint">{t('setup.moreSoon')}</span>
                </div>
              </Field>
              <Field label={t('setup.apiToken')} help="api-token" hint={<Trans i18nKey="settings.tokenHint" components={[<strong />, <strong />]} />}>
                <PasswordInput value={provApiToken} onChange={(e) => { setProvApiToken(e.target.value); setProvTestError(''); }} onKeyDown={(e) => { if (e.key === 'Enter' && provApiToken) handleTestToken(); }} className="font-mono" placeholder={t('settings.tokenPlaceholder')} />
              </Field>
              <Callout tone="info">
                <Trans i18nKey="settings.providerCallout" components={[<a href={CF_TOKEN_URL} target="_blank" rel="noreferrer" className="font-medium underline" />, <Link to="/help/cloudflare-token" className="font-medium underline" />]} />
              </Callout>
              {provTestError && <Callout tone="danger">{provTestError}</Callout>}
              <div className="flex justify-between pt-1">
                <Button variant="secondary" onClick={() => setShowAddProvider(false)}>{t('common.cancel')}</Button>
                <Button onClick={handleTestToken} loading={provTestLoading} disabled={!provApiToken}>{t('common.connect')}</Button>
              </div>
            </>
          )}
          {provModalStep === 'zones' && (
            <>
              <Callout tone="success">{t('setup.tokenValid', { count: provZones.length })}</Callout>
              {provTestError && <Callout tone="danger">{provTestError}</Callout>}
              <div>
                <span className="mb-2 block text-sm font-medium text-fg">{t('settings.zonesToAdd')}</span>
                <MultiSelect
                  items={provZones.map((z) => ({ id: z.id, label: z.name, meta: `${z.id.slice(0, 8)}…` }))}
                  selected={selectedZones}
                  onChange={setSelectedZones}
                />
              </div>
              <div className="flex justify-between pt-1">
                <Button variant="secondary" onClick={() => { setProvModalStep('token'); setProvZones([]); }}>{t('common.back')}</Button>
                <Button onClick={handleSaveZones} loading={provSaveLoading} disabled={selectedZones.size === 0}>{t('setup.addZones', { count: selectedZones.size })}</Button>
              </div>
            </>
          )}
        </div>
      </Modal>

      <ConfirmDialog open={deleteProviderId !== null} onClose={() => setDeleteProviderId(null)} onConfirm={handleDeleteProvider} title={t('settings.deleteProviderTitle')} message={t('settings.deleteProviderMsg')} confirmLabel={t('common.delete')} danger confirmText={providers.find((p) => p.id === deleteProviderId)?.name} />
      <ConfirmDialog open={deleteZoneId !== null} onClose={() => setDeleteZoneId(null)} onConfirm={handleDeleteZone} title={t('settings.removeZoneTitle')} message={t('settings.removeZoneMsg')} confirmLabel={t('common.remove')} danger />
    </div>
  );
}

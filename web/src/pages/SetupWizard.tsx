import { useState, useEffect, useRef, useCallback } from 'react';
import { useTranslation, Trans } from 'react-i18next';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';
import { copyText } from '../lib/clipboard';
import { agentInstallCommand } from '../lib/install';
import type { Agent, Zone } from '../lib/types';
import type { TestProviderZone } from '../lib/api';
import { Check } from 'lucide-react';
import Button, { Spinner } from '../components/Button';
import { Field, Input, PasswordInput } from '../components/Field';
import Callout from '../components/Callout';
import HelpTip from '../components/HelpTip';
import BrandMark from '../components/BrandMark';
import MultiSelect from '../components/MultiSelect';
import StatusBadge from '../components/StatusBadge';

interface SetupWizardProps {
  onComplete: () => void;
}

const STEPS = [
  { key: 'provider', labelKey: 'setup.stepProvider' },
  { key: 'tls', labelKey: 'setup.stepTls' },
  { key: 'agent', labelKey: 'setup.stepAgent' },
  { key: 'done', labelKey: 'setup.stepDone' },
] as const;

const CF_TOKEN_URL = 'https://dash.cloudflare.com/?to=/:account/api-tokens';

export default function SetupWizard({ onComplete }: SetupWizardProps) {
  const { t } = useTranslation();
  const [currentStep, setCurrentStep] = useState(0);

  // Provider step
  const [provApiToken, setProvApiToken] = useState('');
  const [provTestLoading, setProvTestLoading] = useState(false);
  const [provTestError, setProvTestError] = useState('');
  const [provZones, setProvZones] = useState<TestProviderZone[]>([]);
  const [selectedZones, setSelectedZones] = useState<Set<string>>(new Set());
  const [provSaveLoading, setProvSaveLoading] = useState(false);
  const [provError, setProvError] = useState('');
  const [zonesCreated, setZonesCreated] = useState<string[]>([]);
  const [provStep, setProvStep] = useState<'token' | 'zones' | 'saved'>('token');
  const provType = 'cloudflare';

  // Agent step
  const [agents, setAgents] = useState<Agent[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const stepKey = STEPS[currentStep].key;
  const pollingAgents = stepKey === 'agent';

  // TLS / ACME step
  const [acmeEmail, setAcmeEmail] = useState('');
  const [acmeSaving, setAcmeSaving] = useState(false);
  const [acmeError, setAcmeError] = useState('');
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const [orchestratorUrl, setOrchestratorUrl] = useState(window.location.origin);
  const [agentFqdn, setAgentFqdn] = useState('');
  const [waitedLong, setWaitedLong] = useState(false);
  const [adoptingId, setAdoptingId] = useState<string | null>(null);
  const [adoptName, setAdoptName] = useState('');
  const [adoptZoneIds, setAdoptZoneIds] = useState<Set<string>>(new Set());
  const [adoptDnsMode, setAdoptDnsMode] = useState<'static' | 'ddns'>('static');
  const [adoptLoading, setAdoptLoading] = useState(false);
  const [adoptError, setAdoptError] = useState('');
  const [agentAdopted, setAgentAdopted] = useState(false);

  const [completing, setCompleting] = useState(false);
  const [copied, setCopied] = useState(false);

  const fetchZones = useCallback(async () => {
    try { setZones(await api.listAllZones()); } catch { /* ignore */ }
  }, []);
  const pollAgents = useCallback(async () => {
    try { setAgents(await api.listAgents()); } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    if (STEPS[currentStep].key === 'agent') {
      fetchZones();
      pollAgents();
      pollRef.current = setInterval(pollAgents, 3000);
      const t = setTimeout(() => setWaitedLong(true), 30000);
      return () => {
        if (pollRef.current) clearInterval(pollRef.current);
        clearTimeout(t);
      };
    }
    if (pollRef.current) clearInterval(pollRef.current);
  }, [currentStep, fetchZones, pollAgents]);

  async function handleTestToken() {
    setProvTestLoading(true);
    setProvTestError('');
    setProvZones([]);
    try {
      const result = await api.testProvider({ type: provType, config: { api_token: provApiToken } });
      if (!result.valid) { setProvTestError(result.message); return; }
      if (result.zones && result.zones.length > 0) {
        setProvZones(result.zones);
        setSelectedZones(new Set(result.zones.map((z) => z.id)));
        setProvStep('zones');
      } else {
        setProvTestError(t('setup.noZones'));
      }
    } catch (err) {
      setProvTestError(err instanceof Error ? err.message.replace(/^API error \d+:\s*/, '') : t('setup.connFailed'));
    } finally {
      setProvTestLoading(false);
    }
  }

  async function handleSaveZones() {
    if (selectedZones.size === 0) return;
    setProvSaveLoading(true);
    setProvError('');
    try {
      const provider = await api.createProvider({ type: provType, name: provType, config: { api_token: provApiToken } });
      const zonesToCreate = provZones.filter((z) => selectedZones.has(z.id)).map((z) => ({ external_id: z.id, name: z.name }));
      const created = await api.createZonesBatch({ provider_id: provider.id, zones: zonesToCreate });
      setZonesCreated(created.map((z) => z.name));
      setProvStep('saved');
    } catch (err) {
      setProvError(err instanceof Error ? err.message.replace(/^API error \d+:\s*/, '') : t('setup.saveFailed'));
    } finally {
      setProvSaveLoading(false);
    }
  }

  async function handleSaveAcme() {
    setAcmeSaving(true);
    setAcmeError('');
    try {
      // Persist the contact email (empty is allowed — issuance just stays off
      // until it is set). The orchestrator reads it lazily, so no restart needed.
      await api.updateSetting('acme_email', acmeEmail.trim());
      setCurrentStep(currentStep + 1);
    } catch (err) {
      setAcmeError(err instanceof Error ? err.message.replace(/^API error \d+:\s*/, '') : t('setup.saveFailed'));
    } finally {
      setAcmeSaving(false);
    }
  }

  function startAdopt(agent: Agent) {
    setAdoptingId(agent.id);
    setAdoptName(agent.fqdn);
    setAdoptZoneIds(new Set());
    setAdoptDnsMode('static');
    setAdoptError('');
  }

  async function handleConfirmAdopt() {
    if (!adoptingId) return;
    setAdoptLoading(true);
    setAdoptError('');
    try {
      await api.adoptAgent(adoptingId, {
        name: adoptName || undefined,
        zone_ids: adoptZoneIds.size > 0 ? [...adoptZoneIds] : undefined,
        dns_mode: adoptDnsMode,
      });
      setAgentAdopted(true);
      setAdoptingId(null);
      pollAgents();
    } catch (err) {
      setAdoptError(err instanceof Error ? err.message.replace(/^API error \d+:\s*/, '') : t('setup.adoptFailed'));
    } finally {
      setAdoptLoading(false);
    }
  }

  async function handleFinish() {
    setCompleting(true);
    try { await api.updateSetting('setup_complete', 'true'); } catch { /* proceed anyway */ }
    onComplete();
  }
  async function handleSkipStep() {
    if (currentStep < STEPS.length - 1) setCurrentStep(currentStep + 1);
    else await handleFinish();
  }

  const installCommand = agentInstallCommand(orchestratorUrl, agentFqdn);

  async function copyToClipboard(text: string) {
    // copyText falls back to execCommand on insecure origins (plain http on a
    // LAN IP / behind a proxy), where navigator.clipboard is undefined.
    if (await copyText(text)) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  const pendingAgents = agents.filter((a) => a.status === 'pending');

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg px-4 py-12">
      <div className="w-full max-w-lg">
        <div className="mb-8 flex flex-col items-center text-center">
          <BrandMark size={34} />
          <h1 className="mt-3 font-display text-2xl font-bold tracking-tight text-fg">{t('setup.title')}</h1>
          <p className="mt-1 text-sm text-fg-muted">
            <Trans i18nKey="setup.intro" components={[<Link to="/help/getting-started" className="font-medium text-accent hover:underline" />]} />
          </p>
        </div>

        {/* Stepper */}
        <ol className="mb-8 flex items-center justify-center gap-2">
          {STEPS.map((step, i) => (
            <li key={step.key} className="flex items-center gap-2">
              <button
                onClick={() => { if (i < currentStep) setCurrentStep(i); }}
                disabled={i > currentStep}
                className={`flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold transition-colors ${
                  i === currentStep ? 'bg-accent text-accent-fg'
                    : i < currentStep ? 'cursor-pointer bg-accent-soft text-accent hover:brightness-105'
                    : 'bg-surface-2 text-fg-faint'
                }`}
              >
                {i < currentStep ? (
                  <Check className="h-4 w-4" strokeWidth={3} />
                ) : (i + 1)}
              </button>
              <span className={`text-xs font-medium ${i === currentStep ? 'text-fg' : 'text-fg-faint'}`}>{t(step.labelKey)}</span>
              {i < STEPS.length - 1 && <span className={`mx-1 h-px w-6 ${i < currentStep ? 'bg-accent' : 'bg-border'}`} />}
            </li>
          ))}
        </ol>

        <div className="rounded-xl border border-border bg-surface p-6 shadow-card">
          {/* STEP 1 — provider */}
          {stepKey === 'provider' && (
            <div className="space-y-5">
              <div>
                <h2 className="text-lg font-semibold text-fg">{t('setup.providerTitle')}</h2>
                <p className="mt-1 text-sm text-fg-muted">{t('setup.providerSub')}</p>
              </div>

              {provError && <Callout tone="danger">{provError}</Callout>}

              {provStep === 'token' && (
                <>
                  <Field label={t('setup.provider')}>
                    <div className="flex items-center gap-2 rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm text-fg">
                      <span className="font-medium">Cloudflare</span>
                      <span className="rounded bg-surface-3 px-1.5 py-0.5 text-xs text-fg-faint">{t('setup.moreSoon')}</span>
                    </div>
                  </Field>

                  <Field
                    label={t('setup.apiToken')}
                    help="api-token"
                    hint={<Trans i18nKey="setup.tokenHint" components={[<strong className="font-semibold" />, <strong className="font-semibold" />]} />}
                  >
                    <PasswordInput
                      value={provApiToken}
                      onChange={(e) => { setProvApiToken(e.target.value); setProvTestError(''); }}
                      className="font-mono"
                      placeholder={t('setup.tokenPlaceholder')}
                      onKeyDown={(e) => { if (e.key === 'Enter' && provApiToken) handleTestToken(); }}
                    />
                  </Field>

                  <Callout tone="info" title={t('setup.whereTitle')}>
                    <Trans
                      i18nKey="setup.whereBody"
                      components={[
                        <a href={CF_TOKEN_URL} target="_blank" rel="noreferrer" className="font-medium underline" />,
                        <strong />,
                        <strong />,
                        <Link to="/help/cloudflare-token" className="font-medium underline" />,
                      ]}
                    />
                  </Callout>

                  {provTestError && <Callout tone="danger">{provTestError}</Callout>}

                  <div className="flex items-center justify-between pt-1">
                    <Button variant="ghost" onClick={handleSkipStep}>{t('setup.skipForNow')}</Button>
                    <Button onClick={handleTestToken} loading={provTestLoading} disabled={!provApiToken}>
                      {provTestLoading ? t('common.connecting') : t('common.connect')}
                    </Button>
                  </div>
                </>
              )}

              {provStep === 'zones' && (
                <>
                  <Callout tone="success">{t('setup.tokenValid', { count: provZones.length })}</Callout>
                  <div>
                    <span className="mb-2 flex items-center gap-1.5 text-sm font-medium text-fg">
                      {t('setup.zonesToManage')} <HelpTip term="zone" />
                    </span>
                    <MultiSelect
                      items={provZones.map((z) => ({ id: z.id, label: z.name, meta: `${z.id.slice(0, 8)}…` }))}
                      selected={selectedZones}
                      onChange={setSelectedZones}
                    />
                    <p className="mt-1.5 text-xs text-fg-faint">{t('setup.manageHint')}</p>
                  </div>
                  <div className="flex items-center justify-between pt-1">
                    <Button variant="secondary" onClick={() => { setProvStep('token'); setProvZones([]); }}>{t('common.back')}</Button>
                    <Button onClick={handleSaveZones} loading={provSaveLoading} disabled={selectedZones.size === 0}>
                      {provSaveLoading ? t('setup.adding') : t('setup.addZones', { count: selectedZones.size })}
                    </Button>
                  </div>
                </>
              )}

              {provStep === 'saved' && (
                <>
                  <Callout tone="success" title={t('setup.zonesAdded', { count: zonesCreated.length })}>
                    <div className="mt-1.5 flex flex-wrap gap-1.5">
                      {zonesCreated.map((name) => (
                        <span key={name} className="rounded-md bg-success/15 px-2 py-0.5 text-xs font-medium">{name}</span>
                      ))}
                    </div>
                  </Callout>
                  <div className="flex justify-end">
                    <Button onClick={() => setCurrentStep(currentStep + 1)}>{t('common.continue')}</Button>
                  </div>
                </>
              )}
            </div>
          )}

          {/* STEP 2 — TLS / ACME contact email */}
          {stepKey === 'tls' && (
            <div className="space-y-5">
              <div>
                <h2 className="text-lg font-semibold text-fg">{t('setup.tlsTitle')}</h2>
                <p className="mt-1 text-sm text-fg-muted">{t('setup.tlsSub')}</p>
              </div>

              <Callout tone="info" title={t('setup.tlsPrivacyTitle')}>
                {t('setup.tlsPrivacyBody')}
              </Callout>

              {acmeError && <Callout tone="danger">{acmeError}</Callout>}

              <Field label={t('setup.tlsEmailLabel')}>
                <Input
                  type="email"
                  value={acmeEmail}
                  onChange={(e) => { setAcmeEmail(e.target.value); setAcmeError(''); }}
                  placeholder="you@example.com"
                  autoComplete="email"
                />
              </Field>
              <p className="-mt-2 text-xs text-fg-faint">{t('setup.tlsEmailHelp')}</p>

              <div className="flex justify-between">
                <Button variant="secondary" onClick={() => setCurrentStep(currentStep - 1)}>{t('common.back')}</Button>
                <div className="flex gap-2">
                  <Button variant="secondary" onClick={() => setCurrentStep(currentStep + 1)} disabled={acmeSaving}>{t('setup.tlsSkip')}</Button>
                  <Button onClick={handleSaveAcme} loading={acmeSaving} disabled={!acmeEmail.trim()}>{t('common.continue')}</Button>
                </div>
              </div>
            </div>
          )}

          {/* STEP 3 — agent */}
          {stepKey === 'agent' && (
            <div className="space-y-5">
              <div>
                <h2 className="text-lg font-semibold text-fg">{t('setup.agentTitle')}</h2>
                <p className="mt-1 text-sm text-fg-muted">{t('setup.agentSub')}</p>
              </div>

              <Field
                label={t('setup.orchestratorUrl')}
                help="orchestrator-url"
                hint={t('setup.orchestratorHint')}
              >
                <Input value={orchestratorUrl} onChange={(e) => setOrchestratorUrl(e.target.value)} className="font-mono" placeholder="https://nurproxy.example.com" />
              </Field>

              <Field
                label={t('setup.fqdnLabel')}
                help="fqdn"
                hint={t('setup.fqdnHint')}
              >
                <Input value={agentFqdn} onChange={(e) => setAgentFqdn(e.target.value)} className="font-mono" placeholder="edge1.example.com" />
              </Field>

              <div>
                <p className="mb-2 text-sm font-medium text-fg">{t('setup.runThis')}</p>
                <div className="relative">
                  <pre className="overflow-x-auto rounded-lg border border-border bg-surface-2 p-4 text-xs leading-relaxed text-fg">{installCommand}</pre>
                  <button onClick={() => copyToClipboard(installCommand)} className="absolute right-2 top-2 rounded-md border border-border bg-surface px-2 py-1 text-xs font-medium text-fg-muted transition-colors hover:text-fg">
                    {copied ? t('setup.copied') : t('setup.copy')}
                  </button>
                </div>
              </div>

              {agentAdopted ? (
                <Callout tone="success" title={t('setup.agentAdopted')}>{t('setup.agentAdoptedBody')}</Callout>
              ) : pendingAgents.length === 0 ? (
                <div className="rounded-lg border border-border bg-surface-2 px-4 py-6 text-center">
                  {pollingAgents && <div className="mb-3 flex justify-center"><Spinner className="h-7 w-7 text-fg-faint" /></div>}
                  <p className="text-sm text-fg-muted">{t('setup.waiting')}</p>
                  <p className="mt-1 text-xs text-fg-faint">{t('setup.checking')}</p>
                  {waitedLong && (
                    <div className="mt-4 text-left">
                      <Callout tone="warning" title={t('setup.notShowing')}>
                        <ul className="mt-1 list-disc space-y-1 pl-4 text-xs">
                          <li>{t('setup.troubleReach', { url: orchestratorUrl || 'the orchestrator URL' })}</li>
                          <li>{t('setup.troubleFirewall')}</li>
                          <li>{t('setup.troubleLogs')}</li>
                        </ul>
                        <Link to="/help/agent-reachability" className="mt-1.5 inline-block font-medium underline">{t('setup.troubleGuide')}</Link>
                      </Callout>
                    </div>
                  )}
                </div>
              ) : (
                <div className="space-y-3">
                  <p className="flex items-center gap-1.5 text-sm font-medium text-fg">
                    {t('setup.waitingApproval', { count: pendingAgents.length })} <HelpTip term="adoption" />
                  </p>
                  {pendingAgents.map((agent) => (
                    <div key={agent.id} className="rounded-lg border border-border bg-surface-2 p-4">
                      <div className="flex items-center justify-between gap-2">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <p className="truncate font-medium text-fg">{agent.fqdn}</p>
                            <StatusBadge status={agent.status} />
                          </div>
                          <p className="mt-0.5 text-xs text-fg-faint">
                            {agent.public_ip && `IP ${agent.public_ip}`}{agent.version && ` · v${agent.version}`}
                          </p>
                        </div>
                        {adoptingId !== agent.id && <Button variant="primary" size="sm" onClick={() => startAdopt(agent)}>{t('setup.approve')}</Button>}
                      </div>

                      {adoptingId === agent.id && (
                        <div className="mt-4 space-y-3 border-t border-border pt-4">
                          {adoptError && <Callout tone="danger">{adoptError}</Callout>}
                          <Field label={t('setup.displayName')}>
                            <Input value={adoptName} onChange={(e) => setAdoptName(e.target.value)} placeholder={t('setup.displayNamePh')} />
                          </Field>
                          <Field label={t('setup.dnsZones')} help="zone">
                            <MultiSelect
                              items={zones.map((z) => ({ id: z.id, label: z.name }))}
                              selected={adoptZoneIds}
                              onChange={setAdoptZoneIds}
                              maxHeightClass="max-h-36"
                              emptyHint={t('setup.noZonesYet')}
                            />
                          </Field>
                          <Field label={t('setup.dnsMode')} help="dns-mode">
                            <div className="flex gap-4">
                              <label className="flex cursor-pointer items-center gap-2 text-sm text-fg">
                                <input type="radio" name="wiz-dns-mode" checked={adoptDnsMode === 'static'} onChange={() => setAdoptDnsMode('static')} className="accent-[var(--accent)]" />
                                {t('setup.static')}
                              </label>
                              <label className="flex cursor-pointer items-center gap-2 text-sm text-fg">
                                <input type="radio" name="wiz-dns-mode" checked={adoptDnsMode === 'ddns'} onChange={() => setAdoptDnsMode('ddns')} className="accent-[var(--accent)]" />
                                {t('setup.ddns')}
                              </label>
                            </div>
                          </Field>
                          <div className="flex justify-end gap-3">
                            <Button variant="secondary" size="sm" onClick={() => setAdoptingId(null)}>{t('common.cancel')}</Button>
                            <Button size="sm" onClick={handleConfirmAdopt} loading={adoptLoading}>{t('setup.approveAgent')}</Button>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              <div className="flex items-center justify-between pt-1">
                <Button variant="secondary" onClick={() => setCurrentStep(currentStep - 1)}>{t('common.back')}</Button>
                <div className="flex gap-3">
                  <Button variant="ghost" onClick={handleSkipStep}>{t('common.skip')}</Button>
                  {agentAdopted && <Button onClick={() => setCurrentStep(currentStep + 1)}>{t('common.continue')}</Button>}
                </div>
              </div>
            </div>
          )}

          {/* STEP 4 — done */}
          {stepKey === 'done' && (
            <div className="text-center">
              <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-success-soft text-success-fg">
                <Check className="h-7 w-7" />
              </div>
              <h2 className="text-lg font-semibold text-fg">{t('setup.allSet')}</h2>
              <p className="mt-2 text-sm text-fg-muted">{t('setup.whatConfigured')}</p>

              <div className="mt-6 space-y-2 text-left">
                <SummaryItem label={t('setup.summaryZones')} value={zonesCreated.length > 0 ? zonesCreated.join(', ') : null} />
                <SummaryItem label={t('setup.summaryAgent')} value={agentAdopted ? t('setup.summaryAgentConnected') : null} />
              </div>

              <p className="mt-6 text-xs text-fg-faint">{t('setup.addLater')}</p>
              <Button onClick={handleFinish} loading={completing} className="mt-6 w-full justify-center">{t('setup.goDashboard')}</Button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function SummaryItem({ label, value }: { label: string; value: string | null }) {
  const { t } = useTranslation();
  return (
    <div className="flex items-center justify-between gap-3 rounded-lg bg-surface-2 px-4 py-3">
      <span className="text-sm font-medium text-fg">{label}</span>
      {value ? (
        <span className="flex items-center gap-1.5 text-sm text-success-fg">
          <Check className="h-4 w-4" />
          {value}
        </span>
      ) : (
        <span className="text-sm text-fg-faint">{t('setup.summarySkipped')}</span>
      )}
    </div>
  );
}

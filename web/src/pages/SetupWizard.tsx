import { useState, useEffect, useRef, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';
import type { Agent, Zone } from '../lib/types';
import type { TestProviderZone } from '../lib/api';
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
  { key: 'provider', label: 'DNS provider' },
  { key: 'agent', label: 'Connect agent' },
  { key: 'done', label: 'Done' },
] as const;

const CF_TOKEN_URL = 'https://dash.cloudflare.com/?to=/:account/api-tokens';

export default function SetupWizard({ onComplete }: SetupWizardProps) {
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
  const pollingAgents = currentStep === 1;
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
    if (currentStep === 1) {
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
        setProvTestError('Token is valid, but no zones were found. Make sure it has Zone → Read for the domains you want.');
      }
    } catch (err) {
      setProvTestError(err instanceof Error ? err.message.replace(/^API error \d+:\s*/, '') : 'Connection failed.');
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
      setProvError(err instanceof Error ? err.message.replace(/^API error \d+:\s*/, '') : 'Failed to save provider.');
    } finally {
      setProvSaveLoading(false);
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
      setAdoptError(err instanceof Error ? err.message.replace(/^API error \d+:\s*/, '') : 'Failed to adopt agent.');
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

  const installCommand =
    `curl -fsSL https://get.nurproxy.dev | sh -s -- agent \\\n` +
    `  --orchestrator ${orchestratorUrl || 'https://your-dashboard-url'} \\\n` +
    `  --fqdn ${agentFqdn || 'edge1.example.com'}`;

  async function copyToClipboard(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch { /* ignore */ }
  }

  const pendingAgents = agents.filter((a) => a.status === 'pending');

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg px-4 py-12">
      <div className="w-full max-w-lg">
        <div className="mb-8 flex flex-col items-center text-center">
          <BrandMark size={34} />
          <h1 className="mt-3 font-display text-2xl font-bold tracking-tight text-fg">Set up NurProxy</h1>
          <p className="mt-1 text-sm text-fg-muted">
            Two quick steps. New to this?{' '}
            <Link to="/help/getting-started" className="font-medium text-accent hover:underline">Read the guide</Link>.
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
                  <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                ) : (i + 1)}
              </button>
              <span className={`text-xs font-medium ${i === currentStep ? 'text-fg' : 'text-fg-faint'}`}>{step.label}</span>
              {i < STEPS.length - 1 && <span className={`mx-1 h-px w-6 ${i < currentStep ? 'bg-accent' : 'bg-border'}`} />}
            </li>
          ))}
        </ol>

        <div className="rounded-xl border border-border bg-surface p-6 shadow-card">
          {/* STEP 1 — provider */}
          {currentStep === 0 && (
            <div className="space-y-5">
              <div>
                <h2 className="text-lg font-semibold text-fg">Connect your DNS provider</h2>
                <p className="mt-1 text-sm text-fg-muted">Paste an API token and we’ll detect the domains it can manage.</p>
              </div>

              {provError && <Callout tone="danger">{provError}</Callout>}

              {provStep === 'token' && (
                <>
                  <Field label="Provider">
                    <div className="flex items-center gap-2 rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm text-fg">
                      <span className="font-medium">Cloudflare</span>
                      <span className="rounded bg-surface-3 px-1.5 py-0.5 text-xs text-fg-faint">more coming soon</span>
                    </div>
                  </Field>

                  <Field
                    label="API token"
                    help="api-token"
                    hint={<>Needs <strong className="font-semibold">Zone → Read</strong> and <strong className="font-semibold">DNS → Edit</strong>. Stored encrypted at rest.</>}
                  >
                    <PasswordInput
                      value={provApiToken}
                      onChange={(e) => { setProvApiToken(e.target.value); setProvTestError(''); }}
                      className="font-mono"
                      placeholder="Paste your Cloudflare API token"
                      onKeyDown={(e) => { if (e.key === 'Enter' && provApiToken) handleTestToken(); }}
                    />
                  </Field>

                  <Callout tone="info" title="Where do I get this?">
                    In Cloudflare, open{' '}
                    <a href={CF_TOKEN_URL} target="_blank" rel="noreferrer" className="font-medium underline">My Profile → API Tokens</a>,
                    click <strong>Create Token</strong>, and use the <strong>“Edit zone DNS”</strong> template. You can scope it to
                    only the zones you want, or all zones in your account.{' '}
                    <Link to="/help/cloudflare-token" className="font-medium underline">Full walkthrough →</Link>
                  </Callout>

                  {provTestError && <Callout tone="danger">{provTestError}</Callout>}

                  <div className="flex items-center justify-between pt-1">
                    <Button variant="ghost" onClick={handleSkipStep}>Skip for now</Button>
                    <Button onClick={handleTestToken} loading={provTestLoading} disabled={!provApiToken}>
                      {provTestLoading ? 'Connecting…' : 'Connect'}
                    </Button>
                  </div>
                </>
              )}

              {provStep === 'zones' && (
                <>
                  <Callout tone="success">Token valid — {provZones.length} zone{provZones.length !== 1 ? 's' : ''} found.</Callout>
                  <div>
                    <span className="mb-2 flex items-center gap-1.5 text-sm font-medium text-fg">
                      Zones to manage <HelpTip term="zone" />
                    </span>
                    <MultiSelect
                      items={provZones.map((z) => ({ id: z.id, label: z.name, meta: `${z.id.slice(0, 8)}…` }))}
                      selected={selectedZones}
                      onChange={setSelectedZones}
                    />
                    <p className="mt-1.5 text-xs text-fg-faint">You can manage domains under each zone afterwards.</p>
                  </div>
                  <div className="flex items-center justify-between pt-1">
                    <Button variant="secondary" onClick={() => { setProvStep('token'); setProvZones([]); }}>Back</Button>
                    <Button onClick={handleSaveZones} loading={provSaveLoading} disabled={selectedZones.size === 0}>
                      {provSaveLoading ? 'Adding…' : `Add ${selectedZones.size} zone${selectedZones.size !== 1 ? 's' : ''}`}
                    </Button>
                  </div>
                </>
              )}

              {provStep === 'saved' && (
                <>
                  <Callout tone="success" title={`${zonesCreated.length} zone${zonesCreated.length !== 1 ? 's' : ''} added`}>
                    <div className="mt-1.5 flex flex-wrap gap-1.5">
                      {zonesCreated.map((name) => (
                        <span key={name} className="rounded-md bg-success/15 px-2 py-0.5 text-xs font-medium">{name}</span>
                      ))}
                    </div>
                  </Callout>
                  <div className="flex justify-end">
                    <Button onClick={() => setCurrentStep(1)}>Continue</Button>
                  </div>
                </>
              )}
            </div>
          )}

          {/* STEP 2 — agent */}
          {currentStep === 1 && (
            <div className="space-y-5">
              <div>
                <h2 className="text-lg font-semibold text-fg">Connect an agent</h2>
                <p className="mt-1 text-sm text-fg-muted">Run the NurProxy agent on the edge server that will serve your traffic.</p>
              </div>

              <Field
                label="Orchestrator URL"
                help="orchestrator-url"
                hint="This is how the agent reaches this dashboard. It must be reachable from the edge server — often a LAN IP, VPN address, or public hostname, not the URL in your browser’s address bar."
              >
                <Input value={orchestratorUrl} onChange={(e) => setOrchestratorUrl(e.target.value)} className="font-mono" placeholder="https://nurproxy.example.com" />
              </Field>

              <Field
                label="Edge server FQDN"
                help="fqdn"
                hint="The public hostname for this edge server. The agent creates an A record for it at your DNS provider pointing to the server’s IP, and every subdomain you add for this agent becomes a CNAME to it. Change it only if you want a different anchor hostname than the server’s own FQDN."
              >
                <Input value={agentFqdn} onChange={(e) => setAgentFqdn(e.target.value)} className="font-mono" placeholder="edge1.example.com" />
              </Field>

              <div>
                <p className="mb-2 text-sm font-medium text-fg">Run this on your edge server</p>
                <div className="relative">
                  <pre className="overflow-x-auto rounded-lg border border-border bg-surface-2 p-4 text-xs leading-relaxed text-fg">{installCommand}</pre>
                  <button onClick={() => copyToClipboard(installCommand)} className="absolute right-2 top-2 rounded-md border border-border bg-surface px-2 py-1 text-xs font-medium text-fg-muted transition-colors hover:text-fg">
                    {copied ? 'Copied!' : 'Copy'}
                  </button>
                </div>
              </div>

              {agentAdopted ? (
                <Callout tone="success" title="Agent adopted">It’s connected and ready to serve domains.</Callout>
              ) : pendingAgents.length === 0 ? (
                <div className="rounded-lg border border-border bg-surface-2 px-4 py-6 text-center">
                  {pollingAgents && <div className="mb-3 flex justify-center"><Spinner className="h-7 w-7 text-fg-faint" /></div>}
                  <p className="text-sm text-fg-muted">Waiting for the agent to connect…</p>
                  <p className="mt-1 text-xs text-fg-faint">Checking every 3 seconds</p>
                  {waitedLong && (
                    <div className="mt-4 text-left">
                      <Callout tone="warning" title="Not showing up yet?">
                        <ul className="mt-1 list-disc space-y-1 pl-4 text-xs">
                          <li>Make sure <span className="font-mono">{orchestratorUrl || 'the orchestrator URL'}</span> is reachable <em>from the edge server</em> (try <span className="font-mono">curl</span> it there).</li>
                          <li>Check the server’s firewall isn’t blocking outbound HTTPS.</li>
                          <li>Look at the agent logs for connection errors.</li>
                        </ul>
                        <Link to="/help/agent-reachability" className="mt-1.5 inline-block font-medium underline">Troubleshooting guide →</Link>
                      </Callout>
                    </div>
                  )}
                </div>
              ) : (
                <div className="space-y-3">
                  <p className="flex items-center gap-1.5 text-sm font-medium text-fg">
                    {pendingAgents.length} agent{pendingAgents.length !== 1 ? 's' : ''} waiting for approval <HelpTip term="adoption" />
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
                        {adoptingId !== agent.id && <Button variant="primary" size="sm" onClick={() => startAdopt(agent)}>Approve</Button>}
                      </div>

                      {adoptingId === agent.id && (
                        <div className="mt-4 space-y-3 border-t border-border pt-4">
                          {adoptError && <Callout tone="danger">{adoptError}</Callout>}
                          <Field label="Display name">
                            <Input value={adoptName} onChange={(e) => setAdoptName(e.target.value)} placeholder="e.g. Edge — Frankfurt" />
                          </Field>
                          <Field label="DNS zones" help="zone">
                            <MultiSelect
                              items={zones.map((z) => ({ id: z.id, label: z.name }))}
                              selected={adoptZoneIds}
                              onChange={setAdoptZoneIds}
                              maxHeightClass="max-h-36"
                              emptyHint="No zones yet — add a provider first."
                            />
                          </Field>
                          <Field label="DNS mode" help="dns-mode">
                            <div className="flex gap-4">
                              <label className="flex cursor-pointer items-center gap-2 text-sm text-fg">
                                <input type="radio" name="wiz-dns-mode" checked={adoptDnsMode === 'static'} onChange={() => setAdoptDnsMode('static')} className="accent-[var(--accent)]" />
                                Static
                              </label>
                              <label className="flex cursor-pointer items-center gap-2 text-sm text-fg">
                                <input type="radio" name="wiz-dns-mode" checked={adoptDnsMode === 'ddns'} onChange={() => setAdoptDnsMode('ddns')} className="accent-[var(--accent)]" />
                                DDNS
                              </label>
                            </div>
                          </Field>
                          <div className="flex justify-end gap-3">
                            <Button variant="secondary" size="sm" onClick={() => setAdoptingId(null)}>Cancel</Button>
                            <Button size="sm" onClick={handleConfirmAdopt} loading={adoptLoading}>Approve agent</Button>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              <div className="flex items-center justify-between pt-1">
                <Button variant="secondary" onClick={() => setCurrentStep(0)}>Back</Button>
                <div className="flex gap-3">
                  <Button variant="ghost" onClick={handleSkipStep}>Skip</Button>
                  {agentAdopted && <Button onClick={() => setCurrentStep(2)}>Continue</Button>}
                </div>
              </div>
            </div>
          )}

          {/* STEP 3 — done */}
          {currentStep === 2 && (
            <div className="text-center">
              <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-success-soft text-success-fg">
                <svg className="h-7 w-7" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
              </div>
              <h2 className="text-lg font-semibold text-fg">You’re all set</h2>
              <p className="mt-2 text-sm text-fg-muted">Here’s what’s configured:</p>

              <div className="mt-6 space-y-2 text-left">
                <SummaryItem label="DNS zones" value={zonesCreated.length > 0 ? zonesCreated.join(', ') : null} />
                <SummaryItem label="Agent" value={agentAdopted ? 'Connected and adopted' : null} />
              </div>

              <p className="mt-6 text-xs text-fg-faint">You can add more providers and agents anytime from Settings and Agents.</p>
              <Button onClick={handleFinish} loading={completing} className="mt-6 w-full justify-center">Go to dashboard</Button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function SummaryItem({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-lg bg-surface-2 px-4 py-3">
      <span className="text-sm font-medium text-fg">{label}</span>
      {value ? (
        <span className="flex items-center gap-1.5 text-sm text-success-fg">
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
          {value}
        </span>
      ) : (
        <span className="text-sm text-fg-faint">Skipped</span>
      )}
    </div>
  );
}

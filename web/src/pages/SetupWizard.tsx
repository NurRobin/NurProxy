import { useState, useEffect, useRef, useCallback } from 'react';
import { api } from '../lib/api';
import type { Agent, Zone } from '../lib/types';
import type { TestProviderZone } from '../lib/api';
import StatusBadge from '../components/StatusBadge';

interface SetupWizardProps {
  onComplete: () => void;
}

const STEPS = [
  { key: 'provider', label: 'DNS Provider' },
  { key: 'agent', label: 'Connect Agent' },
  { key: 'done', label: 'Done' },
] as const;

export default function SetupWizard({ onComplete }: SetupWizardProps) {
  const [currentStep, setCurrentStep] = useState(0);

  // Provider step state
  const [provType, setProvType] = useState('cloudflare');
  const [provApiToken, setProvApiToken] = useState('');
  const [provTestLoading, setProvTestLoading] = useState(false);
  const [provTestError, setProvTestError] = useState('');
  const [provZones, setProvZones] = useState<TestProviderZone[]>([]);
  const [selectedZones, setSelectedZones] = useState<Set<string>>(new Set());
  const [provSaveLoading, setProvSaveLoading] = useState(false);
  const [provError, setProvError] = useState('');
  const [zonesCreated, setZonesCreated] = useState<string[]>([]);
  const [provStep, setProvStep] = useState<'token' | 'zones' | 'saved'>('token');

  // Agent step state
  const [agents, setAgents] = useState<Agent[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const pollingAgents = currentStep === 1;
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
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
    try {
      const z = await api.listAllZones();
      setZones(z);
    } catch { /* ignore */ }
  }, []);

  const pollAgents = useCallback(async () => {
    try {
      const a = await api.listAgents();
      setAgents(a);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    if (currentStep === 1) {
      fetchZones();
      pollAgents();
      pollRef.current = setInterval(pollAgents, 3000);
    } else {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    }
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [currentStep, fetchZones, pollAgents]);

  async function handleTestToken() {
    setProvTestLoading(true);
    setProvTestError('');
    setProvZones([]);
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
        setProvStep('zones');
      } else {
        setProvTestError('Token is valid but no zones found. Make sure the token has Zone:Read permission.');
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
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleAllZones() {
    if (selectedZones.size === provZones.length) {
      setSelectedZones(new Set());
    } else {
      setSelectedZones(new Set(provZones.map(z => z.id)));
    }
  }

  async function handleSaveZones() {
    if (selectedZones.size === 0) return;
    setProvSaveLoading(true);
    setProvError('');
    try {
      // Step 1: Create a single provider
      const provider = await api.createProvider({
        type: provType,
        name: provType,
        config: { api_token: provApiToken },
      });

      // Step 2: Batch-create selected zones
      const zonesToCreate = provZones
        .filter(z => selectedZones.has(z.id))
        .map(z => ({ external_id: z.id, name: z.name }));

      const created = await api.createZonesBatch({
        provider_id: provider.id,
        zones: zonesToCreate,
      });

      setZonesCreated(created.map(z => z.name));
      setProvStep('saved');
    } catch (err) {
      setProvError(err instanceof Error ? err.message : 'Failed to save provider');
    } finally {
      setProvSaveLoading(false);
    }
  }

  async function handleAdoptAgent(agent: Agent) {
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
      setAdoptError(err instanceof Error ? err.message : 'Failed to adopt agent');
    } finally {
      setAdoptLoading(false);
    }
  }

  async function handleFinish() {
    setCompleting(true);
    try {
      await api.updateSetting('setup_complete', 'true');
    } catch { /* proceed anyway */ }
    onComplete();
  }

  async function handleSkipStep() {
    if (currentStep < STEPS.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      await handleFinish();
    }
  }

  const orchestratorUrl = window.location.origin;
  const installCommand = `curl -fsSL https://get.nurproxy.dev | sh -s -- agent \\
  --orchestrator ${orchestratorUrl} \\
  --fqdn your-edge-server.yourdomain.com`;

  async function copyToClipboard(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch { /* ignore */ }
  }

  const pendingAgents = agents.filter((a) => a.status === 'pending');

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950 px-4 py-12">
      <div className="w-full max-w-lg">
        <div className="mb-8 text-center">
          <h1 className="text-2xl font-bold text-white">NurProxy Setup</h1>
          <p className="mt-1 text-sm text-gray-400">Let's get your reverse proxy running.</p>
        </div>

        {/* Step Indicator */}
        <div className="mb-8">
          <div className="flex items-center justify-center gap-2">
            {STEPS.map((step, i) => (
              <div key={step.key} className="flex items-center gap-2">
                <button
                  onClick={() => { if (i < currentStep) setCurrentStep(i); }}
                  disabled={i > currentStep}
                  className={`flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold transition-colors ${
                    i === currentStep
                      ? 'bg-blue-600 text-white'
                      : i < currentStep
                        ? 'bg-blue-900/60 text-blue-300 hover:bg-blue-800/60 cursor-pointer'
                        : 'bg-gray-800 text-gray-500'
                  }`}
                >
                  {i < currentStep ? (
                    <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                  ) : (i + 1)}
                </button>
                <span className={`text-xs font-medium ${i === currentStep ? 'text-gray-200' : i < currentStep ? 'text-gray-400' : 'text-gray-600'}`}>
                  {step.label}
                </span>
                {i < STEPS.length - 1 && (
                  <div className={`mx-1 h-px w-8 ${i < currentStep ? 'bg-blue-700' : 'bg-gray-800'}`} />
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Step Content */}
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-6">

          {/* Step 1: DNS Provider */}
          {currentStep === 0 && (
            <div>
              <h2 className="text-lg font-semibold text-white">Connect DNS Provider</h2>
              <p className="mt-1 text-sm text-gray-400">
                Add an API token and we'll auto-detect your zones.
              </p>

              <div className="mt-5 space-y-4">
                {provError && (
                  <div className="rounded-lg bg-red-900/30 border border-red-800 px-3 py-2 text-sm text-red-400">{provError}</div>
                )}

                {/* Sub-step: Enter token */}
                {provStep === 'token' && (
                  <>
                    <div>
                      <label className="block text-sm font-medium text-gray-300">Provider</label>
                      <select
                        value={provType}
                        onChange={(e) => setProvType(e.target.value)}
                        className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                      >
                        <option value="cloudflare">Cloudflare</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-300">API Token</label>
                      <input
                        type="password"
                        value={provApiToken}
                        onChange={(e) => { setProvApiToken(e.target.value); setProvTestError(''); }}
                        className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                        placeholder="Paste your API token"
                        onKeyDown={(e) => { if (e.key === 'Enter' && provApiToken) handleTestToken(); }}
                      />
                      <p className="mt-1 text-xs text-gray-500">Needs Zone:Read and DNS:Edit permissions.</p>
                    </div>

                    {provTestError && (
                      <div className="rounded-lg bg-red-900/30 border border-red-800 px-3 py-2 text-sm text-red-400">{provTestError}</div>
                    )}

                    <div className="flex items-center justify-between pt-2">
                      <button
                        onClick={handleSkipStep}
                        className="rounded-lg border border-gray-700 px-4 py-2 text-sm font-medium text-gray-400 hover:bg-gray-800 hover:text-gray-300"
                      >
                        Skip
                      </button>
                      <button
                        onClick={handleTestToken}
                        disabled={provTestLoading || !provApiToken}
                        className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
                      >
                        {provTestLoading ? <span className="flex items-center gap-2"><Spinner />Connecting...</span> : 'Connect'}
                      </button>
                    </div>
                  </>
                )}

                {/* Sub-step: Select zones */}
                {provStep === 'zones' && (
                  <>
                    <div className="rounded-lg bg-green-900/30 border border-green-800 px-3 py-2 text-sm text-green-400 flex items-center gap-2">
                      <svg className="h-4 w-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                      </svg>
                      Token valid — {provZones.length} zone{provZones.length !== 1 ? 's' : ''} found
                    </div>

                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <label className="block text-sm font-medium text-gray-300">Select zones to manage</label>
                        <button
                          onClick={toggleAllZones}
                          className="text-xs text-blue-400 hover:text-blue-300"
                        >
                          {selectedZones.size === provZones.length ? 'Deselect all' : 'Select all'}
                        </button>
                      </div>
                      <div className="space-y-1 max-h-48 overflow-y-auto rounded-lg border border-gray-700 bg-gray-800 p-2">
                        {provZones.map((zone) => (
                          <label
                            key={zone.id}
                            className={`flex items-center gap-3 rounded-md px-3 py-2.5 cursor-pointer transition-colors ${
                              selectedZones.has(zone.id) ? 'bg-blue-900/30' : 'hover:bg-gray-700/50'
                            }`}
                          >
                            <input
                              type="checkbox"
                              checked={selectedZones.has(zone.id)}
                              onChange={() => toggleZone(zone.id)}
                              className="accent-blue-500 h-4 w-4"
                            />
                            <span className="text-sm text-white font-medium">{zone.name}</span>
                            <span className="text-xs text-gray-500 ml-auto font-mono">{zone.id.slice(0, 8)}…</span>
                          </label>
                        ))}
                      </div>
                      <p className="mt-1.5 text-xs text-gray-500">
                        Selected zones will be added to your provider. You can manage domains under each zone separately.
                      </p>
                    </div>

                    <div className="flex items-center justify-between pt-2">
                      <button
                        onClick={() => { setProvStep('token'); setProvZones([]); }}
                        className="rounded-lg border border-gray-700 px-4 py-2 text-sm font-medium text-gray-400 hover:bg-gray-800 hover:text-gray-300"
                      >
                        Back
                      </button>
                      <button
                        onClick={handleSaveZones}
                        disabled={provSaveLoading || selectedZones.size === 0}
                        className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
                      >
                        {provSaveLoading
                          ? <span className="flex items-center gap-2"><Spinner />Adding {selectedZones.size} zone{selectedZones.size !== 1 ? 's' : ''}...</span>
                          : `Add ${selectedZones.size} zone${selectedZones.size !== 1 ? 's' : ''}`
                        }
                      </button>
                    </div>
                  </>
                )}

                {/* Sub-step: Saved confirmation */}
                {provStep === 'saved' && (
                  <>
                    <div className="rounded-lg bg-green-900/30 border border-green-800 px-4 py-3">
                      <div className="flex items-center gap-2 mb-2">
                        <svg className="h-5 w-5 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                        </svg>
                        <p className="text-sm font-medium text-green-400">
                          {zonesCreated.length} zone{zonesCreated.length !== 1 ? 's' : ''} added
                        </p>
                      </div>
                      <div className="flex flex-wrap gap-1.5 ml-7">
                        {zonesCreated.map((name) => (
                          <span key={name} className="rounded-md bg-green-900/40 px-2 py-0.5 text-xs font-medium text-green-300">
                            {name}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="flex justify-end pt-2">
                      <button
                        onClick={() => setCurrentStep(1)}
                        className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
                      >
                        Continue
                      </button>
                    </div>
                  </>
                )}
              </div>
            </div>
          )}

          {/* Step 2: Connect Agent */}
          {currentStep === 1 && (
            <div>
              <h2 className="text-lg font-semibold text-white">Connect an Agent</h2>
              <p className="mt-1 text-sm text-gray-400">
                Install the NurProxy agent on your edge server.
              </p>

              <div className="mt-5 space-y-5">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Run this on your server:</label>
                  <div className="relative">
                    <pre className="overflow-x-auto rounded-lg border border-gray-700 bg-gray-800 p-4 text-sm text-gray-200 font-mono leading-relaxed">
                      {installCommand}
                    </pre>
                    <button
                      onClick={() => copyToClipboard(installCommand)}
                      className="absolute right-2 top-2 rounded-md border border-gray-600 bg-gray-700 px-2 py-1 text-xs font-medium text-gray-300 hover:bg-gray-600 transition-colors"
                    >
                      {copied ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                  <p className="mt-2 text-xs text-gray-500">
                    Replace <code className="rounded bg-gray-800 px-1 py-0.5 text-gray-400">your-edge-server.yourdomain.com</code> with your server's FQDN.
                  </p>
                </div>

                {agentAdopted ? (
                  <div className="rounded-lg bg-green-900/30 border border-green-800 px-4 py-3">
                    <div className="flex items-center gap-2">
                      <svg className="h-5 w-5 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                      </svg>
                      <p className="text-sm font-medium text-green-400">Agent adopted successfully!</p>
                    </div>
                  </div>
                ) : pendingAgents.length === 0 ? (
                  <div className="rounded-lg border border-gray-700 bg-gray-800/50 px-4 py-6 text-center">
                    {pollingAgents && <div className="flex justify-center mb-3"><SpinnerLarge /></div>}
                    <p className="text-sm text-gray-400">Waiting for an agent to connect...</p>
                    <p className="mt-1 text-xs text-gray-500">Checking every 3 seconds</p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    <p className="text-sm font-medium text-yellow-400">
                      {pendingAgents.length} pending agent{pendingAgents.length !== 1 ? 's' : ''} found:
                    </p>
                    {pendingAgents.map((agent) => (
                      <div key={agent.id} className="rounded-lg border border-gray-700 bg-gray-800 p-4">
                        <div className="flex items-center justify-between">
                          <div>
                            <div className="flex items-center gap-2">
                              <p className="font-medium text-white">{agent.fqdn}</p>
                              <StatusBadge status={agent.status} />
                            </div>
                            <p className="mt-0.5 text-xs text-gray-400">
                              {agent.public_ip && `IP: ${agent.public_ip}`}
                              {agent.version && ` · v${agent.version}`}
                            </p>
                          </div>
                          {adoptingId !== agent.id && (
                            <button
                              onClick={() => handleAdoptAgent(agent)}
                              className="rounded-lg bg-green-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-green-700"
                            >
                              Adopt
                            </button>
                          )}
                        </div>

                        {adoptingId === agent.id && (
                          <div className="mt-4 space-y-3 border-t border-gray-700 pt-4">
                            {adoptError && (
                              <div className="rounded-lg bg-red-900/30 border border-red-800 px-3 py-2 text-sm text-red-400">{adoptError}</div>
                            )}
                            <div>
                              <label className="block text-sm font-medium text-gray-300">Name</label>
                              <input
                                value={adoptName}
                                onChange={(e) => setAdoptName(e.target.value)}
                                className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                                placeholder="Agent display name"
                              />
                            </div>
                            <div>
                              <label className="block text-sm font-medium text-gray-300">DNS Zones</label>
                              {zones.length === 0 ? (
                                <p className="mt-1 text-sm text-gray-500">No zones available. Add a provider first.</p>
                              ) : (
                                <div className="mt-1 space-y-1 max-h-36 overflow-y-auto rounded-lg border border-gray-700 bg-gray-900 p-2">
                                  {zones.map((z) => (
                                    <label
                                      key={z.id}
                                      className={`flex items-center gap-3 rounded-md px-3 py-2 cursor-pointer transition-colors ${
                                        adoptZoneIds.has(z.id) ? 'bg-blue-900/30' : 'hover:bg-gray-800/50'
                                      }`}
                                    >
                                      <input
                                        type="checkbox"
                                        checked={adoptZoneIds.has(z.id)}
                                        onChange={() => {
                                          setAdoptZoneIds(prev => {
                                            const next = new Set(prev);
                                            if (next.has(z.id)) next.delete(z.id);
                                            else next.add(z.id);
                                            return next;
                                          });
                                        }}
                                        className="accent-blue-500 h-4 w-4"
                                      />
                                      <span className="text-sm text-white">{z.name}</span>
                                    </label>
                                  ))}
                                </div>
                              )}
                            </div>
                            <div>
                              <label className="block text-sm font-medium text-gray-300">DNS Mode</label>
                              <div className="mt-1 flex gap-4">
                                <label className="flex items-center gap-2 text-sm text-gray-300">
                                  <input type="radio" checked={adoptDnsMode === 'static'} onChange={() => setAdoptDnsMode('static')} className="accent-blue-500" />
                                  Static
                                </label>
                                <label className="flex items-center gap-2 text-sm text-gray-300">
                                  <input type="radio" checked={adoptDnsMode === 'ddns'} onChange={() => setAdoptDnsMode('ddns')} className="accent-blue-500" />
                                  DDNS
                                </label>
                              </div>
                            </div>
                            <div className="flex justify-end gap-3">
                              <button
                                onClick={() => setAdoptingId(null)}
                                className="rounded-lg border border-gray-600 px-3 py-1.5 text-sm font-medium text-gray-300 hover:bg-gray-700"
                              >
                                Cancel
                              </button>
                              <button
                                onClick={handleConfirmAdopt}
                                disabled={adoptLoading}
                                className="rounded-lg bg-green-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-green-700 disabled:opacity-50"
                              >
                                {adoptLoading ? <span className="flex items-center gap-2"><Spinner />Adopting...</span> : 'Confirm Adopt'}
                              </button>
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                <div className="flex items-center justify-between pt-2">
                  <button
                    onClick={() => setCurrentStep(0)}
                    className="rounded-lg border border-gray-700 px-4 py-2 text-sm font-medium text-gray-400 hover:bg-gray-800 hover:text-gray-300"
                  >
                    Back
                  </button>
                  <div className="flex gap-3">
                    <button
                      onClick={handleSkipStep}
                      className="rounded-lg border border-gray-700 px-4 py-2 text-sm font-medium text-gray-400 hover:bg-gray-800 hover:text-gray-300"
                    >
                      Skip
                    </button>
                    {agentAdopted && (
                      <button
                        onClick={() => setCurrentStep(2)}
                        className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
                      >
                        Continue
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Step 3: Done */}
          {currentStep === 2 && (
            <div className="text-center">
              <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-green-900/40">
                <svg className="h-7 w-7 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <h2 className="text-lg font-semibold text-white">You're all set!</h2>
              <p className="mt-2 text-sm text-gray-400">Here's what was configured:</p>

              <div className="mt-6 space-y-3 text-left">
                <SummaryItem
                  label="DNS Zones"
                  value={zonesCreated.length > 0 ? zonesCreated.join(', ') : null}
                  skipped={zonesCreated.length === 0}
                />
                <SummaryItem
                  label="Agent"
                  value={agentAdopted ? 'Connected and adopted' : null}
                  skipped={!agentAdopted}
                />
              </div>

              <p className="mt-6 text-xs text-gray-500">
                You can always add more providers and agents from Settings and Agents pages.
              </p>

              <button
                onClick={handleFinish}
                disabled={completing}
                className="mt-6 w-full rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
              >
                {completing ? <span className="flex items-center justify-center gap-2"><Spinner />Finishing...</span> : 'Go to Dashboard'}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function SummaryItem({ label, value, skipped }: { label: string; value: string | null; skipped: boolean }) {
  return (
    <div className="flex items-center justify-between rounded-lg bg-gray-800 px-4 py-3">
      <span className="text-sm font-medium text-gray-300">{label}</span>
      {skipped ? (
        <span className="text-sm text-gray-500">Skipped</span>
      ) : (
        <span className="flex items-center gap-1.5 text-sm text-green-400">
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
          </svg>
          {value}
        </span>
      )}
    </div>
  );
}

function Spinner() {
  return (
    <svg className="h-4 w-4 animate-spin" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  );
}

function SpinnerLarge() {
  return (
    <svg className="h-8 w-8 animate-spin text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  );
}

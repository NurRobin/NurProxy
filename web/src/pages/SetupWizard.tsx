import { useState, useEffect, useRef, useCallback } from 'react';
import { api } from '../lib/api';
import type { Agent, Provider } from '../lib/types';
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
  const [provName, setProvName] = useState('');
  const [provApiToken, setProvApiToken] = useState('');
  const [provZoneId, setProvZoneId] = useState('');
  const [provZoneName, setProvZoneName] = useState('');
  const [provTestResult, setProvTestResult] = useState<{ valid: boolean; message: string } | null>(null);
  const [provTestLoading, setProvTestLoading] = useState(false);
  const [provSaveLoading, setProvSaveLoading] = useState(false);
  const [provError, setProvError] = useState('');
  const [providerCreated, setProviderCreated] = useState<{ id: string; name: string } | null>(null);

  // Agent step state
  const [agents, setAgents] = useState<Agent[]>([]);
  const [providers, setProviders] = useState<Provider[]>([]);
  const [pollingAgents, setPollingAgents] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const [adoptingId, setAdoptingId] = useState<string | null>(null);
  const [adoptName, setAdoptName] = useState('');
  const [adoptProvider, setAdoptProvider] = useState('');
  const [adoptDnsMode, setAdoptDnsMode] = useState<'static' | 'ddns'>('static');
  const [adoptLoading, setAdoptLoading] = useState(false);
  const [adoptError, setAdoptError] = useState('');
  const [agentAdopted, setAgentAdopted] = useState(false);

  // Summary state
  const [completing, setCompleting] = useState(false);

  // Clipboard state
  const [copied, setCopied] = useState(false);

  // Fetch providers when entering agent step
  const fetchProviders = useCallback(async () => {
    try {
      const p = await api.listProviders();
      setProviders(p);
    } catch {
      // ignore
    }
  }, []);

  // Poll for agents
  const pollAgents = useCallback(async () => {
    try {
      const a = await api.listAgents();
      setAgents(a);
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    if (currentStep === 1) {
      setPollingAgents(true);
      fetchProviders();
      pollAgents();
      pollRef.current = setInterval(pollAgents, 3000);
    } else {
      setPollingAgents(false);
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
  }, [currentStep, fetchProviders, pollAgents]);

  function getProviderConfig() {
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

  async function handleSaveProvider() {
    if (!provName || !provApiToken) return;
    setProvSaveLoading(true);
    setProvError('');
    try {
      const result = await api.createProvider({
        type: provType,
        name: provName,
        config: getProviderConfig(),
        zone_id: provZoneId || undefined,
        zone_name: provZoneName || undefined,
      });
      setProviderCreated(result);
      setCurrentStep(1);
    } catch (err) {
      setProvError(err instanceof Error ? err.message : 'Failed to create provider');
    } finally {
      setProvSaveLoading(false);
    }
  }

  async function handleAdoptAgent(agent: Agent) {
    setAdoptingId(agent.id);
    setAdoptName(agent.fqdn);
    setAdoptProvider(providers[0]?.id ?? '');
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
        provider_id: adoptProvider || undefined,
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
    } catch {
      // If the setting fails to save, still proceed
    }
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
    } catch {
      // fallback: select text
    }
  }

  const pendingAgents = agents.filter((a) => a.status === 'pending');

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950 px-4 py-12">
      <div className="w-full max-w-lg">
        {/* Header */}
        <div className="mb-8 text-center">
          <h1 className="text-2xl font-bold text-white">NurProxy Setup</h1>
          <p className="mt-1 text-sm text-gray-400">
            Let's get your reverse proxy running in a few steps.
          </p>
        </div>

        {/* Step Indicator */}
        <div className="mb-8">
          <div className="flex items-center justify-center gap-2">
            {STEPS.map((step, i) => (
              <div key={step.key} className="flex items-center gap-2">
                <button
                  onClick={() => {
                    if (i < currentStep) setCurrentStep(i);
                  }}
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
                  ) : (
                    i + 1
                  )}
                </button>
                <span
                  className={`text-xs font-medium ${
                    i === currentStep ? 'text-gray-200' : i < currentStep ? 'text-gray-400' : 'text-gray-600'
                  }`}
                >
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
              <h2 className="text-lg font-semibold text-white">Add a DNS Provider</h2>
              <p className="mt-1 text-sm text-gray-400">
                Connect a DNS provider so NurProxy can manage DNS records for your domains.
              </p>

              <div className="mt-5 space-y-4">
                {provError && (
                  <div className="rounded-lg bg-red-900/30 border border-red-800 px-3 py-2 text-sm text-red-400">
                    {provError}
                  </div>
                )}

                <div>
                  <label className="block text-sm font-medium text-gray-300">Provider Type</label>
                  <select
                    value={provType}
                    onChange={(e) => setProvType(e.target.value)}
                    className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                  >
                    <option value="cloudflare">Cloudflare</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300">Provider Name</label>
                  <input
                    value={provName}
                    onChange={(e) => setProvName(e.target.value)}
                    className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                    placeholder="e.g. My Cloudflare"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300">API Token</label>
                  <input
                    type="password"
                    value={provApiToken}
                    onChange={(e) => setProvApiToken(e.target.value)}
                    className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                    placeholder="Your Cloudflare API token"
                  />
                  <p className="mt-1 text-xs text-gray-500">
                    Needs Zone:Read and DNS:Edit permissions.
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-sm font-medium text-gray-300">Zone ID</label>
                    <input
                      value={provZoneId}
                      onChange={(e) => setProvZoneId(e.target.value)}
                      className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                      placeholder="Optional"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-300">Zone Name</label>
                    <input
                      value={provZoneName}
                      onChange={(e) => setProvZoneName(e.target.value)}
                      className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                      placeholder="e.g. example.com"
                    />
                  </div>
                </div>

                {/* Test Result */}
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

                <div className="flex items-center justify-between pt-2">
                  <button
                    onClick={handleTestProvider}
                    disabled={provTestLoading || !provApiToken}
                    className="rounded-lg border border-gray-600 px-4 py-2 text-sm font-medium text-gray-300 hover:bg-gray-800 disabled:opacity-50"
                  >
                    {provTestLoading ? (
                      <span className="flex items-center gap-2">
                        <Spinner />
                        Testing...
                      </span>
                    ) : (
                      'Test Connection'
                    )}
                  </button>
                  <div className="flex gap-3">
                    <button
                      onClick={handleSkipStep}
                      className="rounded-lg border border-gray-700 px-4 py-2 text-sm font-medium text-gray-400 hover:bg-gray-800 hover:text-gray-300"
                    >
                      Skip
                    </button>
                    <button
                      onClick={handleSaveProvider}
                      disabled={provSaveLoading || !provName || !provApiToken}
                      className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
                    >
                      {provSaveLoading ? (
                        <span className="flex items-center gap-2">
                          <Spinner />
                          Saving...
                        </span>
                      ) : (
                        'Save & Continue'
                      )}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Step 2: Connect Agent */}
          {currentStep === 1 && (
            <div>
              <h2 className="text-lg font-semibold text-white">Connect an Agent</h2>
              <p className="mt-1 text-sm text-gray-400">
                Install the NurProxy agent on your edge server. It will register itself with this orchestrator.
              </p>

              <div className="mt-5 space-y-5">
                {/* Install instructions */}
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Run this on your server:
                  </label>
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
                    Replace <code className="rounded bg-gray-800 px-1 py-0.5 text-gray-400">your-edge-server.yourdomain.com</code> with the FQDN of your server.
                  </p>
                </div>

                {/* Waiting / Agent list */}
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
                    <div className="flex justify-center mb-3">
                      {pollingAgents && <SpinnerLarge />}
                    </div>
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
                              {agent.version && ` | v${agent.version}`}
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

                        {/* Inline adopt form */}
                        {adoptingId === agent.id && (
                          <div className="mt-4 space-y-3 border-t border-gray-700 pt-4">
                            {adoptError && (
                              <div className="rounded-lg bg-red-900/30 border border-red-800 px-3 py-2 text-sm text-red-400">
                                {adoptError}
                              </div>
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
                              <label className="block text-sm font-medium text-gray-300">DNS Provider</label>
                              <select
                                value={adoptProvider}
                                onChange={(e) => setAdoptProvider(e.target.value)}
                                className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                              >
                                <option value="">None</option>
                                {providers.map((p) => (
                                  <option key={p.id} value={p.id}>
                                    {p.name} ({p.zone_name})
                                  </option>
                                ))}
                              </select>
                            </div>
                            <div>
                              <label className="block text-sm font-medium text-gray-300">DNS Mode</label>
                              <div className="mt-1 flex gap-4">
                                <label className="flex items-center gap-2 text-sm text-gray-300">
                                  <input
                                    type="radio"
                                    checked={adoptDnsMode === 'static'}
                                    onChange={() => setAdoptDnsMode('static')}
                                    className="accent-blue-500"
                                  />
                                  Static
                                </label>
                                <label className="flex items-center gap-2 text-sm text-gray-300">
                                  <input
                                    type="radio"
                                    checked={adoptDnsMode === 'ddns'}
                                    onChange={() => setAdoptDnsMode('ddns')}
                                    className="accent-blue-500"
                                  />
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
                                {adoptLoading ? (
                                  <span className="flex items-center gap-2">
                                    <Spinner />
                                    Adopting...
                                  </span>
                                ) : (
                                  'Confirm Adopt'
                                )}
                              </button>
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {/* Navigation */}
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
              <p className="mt-2 text-sm text-gray-400">
                Here's a summary of what was configured:
              </p>

              <div className="mt-6 space-y-3 text-left">
                <SummaryItem
                  label="DNS Provider"
                  value={providerCreated ? providerCreated.name : null}
                  skipped={!providerCreated}
                />
                <SummaryItem
                  label="Agent"
                  value={agentAdopted ? 'Connected and adopted' : null}
                  skipped={!agentAdopted}
                />
              </div>

              <p className="mt-6 text-xs text-gray-500">
                You can always add more providers and agents from the Settings and Agents pages.
              </p>

              <button
                onClick={handleFinish}
                disabled={completing}
                className="mt-6 w-full rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
              >
                {completing ? (
                  <span className="flex items-center justify-center gap-2">
                    <Spinner />
                    Finishing...
                  </span>
                ) : (
                  'Go to Dashboard'
                )}
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

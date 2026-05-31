// Canonical install entry point. This is the single source of truth for the
// installer URL shown in the dashboard. When the dedicated install site
// (proxy.nurrobin.de/get) goes live, change INSTALL_URL here and every command
// in the UI follows.
export const INSTALL_URL =
  'https://raw.githubusercontent.com/NurRobin/NurProxy/main/scripts/install.sh';

// agentInstallCommand renders the one-shot agent install one-liner. The bare
// `agent` subcommand plus passthrough flags is handled by scripts/install.sh.
export function agentInstallCommand(orchestratorUrl: string, fqdn: string): string {
  return (
    `curl -fsSL ${INSTALL_URL} | sh -s -- agent \\\n` +
    `  --orchestrator ${orchestratorUrl || 'https://your-dashboard-url'} \\\n` +
    `  --fqdn ${fqdn || 'edge1.example.com'}`
  );
}

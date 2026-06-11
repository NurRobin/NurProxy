/**
 * Short, plain-language definitions surfaced by <HelpTip term="...">.
 * `doc` points at the wiki page that explains the term in full, so the
 * inline tooltip stays a reminder and the wiki does the teaching.
 */
export interface GlossaryEntry {
  term: string;
  short: string;
  doc?: string; // wiki slug, e.g. "glossary"
}

export const glossary: Record<string, GlossaryEntry> = {
  zone: {
    term: 'DNS Zone',
    short: 'A domain you control at your DNS provider (e.g. example.com). NurProxy creates subdomain records inside zones you grant it.',
    doc: 'glossary',
  },
  fqdn: {
    term: 'FQDN',
    short: 'Fully Qualified Domain Name — the complete address of a host, like edge1.example.com. An agent gets an A record at this name; the subdomains you add for it become CNAMEs pointing here.',
    doc: 'glossary',
  },
  ddns: {
    term: 'DDNS',
    short: 'Dynamic DNS. The agent reports its current public IP on an interval, so records follow a server whose IP changes.',
    doc: 'dns-modes',
  },
  'dns-mode': {
    term: 'DNS Mode',
    short: 'Static keeps a fixed IP in DNS. DDNS lets the agent update its record automatically when its IP changes.',
    doc: 'dns-modes',
  },
  adoption: {
    term: 'Adopting an agent',
    short: 'Approving a server that has registered itself, so NurProxy trusts it and starts managing its proxy + DNS.',
    doc: 'agents',
  },
  reconciler: {
    term: 'Reconciler',
    short: 'The background loop that keeps DNS records and proxy configs matching your desired settings.',
    doc: 'glossary',
  },
  'proxy-detection': {
    term: 'Detected proxy',
    short: 'A read-only report of any reverse proxy already installed on the host (kind, version, config dir, log paths) plus which process holds :80/:443. NurProxy only observes this — it manages nothing here.',
    doc: 'agents',
  },
  'force-https': {
    term: 'Force HTTPS',
    short: 'Redirect any plain http:// request to https:// automatically.',
    doc: 'domains',
  },
  websocket: {
    term: 'WebSocket',
    short: 'Allow long-lived bidirectional connections (chat, live updates) to pass through the proxy.',
    doc: 'domains',
  },
  'max-body-size': {
    term: 'Max body size',
    short: 'Largest request the proxy will accept, e.g. 100mb. Raise it for large file uploads.',
    doc: 'domains',
  },
  'api-token': {
    term: 'DNS API Token',
    short: 'A scoped key from your DNS provider that lets NurProxy read zones and edit records. Stored encrypted.',
    doc: 'cloudflare-token',
  },
  'admin-api-key': {
    term: 'Admin API key',
    short: 'A Bearer token for NurProxy’s own API and the MCP server — programmatic access to this dashboard. Shown once when created. Not a DNS provider token.',
    doc: 'security',
  },
  'orchestrator-url': {
    term: 'Orchestrator URL',
    short: 'The address the agent uses to reach this dashboard. It must be reachable from the agent’s server — not necessarily the URL you use.',
    doc: 'agent-reachability',
  },
  server: {
    term: 'Server (upstream)',
    short: 'A backend address an agent proxies to, like 192.168.1.10. Domains point at a server + port.',
    doc: 'servers',
  },
  agent: {
    term: 'Agent',
    short: 'The NurProxy daemon running on an edge server. It runs Caddy and applies the configs you set here.',
    doc: 'agents',
  },
  'config-artifact': {
    term: 'Config artifact',
    short: 'A versioned unit of proxy config NurProxy manages on a host — built-in Caddy routes or a file. Every change is versioned so you can diff, roll back, and review drift.',
    doc: 'glossary',
  },
};

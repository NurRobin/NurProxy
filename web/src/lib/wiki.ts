import gettingStarted from '../../../wiki/getting-started.md?raw';
import cloudflareToken from '../../../wiki/cloudflare-token.md?raw';
import agentReachability from '../../../wiki/agent-reachability.md?raw';
import dnsModes from '../../../wiki/dns-modes.md?raw';
import domainsDoc from '../../../wiki/domains.md?raw';
import agentsDoc from '../../../wiki/agents.md?raw';
import security from '../../../wiki/security.md?raw';
import glossary from '../../../wiki/glossary.md?raw';

export interface Topic {
  slug: string;
  title: string;
  blurb: string;
  content: string;
}

export const TOPICS: Topic[] = [
  { slug: 'getting-started', title: 'Getting started', blurb: 'The two-step setup, end to end.', content: gettingStarted },
  { slug: 'cloudflare-token', title: 'Cloudflare API token', blurb: 'Exactly which permissions, and where to click.', content: cloudflareToken },
  { slug: 'agent-reachability', title: 'Agent can’t connect', blurb: 'Fix the #1 setup snag: the orchestrator URL.', content: agentReachability },
  { slug: 'agents', title: 'Agents', blurb: 'Register, approve, and manage edge servers.', content: agentsDoc },
  { slug: 'domains', title: 'Domains', blurb: 'Proxy a subdomain to a server, plus advanced config.', content: domainsDoc },
  { slug: 'dns-modes', title: 'DNS modes', blurb: 'Static vs DDNS — which to choose.', content: dnsModes },
  { slug: 'security', title: 'Security', blurb: 'Passwords, tokens, API keys, agent trust.', content: security },
  { slug: 'glossary', title: 'Glossary', blurb: 'Every term in one place.', content: glossary },
];

export const DEFAULT_SLUG = 'getting-started';

export function getTopic(slug?: string): Topic {
  return TOPICS.find((t) => t.slug === slug) ?? TOPICS.find((t) => t.slug === DEFAULT_SLUG)!;
}

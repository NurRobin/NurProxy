import { useEffect, useState } from 'react';
import { TriangleAlert } from 'lucide-react';
import { api } from '../lib/api';

// DryRunBanner renders a persistent strip across the top of the dashboard while
// the orchestrator runs in sandbox mode (#93), so an operator can never mistake a
// dry-run instance — where DNS/ACME calls are simulated — for a live one. It
// stays out of the way (and renders nothing) on a normal instance.
export default function DryRunBanner() {
  const [health, setHealth] = useState<{ dns_dry_run?: boolean; acme_dry_run?: boolean } | null>(null);

  useEffect(() => {
    let active = true;
    api.health().then((h) => { if (active) setHealth(h); }).catch(() => { /* health is best-effort */ });
    return () => { active = false; };
  }, []);

  if (!health || (!health.dns_dry_run && !health.acme_dry_run)) return null;

  const parts: string[] = [];
  if (health.dns_dry_run) parts.push('DNS');
  if (health.acme_dry_run) parts.push('ACME');
  const scope = parts.join(' + ');

  return (
    <div
      role="status"
      className="flex items-center justify-center gap-2 border-b border-warning/60 bg-warning-soft px-4 py-1.5 text-center text-xs font-medium text-warning-fg"
    >
      <TriangleAlert className="h-3.5 w-3.5 flex-shrink-0" aria-hidden="true" />
      <span>
        Dry-run mode — {scope} calls are simulated. No external requests leave this instance.
      </span>
    </div>
  );
}

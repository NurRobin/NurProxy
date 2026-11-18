import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '../lib/api';
import type { CertCandidates } from '../lib/types';
import Button from './Button';
import Callout from './Callout';
import { useToast, errMessage } from './toast-context';

function day(iso: string) {
  return new Date(iso).toLocaleDateString();
}

/**
 * Certificates the agents found on their hosts for this domain (#80), with an
 * Adopt action. Adopting asks the agent to upload that bundle; NurProxy then
 * serves and later renews it instead of ordering a duplicate from the CA.
 * Renders nothing when no agent reports a matching certificate.
 */
export default function DiskCertificates({ domainId }: { domainId: number }) {
  const { t } = useTranslation();
  const toast = useToast();
  const [data, setData] = useState<CertCandidates | null>(null);
  const [adopting, setAdopting] = useState('');

  const load = useCallback(() => {
    api.getCertCandidates(domainId).then(setData).catch(() => setData(null));
  }, [domainId]);
  useEffect(() => { load(); }, [load]);

  if (!data || (data.candidates.length === 0 && data.hints.length === 0)) return null;

  const adopt = async (fingerprint: string, agentId: string) => {
    setAdopting(fingerprint);
    try {
      const res = await api.adoptCertificate(domainId, fingerprint, agentId);
      toast.success(t('domains.diskCertAdopted', { date: day(res.expires_at) }));
      if (res.warning) toast.push(res.warning, 'info');
      load();
    } catch (err) {
      toast.error(errMessage(err, t('domains.diskCertAdoptFailed')));
    } finally {
      setAdopting('');
    }
  };

  return (
    <div className="space-y-3 rounded-lg border border-border p-3.5">
      <div>
        <p className="text-sm font-medium text-fg">{t('domains.diskCertTitle')}</p>
        <p className="text-xs text-fg-faint">{t('domains.diskCertIntro')}</p>
      </div>
      {data.issuance_deferred_until && !data.certificate_on_file && (
        <Callout tone="info">{t('domains.diskCertDeferred', { time: new Date(data.issuance_deferred_until).toLocaleTimeString() })}</Callout>
      )}
      {data.candidates.map((c) => (
        <div key={`${c.agent_id}-${c.fingerprint}`} className="flex flex-wrap items-start justify-between gap-3 border-t border-border pt-3 first:border-t-0 first:pt-0">
          <div className="min-w-0 space-y-0.5 text-xs">
            <p className="text-sm text-fg">{(c.names ?? []).join(', ')}</p>
            <p className="text-fg-muted">
              {t('domains.diskCertMeta', { agent: c.agent_name, source: c.source, date: day(c.not_after) })}
              {c.issuer ? ` · ${c.issuer}` : ''}
            </p>
            <p className="truncate font-mono text-fg-faint" title={c.cert_path}>{c.cert_path}</p>
            {!c.adoptable && c.reason && <p className="text-warning-fg">{c.reason}</p>}
          </div>
          <Button size="sm" variant={c.serving ? 'primary' : 'secondary'} disabled={!c.adoptable || (adopting !== '' && adopting !== c.fingerprint)}
            loading={adopting === c.fingerprint} onClick={() => adopt(c.fingerprint ?? '', c.agent_id)}>
            {t('domains.diskCertAdopt')}
          </Button>
        </div>
      ))}
      {data.hints.map((h) => (
        <p key={`${h.agent_id}-${h.path}`} className="text-xs text-fg-faint">
          {t('domains.diskCertHint', { agent: h.agent_name, path: h.path, error: h.error })}
        </p>
      ))}
    </div>
  );
}

import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import Modal from './Modal';
import Callout from './Callout';
import { api } from '../lib/api';
import type { LogTailLine } from '../lib/types';

interface Props {
  agentId: string;
  path: string;
  open: boolean;
  onClose: () => void;
}

const POLL_MS = 1000;
const MAX_LINES = 2000;

// LogTailViewer is the dashboard side of the on-demand log tail (§15). It is
// deliberately scoped to the open view: starting the session on open, polling for
// new lines while open, and stopping the session on close/unmount. There is never
// a continuous firehose — the agent only tails while a viewer is mounted, and the
// agent dials out for every hop (the orchestrator never reaches the agent).
export default function LogTailViewer({ agentId, path, open, onClose }: Props) {
  const { t } = useTranslation();
  const [lines, setLines] = useState<LogTailLine[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [starting, setStarting] = useState(true);
  const scrollRef = useRef<HTMLDivElement>(null);
  const atBottomRef = useRef(true);

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    let sessionId = '';
    let cursor = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const poll = async () => {
      if (cancelled || !sessionId) return;
      try {
        const res = await api.pollLogTail(agentId, sessionId, cursor);
        if (cancelled) return;
        cursor = res.cursor;
        if (res.lines.length > 0) {
          setLines((prev) => {
            const next = [...prev, ...res.lines];
            return next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next;
          });
        }
        if (res.error) setError(res.error);
        if (res.done) {
          setDone(true);
          return; // terminal — stop polling
        }
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
        return;
      }
      timer = setTimeout(poll, POLL_MS);
    };

    (async () => {
      setLines([]);
      setError(null);
      setDone(false);
      setStarting(true);
      try {
        const res = await api.startLogTail(agentId, path);
        if (cancelled) {
          // Raced a close before start returned: stop the just-opened session.
          await api.stopLogTail(agentId, res.session_id).catch(() => {});
          return;
        }
        sessionId = res.session_id;
        setStarting(false);
        poll();
      } catch (e) {
        if (!cancelled) {
          setStarting(false);
          setError(e instanceof Error ? e.message : String(e));
        }
      }
    })();

    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
      // Close → stop: tear the agent-side tail down when the view closes.
      if (sessionId) api.stopLogTail(agentId, sessionId).catch(() => {});
    };
  }, [open, agentId, path]);

  // Keep the view pinned to the newest line unless the operator scrolled up.
  useEffect(() => {
    const el = scrollRef.current;
    if (el && atBottomRef.current) el.scrollTop = el.scrollHeight;
  }, [lines]);

  return (
    <Modal open={open} onClose={onClose} title={t('logtail.title')} description={path} wide>
      {error && (
        <Callout tone="danger" title={t('logtail.error')}>
          {error}
        </Callout>
      )}
      {starting && !error && <p className="text-sm text-fg-faint">{t('logtail.starting')}</p>}
      <div
        ref={scrollRef}
        onScroll={(e) => {
          const el = e.currentTarget;
          atBottomRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
        }}
        className="mt-2 h-[55vh] overflow-y-auto rounded-lg border border-border bg-[oklch(0.18_0.01_60)] p-3 font-mono text-xs leading-relaxed text-fg"
      >
        {lines.length === 0 && !starting ? (
          <p className="text-fg-faint">{t('logtail.empty')}</p>
        ) : (
          lines.map((l) => (
            <div key={l.seq} className="whitespace-pre-wrap break-all">
              {l.text}
            </div>
          ))
        )}
      </div>
      <p className="mt-2 text-xs text-fg-faint">
        {done ? t('logtail.ended') : t('logtail.live')}
      </p>
    </Modal>
  );
}

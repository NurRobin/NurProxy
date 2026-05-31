import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Check, Copy } from 'lucide-react';
import { copyText } from '../lib/clipboard';

/**
 * CommandBlock renders a labelled <pre> of copy-paste shell text with a working
 * copy button. It uses copyText so it works over plain http too (hidden-textarea
 * fallback); the text also stays visible for manual selection if the copy fails.
 * Shared by the Existing-setup flow and the agent permission self-test block.
 *
 * An optional `explanation` adds a collapsible "What is this for?" disclosure
 * (§54) so an operator can understand a command before pasting it as root,
 * instead of running an opaque block on trust.
 */
export function CommandBlock({ text, label, explanation }: { text: string; label: string; explanation?: string }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);

  async function copy() {
    if (await copyText(text)) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  return (
    <div>
      <div className="mb-1 flex items-center justify-between gap-2">
        <span className="text-xs font-medium text-fg-muted">{label}</span>
        <button
          type="button"
          onClick={copy}
          className="inline-flex items-center gap-1 rounded-md border border-border bg-surface px-2 py-1 text-xs font-medium text-fg-muted transition-colors hover:text-fg"
        >
          {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
          {copied ? t('common.copied') : t('common.copy')}
        </button>
      </div>
      <pre className="overflow-x-auto rounded-lg border border-border bg-surface-2 p-3 font-mono text-xs leading-relaxed text-fg">
        {text}
      </pre>
      {explanation && (
        <details className="group mt-1.5">
          <summary className="cursor-pointer list-none text-xs font-medium text-fg-muted hover:text-fg">
            <span className="mr-1 inline-block select-none transition-transform group-open:rotate-90">▸</span>
          {t('commandBlock.whatIsThis')}
          </summary>
          <p className="mt-1.5 whitespace-pre-line text-xs leading-relaxed text-fg-faint">{explanation}</p>
        </details>
      )}
    </div>
  );
}

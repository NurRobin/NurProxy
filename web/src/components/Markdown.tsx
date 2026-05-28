import { Fragment, type ReactNode } from 'react';
import { Link } from 'react-router-dom';

/**
 * A small, dependency-free Markdown renderer for the offline wiki.
 * Supports: headings, paragraphs, ordered/unordered (nested) lists, fenced and
 * inline code, bold, links, blockquotes, and horizontal rules — the subset the
 * wiki actually uses. Internal links (no scheme) route to /help/<slug>.
 */

function slugify(s: string) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
}

const INLINE = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\*[^*\n]+\*)|(\[[^\]]+\]\([^)]+\))/g;

function renderInline(text: string, keyBase: string, onLink?: (slug: string) => void): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  let n = 0;
  INLINE.lastIndex = 0;
  while ((m = INLINE.exec(text)) !== null) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const token = m[0];
    const key = `${keyBase}-${n++}`;
    if (token.startsWith('`')) {
      out.push(<code key={key} className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[0.85em] text-fg">{token.slice(1, -1)}</code>);
    } else if (token.startsWith('**')) {
      out.push(<strong key={key} className="font-semibold text-fg">{token.slice(2, -2)}</strong>);
    } else if (token.startsWith('*')) {
      out.push(<em key={key} className="italic">{token.slice(1, -1)}</em>);
    } else {
      const mm = /^\[([^\]]+)\]\(([^)]+)\)$/.exec(token)!;
      const label = mm[1];
      const href = mm[2];
      const linkCls = 'font-medium text-accent hover:underline';
      if (/^(https?:|mailto:|\/)/.test(href)) {
        out.push(<a key={key} href={href} target="_blank" rel="noreferrer" className={linkCls}>{label}</a>);
      } else if (onLink) {
        // In-panel: switch topic without leaving the current page/form.
        out.push(<button key={key} type="button" onClick={() => onLink(href)} className={linkCls}>{label}</button>);
      } else {
        out.push(<Link key={key} to={`/help/${href}`} className={linkCls}>{label}</Link>);
      }
    }
    last = m.index + token.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

const leading = (s: string) => (s.match(/^ */)?.[0].length ?? 0);
const isListItem = (s: string) => /^\s*([-*]|\d+\.)\s+/.test(s);

function parseList(lines: string[], start: number, key: string, onLink?: (slug: string) => void): { node: ReactNode; next: number } {
  const baseIndent = leading(lines[start]);
  const ordered = /^\s*\d+\.\s/.test(lines[start]);
  const items: ReactNode[] = [];
  let i = start;
  while (i < lines.length) {
    const line = lines[i];
    if (line.trim() === '' || !isListItem(line) || leading(line) < baseIndent) break;
    const m = line.match(/^\s*(?:[-*]|\d+\.)\s+(.*)$/)!;
    if (leading(line) > baseIndent) break; // handled as nested by parent
    const parts = [m[1]];
    i++;
    // Absorb wrapped continuation lines (indented, non-blank, not a new item).
    while (i < lines.length && lines[i].trim() !== '' && !isListItem(lines[i]) && leading(lines[i]) > baseIndent) {
      parts.push(lines[i].trim());
      i++;
    }
    const content = parts.join(' ');
    let children: ReactNode = null;
    if (i < lines.length && isListItem(lines[i]) && leading(lines[i]) > baseIndent) {
      const sub = parseList(lines, i, `${key}-${items.length}s`, onLink);
      children = sub.node;
      i = sub.next;
    }
    items.push(<li key={items.length}>{renderInline(content, `${key}-${items.length}`, onLink)}{children}</li>);
  }
  const cls = ordered ? 'list-decimal' : 'list-disc';
  const node = ordered
    ? <ol key={key} className={`${cls} space-y-1.5 pl-5 text-fg-muted`}>{items}</ol>
    : <ul key={key} className={`${cls} space-y-1.5 pl-5 text-fg-muted`}>{items}</ul>;
  return { node, next: i };
}

export default function Markdown({ source, onLink }: { source: string; onLink?: (slug: string) => void }) {
  const lines = source.replace(/\r\n/g, '\n').split('\n');
  const blocks: ReactNode[] = [];
  let i = 0;
  let k = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (line.trim() === '') { i++; continue; }

    // Fenced code
    if (line.trim().startsWith('```')) {
      const code: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith('```')) { code.push(lines[i]); i++; }
      i++; // closing fence
      blocks.push(
        <pre key={k++} className="overflow-x-auto rounded-lg border border-border bg-surface-2 p-4 text-xs leading-relaxed text-fg">
          <code>{code.join('\n')}</code>
        </pre>,
      );
      continue;
    }

    // Heading
    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) {
      const level = h[1].length;
      const text = h[2];
      const id = slugify(text);
      const cls = level === 1 ? 'font-display text-2xl font-bold tracking-tight text-fg'
        : level === 2 ? 'font-display text-lg font-semibold text-fg mt-2'
        : 'text-sm font-semibold uppercase tracking-wide text-fg-faint';
      const props = { key: k++, id, className: cls };
      blocks.push(level === 1 ? <h1 {...props}>{text}</h1> : level === 2 ? <h2 {...props}>{text}</h2> : <h3 {...props}>{text}</h3>);
      i++;
      continue;
    }

    // Horizontal rule
    if (/^-{3,}$/.test(line.trim())) { blocks.push(<hr key={k++} className="border-border" />); i++; continue; }

    // Blockquote
    if (line.trimStart().startsWith('>')) {
      const quote: string[] = [];
      while (i < lines.length && lines[i].trimStart().startsWith('>')) {
        quote.push(lines[i].replace(/^\s*>\s?/, ''));
        i++;
      }
      blocks.push(
        <div key={k++} className="rounded-lg border border-border bg-surface-2 px-4 py-3 text-sm leading-relaxed text-fg-muted">
          {renderInline(quote.join(' '), `q${k}`, onLink)}
        </div>,
      );
      continue;
    }

    // List
    if (isListItem(line)) {
      const { node, next } = parseList(lines, i, `l${k++}`, onLink);
      blocks.push(<Fragment key={k++}>{node}</Fragment>);
      i = next;
      continue;
    }

    // Paragraph (gather consecutive plain lines)
    const para: string[] = [];
    while (i < lines.length && lines[i].trim() !== '' && !lines[i].trim().startsWith('```')
      && !lines[i].match(/^#{1,4}\s/) && !isListItem(lines[i])
      && !lines[i].trimStart().startsWith('>') && !/^-{3,}$/.test(lines[i].trim())) {
      para.push(lines[i].trim());
      i++;
    }
    blocks.push(<p key={k++} className="text-sm leading-relaxed text-fg-muted">{renderInline(para.join(' '), `p${k}`, onLink)}</p>);
  }

  return <div className="space-y-4">{blocks}</div>;
}

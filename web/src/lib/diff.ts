/**
 * Minimal line-based diff for the config drift/version views. Computes an LCS
 * over lines and emits an ordered list of equal / added / removed lines, which
 * the UI renders as a unified diff. Kept dependency-free and small — config
 * artifacts are short config files, not large source trees.
 */

export type DiffOp = 'equal' | 'add' | 'remove';

export interface DiffLine {
  op: DiffOp;
  /** Line number in the "before" text (1-indexed), undefined for added lines. */
  oldNo?: number;
  /** Line number in the "after" text (1-indexed), undefined for removed lines. */
  newNo?: number;
  text: string;
}

function splitLines(s: string): string[] {
  // Trailing newline yields an empty final element we don't want to diff.
  const lines = s.split('\n');
  if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
  return lines;
}

/** diffLines computes a unified line diff from `before` to `after`. */
export function diffLines(before: string, after: string): DiffLine[] {
  const a = splitLines(before);
  const b = splitLines(after);
  const n = a.length;
  const m = b.length;

  // LCS length table.
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }

  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ op: 'equal', oldNo: i + 1, newNo: j + 1, text: a[i] });
      i++;
      j++;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      out.push({ op: 'remove', oldNo: i + 1, text: a[i] });
      i++;
    } else {
      out.push({ op: 'add', newNo: j + 1, text: b[j] });
      j++;
    }
  }
  while (i < n) {
    out.push({ op: 'remove', oldNo: i + 1, text: a[i] });
    i++;
  }
  while (j < m) {
    out.push({ op: 'add', newNo: j + 1, text: b[j] });
    j++;
  }
  return out;
}

/** diffStats returns the count of added and removed lines for a summary chip. */
export function diffStats(lines: DiffLine[]): { added: number; removed: number } {
  let added = 0;
  let removed = 0;
  for (const l of lines) {
    if (l.op === 'add') added++;
    else if (l.op === 'remove') removed++;
  }
  return { added, removed };
}

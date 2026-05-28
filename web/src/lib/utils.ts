import i18n from './i18n';

/**
 * Locale-aware compact relative time (e.g. "5m ago" / "vor 5 Min."). Uses
 * Intl.RelativeTimeFormat keyed to the current language so it follows the
 * language switcher; falls back to en.
 */
export function formatRelativeTime(dateString: string): string {
  const diffSec = Math.round((Date.now() - new Date(dateString).getTime()) / 1000);
  const rtf = new Intl.RelativeTimeFormat(i18n.resolvedLanguage || 'en', { numeric: 'auto', style: 'narrow' });

  const abs = Math.abs(diffSec);
  if (abs < 60) return rtf.format(-diffSec, 'second');
  const min = Math.round(diffSec / 60);
  if (Math.abs(min) < 60) return rtf.format(-min, 'minute');
  const hr = Math.round(min / 60);
  if (Math.abs(hr) < 24) return rtf.format(-hr, 'hour');
  const day = Math.round(hr / 24);
  if (Math.abs(day) < 30) return rtf.format(-day, 'day');
  const mo = Math.round(day / 30);
  if (Math.abs(mo) < 12) return rtf.format(-mo, 'month');
  return rtf.format(-Math.round(mo / 12), 'year');
}

import { useParams, Link, useNavigate } from 'react-router-dom';
import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import Markdown from '../components/Markdown';
import { TOPICS, getTopic } from '../lib/wiki';

export default function Help() {
  const { t } = useTranslation();
  const { slug } = useParams();
  const navigate = useNavigate();
  const known = TOPICS.some((t) => t.slug === slug);

  // Unknown slug → fall back to the index.
  useEffect(() => {
    if (slug && !known) navigate('/help', { replace: true });
  }, [slug, known, navigate]);

  const current = getTopic(slug);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-display text-3xl font-bold tracking-tight text-fg">{t('help.title')}</h1>
        <p className="mt-1 text-sm text-fg-muted">{t('help.subtitle')}</p>
      </div>

      <div className="grid gap-8 lg:grid-cols-[15rem_1fr]">
        <nav className="lg:sticky lg:top-20 lg:self-start">
          <ul className="flex gap-2 overflow-x-auto pb-2 lg:flex-col lg:gap-0.5 lg:overflow-visible lg:pb-0">
            {TOPICS.map((t) => (
              <li key={t.slug} className="flex-shrink-0">
                <Link
                  to={`/help/${t.slug}`}
                  className={`block whitespace-nowrap rounded-lg px-3 py-2 text-sm font-medium transition-colors lg:whitespace-normal ${
                    t.slug === current.slug ? 'bg-accent-soft text-accent' : 'text-fg-muted hover:bg-surface-2 hover:text-fg'
                  }`}
                >
                  {t.title}
                </Link>
              </li>
            ))}
          </ul>
        </nav>

        <article className="min-w-0 max-w-2xl rounded-xl border border-border bg-surface p-6 shadow-card sm:p-8">
          <Markdown source={current.content} />
        </article>
      </div>
    </div>
  );
}

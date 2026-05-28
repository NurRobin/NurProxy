export default function BrandMark({ size = 26 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" aria-hidden="true" className="flex-shrink-0">
      <rect width="32" height="32" rx="8" fill="var(--accent)" />
      <g stroke="var(--accent-fg)" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" fill="none">
        <path d="M9 16 H15" />
        <path d="M15 16 C19 16 19 10 23 10" />
        <path d="M15 16 C19 16 19 22 23 22" />
      </g>
      <g fill="var(--accent-fg)">
        <circle cx="9" cy="16" r="2.6" />
        <circle cx="23" cy="10" r="2.4" />
        <circle cx="23" cy="22" r="2.4" />
      </g>
    </svg>
  );
}

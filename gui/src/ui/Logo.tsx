/** brainproxy's mark: a request passing through a gate, on the brand gradient. */
export function Logo({ size }: { size: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden className="logo">
      <defs>
        <linearGradient id="bp-logo" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#b33fe8" />
          <stop offset="1" stopColor="#7c5cd6" />
        </linearGradient>
      </defs>
      <rect x="1" y="1" width="30" height="30" rx="9" fill="url(#bp-logo)" />
      <path d="M8.5 11 L14 16 L8.5 21" fill="none" stroke="#fff" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="19.5" cy="16" r="2.4" fill="#fff" />
      <path d="M22 11 L24.5 11 M22 21 L24.5 21" stroke="#fff" strokeWidth="2.6" strokeLinecap="round" />
    </svg>
  );
}

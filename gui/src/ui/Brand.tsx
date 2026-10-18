// Assertive Infosec branding: the "A" mark and the clickable logo.

import { inTauri } from "../api";

export const SITE = "https://assertivesolutions.io";

/** Opens a link in the system browser (the desktop webview would otherwise navigate itself). */
export async function openExternal(url: string) {
  if (inTauri) {
    const { openUrl } = await import("@tauri-apps/plugin-opener");
    await openUrl(url);
  } else {
    window.open(url, "_blank", "noopener");
  }
}

/** The Assertive Infosec "A": letterform in the text colour, bar in the accent. */
export function AssertiveMark({ size }: { size: number }) {
  return (
    <svg width={size} height={size} viewBox="380 372 240 256" aria-label="Assertive Infosec" role="img">
      <path
        d="M391.57,616.56l131.89-233.12h71.37v233.12h-40.65v-50.95h-81.44l-27.13,50.95h-54.03ZM495.89,523.49h58.29v-106.65l-58.29,106.65Z"
        fill="var(--text)"
      />
      <path d="M554.17,616.56v-233.12h54.25v233.12h-54.25Z" fill="var(--accent)" />
    </svg>
  );
}

/** The AssertiveInfosec logo, linking to the site. */
function BrandLink({ className }: { className: string }) {
  return (
    <a
      href={SITE}
      onClick={(e) => {
        e.preventDefault();
        openExternal(SITE);
      }}
      className={className}
      title="Assertive Infosec: makers of brainproxy"
    >
      <AssertiveMark size={14} />
      <span className="madeby-word">
        Assertive<span>Infosec</span>
      </span>
    </a>
  );
}

/** Welcome screen: who makes brainproxy. */
export function MadeBy() {
  return <BrandLink className="madeby" />;
}

/** Sidebar, above Collapse: the logo, or just the mark when the sidebar is collapsed. */
export function SideBrand({ collapsed }: { collapsed: boolean }) {
  if (collapsed)
    return (
      <a
        href={SITE}
        onClick={(e) => {
          e.preventDefault();
          openExternal(SITE);
        }}
        className="side-brand-mark"
        title="Assertive Infosec: makers of brainproxy"
      >
        <AssertiveMark size={18} />
      </a>
    );
  return <BrandLink className="side-brand" />;
}

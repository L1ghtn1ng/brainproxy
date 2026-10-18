// Assertive Infosec branding: the "A" mark and the "made by" badge in the top bar.

import { inTauri } from "../api";
import { Icon } from "./Icons";

export const SITE = "https://assertivesolutions.io";
export const BRAINTRUDER = `${SITE}/products/braintruder`;

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

/** Centre of the top bar: who makes brainproxy, and their autonomous pentester. */
export function MadeBy() {
  const go = (url: string) => (e: React.MouseEvent) => {
    e.preventDefault();
    openExternal(url);
  };
  return (
    <div className="madeby">
      <a href={SITE} onClick={go(SITE)} className="madeby-brand" title="Assertive Infosec: AI-first security and compliance">
        <AssertiveMark size={15} />
        <span className="madeby-word">
          Assertive<span>Infosec</span>
        </span>
      </a>
      <span className="madeby-sep" />
      <a href={BRAINTRUDER} onClick={go(BRAINTRUDER)} className="madeby-pitch" title="Braintruder: autonomous AI pentesting, built on brainproxy">
        <span>
          Meet <b>Braintruder</b>, the autonomous AI pentester
        </span>
        <Icon name="arrow" size={13} />
      </a>
    </div>
  );
}

/** Sidebar version, above Collapse: a small card, or just the mark when the sidebar is collapsed. */
export function SideBrand({ collapsed }: { collapsed: boolean }) {
  const go = (url: string) => (e: React.MouseEvent) => {
    e.preventDefault();
    openExternal(url);
  };
  if (collapsed)
    return (
      <a href={SITE} onClick={go(SITE)} className="side-brand-mark" title="Assertive Infosec: makers of brainproxy and Braintruder">
        <AssertiveMark size={18} />
      </a>
    );
  return (
    <div className="side-brand">
      <a href={SITE} onClick={go(SITE)} className="side-brand-top" title="Assertive Infosec: AI-first security and compliance">
        <AssertiveMark size={15} />
        <span className="madeby-word">
          Assertive<span>Infosec</span>
        </span>
      </a>
      <a href={BRAINTRUDER} onClick={go(BRAINTRUDER)} className="side-brand-pitch" title="Braintruder: autonomous AI pentesting, built on brainproxy">
        Meet <b>Braintruder</b>, the autonomous AI pentester <Icon name="arrow" size={12} />
      </a>
    </div>
  );
}

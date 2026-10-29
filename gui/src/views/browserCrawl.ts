// The JavaScript (browser) crawl: whether it can run here, the flags that ask for it, and
// its progress line. It needs a Chromium-based browser (`brainproxy browser list`).

export interface BrowserInfo {
  id: string;
  name: string;
  kind: "chromium" | "firefox";
  path: string;
}

export interface BrowserList {
  browsers: BrowserInfo[];
  /** Whether this platform can run the browser crawl (not on Windows). */
  browser_crawl?: boolean;
}

/** Whether `browser list` found a Chromium-based browser the crawl can drive, on a platform that can run it. */
export const hasChromium = (list: BrowserList | null | undefined): boolean =>
  !!list && list.browser_crawl !== false && !!list.browsers?.some((b) => b.kind === "chromium");

/** `--browser` when it is asked for and a browser can run it. */
export const browserFlag = (wanted: boolean, available: boolean): string[] => (wanted && available ? ["--browser"] : []);

/** The guided scan runs JavaScript only at Thorough depth (it is slower than the plain crawl). */
export const wizardBrowserArgs = (depth: string, available: boolean): string[] => browserFlag(depth === "thorough", available);

/** Progress of a browser crawl (its progress carries `states`), or null for a plain crawl. */
export function browserProgress(p: Record<string, number | string> | null): string | null {
  if (!p || p.states == null) return null;
  return `browser · depth ${p.depth ?? 0} · ${p.states} states · ${p.clicks ?? 0} clicks · ${p.requests ?? 0} req · ${p.endpoints ?? 0} endpoints · ${p.queued ?? 0} queued`;
}

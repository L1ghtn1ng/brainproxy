import { useCallback, useEffect, useRef, useState } from "react";

/** Calls `load` now and every `ms` while the window is visible; returns [data, refreshNow]. */
export function usePoll<T>(load: () => Promise<T>, ms: number, enabled = true): [T | null, () => void] {
  const [data, setData] = useState<T | null>(null);
  const loader = useRef(load);
  loader.current = load;
  const refresh = useCallback(() => {
    loader.current().then(setData, () => {});
  }, []);
  useEffect(() => {
    if (!enabled) return;
    refresh();
    const t = setInterval(() => document.visibilityState === "visible" && refresh(), ms);
    return () => clearInterval(t);
  }, [ms, enabled, refresh]);
  return [data, refresh];
}

// For Jean-Luc Picard: typing "engage" outside a text field gets the reply he would give, and
// clicking the reply opens the ship.

import { useEffect, useRef, useState } from "react";
import { editable, MISSION, REPLY, RIP, SHIP, typed } from "./picard";

let open: (() => void) | null = null;

/** Replies through `reply` (a toast that runs `onClick` when clicked). Needs a mounted <EngageHost />. */
export function useEngage(reply: (text: string, kind: "info", onClick: () => void) => void) {
  const sofar = useRef("");
  const replyRef = useRef(reply);
  replyRef.current = reply;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key.length !== 1 || e.ctrlKey || e.metaKey || e.altKey || editable(e.target)) {
        sofar.current = "";
        return;
      }
      const [rest, done] = typed(sofar.current, e.key);
      sofar.current = rest;
      if (done) replyRef.current(REPLY, "info", () => open?.());
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
}

export function EngageHost() {
  const [shown, setShown] = useState(false);
  useEffect(() => {
    open = () => setShown(true);
    return () => {
      open = null;
    };
  }, []);
  if (!shown) return null;
  const close = () => setShown(false);
  return (
    <div className="confirm-backdrop" onClick={close} onKeyDown={(e) => e.key === "Escape" && close()}>
      <div className="confirm-dialog engage-dialog" role="dialog" aria-modal="true" aria-label="Engage" onClick={(e) => e.stopPropagation()}>
        <pre className="engage-ship">{SHIP}</pre>
        <p className="engage-mission">{MISSION}</p>
        <p className="engage-sign">Captain Jean-Luc Picard</p>
        <p className="engage-rip">{RIP}</p>
        <div className="row gap">
          <span className="grow" />
          <button className="btn" autoFocus onClick={close}>
            Make it so
          </button>
        </div>
      </div>
    </div>
  );
}

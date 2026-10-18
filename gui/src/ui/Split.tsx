// Two panes with a draggable divider. The split is a fraction, remembered per `id`.

import { useRef, useState, type ReactNode } from "react";

export function Split(p: { id: string; dir: "row" | "col"; initial?: number; children: [ReactNode, ReactNode] }) {
  const storeKey = `split:${p.id}`;
  const [frac, setFrac] = useState(() => {
    try {
      return Number(localStorage.getItem(storeKey)) || p.initial || 0.5;
    } catch {
      return p.initial ?? 0.5;
    }
  });
  const box = useRef<HTMLDivElement>(null);

  const drag = (e: React.MouseEvent) => {
    e.preventDefault();
    const rect = box.current!.getBoundingClientRect();
    let last = frac;
    const move = (m: MouseEvent) => {
      const f = p.dir === "row" ? (m.clientX - rect.left) / rect.width : (m.clientY - rect.top) / rect.height;
      last = Math.min(0.9, Math.max(0.1, f));
      setFrac(last);
    };
    const up = () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
      try {
        localStorage.setItem(storeKey, String(last));
      } catch {
        /* storage unavailable */
      }
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  };

  return (
    <div className={`split split-${p.dir}`} ref={box}>
      <div className="pane" style={{ flexBasis: `${frac * 100}%` }}>
        {p.children[0]}
      </div>
      <div className="divider" onMouseDown={drag} />
      <div className="pane" style={{ flexBasis: `${(1 - frac) * 100}%` }}>
        {p.children[1]}
      </div>
    </div>
  );
}

// Stacked transform pipeline: the input, then one panel per step, each step applied to the
// previous panel's output by `brainproxy encode|decode|hash KIND -`.

import { useEffect, useState } from "react";
import { bodyText, run, type Body } from "../api";

type Op = "encode" | "decode" | "hash";

const KINDS: Record<Op, string[]> = {
  encode: ["base64", "base64url", "url", "url-all", "hex", "html"],
  decode: ["base64", "base64url", "url", "hex", "html", "jwt"],
  hash: ["md5", "sha1", "sha256", "sha512"],
};

interface Step {
  op: Op;
  kind: string;
}

export function DecoderView() {
  const [input, setInput] = useState("");
  const [steps, setSteps] = useState<Step[]>([{ op: "decode", kind: "url" }]);
  const [outputs, setOutputs] = useState<{ text: string; error?: string }[]>([]);

  useEffect(() => {
    let live = true;
    const t = setTimeout(async () => {
      const out: { text: string; error?: string }[] = [];
      let text = input;
      for (const s of steps) {
        if (out.some((o) => o.error) || !text) {
          out.push({ text: "" });
          continue;
        }
        try {
          const d = await run<{ output: Body | unknown }>([s.op, s.kind, "-"], text);
          const o = d.output as Body;
          text = o && typeof o === "object" && "content" in o ? bodyText(o) : JSON.stringify(d.output, null, 2);
          out.push({ text });
        } catch (e: any) {
          out.push({ text: "", error: e.message });
        }
      }
      if (live) setOutputs(out);
    }, 250);
    return () => {
      live = false;
      clearTimeout(t);
    };
  }, [input, steps]);

  const update = (i: number, s: Partial<Step>) =>
    setSteps((ss) =>
      ss.map((x, j) => {
        if (j !== i) return x;
        const next = { ...x, ...s };
        if (!KINDS[next.op].includes(next.kind)) next.kind = KINDS[next.op][0];
        return next;
      }),
    );

  return (
    <div className="decoder">
      <div className="dec-panel">
        <div className="dec-head">
          <span className="label">Input</span>
        </div>
        <textarea className="code dec-text" spellCheck={false} value={input} onChange={(e) => setInput(e.target.value)} placeholder="Paste text to transform" />
      </div>
      {steps.map((s, i) => (
        <div className="dec-panel" key={i}>
          <div className="dec-head">
            <div className="seg">
              {(Object.keys(KINDS) as Op[]).map((op) => (
                <button key={op} className={s.op === op ? "on" : ""} onClick={() => update(i, { op })}>
                  {op === "encode" ? "Encode" : op === "decode" ? "Decode" : "Hash"}
                </button>
              ))}
            </div>
            <select className="input" value={s.kind} onChange={(e) => update(i, { kind: e.target.value })}>
              {KINDS[s.op].map((k) => (
                <option key={k}>{k}</option>
              ))}
            </select>
            <span className="grow" />
            <button className="btn small" onClick={() => navigator.clipboard.writeText(outputs[i]?.text ?? "")}>
              Copy
            </button>
            <button className="btn small" onClick={() => setInput(outputs[i]?.text ?? "")} title="Use this output as the input">
              Use as input
            </button>
            <button className="btn small" onClick={() => setSteps((ss) => ss.filter((_, j) => j !== i))} disabled={steps.length === 1}>
              Remove
            </button>
          </div>
          {outputs[i]?.error ? <div className="error">{outputs[i].error}</div> : <pre className="code dec-text">{outputs[i]?.text}</pre>}
        </div>
      ))}
      <button className="btn" onClick={() => setSteps((ss) => [...ss, { op: "decode", kind: "base64" }])}>
        + Add step
      </button>
    </div>
  );
}

// What the Render view of a response shows. Bodies arrive as text from `bodyText`: UTF-8
// as is, binary (base64 in the DB) as Latin-1 with one char per byte.

/** Responses above this are rendered only after a click. */
export const RENDER_CAP = 5 * 1024 * 1024;

// No network at all from the rendered page: requests would bypass the proxy and tip off
// the target. The iframe's sandbox="" already blocks scripts, forms, popups and navigation.
const LOCKDOWN =
  `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src data:">` +
  `<meta http-equiv="x-dns-prefetch-control" content="off">`;

export type Rendered =
  | { kind: "html"; srcdoc: string }
  | { kind: "image"; src: string }
  | { kind: "none"; type: string };

function bytes(s: string): Uint8Array {
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) > 255) return new TextEncoder().encode(s);
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

/** Decodes a Latin-1 byte string with the response charset; text that is already Unicode stays. */
function decodeBody(body: string, charset: string): string {
  if (/[^\x00-\xff]/.test(body)) return body;
  try {
    return new TextDecoder(charset, { fatal: /^utf-?8$/i.test(charset) }).decode(bytes(body));
  } catch {
    return body;
  }
}

/** Splits a raw response (\n line endings) and picks how to render its body. */
export function renderable(text: string): Rendered {
  const i = text.indexOf("\n\n");
  const head = i < 0 ? text : text.slice(0, i);
  const body = i < 0 ? "" : text.slice(i + 2);
  const ct = /^content-type:\s*([^\n]*)$/im.exec(head)?.[1].trim() ?? "";
  const type = ct.split(";")[0].trim().toLowerCase();
  if (type === "text/html" || type === "application/xhtml+xml") {
    const charset = /charset\s*=\s*"?([\w.:-]+)/i.exec(ct)?.[1] ?? "utf-8";
    // Page-supplied <meta> (refresh, its own CSP, ...) goes; ours comes first so it covers everything.
    // A regex, not a parser: the sandbox and the app CSP's frame-src remain the real guard.
    const html = decodeBody(body, charset).replace(/<meta\b[^>]*>/gi, "");
    return { kind: "html", srcdoc: LOCKDOWN + html };
  }
  if (type.startsWith("image/")) {
    let bin = "";
    const b = bytes(body);
    for (let n = 0; n < b.length; n += 0x8000) bin += String.fromCharCode(...b.subarray(n, n + 0x8000));
    return { kind: "image", src: `data:${type};base64,${btoa(bin)}` };
  }
  return { kind: "none", type: type || "no Content-Type" };
}

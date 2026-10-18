// URL encoding for raw requests typed by hand.

/** Characters that may appear literally in a URL (RFC 3986 unreserved, reserved, and '%'). */
const URL_SAFE = /[A-Za-z0-9\-._~!$&'()*+,;=:@/?%[\]]/;

/**
 * Percent-encodes what isn't valid in a URL (space, quotes, <>, #, `, {}, |, \, ^, controls,
 * non-ASCII as UTF-8) and keeps everything that gives it structure (/ ? & = ; and existing
 * %XX escapes), so `?q=a b&x=1` becomes `?q=a%20b&x=1`. A '%' not followed by two hex
 * digits becomes %25.
 */
export function encodeLoose(s: string): string {
  return encodeCounted(s)[0];
}

/** encodeLoose, plus how many characters it encoded. */
function encodeCounted(s: string): [string, number] {
  let out = "";
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "%" && /^[0-9a-fA-F]{2}$/.test(s.slice(i + 1, i + 3))) {
      out += c;
    } else if (c !== "%" && URL_SAFE.test(c)) {
      out += c;
    } else {
      // Keep surrogate pairs together so non-BMP characters encode as one UTF-8 sequence.
      const ch = String.fromCodePoint(s.codePointAt(i)!);
      out += encodeURIComponent(ch);
      i += ch.length - 1;
      n++;
    }
  }
  return [out, n];
}

/** Encodes everything except unreserved characters, for a selected value (Ctrl+U). */
export function encodeAll(s: string): string {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}

/** Decodes %XX escapes (and '+' as space when `plus`); leaves invalid escapes as they are. */
export function decode(s: string, plus = false): string {
  const t = plus ? s.replace(/\+/g, " ") : s;
  return t.replace(/(%[0-9a-fA-F]{2})+/g, (run) => {
    try {
      return decodeURIComponent(run);
    } catch {
      return run;
    }
  });
}

/**
 * Applies encodeLoose to a raw request's target (request line) and, for
 * application/x-www-form-urlencoded bodies, to the body. Returns the request to send and
 * how many characters were encoded.
 */
export function autoEncodeRequest(raw: string): { text: string; encoded: number } {
  const text = raw.replace(/\r\n/g, "\n");
  const split = text.indexOf("\n\n");
  const head = split < 0 ? text : text.slice(0, split);
  let body = split < 0 ? "" : text.slice(split + 2);
  const lines = head.split("\n");
  let encoded = 0;

  const m = /^(\S+)(\s+)(.+?)(\s+HTTP\/[\d.]+)?$/.exec(lines[0] ?? "");
  if (m) {
    const [target, n] = encodeCounted(m[3]);
    encoded += n;
    lines[0] = m[1] + m[2] + target + (m[4] ?? "");
  }
  if (lines.some((l) => /^content-type:\s*application\/x-www-form-urlencoded/i.test(l)) && body) {
    const [enc, n] = encodeCounted(body);
    body = enc;
    encoded += n;
  }
  return { text: lines.join("\n") + (split < 0 ? "" : "\n\n" + body), encoded };
}

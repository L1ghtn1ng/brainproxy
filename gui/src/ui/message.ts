// Line endings in raw messages shown and edited as text. A textarea holds only \n, and
// `send` turns a head's \n back into CRLF, but it leaves the body alone: a multipart or
// binary body that had CRLF must get its bytes back here.

// With its extension, so node --test can load this module (as the tests import theirs).
import { textBytes } from "../api.ts";

/** Head, blank-line separator and body of a raw message (CRLF or LF, whichever comes first). */
export function splitRaw(raw: string): { head: string; sep: string; body: string } {
  const crlf = raw.indexOf("\r\n\r\n");
  const lf = raw.indexOf("\n\n");
  if (crlf >= 0 && (lf < 0 || crlf < lf)) return { head: raw.slice(0, crlf), sep: "\r\n\r\n", body: raw.slice(crlf + 4) };
  if (lf >= 0) return { head: raw.slice(0, lf), sep: "\n\n", body: raw.slice(lf + 2) };
  return { head: raw, sep: "", body: "" };
}

/** The message with \n line endings in its head; the body as it was. */
export function normalizeHead(raw: string): string {
  const { head, sep, body } = splitRaw(raw);
  return head.replace(/\r\n/g, "\n") + (sep ? "\n\n" : "") + body;
}

/**
 * An edited message (all \n, as a textarea gives it) with the original's body line
 * endings: a body left as it was keeps its exact text, and an edited one gets CRLF
 * where the original body used CRLF.
 */
export function withBody(edited: string, original: string): string {
  const e = splitRaw(edited);
  const o = splitRaw(original);
  if (!e.sep || !o.body.includes("\r\n")) return edited;
  if (e.body === o.body.replace(/\r\n/g, "\n")) return e.head + e.sep + o.body;
  return e.head + e.sep + e.body.replace(/\r?\n/g, "\r\n");
}

/** UTF-8 bytes of the payload marker: what the fuzz engine looks for. */
const MARKER = new TextEncoder().encode("§");

/**
 * A fuzz template's bytes. Markers go out as UTF-8 "§" even when the text holds a
 * binary body (one char per byte), where "§" in the body is the byte 0xA7, not a
 * marker: positions in a binary body aren't possible.
 */
export function templateBytes(raw: string, binary: boolean): Uint8Array {
  if (!binary) return textBytes(raw);
  const { head, sep, body } = splitRaw(raw);
  const parts: Uint8Array[] = [];
  head.split("§").forEach((part, i) => {
    if (i > 0) parts.push(MARKER);
    parts.push(textBytes(part, true));
  });
  parts.push(textBytes(sep + body, true));
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** Where a template's markers may be: all of it, or only the head of a binary one. */
export function markable(raw: string, binary: boolean): string {
  return binary ? splitRaw(raw).head : raw;
}

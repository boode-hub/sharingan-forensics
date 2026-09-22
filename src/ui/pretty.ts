/**
 * Makes a structured value readable: XML one element per line and indented,
 * JSON indented. An event's payload arrives as a single line of XML, which is
 * faithful and unreadable; this is the same content laid out so each Data
 * value sits on a line of its own.
 */
import { parseXml, type XNode } from '../parsers/evtx/xpath';

const escText = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const escAttr = (s: string) => escText(s).replace(/"/g, '&quot;');

function render(n: XNode, depth: number, out: string[]) {
  const pad = '  '.repeat(depth);
  const attrs = Object.entries(n.attrs)
    .map(([k, v]) => ` ${k}="${escAttr(v)}"`)
    .join('');
  if (n.children.length === 0) {
    out.push(n.text ? `${pad}<${n.name}${attrs}>${escText(n.text)}</${n.name}>` : `${pad}<${n.name}${attrs}/>`);
    return;
  }
  out.push(`${pad}<${n.name}${attrs}>`);
  // Text beside child elements is rare in event XML, but it is content, so it
  // is kept rather than dropped for the sake of the layout.
  if (n.text.trim()) out.push(`${pad}  ${escText(n.text.trim())}`);
  for (const c of n.children) render(c, depth + 1, out);
  out.push(`${pad}</${n.name}>`);
}

/** XML laid out one element per line; null when the text is not XML. */
export function prettyXml(text: string): string | null {
  const t = text.trim();
  if (!t.startsWith('<') || !t.endsWith('>')) return null;
  const tree = parseXml(t);
  if (!tree) return null;
  const out: string[] = [];
  render(tree, 0, out);
  return out.join('\n');
}

/** JSON indented; null when the text is not a JSON object or array. */
export function prettyJson(text: string): string | null {
  const t = text.trim();
  if (!(t.startsWith('{') && t.endsWith('}')) && !(t.startsWith('[') && t.endsWith(']'))) return null;
  try {
    return JSON.stringify(JSON.parse(t), null, 2);
  } catch {
    return null;
  }
}

/** The readable form of a cell, or null when it is not structured. */
export function pretty(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  return prettyXml(value) ?? prettyJson(value);
}

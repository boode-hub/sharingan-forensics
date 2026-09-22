/**
 * A minimal XML reader and path selector for EvtxECmd's event maps.
 *
 * EvtxECmd loads each record's XML into an XPathDocument and resolves every
 * map value with SelectSingleNode. We cannot do that here: DOMParser does not
 * exist in a Web Worker, and a full XPath engine is far more than the maps
 * need. Across all 468 of his maps the paths use only four shapes —
 *
 *   /Event/EventData/Data[@Name="TargetUserName"]
 *   /Event/EventData/Data[3]
 *   /Event/UserData/EventInfo/Username
 *   /Event/System/Correlation/@ActivityID
 *
 * — so this resolves exactly those, with the same semantics: first match in
 * document order, an element's value being all of its descendant text.
 */

export interface XNode {
  name: string;
  attrs: Record<string, string>;
  children: XNode[];
  /** Text directly inside this element, already entity-decoded. */
  text: string;
}

const ENTITIES: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
};

export function decodeEntities(s: string): string {
  if (!s.includes('&')) return s;
  return s.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (whole, body: string) => {
    if (body[0] === '#') {
      const code = body[1] === 'x' || body[1] === 'X'
        ? parseInt(body.slice(2), 16)
        : parseInt(body.slice(1), 10);
      return Number.isFinite(code) && code > 0 ? String.fromCodePoint(code) : whole;
    }
    return ENTITIES[body] ?? whole;
  });
}

const TAG = /<(\/)?([A-Za-z_][\w.:-]*)((?:\s+[\w.:-]+\s*=\s*"[^"]*")*)\s*(\/)?>/g;
const ATTR = /([\w.:-]+)\s*=\s*"([^"]*)"/g;

/**
 * Parses the subset of XML our BinXML renderer emits. Anything it does not
 * recognise (comments, processing instructions, stray text) is skipped rather
 * than treated as an error: a record that renders oddly should still give up
 * whatever fields it does have.
 */
export function parseXml(xml: string): XNode | null {
  const root: XNode = { name: '#root', attrs: {}, children: [], text: '' };
  const stack: XNode[] = [root];

  TAG.lastIndex = 0;
  let last = 0;
  let m: RegExpExecArray | null;

  while ((m = TAG.exec(xml)) !== null) {
    const top = stack[stack.length - 1];
    if (m.index > last) {
      const between = xml.slice(last, m.index);
      if (between.trim()) top.text += decodeEntities(between);
    }
    last = TAG.lastIndex;

    const [, closing, name, attrText, selfClosing] = m;

    if (closing) {
      // Tolerate a stray close tag by unwinding only to a matching open.
      for (let i = stack.length - 1; i > 0; i--) {
        if (stack[i].name === name) {
          stack.length = i;
          break;
        }
      }
      continue;
    }

    const attrs: Record<string, string> = {};
    if (attrText) {
      ATTR.lastIndex = 0;
      let a: RegExpExecArray | null;
      while ((a = ATTR.exec(attrText)) !== null) attrs[a[1]] = decodeEntities(a[2]);
    }

    const node: XNode = { name, attrs, children: [], text: '' };
    top.children.push(node);
    if (!selfClosing) stack.push(node);
  }

  return root.children[0] ?? null;
}

/** All text in this element and its descendants, which is XPath's node value. */
export function nodeValue(n: XNode): string {
  let s = n.text;
  for (const c of n.children) s += nodeValue(c);
  return s;
}

/**
 * Resolves one of his map paths. Returns null when nothing matches, which is
 * the case EvtxECmd logs and substitutes with an empty string.
 */
export function selectSingleNode(root: XNode | null, path: string): string | null {
  if (!root || !path.startsWith('/')) return null;

  const segments = path.slice(1).split('/');
  if (segments.length === 0) return null;

  // A trailing /@Attr selects an attribute of the element before it.
  let attr: string | null = null;
  if (segments[segments.length - 1].startsWith('@')) {
    attr = segments.pop()!.slice(1);
    if (segments.length === 0) return null;
  }

  if (segments[0] !== root.name) return null;

  let current: XNode[] = [root];
  for (const seg of segments.slice(1)) {
    const named = /^([\w.:-]+)(?:\[(.+)\])?$/.exec(seg);
    if (!named) return null;
    const [, name, pred] = named;

    let next: XNode[] = [];
    for (const n of current) {
      next = next.concat(n.children.filter((c) => c.name === name));
    }

    if (pred !== undefined) {
      const byAttr = /^@([\w.:-]+)\s*=\s*"([^"]*)"$/.exec(pred);
      if (byAttr) {
        next = next.filter((n) => n.attrs[byAttr[1]] === byAttr[2]);
      } else if (/^\d+$/.test(pred)) {
        // XPath positions are 1-based.
        const one = next[parseInt(pred, 10) - 1];
        next = one ? [one] : [];
      } else {
        return null;
      }
    }

    if (next.length === 0) return null;
    current = next;
  }

  const node = current[0];
  if (attr !== null) return node.attrs[attr] ?? null;
  return nodeValue(node);
}

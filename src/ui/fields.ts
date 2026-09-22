/**
 * Finding a named field in a row, wherever it lives.
 *
 * A column is the obvious place, but for an event log most of what an analyst
 * filters on is inside the payload: TargetUserName, LogonType, CommandLine are
 * Data elements in the EventData, not columns. The filter language and the
 * Sigma engine both ask for fields by name, so both come through here, and a
 * name resolves to a column first and to the event's own fields second.
 */
import type { Column, Row } from '../core/types';
import { parseXml, type XNode } from '../parsers/evtx/xpath';

/** Case, spaces and punctuation ignored: "Event Id", "eventId" and "EventID" are one field. */
export function norm(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/** Normalised column key or label to the column key. */
export function columnIndex(columns: Column[]): Map<string, string> {
  const index = new Map<string, string>();
  for (const c of columns) {
    index.set(norm(c.key), c.key);
    index.set(norm(c.label), c.key);
  }
  return index;
}

const cache = new WeakMap<Row, Map<string, string[]>>();

function add(out: Map<string, string[]>, name: string, value: string) {
  const k = norm(name);
  if (!k) return;
  const list = out.get(k);
  if (list) list.push(value);
  else out.set(k, [value]);
}

function textOf(n: XNode): string {
  let s = n.text;
  for (const c of n.children) s += textOf(c);
  return s;
}

function collect(n: XNode, out: Map<string, string[]>) {
  // <Data Name="TargetUserName">bob</Data> is the field TargetUserName.
  if (n.name === 'Data' && n.attrs.Name !== undefined) {
    add(out, n.attrs.Name, textOf(n));
  } else if (n.children.length === 0) {
    // A leaf element: UserData payloads name their fields by tag.
    add(out, n.name, n.text);
  }
  // Attributes as Tag_Attr, which is how Sigma names System fields such as
  // Provider_Name.
  for (const [attr, value] of Object.entries(n.attrs)) {
    if (n.name === 'Data' && attr === 'Name') continue;
    add(out, `${n.name}_${attr}`, value);
  }
  for (const c of n.children) collect(c, out);
}

/**
 * Every named field in an event's XML. Parsed once per row and kept for as
 * long as the row is, because a filter or a rule asks the same row for many
 * fields.
 */
export function eventFields(row: Row): Map<string, string[]> {
  const hit = cache.get(row);
  if (hit) return hit;
  const out = new Map<string, string[]>();
  for (const source of [row.xml, row.payload]) {
    if (typeof source !== 'string' || !source.startsWith('<')) continue;
    const tree = parseXml(source);
    if (tree) collect(tree, out);
    // The full record already contains the payload, so one is enough.
    if (out.size > 0) break;
  }
  cache.set(row, out);
  return out;
}

/**
 * The values of a field in a row: the column's value if there is such a
 * column, otherwise every occurrence of that name in the event's XML. An empty
 * list means the row has no such field, which is different from a field that
 * is present and empty.
 */
export function fieldValues(row: Row, field: string, index: Map<string, string>): unknown[] {
  const key = index.get(norm(field));
  if (key !== undefined) {
    const v = row[key];
    return v === null || v === undefined ? [] : [v];
  }
  return eventFields(row).get(norm(field)) ?? [];
}

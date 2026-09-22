/**
 * A registry hive opened as a tree of keys, for parsers that read an artifact
 * stored inside one (Amcache, shimcache, shell bags).
 *
 * Follows Eric Zimmerman's RegistryHive (https://github.com/EricZimmerman/Registry):
 * ParseHive builds the live tree from the root, then BuildDeletedRegistryKeys
 * attaches recovered keys to it. A deleted key whose parent is another deleted
 * key becomes that key's child; a deleted key whose parent is still live is
 * appended to the live parent's SubKeys after its live children. That is why
 * his tools built on GetKey report deleted entries alongside live ones, and so
 * does anything built on this.
 */
import type { Ctx, Reader } from '../../core/types';
import { magic } from '../../core/binary';
import {
  collectCells,
  isFree,
  parseKey,
  readDataCell,
  readRawValue,
  valueText,
  type CellRec,
} from '../registry';
import { replayIfDirty } from './translog';

export interface HiveKey {
  rel: number;
  name: string;
  lastWrite: Date | null;
  /** Recovered from unallocated space rather than reached from the root. */
  deleted: boolean;
}

export interface HiveValue {
  name: string;
  type: number;
  bytes: Uint8Array;
  /** The value rendered as his KeyValue.ValueData. */
  data: string;
  rel: number;
  /** The vk cell is unallocated: the value outlived its deletion. */
  deleted: boolean;
}

export interface Hive {
  reader: Reader;
  root: HiveKey;
  /** Live subkeys in list order, then associated deleted ones. */
  subkeys(key: HiveKey): HiveKey[];
  /** His GetKey: a path below `from`, case-insensitive, live keys first. */
  key(from: HiveKey, path: string): HiveKey | null;
  values(key: HiveKey): Promise<HiveValue[]>;
}

const LF = 0x666c;
const LH = 0x686c;
const LI = 0x696c;
const RI = 0x6972;

/**
 * Replays the hive's logs if it is dirty and they came with it, then walks it.
 * Returns null, having said why, when the file is not a usable hive.
 */
export async function openHive(source: Reader, ctx: Ctx): Promise<Hive | null> {
  const reader = await replayIfDirty(source, ctx);
  const head = await reader.bytes(0, 4096);
  if (head.length < 4096 || !magic(head, 'regf', 0)) {
    ctx.warn(0, 'not a registry hive');
    return null;
  }
  const hv = new DataView(head.buffer, head.byteOffset, head.byteLength);
  if (hv.getUint32(4, true) !== hv.getUint32(8, true)) {
    ctx.warn(
      4,
      'hive is dirty and its .LOG1/.LOG2 files were not opened with it, so what follows is the hive as it was last flushed; open the logs alongside it to have them replayed',
    );
  }
  const minor = hv.getUint32(24, true);
  const rootRel = hv.getUint32(36, true);

  const { cells, lists, rootOffsets } = await collectCells(reader, ctx, hv.getUint32(40, true));
  const rootCell = cells.get(rootOffsets[0] ?? rootRel);
  const rootRec = rootCell?.sig === 'nk' ? parseKey(rootCell.buf) : null;
  if (!rootCell || !rootRec) {
    ctx.warn(0, 'root key not found');
    return null;
  }

  const children = new Map<number, HiveKey[]>();
  const live = new Set<number>();

  function listEntries(listRel: number, out: number[], depth: number) {
    const list = lists.get(listRel);
    if (!list || depth > 32) return;
    const dv = new DataView(list.buf.buffer, list.buf.byteOffset, list.buf.byteLength);
    const sig = dv.getUint16(4, true);
    const n = dv.getUint16(6, true);
    const stride = sig === LF || sig === LH ? 8 : 4; // lf/lh carry a name hash
    for (let i = 0; i < n; i++) {
      const at = 8 + i * stride;
      if (at + 4 > list.buf.length) break;
      const rel = dv.getUint32(at, true);
      if (sig === RI) listEntries(rel, out, depth + 1); // ri points at more lists
      else if (sig === LF || sig === LH || sig === LI) out.push(rel);
    }
  }

  async function valueList(listRel: number, count: number, extra: boolean): Promise<number[]> {
    if (listRel === 0 || listRel === 0xffffffff) return [];
    const list = await readDataCell(reader, listRel);
    if (!list) return [];
    const dv = new DataView(list.buffer, list.byteOffset, list.byteLength);
    const out: number[] = [];
    let i = 0;
    for (; i < count && i * 4 + 4 <= list.length; i++) out.push(dv.getUint32(i * 4, true));
    // A deleted key's list can still hold offsets from when it had more values.
    for (; extra && i * 4 + 4 <= list.length; i++) {
      const os = dv.getUint32(i * 4, true);
      if (os < 8 || os % 8 !== 0) break;
      if (!out.includes(os)) out.push(os);
    }
    return out;
  }

  const toKey = (cell: CellRec, deleted: boolean): HiveKey | null => {
    const k = parseKey(cell.buf);
    return k ? { rel: cell.rel, name: k.name, lastWrite: k.lastWrite, deleted } : null;
  };

  // The live tree, from the subkey lists alone, which are already in memory.
  // Values are read only when asked for: a SOFTWARE hive has hundreds of
  // thousands of keys and an artifact parser wants a handful of them.
  const root = toKey(rootCell, false) as HiveKey;
  const queue: HiveKey[] = [root];
  live.add(root.rel);
  for (let q = 0; q < queue.length; q++) {
    if (ctx.signal?.aborted) break;
    const key = queue[q];
    const rec = parseKey((cells.get(key.rel) as CellRec).buf);
    const subs: HiveKey[] = [];
    if (rec && rec.subkeyCount > 0) {
      const rels: number[] = [];
      listEntries(rec.subkeyListRel, rels, 0);
      for (const rel of rels) {
        const cell = cells.get(rel);
        if (!cell || cell.sig !== 'nk' || live.has(rel)) continue;
        const sub = toKey(cell, false);
        if (!sub) continue;
        live.add(rel);
        subs.push(sub);
        queue.push(sub);
      }
    }
    children.set(key.rel, subs);
  }

  // Deleted keys, with his sanity checks: a record too short for its own name
  // is not a key, and a value count this large is a reused cell.
  const deletedKeys = new Map<number, HiveKey>();
  const deletedParents = new Map<number, number>();
  for (const [rel, cell] of cells) {
    if (cell.sig !== 'nk' || live.has(rel)) continue;
    const rec = parseKey(cell.buf);
    if (!rec || rec.valueCount > 10000 || rec.name.length === 0) continue;
    deletedParents.set(rel, rec.parentRel);
    children.set(rel, []);
    deletedKeys.set(rel, toKey(cell, true) as HiveKey);
  }
  for (const [rel, parent] of deletedParents) {
    const key = deletedKeys.get(rel) as HiveKey;
    const parentCell = cells.get(parent);
    if (deletedKeys.has(parent) && parent !== rel) {
      (children.get(parent) as HiveKey[]).push(key);
    } else if (live.has(parent) && parentCell && !isFree(parentCell.buf)) {
      (children.get(parent) as HiveKey[]).push(key);
    }
  }

  // Every vk a live key lists. Needed only to keep an allocated value that a
  // live key owns from being claimed by a deleted key's stale list, so it is
  // built the first time that question comes up, not before.
  let referenced: Promise<Set<number>> | null = null;
  const referencedValues = () =>
    (referenced ??= (async () => {
      const set = new Set<number>();
      for (const rel of live) {
        const rec = parseKey((cells.get(rel) as CellRec).buf);
        if (rec) for (const v of await valueList(rec.valueListRel, rec.valueCount, false)) set.add(v);
      }
      return set;
    })());

  const values = async (key: HiveKey): Promise<HiveValue[]> => {
    const rec = parseKey((cells.get(key.rel) as CellRec).buf);
    if (!rec) return [];
    const out: HiveValue[] = [];
    for (const rel of await valueList(rec.valueListRel, rec.valueCount, key.deleted)) {
      const vk = cells.get(rel);
      if (vk?.sig !== 'vk') continue;
      // His rule for a deleted key: a value in use and claimed by a live key
      // is not this key's.
      if (key.deleted && !isFree(vk.buf) && (await referencedValues()).has(rel)) continue;
      const v = await readRawValue(reader, vk, minor);
      if (v) out.push({ ...v, data: valueText(v), rel, deleted: isFree(vk.buf) });
    }
    return out;
  };

  const subkeys = (key: HiveKey): HiveKey[] => children.get(key.rel) ?? [];

  return {
    reader,
    root,
    subkeys,
    values,
    key(from, path) {
      let current: HiveKey | null = from;
      for (const part of path.split('\\').filter(Boolean)) {
        if (!current) return null;
        const want = part.toLowerCase();
        const subs: HiveKey[] = subkeys(current).filter((k) => k.name.toLowerCase() === want);
        current = subs.find((k) => !k.deleted) ?? subs[0] ?? null;
      }
      return current;
    },
  };
}

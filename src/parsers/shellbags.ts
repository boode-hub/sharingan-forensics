/**
 * Shell bags: the folder browsing history Windows keeps in BagMRU.
 *
 * Every folder a user opens in Explorer leaves an entry, and the entry
 * survives the folder itself. A shell bag for a path on a removable drive, or
 * inside a deleted directory, or on a network share, is often the only
 * remaining evidence that the user went there.
 *
 * Eric Zimmerman's Shell Bags Explorer and SBECmd are not open source, so this
 * is not a port of them. What matters most, though, is: the entries are shell
 * items, and the shell item decoder here is ported from his Lnk library, which
 * uses the same ShellBag classes. The container around them - numbered keys
 * holding numbered binary values, with a NodeSlot and an MRUListEx - is
 * documented and simple.
 *
 * BagMRU lives at:
 *   UsrClass.dat  Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU
 *   NTUSER.DAT    Software\\Microsoft\\Windows\\Shell\\BagMRU
 *                 Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU
 */
import type { Column, Ctx, Parser, Reader, Row } from '../core/types';
import { magic } from '../core/binary';
import {
  collectCells,
  parseKey,
  readDataCell,
  readRawValue,
  type CellRec,
} from './registry';
import { parseShellItem, type ShellItem } from '../core/shellitem';

const columns: Column[] = [
  { key: 'absolutePath', label: 'Absolute Path', type: 'str' },
  { key: 'value', label: 'Value', type: 'str' },
  { key: 'shellType', label: 'Shell Type', type: 'str' },
  { key: 'created', label: 'Created On', type: 'date' },
  { key: 'modified', label: 'Modified On', type: 'date' },
  { key: 'accessed', label: 'Accessed On', type: 'date' },
  { key: 'mftEntry', label: 'MFT Entry', type: 'num' },
  { key: 'mftSequence', label: 'MFT Sequence', type: 'num' },
  { key: 'fileSystemHint', label: 'File System Hint', type: 'str' },
  { key: 'nodeSlot', label: 'Node Slot', type: 'num' },
  { key: 'mruPosition', label: 'MRU Position', type: 'num' },
  { key: 'lastWrite', label: 'Key Last Write', type: 'date' },
  { key: 'bagPath', label: 'Bag Path', type: 'str' },
  { key: 'sourceFile', label: 'Source File', type: 'str' },
  { key: 'offset', label: 'Offset', type: 'num', secondary: true },
];

/** How deep a bag tree may go before we assume the hive is lying to us. */
const MAX_DEPTH = 64;

export const shellbags: Parser = {
  id: 'shellbags',
  name: 'Shell Bags',
  ezTool: 'Shell Bags Explorer',
  extensions: [],
  columns,
  // A UsrClass.dat is a registry hive, and that is what an analyst who drops
  // one is most likely to want. Shell bags are a second question about the
  // same bytes, asked through "Parse as".
  manual: true,
  sniff(): boolean {
    return false;
  },
  async *parse(reader: Reader, ctx: Ctx): AsyncGenerator<Row> {
    const head = await reader.bytes(0, 4096);
    if (!magic(head, 'regf', 0)) {
      ctx.warn(0, 'not a registry hive, so it cannot hold shell bags');
      return;
    }

    const dv = new DataView(head.buffer, head.byteOffset, head.byteLength);
    const minor = dv.getUint32(24, true);
    const rootRel = dv.getUint32(36, true);
    const hbinLength = dv.getUint32(40, true);

    const { cells, lists, rootOffsets } = await collectCells(reader, ctx, hbinLength);
    const root = cells.get(rootOffsets[0] ?? rootRel);
    if (!root || root.sig !== 'nk') {
      ctx.warn(0, 'root key not found');
      return;
    }

    /** Subkeys of a key, by name, following the stable subkey lists. */
    function subkeys(cell: CellRec, depth = 0): Map<string, CellRec> {
      const out = new Map<string, CellRec>();
      const key = parseKey(cell.buf);
      if (!key || key.subkeyListRel === 0 || key.subkeyListRel === 0xffffffff) return out;

      const visit = (listRel: number, d: number) => {
        if (d > MAX_DEPTH) return;
        const list = lists.get(listRel);
        if (!list) return;
        const lv = new DataView(list.buf.buffer, list.buf.byteOffset, list.buf.byteLength);
        const sig = list.buf[4] | (list.buf[5] << 8);
        const n = lv.getUint16(6, true);
        const stride = sig === 0x666c || sig === 0x686c ? 8 : 4; // lf/lh carry a hash
        for (let i = 0; i < n; i++) {
          const at = 8 + i * stride;
          if (at + 4 > list.buf.length) break;
          const rel = lv.getUint32(at, true);
          if (sig === 0x6972) {
            visit(rel, d + 1); // ri points at more lists
            continue;
          }
          const nk = cells.get(rel);
          if (!nk || nk.sig !== 'nk') continue;
          const k = parseKey(nk.buf);
          if (k) out.set(k.name, nk);
        }
      };

      visit(key.subkeyListRel, depth);
      return out;
    }

    /** Every value of a key, by name. */
    async function values(cell: CellRec): Promise<Map<string, { type: number; bytes: Uint8Array; rel: number }>> {
      const out = new Map<string, { type: number; bytes: Uint8Array; rel: number }>();
      const key = parseKey(cell.buf);
      if (!key || key.valueListRel === 0 || key.valueListRel === 0xffffffff) return out;
      const list = await readDataCell(reader, key.valueListRel);
      if (!list) return out;
      const n = Math.min(key.valueCount, Math.floor(list.length / 4));
      for (let i = 0; i < n; i++) {
        const rel = new DataView(list.buffer, list.byteOffset + i * 4, 4).getUint32(0, true);
        const vk = cells.get(rel);
        if (!vk || vk.sig !== 'vk') continue;
        const v = await readRawValue(reader, vk, minor);
        if (v) out.set(v.name, { type: v.type, bytes: v.bytes, rel });
      }
      return out;
    }

    /** Walks down to a key by path, returning null if any step is missing. */
    function descend(from: CellRec, path: string[]): CellRec | null {
      let current: CellRec | null = from;
      for (const part of path) {
        if (!current) return null;
        const children = subkeys(current);
        current =
          children.get(part) ??
          [...children.entries()].find(([n]) => n.toLowerCase() === part.toLowerCase())?.[1] ??
          null;
      }
      return current;
    }

    const roots: Array<{ label: string; cell: CellRec }> = [];
    for (const path of [
      ['Local Settings', 'Software', 'Microsoft', 'Windows', 'Shell', 'BagMRU'],
      ['Software', 'Microsoft', 'Windows', 'Shell', 'BagMRU'],
      ['Software', 'Microsoft', 'Windows', 'ShellNoRoam', 'BagMRU'],
    ]) {
      const cell = descend(root, path);
      if (cell) roots.push({ label: path.join('\\'), cell });
    }

    if (roots.length === 0) {
      ctx.warn(
        0,
        'no BagMRU key in this hive; shell bags live in UsrClass.dat and NTUSER.DAT, not in SYSTEM or SOFTWARE',
      );
      return;
    }

    let emitted = 0;
    const guidNames = (await import('./lnk/guids')).GUID_NAMES;

    /**
     * Walks a BagMRU node. Each numbered value holds the shell item for the
     * subkey of the same number, so the two are read together: the value gives
     * the name and timestamps, the subkey gives the children.
     */
    async function* walk(
      node: CellRec,
      parentPath: string,
      bagPath: string,
      depth: number,
    ): AsyncGenerator<Row> {
      if (depth > MAX_DEPTH || ctx.signal?.aborted) return;

      const vals = await values(node);
      const kids = subkeys(node);
      const key = parseKey(node.buf);

      const nodeSlotRaw = vals.get('NodeSlot');
      const nodeSlot =
        nodeSlotRaw && nodeSlotRaw.bytes.length >= 4
          ? new DataView(
              nodeSlotRaw.bytes.buffer,
              nodeSlotRaw.bytes.byteOffset,
              nodeSlotRaw.bytes.byteLength,
            ).getUint32(0, true)
          : null;

      // MRUListEx lists the child indexes most-recently-used first, which is
      // the ordering an analyst cares about.
      const mru = vals.get('MRUListEx');
      const order = new Map<number, number>();
      if (mru) {
        const mv = new DataView(mru.bytes.buffer, mru.bytes.byteOffset, mru.bytes.byteLength);
        for (let i = 0; i * 4 + 4 <= mru.bytes.length; i++) {
          const idx = mv.getInt32(i * 4, true);
          if (idx < 0) break; // the list is terminated with -1
          if (!order.has(idx)) order.set(idx, i);
        }
      }

      const numbered = [...vals.entries()]
        .filter(([name]) => /^\d+$/.test(name))
        .sort((a, b) => Number(a[0]) - Number(b[0]));

      for (const [name, val] of numbered) {
        if (ctx.signal?.aborted) return;
        if (val.bytes.length < 3) continue;

        let item: ShellItem;
        try {
          item = parseShellItem(val.bytes, 0, guidNames);
        } catch {
          ctx.warn(val.rel + 4096, `shell bag value ${bagPath}\\${name} did not decode`);
          continue;
        }

        const absolutePath = parentPath ? `${parentPath}\\${item.value}` : item.value;
        const childBag = bagPath ? `${bagPath}\\${name}` : name;

        emitted++;
        yield {
          absolutePath,
          value: item.value,
          shellType: item.friendlyName,
          created: item.created,
          modified: item.modified,
          accessed: item.accessed,
          mftEntry: item.mftEntry,
          mftSequence: item.mftSequence,
          fileSystemHint: item.fileSystemHint,
          nodeSlot,
          mruPosition: order.has(Number(name)) ? order.get(Number(name)) : null,
          lastWrite: key?.lastWrite ?? null,
          bagPath: childBag,
          sourceFile: reader.name,
          offset: val.rel + 4096,
        };

        const child = kids.get(name);
        if (child) yield* walk(child, absolutePath, childBag, depth + 1);
      }
    }

    for (const { label, cell } of roots) {
      yield* walk(cell, '', label, 0);
    }

    if (emitted === 0) {
      ctx.warn(0, 'BagMRU is present but holds no entries');
    }
  },
};

/**
 * Application Compatibility Cache, better known as shimcache.
 *
 * Ported from Eric Zimmerman's AppCompatCache library (WindowsXP,
 * VistaWin2k3Win2k8, Windows7, Windows8x and Windows10 in
 * https://github.com/EricZimmerman/AppCompatCacheParser).
 *
 * Windows records the path, size and last-modified time of executables the
 * shim engine looked at, whether or not they ran, and keeps the list in the
 * SYSTEM hive until shutdown. It is one of the few places an executable that
 * has since been deleted still leaves its full path, which is why it is a
 * first stop for evidence of execution. On Windows 7 and earlier an entry also
 * records whether the program actually ran; from Windows 8 onwards that flag
 * is less reliable and is reported as the file says it, not interpreted.
 *
 * It lives in SYSTEM at:
 *   ControlSet00N\\Control\\Session Manager\\AppCompatCache\\AppCompatCache
 *   ControlSet00N\\Control\\Session Manager\\AppCompatibility\\AppCompatCache  (XP)
 */
import type { Column, Ctx, Parser, Reader, Row } from '../core/types';
import { filetime, magic } from '../core/binary';
import {
  collectCells,
  parseKey,
  readDataCell,
  readRawValue,
  type CellRec,
} from './registry';

const columns: Column[] = [
  { key: 'position', label: 'Cache Entry Position', type: 'num' },
  { key: 'path', label: 'Path', type: 'str' },
  { key: 'lastModified', label: 'Last Modified', type: 'date' },
  { key: 'executed', label: 'Executed', type: 'str' },
  { key: 'duplicate', label: 'Duplicate', type: 'bool' },
  { key: 'controlSet', label: 'Control Set', type: 'num' },
  { key: 'osVersion', label: 'Detected OS', type: 'str' },
  { key: 'sourceFile', label: 'Source File', type: 'str' },
  { key: 'offset', label: 'Offset', type: 'num', secondary: true },
];

/** His InsertFlag.Executed. The other bits are unknown and stay unread. */
const INSERT_EXECUTED = 0x00000002;

interface Entry {
  position: number;
  path: string;
  lastModified: Date | null;
  executed: string;
}

const utf16 = (b: Uint8Array): string => new TextDecoder('utf-16le').decode(b);

/** Paths are stored with the \??\ device prefix, which he strips. */
function cleanPath(s: string): string {
  return s.replace(/^\\\?\?\\/, '');
}

/** A FILETIME of zero means "not set", which he reports as no time at all. */
function modified(dv: DataView, at: number): Date | null {
  if (at + 8 > dv.byteLength) return null;
  const d = filetime(dv.getBigUint64(at, true));
  return d && d.getUTCFullYear() !== 1601 ? d : null;
}

function parseWindows10(b: Uint8Array, offsetToRecords: number): Entry[] {
  const out: Entry[] = [];
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let at = offsetToRecords;
  let position = 0;

  while (at + 12 <= b.length) {
    if (String.fromCharCode(b[at], b[at + 1], b[at + 2], b[at + 3]) !== '10ts') break;
    at += 8; // signature and four unknown bytes
    at += 4; // entry data size, which the fields below cover anyway

    const pathSize = dv.getUint16(at, true);
    at += 2;
    if (at + pathSize > b.length) break;
    const path = cleanPath(utf16(b.subarray(at, at + pathSize)));
    at += pathSize;

    const lastModified = modified(dv, at);
    at += 8;

    const dataSize = dv.getInt32(at, true);
    at += 4;
    if (dataSize < 0 || at + dataSize > b.length) break;
    const data = b.subarray(at, at + dataSize);
    at += dataSize;

    // The last four bytes of the entry data being 1 indicates execution.
    const executed =
      data.length >= 4 &&
      new DataView(data.buffer, data.byteOffset, data.byteLength).getInt32(data.length - 4, true) === 1
        ? 'Yes'
        : 'No';

    out.push({ position: position++, path, lastModified, executed });
  }
  return out;
}

function parseWindows8(b: Uint8Array, signature: string): Entry[] {
  const out: Entry[] = [];
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let at = 128;
  let position = 0;

  while (at + 12 <= b.length) {
    if (String.fromCharCode(b[at], b[at + 1], b[at + 2], b[at + 3]) !== signature) break;
    at += 8; // signature and four unknown bytes
    at += 4; // entry data size

    const pathSize = dv.getUint16(at, true);
    at += 2;
    if (at + pathSize > b.length) break;
    const path = cleanPath(utf16(b.subarray(at, at + pathSize)));
    at += pathSize;

    // Package data, present on store apps.
    const packageLen = dv.getUint16(at, true);
    at += 2 + packageLen;
    if (at + 16 > b.length) break;

    const insertFlags = dv.getInt32(at, true);
    at += 8; // insertion flags and shim flags

    const lastModified = modified(dv, at);
    at += 8;

    const dataSize = dv.getInt32(at, true);
    at += 4;
    if (dataSize < 0 || at + dataSize > b.length) break;
    at += dataSize;

    out.push({
      position: position++,
      path,
      lastModified,
      executed: (insertFlags & INSERT_EXECUTED) !== 0 ? 'Yes' : 'No',
    });
  }
  return out;
}

function parseWindows7(b: Uint8Array, is32: boolean): Entry[] {
  const out: Entry[] = [];
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const entryCount = dv.getInt32(4, true);
  if (entryCount === 0) return out;

  let at = 128;
  let position = 0;

  while (at < b.length && out.length !== entryCount) {
    const pathSize = dv.getUint16(at, true);
    at += 4; // path size and maximum path size

    let pathOffset: number;
    if (is32) {
      pathOffset = dv.getInt32(at, true);
      at += 4;
    } else {
      at += 4; // padding
      pathOffset = Number(dv.getBigInt64(at, true));
      at += 8;
    }

    const lastModified = modified(dv, at);
    at += 8;

    const insertFlags = dv.getInt32(at, true);
    at += 8; // insertion flags and shim flags
    at += is32 ? 8 : 16; // data size and data offset

    if (pathOffset < 0 || pathOffset + pathSize > b.length) break;
    out.push({
      position: position++,
      path: cleanPath(utf16(b.subarray(pathOffset, pathOffset + pathSize))),
      lastModified,
      executed: (insertFlags & INSERT_EXECUTED) !== 0 ? 'Yes' : 'No',
    });
  }
  return out;
}

function parseVista(b: Uint8Array, is32: boolean): Entry[] {
  const out: Entry[] = [];
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const entryCount = dv.getInt32(4, true);
  if (entryCount === 0) return out;

  let at = 8;
  let position = 0;

  while (at < b.length && out.length !== entryCount) {
    const pathSize = dv.getUint16(at, true);
    at += 4;

    let pathOffset: number;
    if (is32) {
      pathOffset = dv.getInt32(at, true);
      at += 4;
    } else {
      at += 4;
      pathOffset = Number(dv.getBigInt64(at, true));
      at += 8;
    }

    const lastModified = modified(dv, at);
    at += 8;
    at += 8; // insertion flags and shim flags

    if (pathOffset < 0 || pathOffset + pathSize > b.length) break;
    out.push({
      position: position++,
      path: cleanPath(utf16(b.subarray(pathOffset, pathOffset + pathSize))),
      lastModified,
      // He does not report execution for Vista: the flag is not trustworthy
      // there, and guessing would be worse than saying nothing.
      executed: 'N/A',
    });
  }
  return out;
}

function parseXp(b: Uint8Array): Entry[] {
  const out: Entry[] = [];
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const entryCount = dv.getInt32(4, true);
  if (entryCount === 0) return out;

  // XP uses fixed 552-byte records after a 400-byte header.
  let at = 400;
  let position = 0;

  while (at + 552 <= b.length && out.length !== entryCount) {
    const path = utf16(b.subarray(at, at + 528)).split('\0')[0].trim();
    at += 528;
    const lastModified = modified(dv, at);
    at += 8;
    at += 8; // file size
    at += 8; // last update time, which he does not report

    out.push({ position: position++, path: cleanPath(path), lastModified, executed: 'N/A' });
  }
  return out;
}

export const appCompatCache: Parser = {
  id: 'appcompatcache',
  name: 'AppCompat Cache (Shimcache)',
  ezTool: 'AppCompatCacheParser',
  extensions: [],
  columns,
  // The file is a SYSTEM hive; shimcache is one value inside it.
  manual: true,
  sniff(): boolean {
    return false;
  },
  async *parse(reader: Reader, ctx: Ctx): AsyncGenerator<Row> {
    const head = await reader.bytes(0, 4096);
    if (!magic(head, 'regf', 0)) {
      ctx.warn(0, 'not a registry hive; shimcache lives in the SYSTEM hive');
      return;
    }

    const hv = new DataView(head.buffer, head.byteOffset, head.byteLength);
    const minor = hv.getUint32(24, true);
    const rootRel = hv.getUint32(36, true);
    const hbinLength = hv.getUint32(40, true);

    const { cells, lists, rootOffsets } = await collectCells(reader, ctx, hbinLength);
    const root = cells.get(rootOffsets[0] ?? rootRel);
    if (!root || root.sig !== 'nk') {
      ctx.warn(0, 'root key not found');
      return;
    }

    function subkeys(cell: CellRec): Map<string, CellRec> {
      const out = new Map<string, CellRec>();
      const key = parseKey(cell.buf);
      if (!key || key.subkeyListRel === 0 || key.subkeyListRel === 0xffffffff) return out;

      const visit = (listRel: number, depth: number) => {
        if (depth > 32) return;
        const list = lists.get(listRel);
        if (!list) return;
        const lv = new DataView(list.buf.buffer, list.buf.byteOffset, list.buf.byteLength);
        const sig = list.buf[4] | (list.buf[5] << 8);
        const n = lv.getUint16(6, true);
        const stride = sig === 0x666c || sig === 0x686c ? 8 : 4;
        for (let i = 0; i < n; i++) {
          const at = 8 + i * stride;
          if (at + 4 > list.buf.length) break;
          const rel = lv.getUint32(at, true);
          if (sig === 0x6972) {
            visit(rel, depth + 1);
            continue;
          }
          const nk = cells.get(rel);
          if (!nk || nk.sig !== 'nk') continue;
          const k = parseKey(nk.buf);
          if (k) out.set(k.name.toLowerCase(), nk);
        }
      };
      visit(key.subkeyListRel, 0);
      return out;
    }

    function descend(from: CellRec, path: string[]): CellRec | null {
      let current: CellRec | null = from;
      for (const part of path) {
        if (!current) return null;
        current = subkeys(current).get(part.toLowerCase()) ?? null;
      }
      return current;
    }

    const controlSets = [...subkeys(root).entries()].filter(([name]) =>
      /^controlset\d+$/.test(name),
    );
    if (controlSets.length === 0) {
      ctx.warn(0, 'no ControlSet keys in this hive; shimcache lives in the SYSTEM hive');
      return;
    }

    let found = 0;

    for (const [setName, setCell] of controlSets) {
      if (ctx.signal?.aborted) return;
      const controlSet = Number(setName.replace(/\D/g, ''));

      for (const path of [
        ['Control', 'Session Manager', 'AppCompatCache'],
        ['Control', 'Session Manager', 'AppCompatibility'],
      ]) {
        const keyCell = descend(setCell, path);
        if (!keyCell) continue;

        const key = parseKey(keyCell.buf);
        if (!key || key.valueListRel === 0 || key.valueListRel === 0xffffffff) continue;
        const list = await readDataCell(reader, key.valueListRel);
        if (!list) continue;

        for (let i = 0; i < Math.min(key.valueCount, Math.floor(list.length / 4)); i++) {
          const rel = new DataView(list.buffer, list.byteOffset + i * 4, 4).getUint32(0, true);
          const vk = cells.get(rel);
          if (!vk || vk.sig !== 'vk') continue;
          const value = await readRawValue(reader, vk, minor);
          if (!value || value.name.toLowerCase() !== 'appcompatcache') continue;

          const b = value.bytes;
          if (b.length < 136) {
            ctx.warn(rel + 4096, `${setName}: AppCompatCache value is too short to hold a cache`);
            continue;
          }

          const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
          const sigNum = dv.getUint32(0, true);
          const sigAt128 = String.fromCharCode(b[128], b[129], b[130], b[131]);

          // 64-bit and 32-bit layouts differ for Vista and Windows 7. A 32-bit
          // cache has its first path offset in the low four bytes where a
          // 64-bit one has padding, so the padding being zero identifies it.
          const is32 = dv.getUint32(132, true) === 0 && sigNum === 0xbadc0fee;

          let entries: Entry[];
          let osVersion: string;

          if (sigNum === 0xdeadbeef) {
            osVersion = 'Windows XP';
            entries = parseXp(b);
          } else if (sigNum === 0xbadc0ffe) {
            osVersion = 'Windows Vista, Server 2003 or 2008';
            entries = parseVista(b, is32);
          } else if (sigNum === 0xbadc0fee) {
            osVersion = is32 ? 'Windows 7 (32-bit)' : 'Windows 7 or Server 2008 R2 (64-bit)';
            entries = parseWindows7(b, is32);
          } else if (sigAt128 === '00ts') {
            osVersion = 'Windows 8.0 or Server 2012';
            entries = parseWindows8(b, '00ts');
          } else if (sigAt128 === '10ts') {
            osVersion = 'Windows 8.1 or Server 2012 R2';
            entries = parseWindows8(b, '10ts');
          } else {
            const offsetToRecords = dv.getInt32(0, true);
            const sigAtRecords =
              offsetToRecords > 0 && offsetToRecords + 4 <= b.length
                ? String.fromCharCode(
                    b[offsetToRecords],
                    b[offsetToRecords + 1],
                    b[offsetToRecords + 2],
                    b[offsetToRecords + 3],
                  )
                : '';
            if (sigAtRecords !== '10ts') {
              ctx.warn(
                rel + 4096,
                `${setName}: unrecognised AppCompatCache header (0x${sigNum.toString(16)}); this is a layout the parser does not know`,
              );
              continue;
            }
            osVersion = offsetToRecords === 0x34 ? 'Windows 10 (1607+) or 11' : 'Windows 10';
            entries = parseWindows10(b, offsetToRecords);
          }

          // A path can appear in more than one control set. He marks the later
          // sightings rather than dropping them, because which control set an
          // entry came from is itself evidence.
          const seen = new Set<string>();
          for (const entry of entries) {
            if (ctx.signal?.aborted) return;
            const dedupeKey = `${entry.lastModified?.getTime() ?? 0}${entry.path.toUpperCase()}`;
            found++;
            yield {
              position: entry.position,
              path: entry.path,
              lastModified: entry.lastModified,
              executed: entry.executed,
              duplicate: seen.has(dedupeKey),
              controlSet,
              osVersion,
              sourceFile: reader.name,
              offset: rel + 4096,
            };
            seen.add(dedupeKey);
          }

          if (entries.length === 0) {
            ctx.warn(rel + 4096, `${setName}: the cache is present but empty`);
          }
        }
      }
    }

    if (found === 0) {
      ctx.warn(0, 'no AppCompatCache entries were found in this hive');
    }
  },
};

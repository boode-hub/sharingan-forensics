/**
 * OLE compound files (CFB): the container behind automatic jump lists, and
 * behind Office 97 documents, MSI packages and Thumbs.db.
 *
 * Ported from Eric Zimmerman's OleCf (https://github.com/EricZimmerman/OleCf),
 * which JLECmd reads jump lists with, checked against [MS-CFB]
 * (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/).
 * As in his OleCfFile, the directory is a flat list of every entry that has a
 * type and a name, in the order they are stored, not a walk of the red-black
 * tree; a jump list only ever needs to find streams by name.
 *
 * Where he throws on a chain that runs off the end of the file, this returns
 * what the chain did hold and says so: a jump list with one damaged stream
 * still has the others.
 */
import { filetime } from './binary';

export interface CfbEntry {
  name: string;
  /** 1 storage, 2 stream, 5 root. */
  type: number;
  created: Date | null;
  modified: Date | null;
  start: number;
  size: number;
}

export interface Cfb {
  entries: CfbEntry[];
  /** A stream's bytes, or null when it cannot be read at all. */
  read(entry: CfbEntry): Uint8Array | null;
}

const MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

export const isCfb = (head: Uint8Array) => MAGIC.every((b, i) => head[i] === b);

export function openCfb(buf: Uint8Array, warn: (offset: number, message: string) => void): Cfb | null {
  if (buf.length < 512 || !isCfb(buf)) {
    warn(0, 'not an OLE compound file');
    return null;
  }
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const sectorShift = dv.getUint16(30, true);
  const miniShift = dv.getUint16(32, true);
  if (sectorShift !== 9 && sectorShift !== 12) {
    warn(30, `sector size 2^${sectorShift} is not one a compound file uses`);
    return null;
  }
  const sectorSize = 1 << sectorShift;
  const miniSize = 1 << Math.min(miniShift, 12);
  const fatSectors = dv.getInt32(44, true);
  const dirStart = dv.getInt32(48, true);
  const miniCutoff = dv.getUint32(56, true);
  const miniFatStart = dv.getInt32(60, true);
  let difatSector = dv.getInt32(68, true);

  // The header sector is the file's first sector-sized block, so sector n
  // starts one sector further in.
  const at = (id: number) => (id + 1) * sectorSize;
  const perSector = sectorSize / 4;

  // Where the FAT's own sectors are: 109 in the header, the rest in a chain
  // of DIFAT sectors whose last slot points at the next one.
  const fatIds: number[] = [];
  for (let i = 0; i < 109 && fatIds.length < fatSectors; i++) {
    const id = dv.getInt32(76 + i * 4, true);
    if (id >= 0) fatIds.push(id);
  }
  const seenDifat = new Set<number>();
  while (difatSector >= 0 && fatIds.length < fatSectors && !seenDifat.has(difatSector)) {
    seenDifat.add(difatSector);
    const base = at(difatSector);
    if (base + sectorSize > buf.length) {
      warn(base, 'the DIFAT chain runs past the end of the file');
      break;
    }
    for (let i = 0; i < perSector - 1 && fatIds.length < fatSectors; i++) {
      const id = dv.getInt32(base + i * 4, true);
      if (id >= 0) fatIds.push(id);
    }
    difatSector = dv.getInt32(base + (perSector - 1) * 4, true);
  }

  const fat: number[] = [];
  for (const id of fatIds) {
    const base = at(id);
    if (base + sectorSize > buf.length) {
      warn(base, `FAT sector ${id} lies past the end of the file`);
      continue;
    }
    for (let i = 0; i < perSector; i++) fat.push(dv.getInt32(base + i * 4, true));
  }

  /** Sector numbers of a chain, stopping at its end marker or at a loop. */
  const chain = (start: number, table: number[]): number[] => {
    const out: number[] = [];
    const seen = new Set<number>();
    for (let id = start; id >= 0 && !seen.has(id); id = table[id] ?? -2) {
      seen.add(id);
      out.push(id);
    }
    return out;
  };

  const readFat = (start: number): Uint8Array => {
    const ids = chain(start, fat);
    const out = new Uint8Array(ids.length * sectorSize);
    let n = 0;
    for (const id of ids) {
      const part = buf.subarray(at(id), Math.min(at(id) + sectorSize, buf.length));
      out.set(part, n);
      n += part.length;
      if (part.length < sectorSize) break;
    }
    return out.subarray(0, n);
  };

  const dirBytes = readFat(dirStart);
  const entries: CfbEntry[] = [];
  const ddv = new DataView(dirBytes.buffer, dirBytes.byteOffset, dirBytes.byteLength);
  for (let off = 0; off + 128 <= dirBytes.length; off += 128) {
    const nameLen = ddv.getInt16(off + 64, true);
    const type = dirBytes[off + 66];
    // His test for a used slot: a type and a name.
    if (type === 0 || nameLen <= 0) continue;
    const nameBytes = dirBytes.subarray(off, off + Math.min(Math.max(nameLen - 2, 0), 64));
    entries.push({
      name: new TextDecoder('utf-16le').decode(nameBytes),
      type,
      created: filetime(ddv.getBigUint64(off + 100, true)),
      modified: filetime(ddv.getBigUint64(off + 108, true)),
      start: ddv.getUint32(off + 116, true),
      size: Math.max(0, ddv.getInt32(off + 120, true)),
    });
  }

  // Streams smaller than the cutoff live in the mini stream, which is the
  // root entry's own data, cut into 64-byte mini sectors with their own FAT.
  const root = entries.find((e) => e.type === 5 || e.name.toLowerCase() === 'root entry');
  const miniStream = root && root.size > 0 ? readFat(root.start) : new Uint8Array(0);
  const miniFatBytes = miniFatStart >= 0 ? readFat(miniFatStart) : new Uint8Array(0);
  const mdv = new DataView(miniFatBytes.buffer, miniFatBytes.byteOffset, miniFatBytes.byteLength);
  const miniFat: number[] = [];
  for (let i = 0; i + 4 <= miniFatBytes.length; i += 4) miniFat.push(mdv.getInt32(i, true));

  return {
    entries,
    read(entry) {
      if (entry.size === 0) return new Uint8Array(0);
      let data: Uint8Array;
      if (entry.size >= miniCutoff) {
        data = readFat(entry.start);
      } else {
        if (miniFat.length === 0) {
          warn(0, `stream ${entry.name} is in the mini stream, but the file has no mini FAT`);
          return null;
        }
        const ids = chain(entry.start, miniFat);
        data = new Uint8Array(ids.length * miniSize);
        let n = 0;
        for (const id of ids) {
          const part = miniStream.subarray(id * miniSize, Math.min((id + 1) * miniSize, miniStream.length));
          data.set(part, n);
          n += part.length;
        }
        data = data.subarray(0, n);
      }
      if (data.length < entry.size) {
        warn(0, `stream ${entry.name} should hold ${entry.size} bytes but its chain gives ${data.length}`);
        return data;
      }
      return data.subarray(0, entry.size);
    },
  };
}

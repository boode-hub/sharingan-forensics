/**
 * Windows Recycle Bin parser ($I and INFO2 files).
 * Format references:
 *   - https://github.com/libyal/dtformats/blob/main/documentation/Windows%20Recycle%20Bin.asciidoc
 *   - Eric Zimmerman's RBCmd
 */
import type { Column, Parser, Reader, Ctx, Row } from '../core/types';
import { Cursor, utf16 } from '../core/binary';

const columns: Column[] = [
  { key: 'fileType', label: 'File Type', type: 'str' },
  { key: 'version', label: 'Version', type: 'num' },
  { key: 'originalPath', label: 'Original Path', type: 'str' },
  { key: 'fileName', label: 'File Name', type: 'str' },
  { key: 'fileSize', label: 'File Size', type: 'num' },
  { key: 'deletedOn', label: 'Deleted On', type: 'date' },
  { key: 'recordIndex', label: 'Record Index', type: 'num', secondary: true },
  { key: 'driveLetter', label: 'Drive Letter', type: 'str', secondary: true },
  { key: 'sourceFile', label: 'Source File', type: 'str' },
  { key: 'offset', label: 'Offset', type: 'num', secondary: true },
];

// The INFO2 header is five 32-bit fields. Reading it as four shifts every
// record four bytes and corrupts all of them, which is the kind of failure
// that produces confident, wrong output rather than an error.
const INFO2_HEADER_SIZE = 20;

// Every INFO2 in the wild uses 800-byte records, and RBCmd reads that size
// unconditionally. The header's own field is checked against it rather than
// trusted, since a wrong value there would desynchronise the whole file.
const INFO2_RECORD_SIZE = 800;

function basename(path: string): string {
  const idx = path.lastIndexOf('\\');
  return idx === -1 ? path : path.slice(idx + 1);
}

function driveLetterFromNumber(driveNum: number): string | null {
  if (driveNum > 25) return null;
  return String.fromCharCode(65 + driveNum) + ':';
}

async function* parseDollarI(reader: Reader, ctx: Ctx): AsyncGenerator<Row> {
  const header = await reader.bytes(0, 24);
  if (header.length < 24) {
    ctx.warn(0, 'truncated $I header');
    return;
  }

  const c = new Cursor(header);
  const version = Number(c.u64());
  const fileSize = Number(c.u64());
  const deletedOn = c.filetime();

  if (version !== 1 && version !== 2) {
    ctx.warn(0, `unknown $I version ${version}`);
    return;
  }

  let originalPath = '';

  if (version === 1) {
    const pathBytes = await reader.bytes(24, 520);
    if (pathBytes.length < 520) {
      ctx.warn(24, `truncated v1 path field (${pathBytes.length}/520 bytes)`);
    }
    originalPath = utf16(pathBytes);
  } else {
    const lenBuf = await reader.bytes(24, 4);
    if (lenBuf.length < 4) {
      ctx.warn(24, 'truncated v2 path length');
      return;
    }
    const lenC = new Cursor(lenBuf);
    const charCount = lenC.u32();
    if (charCount === 0 || charCount > 32768) {
      ctx.warn(24, `implausible v2 path character count ${charCount}`);
      return;
    }
    const byteCount = charCount * 2;
    const pathBytes = await reader.bytes(28, byteCount);
    if (pathBytes.length < byteCount) {
      ctx.warn(28, `truncated v2 path (${pathBytes.length}/${byteCount} bytes)`);
    }
    originalPath = utf16(pathBytes);
  }

  if (!originalPath) {
    ctx.warn(0, 'empty original path');
  }

  yield {
    fileType: '$I',
    version,
    originalPath,
    fileName: basename(originalPath),
    fileSize,
    deletedOn,
    recordIndex: null,
    driveLetter: null,
    sourceFile: reader.name,
    offset: 0,
  };
}

async function* parseInfo2(reader: Reader, ctx: Ctx): AsyncGenerator<Row> {
  const header = await reader.bytes(0, INFO2_HEADER_SIZE);
  if (header.length < INFO2_HEADER_SIZE) {
    ctx.warn(0, 'truncated INFO2 header');
    return;
  }

  const h = new Cursor(header);
  const version = h.u32();
  h.u32(); // record count, unreliable
  h.u32(); // unknown
  const declaredSize = h.u32();

  if (declaredSize !== INFO2_RECORD_SIZE) {
    ctx.warn(
      12,
      `header declares ${declaredSize}-byte records; reading ${INFO2_RECORD_SIZE}-byte records, which is what Windows writes`,
    );
  }

  const recordSize = INFO2_RECORD_SIZE;
  let offset = INFO2_HEADER_SIZE;

  while (true) {
    if (ctx.signal?.aborted) break;

    const recordBuf = await reader.bytes(offset, recordSize);
    if (recordBuf.length === 0) break;
    if (recordBuf.length < 280) {
      ctx.warn(offset, `truncated INFO2 record at offset ${offset} (${recordBuf.length}/${recordSize} bytes)`);
      break;
    }

    const c = new Cursor(recordBuf);

    const ansiPath = c.ascii(260);
    const idx = c.u32();
    const driveNum = c.u32();
    const deletedOn = c.filetime();
    const fileSize = c.u32();
    const unicodePath = c.utf16(520);

    let originalPath = unicodePath;
    if (!originalPath) {
      originalPath = ansiPath;
      if (originalPath) {
        ctx.warn(offset + 280, 'UTF-16 path empty, fell back to ANSI path');
      }
    }

    if (!originalPath) {
      ctx.warn(offset, 'both UTF-16 and ANSI paths empty');
    }

    yield {
      fileType: 'INFO2',
      version,
      originalPath,
      fileName: basename(originalPath),
      fileSize: Number(fileSize),
      deletedOn,
      recordIndex: idx,
      driveLetter: driveLetterFromNumber(driveNum),
      sourceFile: reader.name,
      offset,
    };

    offset += recordSize;

    if (recordBuf.length < recordSize) break;
  }
}

function sniffDollarI(head: Uint8Array, filename: string): boolean {
  const name = filename.toLowerCase();
  if (name.startsWith('$i')) return true;

  if (head.length < 28) return false;
  const c = new Cursor(head);
  const version = c.u64();
  if (version !== 1n && version !== 2n) return false;

  if (version === 2n) {
    if (head.length < 28) return false;
    const len = new DataView(head.buffer, head.byteOffset + 24, 4).getUint32(0, true);
    return len > 0 && len <= 32768;
  }

  return true;
}

/**
 * INFO2 has no magic, so it is recognised by shape: a plausible version, the
 * 800-byte record size every Windows wrote, and a header that is followed by
 * whole records. Matching on the name alone would miss a carved or exported
 * copy, which is how these usually arrive.
 */
function sniffInfo2(head: Uint8Array, filename: string, size?: number): boolean {
  if (filename.toLowerCase() === 'info2') return true;
  if (head.length < INFO2_HEADER_SIZE) return false;

  const dv = new DataView(head.buffer, head.byteOffset, head.byteLength);
  const version = dv.getUint32(0, true);
  if (version > 5) return false;
  if (dv.getUint32(12, true) !== INFO2_RECORD_SIZE) return false;
  if (size !== undefined && (size - INFO2_HEADER_SIZE) % INFO2_RECORD_SIZE !== 0) return false;
  return true;
}

export const recycleBin: Parser = {
  id: 'recyclebin',
  name: 'Recycle Bin',
  ezTool: 'RBCmd',
  extensions: [],
  columns,
  sniff(head: Uint8Array, filename: string): boolean {
    return sniffDollarI(head, filename) || sniffInfo2(head, filename);
  },
  async *parse(reader: Reader, ctx: Ctx): AsyncGenerator<Row> {
    const name = reader.name.toLowerCase();
    const head = await reader.bytes(0, INFO2_HEADER_SIZE + 8);
    // INFO2 is checked first: its shape test is the stricter of the two, and a
    // $I test that leans on the file name would otherwise claim an INFO2
    // exported under a name beginning with "$i".
    if (sniffInfo2(head, name, reader.size)) {
      yield* parseInfo2(reader, ctx);
    } else {
      yield* parseDollarI(reader, ctx);
    }
  },
};
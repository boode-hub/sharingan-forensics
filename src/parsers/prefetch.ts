/**
 * Windows Prefetch parser (.pf files).
 * Format references:
 *   - https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc
 *   - Eric Zimmerman's PECmd
 */
import type { Column, Parser, Reader, Ctx, Row } from '../core/types';
import { Cursor, filetime, magic, utf16 } from '../core/binary';
import { unwrapMam } from '../core/xpress';

const columns: Column[] = [
  { key: 'executable', label: 'Executable', type: 'str' },
  { key: 'runTime', label: 'Run Time', type: 'date' },
  { key: 'runCount', label: 'Run Count', type: 'num' },
  { key: 'version', label: 'Version', type: 'num' },
  { key: 'hash', label: 'Name Hash', type: 'str' },
  { key: 'filesLoaded', label: 'Files Loaded', type: 'num' },
  { key: 'volumeDevice', label: 'Volume Device', type: 'str' },
  { key: 'volumeSerial', label: 'Volume Serial', type: 'str' },
  { key: 'volumeCreated', label: 'Volume Created', type: 'date' },
  { key: 'offset', label: 'Offset', type: 'num', secondary: true },
];

const HEADER_SIZE = 84;
const INFO_BLOCK_OFFSET = 84;

// Known versions: 17 (XP), 23 (Vista/7), 26 (Win8.1), 30 (Win10), 31 (Win11)
const SUPPORTED_VERSIONS = new Set([17, 23, 26, 30, 31]);

function parseHeader(buf: Uint8Array, ctx: Ctx, baseOffset: number): {
  version: number;
  executable: string;
  hash: string;
} | null {
  if (buf.length < HEADER_SIZE) {
    ctx.warn(baseOffset, 'truncated header');
    return null;
  }

  const c = new Cursor(buf, 0);
  const version = c.u32();
  const sig = c.take(4);
  const sigStr = String.fromCharCode(...sig);

  if (sigStr !== 'SCCA') {
    ctx.warn(baseOffset + 4, `expected SCCA signature, got ${sigStr}`);
    return null;
  }

  c.u32(); // unknown at offset 8
  c.u32(); // total file size at offset 12

  const executable = c.utf16(60);
  const hash = c.u32();
  c.u32(); // unknown at offset 80

  if (c.overran) {
    ctx.warn(baseOffset, 'header overrun');
  }

  if (!SUPPORTED_VERSIONS.has(version)) {
    ctx.warn(baseOffset, `unrecognised prefetch version ${version}, attempting v30/v31 layout`);
  }

  return {
    version,
    executable,
    hash: hash.toString(16).toUpperCase().padStart(8, '0'),
  };
}

function parseFileInfoBlock(buf: Uint8Array, ctx: Ctx, baseOffset: number): {
  stringsOffset: number;
  stringsSize: number;
  volumesOffset: number;
  volumesCount: number;
  volumesSize: number;
  runTimes: Array<{ time: Date | null; offset: number }>;
  runCount: number;
} | null {
  // Need at least up to offset 204 (runCount at 200 + 4 bytes)
  if (buf.length < 204) {
    ctx.warn(baseOffset + INFO_BLOCK_OFFSET, 'truncated file information block');
    return null;
  }

  const c = new Cursor(buf, 0);

  // Fields are at absolute offsets
  c.seek(100);
  const stringsOffset = c.u32();
  const stringsSize = c.u32();
  const volumesOffset = c.u32();
  const volumesCount = c.u32();
  const volumesSize = c.u32();

  // Run times at offset 128
  c.seek(128);
  const runTimes: Array<{ time: Date | null; offset: number }> = [];
  for (let i = 0; i < 8; i++) {
    const ft = c.u64();
    const time = filetime(ft);
    // Offset of this run time in the decompressed body
    const runTimeOffset = 128 + i * 8;
    if (time !== null) {
      runTimes.push({ time, offset: runTimeOffset });
    }
  }

  // Run count at offset 200
  c.seek(200);
  const runCount = c.u32();

  if (c.overran) {
    ctx.warn(baseOffset + INFO_BLOCK_OFFSET, 'file information block overrun');
  }

  return {
    stringsOffset,
    stringsSize,
    volumesOffset,
    volumesCount,
    volumesSize,
    runTimes,
    runCount,
  };
}

function parseFilenameStrings(buf: Uint8Array, offset: number, size: number, ctx: Ctx, baseOffset: number): number {
  if (size === 0 || offset + size > buf.length) {
    if (size > 0) {
      ctx.warn(baseOffset + offset, `filename strings exceed buffer (offset=${offset}, size=${size}, bufLen=${buf.length})`);
    }
    return 0;
  }

  let count = 0;
  let pos = offset;
  const end = offset + size;

  while (pos < end) {
    // Read NUL-terminated UTF-16 string
    let strEnd = pos;
    while (strEnd + 1 < end) {
      const dv = new DataView(buf.buffer, buf.byteOffset + strEnd, 2);
      if (dv.getUint16(0, true) === 0) break;
      strEnd += 2;
    }

    if (strEnd >= end) {
      ctx.warn(baseOffset + pos, 'unterminated filename string');
      break;
    }

    count++;
    pos = strEnd + 2; // Skip NUL terminator
  }

  return count;
}

function parseVolumeInfo(buf: Uint8Array, offset: number, count: number, ctx: Ctx, baseOffset: number): {
  device: string | null;
  serial: string | null;
  created: Date | null;
} {
  if (count === 0) {
    ctx.warn(baseOffset + offset, 'volume count is zero');
    return { device: null, serial: null, created: null };
  }

  // First volume entry at offset, each is 96 bytes for v30/v31
  const volOffset = offset;
  if (volOffset + 96 > buf.length) {
    ctx.warn(baseOffset + volOffset, 'volume entry exceeds buffer');
    return { device: null, serial: null, created: null };
  }

  const c = new Cursor(buf, volOffset);
  const devicePathOffset = c.u32(); // Relative to volumes-information offset
  const devicePathLength = c.u32(); // In characters, excluding NUL
  const volumeCreated = c.filetime();
  const volumeSerial = c.u32();

  if (c.overran) {
    ctx.warn(baseOffset + volOffset, 'volume entry overrun');
    return { device: null, serial: null, created: null };
  }

  // Device path is at volumesOffset + devicePathOffset
  const devicePathAbsOffset = offset + devicePathOffset;
  if (devicePathAbsOffset + devicePathLength * 2 > buf.length) {
    ctx.warn(baseOffset + devicePathAbsOffset, 'device path exceeds buffer');
    return { device: null, serial: null, created: null };
  }

  const devicePathBytes = buf.subarray(devicePathAbsOffset, devicePathAbsOffset + devicePathLength * 2);
  const device = utf16(devicePathBytes);
  const serial = volumeSerial.toString(16).toUpperCase().padStart(8, '0');

  return {
    device,
    serial,
    created: volumeCreated,
  };
}

export const prefetch: Parser = {
  id: 'prefetch',
  name: 'Prefetch',
  ezTool: 'PECmd',
  extensions: ['.pf'],
  columns,
  sniff(head: Uint8Array, _filename: string): boolean {
    // Check for MAM header (MAM\x04 or similar)
    if (magic(head, 'MAM', 0)) return true;
    // Check for SCCA at offset 4
    if (magic(head, 'SCCA', 4)) return true;
    return false;
  },
  async *parse(reader: Reader, ctx: Ctx): AsyncGenerator<Row> {
    // Read entire file (prefetch files are small, few hundred KB)
    const rawBuf = await reader.bytes(0, reader.size);

    // Decompress if MAM-wrapped
    let buf: Uint8Array;
    try {
      buf = unwrapMam(rawBuf);
    } catch (e) {
      ctx.warn(0, `MAM decompression failed: ${(e as Error).message}`);
      return;
    }

    // Parse header
    const header = parseHeader(buf, ctx, 0);
    if (!header) return;

    // Parse file information block
    const info = parseFileInfoBlock(buf, ctx, 0);
    if (!info) return;

    // Parse filename strings to get filesLoaded count
    const filesLoaded = parseFilenameStrings(buf, info.stringsOffset, info.stringsSize, ctx, 0);

    // Parse volume information (use first volume)
    const volume = parseVolumeInfo(buf, info.volumesOffset, info.volumesCount, ctx, 0);

    // Emit one row per run time
    for (const rt of info.runTimes) {
      if (ctx.signal?.aborted) break;

      yield {
        executable: header.executable,
        runTime: rt.time,
        runCount: info.runCount,
        version: header.version,
        hash: header.hash,
        filesLoaded,
        volumeDevice: volume.device,
        volumeSerial: volume.serial,
        volumeCreated: volume.created,
        offset: rt.offset,
      };
    }
  },
};